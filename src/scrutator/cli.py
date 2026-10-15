import asyncio
import ipaddress
from pathlib import Path
from typing import Optional

import typer

from scrutator.context import open_context
from scrutator.model import Entity, EntityType
from scrutator.report import build_report, render_html, render_json
from scrutator.scan import run_scan
from scrutator.scope import ScopePolicy
from scrutator.store import Store

app = typer.Typer(add_completion=False, no_args_is_help=True, help="Evidence-backed infrastructure OSINT.")

_FORMATS = {"json", "html"}


@app.callback()
def main() -> None:
    """Scrutator."""


def _parse_seed(raw: str) -> Entity:
    try:
        ipaddress.ip_address(raw.strip())
        return Entity(type=EntityType.IP, value=raw)
    except ValueError:
        return Entity(type=EntityType.DOMAIN, value=raw)


def _default_scope(seed: Entity) -> ScopePolicy:
    if seed.type is EntityType.IP:
        return ScopePolicy(cidrs=[seed.value])
    return ScopePolicy(domains=[seed.value])


def _fail(message: str) -> typer.Exit:
    typer.echo(f"error: {message}", err=True)
    return typer.Exit(2)


@app.command()
def scan(
    seed: str = typer.Argument(..., help="Domain or IP address to investigate."),
    scope_file: Optional[Path] = typer.Option(None, "--scope", help="YAML scope file (domains, cidrs, asns)."),
    out: Path = typer.Option(Path("scrutator-out"), "--out", help="Output directory."),
    db: Optional[Path] = typer.Option(None, "--db", help="SQLite database path (default: <out>/scrutator.db)."),
    formats: str = typer.Option("json,html", "--format", help="Comma-separated: json, html."),
    max_entities: int = typer.Option(5000, "--max-entities", help="Soft cap on discovered entities."),
) -> None:
    """Run a passive scan and write evidence-backed reports."""
    wanted = {f.strip() for f in formats.split(",") if f.strip()}
    if not wanted or not wanted <= _FORMATS:
        raise _fail(f"--format must be a comma-separated subset of {sorted(_FORMATS)}")
    try:
        seed_entity = _parse_seed(seed)
    except ValueError as exc:
        raise _fail(f"invalid seed {seed!r}: give a bare domain or IP address") from exc
    try:
        scope = ScopePolicy.from_file(scope_file) if scope_file else _default_scope(seed_entity)
    except (OSError, ValueError) as exc:
        raise _fail(f"cannot load scope: {exc}") from exc

    out.mkdir(parents=True, exist_ok=True)
    store = Store(db or out / "scrutator.db")

    async def go():
        async with open_context() as ctx:
            return await run_scan(seed_entity, scope, store, ctx, max_entities=max_entities)

    try:
        scan_id, stats = asyncio.run(go())
    except ValueError as exc:
        raise _fail(str(exc)) from exc

    report = build_report(store, scan_id)
    written = []
    if "json" in wanted:
        (out / "report.json").write_text(render_json(report), encoding="utf-8")
        written.append("report.json")
    if "html" in wanted:
        (out / "report.html").write_text(render_html(report), encoding="utf-8")
        written.append("report.html")
    store.close()

    summary = report["summary"]
    typer.echo(
        f"Scan #{scan_id} of {seed_entity.value}: {summary['entities']} entities, "
        f"{summary['edges']} relations, {summary['findings']} findings "
        f"({stats.modules_run} module runs, {stats.rounds} rounds)."
    )
    typer.echo(f"Wrote {', '.join(written)} to {out}")
