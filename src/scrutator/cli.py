import asyncio
import ipaddress
from pathlib import Path
from typing import Optional

import typer
import yaml

from scrutator.ai.config import AIConfig, AIMode, load_config
from scrutator.ai.doctor import render_doctor, run_doctor
from scrutator.ai.setup import build_runtime, cloud_hosts
from scrutator.ai.types import AIError
from scrutator.context import ai_client, open_context
from scrutator.model import Entity, EntityType
from scrutator.report import build_report, render_html, render_json
from scrutator.scan import run_scan
from scrutator.scope import ScopePolicy
from scrutator.store import Store
from scrutator.verify.narrative import summarise

app = typer.Typer(add_completion=False, no_args_is_help=True, help="Evidence-backed infrastructure OSINT.")
ai_app = typer.Typer(no_args_is_help=True, help="Inspect and test the AI backends.")
app.add_typer(ai_app, name="ai")

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


def _mode(value: str) -> AIMode:
    try:
        return AIMode(value)
    except ValueError as exc:
        raise _fail(f"--ai must be one of {[m.value for m in AIMode]}") from exc


def _config(path: Optional[Path]) -> AIConfig:
    try:
        return load_config(path)
    except (OSError, ValueError) as exc:
        raise _fail(f"cannot load config: {exc}") from exc


def _apexes(seed: Entity, scope_file: Optional[Path]) -> list[str]:
    if scope_file is not None:
        data = yaml.safe_load(scope_file.read_text(encoding="utf-8")) or {}
        domains = list(data.get("domains") or [])
        if domains:
            return domains
    return [seed.value] if seed.type is EntityType.DOMAIN else []


def _consent(config: AIConfig, mode: AIMode, yes_cloud: bool) -> None:
    hosts = cloud_hosts(config, mode)
    if not hosts or yes_cloud:
        return
    typer.echo(
        "Cloud AI is configured. These endpoints would receive graph summaries and evidence "
        "excerpts about the target: " + ", ".join(sorted(hosts))
    )
    typer.echo("Nothing is sent in local mode. --redact pseudonymises domains, IPs and organisation names.")
    if not typer.confirm("Send this data?", default=False):
        raise _fail("cloud AI declined")


@app.command()
def scan(
    seed: str = typer.Argument(..., help="Domain or IP address to investigate."),
    scope_file: Optional[Path] = typer.Option(None, "--scope", help="YAML scope file (domains, cidrs, asns)."),
    out: Path = typer.Option(Path("scrutator-out"), "--out", help="Output directory."),
    db: Optional[Path] = typer.Option(None, "--db", help="SQLite database path (default: <out>/scrutator.db)."),
    formats: str = typer.Option("json,html", "--format", help="Comma-separated: json, html."),
    max_entities: int = typer.Option(5000, "--max-entities", help="Soft cap on discovered entities."),
    max_steps: Optional[int] = typer.Option(None, "--max-steps", help="Cap on module runs (default: config, 60)."),
    ai: str = typer.Option("auto", "--ai", help="auto, off, local, cloud or hybrid."),
    model: Optional[str] = typer.Option(None, "--model", help="Model name for every AI role."),
    redact: Optional[bool] = typer.Option(None, "--redact/--no-redact", help="Pseudonymise prompts sent to cloud endpoints."),
    yes_cloud: bool = typer.Option(False, "--yes-cloud", help="Consent to cloud AI without a prompt."),
    summary: bool = typer.Option(True, "--summary/--no-summary", help="Write and verify an AI summary."),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Config file (default: ~/.config/scrutator/config.toml)."),
) -> None:
    """Run a passive scan and write evidence-backed reports."""
    wanted = {f.strip() for f in formats.split(",") if f.strip()}
    if not wanted or not wanted <= _FORMATS:
        raise _fail(f"--format must be a comma-separated subset of {sorted(_FORMATS)}")
    mode = _mode(ai)
    config = _config(config_path)
    try:
        seed_entity = _parse_seed(seed)
    except ValueError as exc:
        raise _fail(f"invalid seed {seed!r}: give a bare domain or IP address") from exc
    try:
        scope = ScopePolicy.from_file(scope_file) if scope_file else _default_scope(seed_entity)
        apexes = _apexes(seed_entity, scope_file)
    except (OSError, ValueError) as exc:
        raise _fail(f"cannot load scope: {exc}") from exc
    _consent(config, mode, yes_cloud)

    out.mkdir(parents=True, exist_ok=True)
    store = Store(db or out / "scrutator.db")

    async def go():
        async with open_context() as ctx, ai_client() as ai_http:
            runtime, used = await build_runtime(
                config, cli_mode=mode, model=model, consent_cloud=True, redact=redact,
                client=ai_http, apex_domains=apexes,
            )
            scan_id, stats = await run_scan(
                seed_entity, scope, store, ctx, ai=runtime,
                max_steps=max_steps or config.max_steps, max_entities=max_entities,
            )
            verdict = await summarise(runtime, store, scan_id) if runtime is not None and summary else None
            return scan_id, stats, runtime, used, verdict

    try:
        scan_id, stats, runtime, used, verdict = asyncio.run(go())
    except (ValueError, AIError) as exc:
        raise _fail(str(exc)) from exc

    ai_info = None
    if runtime is not None:
        ai_info = {"mode": used.value, **runtime.describe()}
    report = build_report(store, scan_id, ai_info=ai_info)
    written = []
    if "json" in wanted:
        (out / "report.json").write_text(render_json(report), encoding="utf-8")
        written.append("report.json")
    if "html" in wanted:
        (out / "report.html").write_text(render_html(report), encoding="utf-8")
        written.append("report.html")
    store.close()

    counts = report["summary"]
    typer.echo(
        f"Scan #{scan_id} of {seed_entity.value}: {counts['entities']} entities, "
        f"{counts['edges']} relations, {counts['findings']} findings "
        f"({stats.modules_run} module runs, {stats.rounds} rounds)."
    )
    if stats.steps_exhausted:
        typer.echo("Step budget reached: some lookups were not run. Raise --max-steps to cover them.")
    failed = sum(h["error"] for h in report["sources"].values())
    if failed:
        typer.echo(f"{failed} source run(s) failed after retries; see Source coverage in the report.")
    if runtime is None:
        typer.echo("AI: off (no local model found, or --ai off). Deterministic mode.")
    else:
        roles = ", ".join(
            f"{role} {p['provider']}/{p['model']} ({'local' if p['local'] else 'cloud'})"
            for role, p in runtime.describe()["providers"].items()
        )
        typer.echo(f"AI: {used.value}: {roles}")
        if verdict is not None:
            typer.echo(
                f"Summary: {len(verdict.verified)} statement(s) verified, {len(verdict.rejected)} rejected"
                + (f" ({verdict.skipped_reason})" if verdict.skipped_reason else "")
                + "."
            )
            if verdict.same_model:
                typer.echo("Warning: writer and verifier use the same model; use a different one for independence.")
    typer.echo(f"Wrote {', '.join(written)} to {out}")


@ai_app.command("doctor")
def doctor(
    ai: str = typer.Option("auto", "--ai", help="auto, local, cloud or hybrid."),
    model: Optional[str] = typer.Option(None, "--model", help="Model name for every AI role."),
    yes_cloud: bool = typer.Option(False, "--yes-cloud", help="Consent to cloud AI without a prompt."),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Config file."),
) -> None:
    """Measure the configured models with a built-in self-test."""
    mode = _mode(ai)
    config = _config(config_path)
    _consent(config, mode, yes_cloud)

    async def go():
        async with ai_client() as ai_http:
            runtime, used = await build_runtime(
                config, cli_mode=mode, model=model, consent_cloud=True, redact=None,
                client=ai_http, apex_domains=[],
            )
            if runtime is None:
                return None, used
            return await run_doctor(runtime), used

    try:
        report, used = asyncio.run(go())
    except AIError as exc:
        raise _fail(str(exc)) from exc
    if report is None:
        typer.echo("no AI runtime available: start Ollama or another local server, or configure [ai.*] roles.")
        raise typer.Exit(1)
    typer.echo(render_doctor(report))
    raise typer.Exit(0 if report.passed else 1)
