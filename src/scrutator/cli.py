import asyncio
import ipaddress
import json
from pathlib import Path
from typing import Optional

import httpx
import typer
import yaml

from scrutator.ai.config import AIConfig, AIMode, load_config
from scrutator.ai.doctor import render_doctor, run_doctor
from scrutator.ai.setup import build_runtime, cloud_hosts
from scrutator.ai.types import AIError
from scrutator.bundle.keys import (
    fingerprint,
    generate_keypair,
    load_private_key,
    load_public_raw,
    private_key_path,
    public_key_path,
)
from scrutator.bundle.reader import read_raw
from scrutator.bundle.replay import replay_evidence
from scrutator.bundle.verify import verify_bundle
from scrutator.bundle.writer import create_bundle
from scrutator.context import ai_client, open_context
from scrutator.diff import diff_reports, render_diff
from scrutator.model import Entity, EntityType
from scrutator.report import build_report, render_html, render_json
from scrutator.scan import run_scan
from scrutator.scope import ScopePolicy
from scrutator.store import Store
from scrutator.verify.narrative import summarise
from scrutator.watch import make_webhook_notifier, parse_interval, validate_webhook, watch_loop

app = typer.Typer(add_completion=False, no_args_is_help=True, help="Evidence-backed infrastructure OSINT.")
ai_app = typer.Typer(no_args_is_help=True, help="Inspect and test the AI backends.")
app.add_typer(ai_app, name="ai")

_FORMATS = {"json", "html"}
_sleep = asyncio.sleep


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


def _signing_key(key_dir: Optional[Path]):
    path = private_key_path(key_dir)
    if not path.exists():
        raise _fail(f"no signing key at {path}: run `scrutator keygen` first")
    try:
        return load_private_key(path)
    except ValueError as exc:
        raise _fail(str(exc)) from exc


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
    bundle: bool = typer.Option(False, "--bundle/--no-bundle", help="Also write a signed proof bundle to <out>/proof.scrutator."),
    key_dir: Optional[Path] = typer.Option(None, "--key-dir", help="Directory with signing.key (default: ~/.config/scrutator)."),
) -> None:
    """Run a passive scan and write evidence-backed reports."""
    wanted = {f.strip() for f in formats.split(",") if f.strip()}
    if not wanted or not wanted <= _FORMATS:
        raise _fail(f"--format must be a comma-separated subset of {sorted(_FORMATS)}")
    mode = _mode(ai)
    config = _config(config_path)
    signing_key = _signing_key(key_dir) if bundle else None
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

    if runtime is not None:
        store.set_meta(scan_id, "ai", json.dumps({"mode": used.value, **runtime.describe()}, sort_keys=True))
    report = build_report(store, scan_id)
    written = []
    if "json" in wanted:
        (out / "report.json").write_text(render_json(report), encoding="utf-8")
        written.append("report.json")
    if "html" in wanted:
        (out / "report.html").write_text(render_html(report), encoding="utf-8")
        written.append("report.html")
    bundle_path = None
    if signing_key is not None:
        bundle_path = out / "proof.scrutator"
        manifest = create_bundle(store, scan_id, signing_key, bundle_path)
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
    if bundle_path is not None:
        typer.echo(f"Proof bundle: {bundle_path} (signing key {manifest['key_fingerprint']})")


@app.command()
def keygen(
    key_dir: Optional[Path] = typer.Option(None, "--key-dir", help="Where to write signing.key and signing.pub."),
) -> None:
    """Create the Ed25519 key used to sign proof bundles."""
    target = key_dir or private_key_path().parent
    try:
        fp = generate_keypair(target)
    except FileExistsError as exc:
        raise _fail(str(exc)) from exc
    typer.echo(f"Wrote {private_key_path(target)} (keep it secret) and {public_key_path(target)} (share it).")
    typer.echo(f"Key fingerprint: {fp}")
    typer.echo("Give readers the fingerprint or signing.pub through a channel they trust; they pin it with `scrutator verify --pin`.")


@app.command()
def export(
    scan_id: Optional[int] = typer.Argument(None, help="Scan id (default: the latest scan in the database)."),
    db: Path = typer.Option(Path("scrutator-out/scrutator.db"), "--db", help="SQLite database."),
    bundle: Path = typer.Option(Path("proof.scrutator"), "--bundle", help="Output bundle path."),
    key_dir: Optional[Path] = typer.Option(None, "--key-dir", help="Directory with signing.key."),
) -> None:
    """Write a signed proof bundle for a scan."""
    key = _signing_key(key_dir)
    if not db.exists():
        raise _fail(f"no database at {db}")
    store = Store(db)
    scans = store.scans()
    if not scans:
        raise _fail("the database holds no scans")
    chosen = scan_id if scan_id is not None else scans[-1]["id"]
    try:
        manifest = create_bundle(store, chosen, key, bundle)
    except KeyError as exc:
        raise _fail(str(exc)) from exc
    finally:
        store.close()
    typer.echo(f"Wrote {bundle} for scan #{chosen} of {manifest['scan']['seed']} (signing key {manifest['key_fingerprint']}).")


def _pinned(pin: Optional[str]) -> Optional[str]:
    if pin is None:
        return None
    path = Path(pin)
    if path.is_file():
        try:
            return fingerprint(load_public_raw(path))
        except ValueError as exc:
            raise _fail(str(exc)) from exc
    return pin


@app.command()
def verify(
    bundle: Path = typer.Argument(..., help="A .scrutator proof bundle."),
    pin: Optional[str] = typer.Option(None, "--pin", help="Signer fingerprint (64 hex) or a signing.pub file to require."),
    replay: bool = typer.Option(False, "--replay", help="Re-issue the recorded requests and report drift."),
) -> None:
    """Check a proof bundle: hashes, signature, audit chain, evidence and findings."""
    report = verify_bundle(bundle, pinned_fingerprint=_pinned(pin))
    for check in report.checks:
        typer.echo(f"{'PASS' if check.ok else 'FAIL'}  {check.name}" + (f"  ({check.detail})" if check.detail else ""))
    if report.key_fingerprint:
        typer.echo(f"Signing key: {report.key_fingerprint}")
    for warning in report.warnings:
        typer.echo(f"Warning: {warning}")
    if not report.ok:
        typer.echo("Verification FAILED: do not rely on this bundle.")
        raise typer.Exit(1)
    typer.echo("Verification passed.")
    if not replay:
        return

    records = [json.loads(line) for line in read_raw(bundle).files["evidence.jsonl"].decode().splitlines() if line.strip()]

    async def go():
        async with open_context() as ctx:
            return await replay_evidence(records, ctx.http, ctx.resolver)

    results = asyncio.run(go())
    tally = {s: sum(1 for r in results if r.status == s) for s in ("unchanged", "changed", "unavailable", "skipped")}
    typer.echo(
        f"replay: {tally['unchanged']} unchanged, {tally['changed']} changed, "
        f"{tally['unavailable']} unavailable, {tally['skipped']} skipped"
    )
    for r in [r for r in results if r.status != "unchanged"][:20]:
        typer.echo(f"  {r.status:<11} {r.source}: {r.request[:90]}" + (f" ({r.detail})" if r.detail else ""))
    typer.echo("Changed and unavailable records are drift, not forgery: sources change and go down.")


def _load_report(ref: str, db: Path) -> tuple[dict, str]:
    if ref.isdigit():
        if not db.exists():
            raise _fail(f"no database at {db}")
        store = Store(db)
        try:
            return build_report(store, int(ref)), f"scan {ref}"
        except KeyError as exc:
            raise _fail(f"no scan {ref} in {db}") from exc
        finally:
            store.close()
    path = Path(ref)
    checked = verify_bundle(path)
    if not checked.ok:
        failing = next(c for c in checked.checks if not c.ok)
        raise _fail(f"{ref} failed verification ({failing.name}); refusing to use it")
    return json.loads(read_raw(path).files["report.json"]), path.name


@app.command()
def diff(
    old: str = typer.Argument(..., help="A scan id in --db, or a .scrutator bundle."),
    new: str = typer.Argument(..., help="A scan id in --db, or a .scrutator bundle."),
    db: Path = typer.Option(Path("scrutator-out/scrutator.db"), "--db", help="SQLite database for scan ids."),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Show what changed between two scans."""
    old_report, old_label = _load_report(old, db)
    new_report, new_label = _load_report(new, db)
    result = diff_reports(old_report, new_report)
    typer.echo(json.dumps(result.to_dict(), indent=2, sort_keys=True) if as_json else render_diff(result, old_label, new_label))


@app.command()
def watch(
    seed: str = typer.Argument(..., help="Domain or IP address to watch."),
    every: str = typer.Option("24h", "--every", help="Interval: 30s, 15m, 6h, 1d."),
    scope_file: Optional[Path] = typer.Option(None, "--scope", help="YAML scope file."),
    out: Path = typer.Option(Path("scrutator-watch"), "--out", help="Output directory."),
    db: Optional[Path] = typer.Option(None, "--db", help="SQLite database (default: <out>/scrutator.db)."),
    webhook: Optional[str] = typer.Option(None, "--webhook", help="POST a JSON summary of changes (https only, or localhost)."),
    max_runs: int = typer.Option(0, "--max-runs", help="Stop after N scans (0 = run until interrupted)."),
    max_steps: int = typer.Option(60, "--max-steps", help="Cap on module runs per scan."),
) -> None:
    """Re-scan on a schedule and report what changed (deterministic scans, no AI)."""
    try:
        interval = parse_interval(every)
        if webhook is not None:
            validate_webhook(webhook)
        seed_entity = _parse_seed(seed)
        scope = ScopePolicy.from_file(scope_file) if scope_file else _default_scope(seed_entity)
    except (OSError, ValueError) as exc:
        raise _fail(str(exc)) from exc
    out.mkdir(parents=True, exist_ok=True)
    store = Store(db or out / "scrutator.db")

    def report_run(scan_id: int, previous: Optional[int], result) -> None:
        typer.echo(f"Run {scan_id}: scan #{scan_id} of {seed_entity.value} finished.")
        if result is None:
            typer.echo("  first scan for this seed; nothing to compare yet")
            return
        typer.echo(render_diff(result, f"scan {previous}", f"scan {scan_id}"))
        if not result.empty:
            (out / f"diff-{scan_id}.json").write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

    async def run_once() -> int:
        async with open_context() as ctx:
            scan_id, _ = await run_scan(seed_entity, scope, store, ctx, max_steps=max_steps)
        return scan_id

    async def go():
        async with httpx.AsyncClient() as client:
            notify = make_webhook_notifier(webhook, client) if webhook else None
            await watch_loop(
                run_once=run_once, store=store, seed=seed_entity.value, interval=interval,
                max_runs=max_runs, notify=notify, sleep=lambda seconds: _sleep(seconds), on_run=report_run,
            )

    try:
        asyncio.run(go())
    except KeyboardInterrupt:
        typer.echo("Stopped.")
    finally:
        store.close()


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
