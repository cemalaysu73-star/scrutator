import asyncio
import ipaddress
import json
import os
import sys
from pathlib import Path
from typing import Optional

import typer
import yaml

from scrutator.ai.config import AIConfig, AIMode, load_config
from scrutator.ai.doctor import render_doctor, run_doctor
from scrutator.ai.setup import build_runtime, cloud_hosts
from scrutator.agent.runner import AgentStats
from scrutator.ai.types import AIError
from scrutator.analyst.leads import run_leads
from scrutator.attribution import BANDS
from scrutator.attribution.model import band_rank
from scrutator.attribution.promote import PromotionError
from scrutator.attribution.promote import promote as promote_candidate
from scrutator.bundle.keys import (
    PASSPHRASE_ENV,
    fingerprint,
    generate_keypair,
    is_encrypted,
    load_private_key,
    load_public_raw,
    permission_problem,
    private_key_path,
    protect_key,
    public_key_path,
)
from scrutator.bundle.reader import read_raw
from scrutator.bundle.replay import replay_evidence, subject_names
from scrutator.bundle.verify import verify_bundle
from scrutator.bundle.writer import create_bundle
from scrutator.context import ai_client, open_context
from scrutator.deadline import DEFAULT_DEADLINE_S, Deadline
from scrutator.engine import DEFAULT_BREAKER_THRESHOLD
from scrutator.diff import diff_reports, render_diff
from scrutator.mcp_tools import ToolSet
from scrutator.model import Entity, EntityType
from scrutator.packs import PackError, build_manifest, load_packs, validate_dir
from scrutator.report import build_report, render_html, render_json
from scrutator.report.sarif import to_sarif
from scrutator.risk.model import Severity, severity_at_least
from scrutator.scan import run_scan
from scrutator.modules.registry import load_builtin_modules
from scrutator.scope import ScopePolicy
from scrutator.sources import SourceError, SourcePolicy
from scrutator.sources import describe as describe_sources
from scrutator.store import Store
from scrutator.textsafe import terminal_safe
from scrutator.verify.narrative import summarise
from scrutator.watch import make_webhook_client, make_webhook_notifier, parse_interval, validate_webhook, watch_loop

app = typer.Typer(add_completion=False, no_args_is_help=True, help="Evidence-backed infrastructure OSINT.")
ai_app = typer.Typer(no_args_is_help=True, help="Inspect and test the AI backends.")
app.add_typer(ai_app, name="ai")
packs_app = typer.Typer(no_args_is_help=True, help="Inspect and validate knowledge packs.")
app.add_typer(packs_app, name="packs")

_FORMATS = {"json", "html"}
_sleep = asyncio.sleep


def _echo(message: object = "", **kwargs) -> None:
    """Everything this tool prints may quote data from sources or from a bundle someone handed you: control and
    bidirectional-override characters are shown as escapes, never sent to the terminal."""
    typer.echo(terminal_safe(str(message)), **kwargs)


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
    _echo(f"error: {message}", err=True)
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
    _echo(
        "Cloud AI is configured. These endpoints would receive graph summaries and evidence "
        "excerpts about the target: " + ", ".join(sorted(hosts))
    )
    _echo("Nothing is sent in local mode. --redact pseudonymises domains, IPs and organisation names.")
    if not typer.confirm("Send this data?", default=False):
        raise _fail("cloud AI declined")


def _load_packs(directories: list[Path]):
    try:
        return load_packs(directories)
    except PackError as exc:
        raise _fail(f"cannot load packs:\n{exc}") from exc


def _source_policy(sources: Optional[str], exclude_sources: Optional[str], no_noncommercial: bool) -> SourcePolicy:
    modules = load_builtin_modules()
    try:
        policy = SourcePolicy.parse(sources, exclude_sources, no_noncommercial, modules)
    except SourceError as exc:
        raise _fail(str(exc)) from exc
    problems = policy.missing_keys(modules)
    if problems:
        raise _fail("; ".join(problems))
    return policy


def _passphrase(purpose: str, *, confirm: bool = False) -> str:
    """From SCRUTATOR_KEY_PASSPHRASE, or asked for on the terminal. Never a command-line argument: that would end up
    in shell history and the process list."""
    value = os.environ.get(PASSPHRASE_ENV)
    if value:
        return value
    if not sys.stdin.isatty():
        raise _fail(f"{purpose} needs a passphrase: set {PASSPHRASE_ENV} (no terminal to ask on)")
    return typer.prompt(f"Passphrase for {purpose}", hide_input=True, confirmation_prompt=confirm)


def _signing_key(key_dir: Optional[Path]):
    path = private_key_path(key_dir)
    if not path.exists():
        raise _fail(f"no signing key at {path}: run `scrutator keygen` first")
    problem = permission_problem(path)
    if problem:
        _echo(f"Warning: {problem}", err=True)
    try:
        if is_encrypted(path):
            return load_private_key(path, _passphrase(f"the signing key {path}"))
        _echo(
            f"Warning: the signing key {path} is not encrypted; anyone who can read the file can sign as you. "
            "Protect it with `scrutator protect-key`.", err=True,
        )
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
    max_entities: int = typer.Option(5000, "--max-entities", min=1, help="Cap on the entities a scan records (names, addresses, networks). Past it, names the sources give are counted in the report, not recorded, and no new lookups start. Cost of large scans: docs/security.md."),
    max_steps: Optional[int] = typer.Option(None, "--max-steps", help="Cap on module runs (default: config, 1000)."),
    ai: str = typer.Option("auto", "--ai", help="auto, off, local, cloud or hybrid."),
    model: Optional[str] = typer.Option(None, "--model", help="Model name for every AI role."),
    redact: Optional[bool] = typer.Option(None, "--redact/--no-redact", help="Pseudonymise prompts sent to cloud endpoints."),
    yes_cloud: bool = typer.Option(False, "--yes-cloud", help="Consent to cloud AI without a prompt."),
    summary: bool = typer.Option(True, "--summary/--no-summary", help="Write and verify an AI summary."),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Config file (default: ~/.config/scrutator/config.toml)."),
    bundle: bool = typer.Option(False, "--bundle/--no-bundle", help="Also write a signed proof bundle to <out>/proof.scrutator."),
    key_dir: Optional[Path] = typer.Option(None, "--key-dir", help="Directory with signing.key (default: ~/.config/scrutator)."),
    packs_dirs: list[Path] = typer.Option([], "--packs", help="Extra knowledge pack directory (repeatable); extends or overrides the bundled packs."),
    attribute: bool = typer.Option(False, "--attribution/--no-attribution", help="Mark names that may belong to the organisation as candidates and look at them passively, once."),
    max_candidates: int = typer.Option(20, "--max-candidates", help="With --attribution: how many candidates to look at."),
    playbooks: bool = typer.Option(True, "--playbooks/--no-playbooks", help="Offer the planner the knowledge packs' playbooks that fit the situation."),
    deadline_s: float = typer.Option(DEFAULT_DEADLINE_S, "--deadline", min=0, help="Seconds the whole scan may take (0: no limit). At the deadline running lookups are cancelled, results so far are kept and the report says what is missing."),
    breaker: int = typer.Option(DEFAULT_BREAKER_THRESHOLD, "--breaker", min=0, help="Consecutive failures or timeouts after which a source is marked down for the rest of the scan (0: never)."),
    sources: Optional[str] = typer.Option(None, "--sources", help="Use only these sources (comma-separated; see `scrutator sources`).", rich_help_panel="Source policy"),
    exclude_sources: Optional[str] = typer.Option(None, "--exclude-sources", help="Do not use these sources (comma-separated).", rich_help_panel="Source policy"),
    noncommercial: bool = typer.Option(True, "--noncommercial/--no-noncommercial", help="--no-noncommercial: leave out sources whose free tier is for non-commercial use only (InternetDB, RIPEstat, CertSpotter, Subdomain Center).", rich_help_panel="Source policy"),
) -> None:
    """Run a passive scan and write evidence-backed reports."""
    policy = _source_policy(sources, exclude_sources, not noncommercial)
    wanted = {f.strip() for f in formats.split(",") if f.strip()}
    if not wanted or not wanted <= _FORMATS:
        raise _fail(f"--format must be a comma-separated subset of {sorted(_FORMATS)}")
    mode = _mode(ai)
    config = _config(config_path)
    signing_key = _signing_key(key_dir) if bundle else None
    packs = _load_packs(packs_dirs)
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
    deadline = Deadline(deadline_s) if deadline_s > 0 else None

    async def within(awaitable):
        """What is left of the deadline, for the steps that come after collection."""
        if deadline is None:
            return await awaitable
        try:
            return await asyncio.wait_for(awaitable, deadline.remaining())
        except asyncio.TimeoutError:
            return None

    async def go():
        async with open_context() as ctx, ai_client() as ai_http:
            runtime, used = await build_runtime(
                config, cli_mode=mode, model=model, consent_cloud=True, redact=redact,
                client=ai_http, apex_domains=apexes,
            )
            scan_id, stats = await run_scan(
                seed_entity, scope, store, ctx, ai=runtime,
                max_steps=max_steps or config.max_steps, max_entities=max_entities, packs=packs,
                attribution=attribute, max_candidates=max_candidates, playbooks=playbooks,
                deadline=deadline, breaker_threshold=breaker, source_policy=policy,
            )
            verdict = await within(summarise(runtime, store, scan_id)) if runtime is not None and summary else None
            leads = await within(run_leads(runtime, store, scan_id)) if runtime is not None and attribute else None
            return scan_id, stats, runtime, used, verdict, leads

    interrupted = False
    try:
        scan_id, stats, runtime, used, verdict, leads = asyncio.run(go())
    except (ValueError, AIError) as exc:
        raise _fail(str(exc)) from exc
    except KeyboardInterrupt:
        # what was collected is already in the database: report it instead of throwing it away
        found = store.latest_scan(seed_entity.value)
        if found is None:
            raise _fail("interrupted before the scan started") from None
        scan_id, stats, runtime, used, verdict, leads = found, AgentStats(), None, None, None, None
        store.append_audit(scan_id, {"event": "interrupted"})
        interrupted = True

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
    _echo(f"Scan #{scan_id} of {seed_entity.value}: {counts['headline']}.")
    _echo(
        f"{counts['entities']} entities, {counts['edges']} relations, {counts['findings']} findings "
        f"({stats.modules_run} module runs, {stats.rounds} rounds)."
    )
    _echo(_findings_line(counts["findings_by_tier"], counts["findings"]))
    if counts.get("names"):
        _echo(_names_line(counts["names"]))
    off = _sources_off_line(report.get("source_policy"))
    if off:
        _echo(off)
    _echo(_risk_line(report["risks"]) + " Run `scrutator risk` for the list.")
    if attribute:
        _echo(_candidate_line(report["attribution"]) + " Run `scrutator candidates` for the list.")
    if interrupted:
        _echo("Interrupted: the report covers what was collected so far (partial).")
    if stats.deadline_hit:
        _echo(
            f"Deadline of {deadline_s:g} s reached: the report is partial. Lookups still running were "
            "cancelled and the rest did not start; Source coverage lists what is missing."
        )
    capped = report["coverage"].get("entity_cap")
    if capped:
        _echo(
            f"Entity cap of {capped['cap']} reached: {capped['dropped']} name(s) the sources gave were not recorded "
            "and nothing past them was looked up. Raise --max-entities to keep them."
        )
    if report["coverage"]["sources_down"]:
        _echo(
            "Sources marked down after repeated failures (no more calls this scan): "
            + ", ".join(report["coverage"]["sources_down"]) + "."
        )
    if stats.steps_exhausted:
        _echo("Step budget reached: some lookups were not run. Raise --max-steps to cover them.")
    failed = sum(h["error"] for h in report["sources"].values())
    if failed:
        _echo(f"{failed} source run(s) failed after retries; see Source coverage in the report.")
    if runtime is None:
        _echo("AI: off (no local model found, or --ai off). Deterministic mode.")
    else:
        roles = ", ".join(
            f"{role} {p['provider']}/{p['model']} ({'local' if p['local'] else 'cloud'})"
            for role, p in runtime.describe()["providers"].items()
        )
        _echo(f"AI: {used.value}: {roles}")
        if verdict is not None:
            _echo(
                f"Summary: {len(verdict.verified)} statement(s) verified, {len(verdict.rejected)} rejected"
                + (f" ({verdict.skipped_reason})" if verdict.skipped_reason else "")
                + "."
            )
            if verdict.same_model:
                _echo("Warning: writer and verifier use the same model; use a different one for independence.")
        if leads is not None:
            _echo(
                f"Leads: {len(leads.verified)} verified, {len(leads.rejected)} rejected, {leads.dropped} dropped"
                + (f" ({leads.skipped_reason})" if leads.skipped_reason else "")
                + "."
            )
    _echo(f"Wrote {', '.join(written)} to {out}")
    if bundle_path is not None:
        _echo(f"Proof bundle: {bundle_path} (signing key {manifest['key_fingerprint']})")


@app.command(name="sources")
def list_sources(
    db: Path = typer.Option(Path("scrutator-out/scrutator.db"), "--db", help="Database whose latest scan shows each source's last observed health."),
    sources: Optional[str] = typer.Option(None, "--sources", help="Preview the effect of this allow list."),
    exclude_sources: Optional[str] = typer.Option(None, "--exclude-sources", help="Preview the effect of this exclude list."),
    noncommercial: bool = typer.Option(True, "--noncommercial/--no-noncommercial", help="--no-noncommercial: preview leaving out non-commercial sources."),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """List every source: keyless or keyed, on or off and why, non-commercial or not, and how it fared last time."""
    from scrutator.report.build import source_health

    modules = load_builtin_modules()
    try:
        policy = SourcePolicy.parse(sources, exclude_sources, not noncommercial, modules)
    except SourceError as exc:
        raise _fail(str(exc)) from exc
    health, label = None, None
    if db.exists():
        store = Store(db)
        try:
            scans = store.scans()
            if scans:
                health, label = source_health(store, scans[-1]["id"]), f"scan #{scans[-1]['id']}"
        finally:
            store.close()
    rows = describe_sources(modules, policy, health, label)
    if as_json:
        _echo(json.dumps(rows, indent=2, sort_keys=True))
        return
    _echo(f"{'Source':<16}{'Access':<38}{'State':<10}{'Non-comm.':<10}Last scan")
    for row in rows:
        state = "on" if row["enabled"] else "off"
        _echo(f"{row['source']:<16}{row['kind']:<38}{state:<10}{'yes' if row['noncommercial'] else 'no':<10}{row['last_scan']}")
        if row["why_disabled"]:
            _echo(f"{'':<16}off: {row['why_disabled']}")
    _echo(
        "Keys come only from the environment variables named above, never from the command line; keyed sources "
        "are implemented against the documented APIs and not live-verified, and are not replayable."
    )


@app.command()
def keygen(
    key_dir: Optional[Path] = typer.Option(None, "--key-dir", help="Where to write signing.key and signing.pub."),
    passphrase: bool = typer.Option(False, "--passphrase/--no-passphrase", help=f"Encrypt the private key (scrypt + ChaCha20-Poly1305). The passphrase is read from {PASSPHRASE_ENV} or asked for, never taken as an argument."),
) -> None:
    """Create the Ed25519 key used to sign proof bundles."""
    target = key_dir or private_key_path().parent
    secret = _passphrase("the new signing key", confirm=True) if passphrase else None
    try:
        fp = generate_keypair(target, secret)
    except (FileExistsError, ValueError) as exc:
        raise _fail(str(exc)) from exc
    _echo(f"Wrote {private_key_path(target)} (keep it secret) and {public_key_path(target)} (share it).")
    if secret is None:
        _echo("The private key is not encrypted. `scrutator keygen --passphrase` (or `scrutator protect-key` later) seals it with a passphrase.")
    _echo(f"Key fingerprint: {fp}")
    _echo("Give readers the fingerprint or signing.pub through a channel they trust; they pin it with `scrutator verify --pin`.")


@app.command("protect-key")
def protect_key_cmd(
    key_dir: Optional[Path] = typer.Option(None, "--key-dir", help="Directory with signing.key (default: ~/.config/scrutator)."),
) -> None:
    """Encrypt an existing signing key with a passphrase, in place. The key and its fingerprint stay the same."""
    path = private_key_path(key_dir)
    if not path.exists():
        raise _fail(f"no signing key at {path}")
    if is_encrypted(path):
        raise _fail(f"{path} is already encrypted")
    try:
        fp = protect_key(path, _passphrase(f"the signing key {path}", confirm=True))
    except ValueError as exc:
        raise _fail(str(exc)) from exc
    _echo(f"Encrypted {path} (fingerprint {fp}, unchanged). Signing now needs the passphrase ({PASSPHRASE_ENV} or a prompt).")


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
    _echo(f"Wrote {bundle} for scan #{chosen} of {manifest['scan']['seed']} (signing key {manifest['key_fingerprint']}).")


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
        _echo(f"{'PASS' if check.ok else 'FAIL'}  {check.name}" + (f"  ({check.detail})" if check.detail else ""))
    if report.key_fingerprint:
        _echo(f"Signing key: {report.key_fingerprint}")
    for warning in report.warnings:
        _echo(f"Warning: {warning}")
    if not report.ok:
        _echo("Verification FAILED: do not rely on this bundle.")
        raise typer.Exit(1)
    _echo("Verification passed.")
    if not replay:
        return

    files = read_raw(bundle).files
    records = [json.loads(line) for line in files["evidence.jsonl"].decode().splitlines() if line.strip()]
    subject = subject_names(json.loads(files["report.json"]))
    if pin is None:
        _echo("Warning: replaying a bundle whose signer is not pinned; the requests it makes are whoever made it. "
              "Replay contacts only the source hosts, and looks up only names inside the bundle's own scope.")

    async def go():
        async with open_context() as ctx:
            return await replay_evidence(records, ctx.http, ctx.resolver, subject=subject)

    results = asyncio.run(go())
    tally = {s: sum(1 for r in results if r.status == s) for s in ("unchanged", "changed", "unavailable", "skipped")}
    _echo(
        f"replay: {tally['unchanged']} unchanged, {tally['changed']} changed, "
        f"{tally['unavailable']} unavailable, {tally['skipped']} skipped"
    )
    for r in [r for r in results if r.status != "unchanged"][:20]:
        _echo(f"  {r.status:<11} {r.source}: {r.request[:90]}" + (f" ({r.detail})" if r.detail else ""))
    _echo("Changed and unavailable records are drift, not forgery: sources change and go down.")


def _load_report(ref: str, db: Path, packs=None) -> tuple[dict, str]:
    if ref.isdigit():
        if not db.exists():
            raise _fail(f"no database at {db}")
        store = Store(db)
        try:
            return build_report(store, int(ref), packs=packs), f"scan {ref}"
        except KeyError as exc:
            raise _fail(f"no scan {ref} in {db}") from exc
        finally:
            store.close()
    if packs is not None:
        raise _fail("--packs re-evaluates a scan from the database; a bundle carries the packs it was made with")
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
    _echo(json.dumps(result.to_dict(), indent=2, sort_keys=True) if as_json else render_diff(result, old_label, new_label))


@app.command()
def watch(
    seed: str = typer.Argument(..., help="Domain or IP address to watch."),
    every: str = typer.Option("24h", "--every", help="Interval: 30s, 15m, 6h, 1d."),
    scope_file: Optional[Path] = typer.Option(None, "--scope", help="YAML scope file."),
    out: Path = typer.Option(Path("scrutator-watch"), "--out", help="Output directory."),
    db: Optional[Path] = typer.Option(None, "--db", help="SQLite database (default: <out>/scrutator.db)."),
    webhook: Optional[str] = typer.Option(None, "--webhook", help="POST a JSON summary of changes (https only, or localhost)."),
    max_runs: int = typer.Option(0, "--max-runs", help="Stop after N scans (0 = run until interrupted)."),
    max_steps: int = typer.Option(1000, "--max-steps", help="Cap on module runs per scan."),
    deadline_s: float = typer.Option(DEFAULT_DEADLINE_S, "--deadline", min=0, help="Seconds each scan may take (0: no limit)."),
    sources: Optional[str] = typer.Option(None, "--sources", help="Use only these sources (comma-separated)."),
    exclude_sources: Optional[str] = typer.Option(None, "--exclude-sources", help="Do not use these sources (comma-separated).", rich_help_panel="Source policy"),
    noncommercial: bool = typer.Option(True, "--noncommercial/--no-noncommercial", help="--no-noncommercial: leave out sources whose free tier is for non-commercial use only.", rich_help_panel="Source policy"),
) -> None:
    """Re-scan on a schedule and report what changed (deterministic scans, no AI)."""
    policy = _source_policy(sources, exclude_sources, not noncommercial)
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
        _echo(f"Run {scan_id}: scan #{scan_id} of {seed_entity.value} finished.")
        if result is None:
            _echo("  first scan for this seed; nothing to compare yet")
            return
        _echo(render_diff(result, f"scan {previous}", f"scan {scan_id}"))
        if not result.empty:
            (out / f"diff-{scan_id}.json").write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

    async def run_once() -> int:
        async with open_context() as ctx:
            scan_id, _ = await run_scan(
                seed_entity, scope, store, ctx, max_steps=max_steps,
                deadline=Deadline(deadline_s) if deadline_s > 0 else None, source_policy=policy,
            )
        return scan_id

    async def go():
        async with make_webhook_client() as client:
            notify = make_webhook_notifier(webhook, client) if webhook else None
            await watch_loop(
                run_once=run_once, store=store, seed=seed_entity.value, interval=interval,
                max_runs=max_runs, notify=notify, sleep=lambda seconds: _sleep(seconds), on_run=report_run,
            )

    try:
        asyncio.run(go())
    except KeyboardInterrupt:
        _echo("Stopped.")
    finally:
        store.close()


def _names_line(names: dict | None) -> str:
    """How many of the in-scope names are live: a list of names is not a list of hosts."""
    if not names:
        return ""
    return (
        f"Names: {names['live']} live, {names['stale']} stale, {names['wildcard']} wildcard-covered, "
        f"{names['unresolved']} unresolved."
    )


def _sources_off_line(policy: dict | None) -> str:
    """The sources the policy turned off, with the reason. Sources that are only waiting for a key are left to
    `scrutator sources`: they were never on."""
    if not policy:
        return ""
    off = {name: why for name, why in policy["disabled"].items() if not why.startswith("needs a key")}
    if not off:
        return ""
    return "Sources off: " + "; ".join(f"{name} ({why})" for name, why in off.items()) + "."


def _findings_line(by_tier: dict[str, int], total: int) -> str:
    """Findings about names DNS or a dated record supports come first; the rest are counted apart."""
    solid = by_tier["verified"] + by_tier["other"]
    return (
        f"Findings: {by_tier['verified']} about verified names"
        + (f" and {by_tier['other']} about addresses and registrations" if by_tier["other"] else "")
        + f"; {total - solid} more about claimed ({by_tier['claimed']}), stale ({by_tier['stale']}) or "
        f"wildcard-covered ({by_tier['wildcard']}) names, kept in the report and collapsed in the HTML."
    )


def _risk_line(risks: list[dict]) -> str:
    counts = {name: sum(1 for r in risks if r["severity"] == name) for name in ("high", "medium", "low", "info")}
    detail = ", ".join(f"{counts[name]} {name}" for name in ("high", "medium", "low", "info"))
    return f"Risks: {len(risks)} ({detail})."


@app.command()
def risk(
    scan_ref: Optional[str] = typer.Argument(None, metavar="[SCAN]", help="A scan id in --db, or a .scrutator bundle (default: the latest scan)."),
    db: Path = typer.Option(Path("scrutator-out/scrutator.db"), "--db", help="SQLite database for scan ids."),
    packs_dirs: list[Path] = typer.Option([], "--packs", help="Re-evaluate a database scan with extra knowledge pack directories."),
    category: str = typer.Option("all", "--category", help="all, risk or analyst."),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable output."),
    sarif: Optional[Path] = typer.Option(None, "--sarif", help="Also write the risks as SARIF 2.1.0 to this file."),
    fail_on: Optional[str] = typer.Option(None, "--fail-on", help="Exit with status 1 if a risk at or above this severity exists: info, low, medium or high."),
) -> None:
    """List the risks of a scan: hygiene findings, provider concentration and analyst detectors.

    Exit status: 0 on success (also when risks exist), 1 when --fail-on is set and a risk at or
    above that severity exists, 2 for usage errors such as a missing database or a bad pack."""
    if category not in ("all", "risk", "analyst"):
        raise _fail("--category must be all, risk or analyst")
    if fail_on is not None and fail_on not in [s.value for s in Severity]:
        raise _fail(f"--fail-on must be one of {[s.value for s in Severity]}")
    packs = _load_packs(packs_dirs) if packs_dirs else None
    if scan_ref is None:
        if not db.exists():
            raise _fail(f"no database at {db}")
        store = Store(db)
        scans = store.scans()
        store.close()
        if not scans:
            raise _fail("the database holds no scans")
        scan_ref = str(scans[-1]["id"])
    report, label = _load_report(scan_ref, db, packs)
    if "risks" not in report:
        raise _fail(f"{label} predates risk analysis: it has no risks section")
    risks = [r for r in report["risks"] if category == "all" or r["category"] == category]

    if sarif is not None:
        sarif.write_text(json.dumps(to_sarif({**report, "risks": risks}), indent=2, sort_keys=True), encoding="utf-8")
    if as_json:
        _echo(json.dumps({"risks": risks, "dependencies": report["dependencies"]}, indent=2, sort_keys=True))
    else:
        _echo(f"{label} of {report['scan']['seed']}. {_risk_line(risks)}")
        if report.get("summary", {}).get("names"):
            _echo(_names_line(report["summary"]["names"]))
        for item in risks:
            _echo(f"[{item['severity'].upper():<6}] {item['rule_id']}  {', '.join(item['entity_ids'][:3])}")
            _echo(f"         {item['title']}. {item['explanation']}")
            _echo(f"         evidence: {len(item['evidence_ids'])} record(s), fingerprint {item['fingerprint']}")
            _echo(f"         fix: {item['remediation']}")
        if report["dependencies"]:
            _echo("Provider dependencies:")
            for dep in report["dependencies"]:
                _echo(f"  {dep['category']:<8} {dep['provider']}  ({len(dep['hostnames'])} name(s) via {', '.join(dep['via'])})")
    if sarif is not None:
        _echo(f"Wrote {sarif}")
    if fail_on is not None:
        blocking = [r for r in risks if severity_at_least(r["severity"], fail_on)]
        if blocking:
            _echo(f"{len(blocking)} risk(s) at or above {fail_on}.", err=True)
            raise typer.Exit(1)


def _candidate_line(attribution: dict) -> str:
    bands = attribution["bands"]
    detail = ", ".join(f"{bands[band]} {band}" for band in BANDS[:3])
    return f"Candidates: {sum(bands[band] for band in BANDS[:3])} ({detail})."


def _latest_scan(db: Path) -> str:
    if not db.exists():
        raise _fail(f"no database at {db}")
    store = Store(db)
    scans = store.scans()
    store.close()
    if not scans:
        raise _fail("the database holds no scans")
    return str(scans[-1]["id"])


def _min_band(value: str) -> int:
    if value not in BANDS:
        raise _fail(f"--min-band must be one of {list(BANDS)}")
    return band_rank(value)


def _entity_id(raw: str) -> str:
    text = raw.strip().lower()
    return text if ":" in text else f"domain:{text}"


def _attribution_of(scan_ref: Optional[str], db: Path) -> tuple[dict, str]:
    report, label = _load_report(scan_ref if scan_ref is not None else _latest_scan(db), db)
    if "attribution" not in report:
        raise _fail(f"{label} predates attribution: it has no attribution section")
    return report, label


@app.command("candidates")
def candidates_cmd(
    scan_ref: Optional[str] = typer.Argument(None, metavar="[SCAN]", help="A scan id in --db, or a .scrutator bundle (default: the latest scan)."),
    db: Path = typer.Option(Path("scrutator-out/scrutator.db"), "--db", help="SQLite database for scan ids."),
    min_band: str = typer.Option("possible", "--min-band", help="confirmed, probable, possible or unlikely."),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """List the names outside the scope that may belong to the organisation, strongest first."""
    floor = _min_band(min_band)
    report, label = _attribution_of(scan_ref, db)
    promoted = {p["entity"] for p in report.get("promotions", [])}
    items = [c for c in report["attribution"]["candidates"] if band_rank(c["band"]) >= floor]
    if as_json:
        _echo(json.dumps({"scan": report["scan"], "candidates": items, "promotions": report.get("promotions", [])}, indent=2, sort_keys=True))
        return
    _echo(f"{label} of {report['scan']['seed']}. {_candidate_line(report['attribution'])}")
    for item in items:
        mark = ", promoted" if item["entity_id"] in promoted else ""
        _echo(f"[{item['band'].upper():<9}] {item['score']:.2f}  {item['entity_id']}  ({item['state']}{mark}; {len(item['signals'])} signal(s), {len(item['evidence_ids'])} evidence record(s))")
    if any(item["state"] == "candidate" for item in items):
        _echo("Explain one with `scrutator attribution --entity NAME`; accept one into scope with `scrutator promote NAME --scope FILE`.")


@app.command("attribution")
def attribution_cmd(
    scan_ref: Optional[str] = typer.Argument(None, metavar="[SCAN]", help="A scan id in --db, or a .scrutator bundle (default: the latest scan)."),
    db: Path = typer.Option(Path("scrutator-out/scrutator.db"), "--db", help="SQLite database for scan ids."),
    entity: Optional[str] = typer.Option(None, "--entity", help="Explain one name (for example partner.example.net)."),
    min_band: str = typer.Option("possible", "--min-band", help="confirmed, probable, possible or unlikely."),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Explain why names outside the scope may belong to the organisation: every signal, the evidence behind it, and what could make it wrong."""
    floor = _min_band(min_band)
    report, label = _attribution_of(scan_ref, db)
    items = report["attribution"]["candidates"]
    if entity is not None:
        wanted = _entity_id(entity)
        items = [c for c in items if c["entity_id"] == wanted]
        if not items:
            raise _fail(f"{wanted} has no attribution in {label}")
    else:
        items = [c for c in items if band_rank(c["band"]) >= floor]
    leads = report.get("leads", {"verified": [], "rejected": []})
    if as_json:
        _echo(json.dumps({"attribution": {**report["attribution"], "candidates": items}, "leads": leads}, indent=2, sort_keys=True))
        return
    _echo(f"{label} of {report['scan']['seed']}. {_candidate_line(report['attribution'])}")
    for item in items:
        _echo(f"\n[{item['band'].upper()}] {item['entity_id']}  score {item['score']:.2f}  ({item['state']})")
        for signal in item["signals"]:
            _echo(f"  {'+' if signal['weight'] > 0 else '-'} {signal['kind']} {signal['weight']:.2f}: {signal['detail']} ({len(signal['evidence_ids'])} evidence record(s))")
            if signal["note"]:
                _echo(f"      {signal['note']}")
        for note in item["premortem"]:
            _echo(f"  ? {note['text']}")
    if leads["verified"]:
        _echo("\nAnalyst leads (AI, verified against the evidence they cite):")
        for lead in leads["verified"]:
            _echo(f"  [{lead['kind']}] {lead['claim']}" + (f"  (suggested check, not run: {lead['check']})" if lead["check"] else ""))


@app.command("promote")
def promote_cmd(
    entity: str = typer.Argument(..., help="The candidate to accept into scope, for example partner.example.net."),
    scope_file: Path = typer.Option(..., "--scope", help="The scope file to add it to; it is the only thing that defines scope."),
    scan_id: Optional[int] = typer.Option(None, "--scan", help="Scan id (default: the latest scan in the database)."),
    db: Path = typer.Option(Path("scrutator-out/scrutator.db"), "--db", help="SQLite database."),
    yes: bool = typer.Option(False, "--yes", help="Do not ask for confirmation."),
) -> None:
    """Accept a candidate into scope: write it to the scope file and record who accepted it, on what evidence, in the audit log."""
    entity_id = _entity_id(entity)
    chosen = scan_id if scan_id is not None else int(_latest_scan(db))
    store = Store(db)
    try:
        try:
            report = build_report(store, chosen)
        except KeyError as exc:
            raise _fail(f"no scan {chosen} in {db}") from exc
        item = next((c for c in report["attribution"]["candidates"] if c["entity_id"] == entity_id), None)
        if item is None or item["state"] != "candidate":
            raise _fail(f"{entity_id} is not a candidate of scan #{chosen}: only candidates can be promoted")
        _echo(
            f"{entity_id} is {item['band']} (score {item['score']:.2f}) on {len(item['evidence_ids'])} evidence record(s). "
            f"Promoting it adds {item['value']} and every name under it to {scope_file}."
        )
        if not yes and not typer.confirm("Accept it into scope?", default=False):
            raise _fail("promotion declined")
        try:
            record = promote_candidate(store, chosen, entity_id, scope_file=scope_file, via="cli")
        except PromotionError as exc:
            raise _fail(str(exc)) from exc
    finally:
        store.close()
    _echo(f"Promoted {entity_id} at {record['at']}; recorded in the audit log of scan #{chosen}.")
    _echo(f"{scope_file} now lists it (the previous file is kept as {scope_file.name}.bak). Scan again to investigate it fully.")


@app.command("mcp")
def mcp_cmd(
    db: Path = typer.Option(Path("scrutator-out/scrutator.db"), "--db", help="SQLite database the tools read (and, with --allow-scan, write)."),
    scope_file: Optional[Path] = typer.Option(None, "--scope", help="The scope file. Needed by --allow-scan and --allow-promote; it alone defines what may be investigated."),
    allow_scan: bool = typer.Option(False, "--allow-scan", help="Also offer the passive `scan` tool, inside the scope file."),
    allow_promote: bool = typer.Option(False, "--allow-promote", help="Also offer `promote_candidate`, which edits the scope file when called with confirm=true."),
) -> None:
    """Serve Scrutator to an MCP client such as Claude Desktop over stdio. Read-only tools by default."""
    if (allow_scan or allow_promote) and scope_file is None:
        raise _fail("--allow-scan and --allow-promote need --scope: the scope file is what keeps a client inside what you allowed")
    if scope_file is not None:
        try:
            ScopePolicy.from_file(scope_file)
        except (OSError, ValueError) as exc:
            raise _fail(f"cannot load scope: {exc}") from exc
    tools = ToolSet(db, scope_file=scope_file, allow_scan=allow_scan, allow_promote=allow_promote)
    try:
        from scrutator.mcp_server import serve

        serve(tools)
    except ImportError as exc:
        raise _fail("the MCP SDK is not installed: run `pip install \"scrutator[mcp]\"`") from exc


@packs_app.command("list")
def packs_list(
    packs_dirs: list[Path] = typer.Option([], "--packs", help="Extra knowledge pack directory (repeatable)."),
) -> None:
    """List the pack files in use and how many entries they hold."""
    packs = _load_packs(packs_dirs)
    _echo(f"{'file':<16}{'kind':<11}{'version':<12}{'origin':<9}{'entries':<8}sha256")
    for item in packs.files:
        _echo(f"{item['name']:<16}{item['kind']:<11}{item['version']:<12}{item['origin']:<9}{item['entries']:<8}{item['content_sha256'][:12]}")
    verified = sum(1 for e in packs.providers if e.verified)
    _echo(
        f"{len(packs.providers)} provider entries ({verified} verified), {len(packs.takeover)} takeover fingerprints, "
        f"{len(packs.signals)} signal frequencies. Merged content sha256 {packs.effective_sha256[:12]}."
    )


@packs_app.command("validate")
def packs_validate(
    directory: Optional[Path] = typer.Argument(None, help="A pack directory (default: the bundled packs)."),
) -> None:
    """Check pack files against the schema and the manifest. Exit status 1 if anything is wrong."""
    problems = validate_dir(directory)
    where = directory if directory is not None else "the bundled packs"
    if problems:
        for line in problems:
            _echo(f"error: {line}", err=True)
        _echo(f"{where}: {len(problems)} problem(s).", err=True)
        raise typer.Exit(1)
    _echo(f"{where}: valid.")


@packs_app.command("manifest")
def packs_manifest(
    directory: Path = typer.Argument(..., help="A pack directory; its manifest.json is (re)written."),
) -> None:
    """Write manifest.json with the sha256 of every pack file (for pack maintainers)."""
    if not directory.is_dir():
        raise _fail(f"{directory} is not a directory")
    manifest = build_manifest(directory)
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _echo(f"Wrote {directory / 'manifest.json'} ({len(manifest['files'])} file(s)).")


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
        _echo("no AI runtime available: start Ollama or another local server, or configure [ai.*] roles.")
        raise typer.Exit(1)
    _echo(render_doctor(report))
    raise typer.Exit(0 if report.passed else 1)


def run() -> None:
    """The `scrutator` command. A database problem anywhere (not a database, damaged, locked by another process) is
    a usage error with the file named and a hint, never a traceback."""
    import sqlite3

    from scrutator.store import StoreError, describe_db_error

    try:
        app()
    except StoreError as exc:
        _echo(f"error: {exc}", err=True)
        raise SystemExit(2) from None
    except sqlite3.Error as exc:
        _echo(f"error: {describe_db_error(Store.last_path or 'in use', exc)}", err=True)
        raise SystemExit(2) from None
