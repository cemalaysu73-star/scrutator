import asyncio
import ipaddress
import json
import os
import sys
from pathlib import Path
from typing import Optional

import httpx
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
from scrutator.bundle.replay import MAX_RECORDS, PROFILE_HOSTS, replay_evidence, subject_names
from scrutator.egress import SOURCE_HOSTS, EgressGuard
from scrutator.bundle.verify import verify_bundle
from scrutator.bundle.writer import BundleTooLarge, create_bundle
from scrutator.context import ai_client, open_context
from scrutator.deadline import DEFAULT_DEADLINE_S, Deadline
from scrutator.engine import DEFAULT_BREAKER_THRESHOLD
from scrutator.diff import diff_reports, render_diff
from scrutator.mcp_tools import ToolSet
from scrutator.model import Entity, EntityType
from scrutator.packs import PackError, build_manifest, load_packs, validate_dir
from scrutator.report import build_report, render_html, render_json
from scrutator.report.sarif import to_sarif
from scrutator.risk.basis import basis, basis_text
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


def _show_version(value: bool) -> None:
    if value:
        from scrutator import __version__

        _echo(f"scrutator {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(False, "--version", callback=_show_version, is_eager=True, help="Print the version and exit."),
    proxy: Optional[str] = typer.Option(None, "--proxy", envvar="SCRUTATOR_PROXY", help="Send every outbound request through this proxy (http://, socks5:// or socks5h://host:port): the HTTP data sources, the opt-in web modules and the active probes. DNS lookups are NOT proxied: see docs/active.md. Prefer the SCRUTATOR_PROXY variable when the URL holds credentials."),
) -> None:
    """Scrutator."""
    if proxy:
        from scrutator import proxy as proxy_setting

        try:
            spec = proxy_setting.set_proxy(proxy)
        except proxy_setting.ProxyError as exc:
            raise _fail(str(exc)) from exc
        _echo(f"Outbound requests go through {spec.label()}. DNS lookups do not (see docs/active.md).", err=True)


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
    brand: bool = typer.Option(False, "--brand", help="Brand presence (off by default; contacts the organisation's site): read the platform links on its home page (robots.txt honoured), check whether those accounts and look-alikes of the brand name exist (profile page status only). For an organisation's domain.", rich_help_panel="Source policy"),
    org: bool = typer.Option(False, "--org", help="Organisation sources (off by default): the legal entity and its group (GLEIF, Wikidata), the breach history of its own services (Have I Been Pwned), its public GitHub account and repositories, and the package namespaces and public handles that carry its brand. Organisations only; never a person. See `scrutator sources` and docs/organisation.md.", rich_help_panel="Organisation"),
    legal_name: Optional[str] = typer.Option(None, "--legal-name", help="With --org: the organisation's legal name, used for the company-record lookups when evidence does not already give one. Recorded with the scan.", rich_help_panel="Organisation"),
    github_org: Optional[str] = typer.Option(None, "--github-org", help="With --org: the organisation's GitHub account login, when it is not found from Wikidata.", rich_help_panel="Organisation"),
    code_leaks: bool = typer.Option(False, "--code-leaks", help="With --org and --self (and SCRUTATOR_GITHUB_TOKEN): a bounded scan of the organisation's OWN public repositories for credential formats. The secret value is never stored (only a format, path, commit, salted fingerprint and 2+2 mask). Rotate, then remove from history.", rich_help_panel="Organisation"),
    self_owned: bool = typer.Option(False, "--self", help="With --org --code-leaks: confirm you own or control the organisation's public repositories and authorise a bounded secret scan of them. Recorded in the signed audit log before any lookup.", rich_help_panel="Organisation"),
    axfr: bool = typer.Option(False, "--axfr", help="Ask each name server of the in-scope zone once for a zone transfer (AXFR, TCP 53). Active-ish: it questions the target's own servers, so it also needs --active. Every answer, refusal included, is evidence.", rich_help_panel="Source policy"),
    active: bool = typer.Option(False, "--active", help="Confirm the active-ish lookups asked for (--axfr): you are authorised to query the target's own name servers. Recorded in the audit log before any lookup.", rich_help_panel="Source policy"),
    live: Optional[bool] = typer.Option(None, "--live/--no-live", help="Print each name the moment DNS confirms it is live, while the scan goes on (default: on when the output is a terminal). The report is the same either way."),
) -> None:
    """Run a passive scan and write evidence-backed reports."""
    policy = _source_policy(sources, exclude_sources, not noncommercial)
    if brand:
        policy = policy.opt("brand")
    org_config = None
    if org:
        import os as _os
        from scrutator.org.run import OrgConfig
        from scrutator.modules.org_github import TOKEN_VAR

        policy = policy.opt("wikidata", "gleif", "hibp", "github", "packages", "handles")
        token_present = bool(_os.environ.get(TOKEN_VAR, "").strip())
        if code_leaks:
            if not self_owned:
                raise _fail("--code-leaks reads the organisation's own repositories for secrets: add --self to confirm you own or control them")
            if not token_present:
                raise _fail(f"--code-leaks needs a GitHub token: set {TOKEN_VAR} (never passed on the command line)")
            policy = policy.opt("github_leaks")
        org_config = OrgConfig(legal_name=legal_name, github_org=github_org, code_leaks=code_leaks, self_attested=self_owned, token_present=token_present)
    elif legal_name or github_org or code_leaks or self_owned:
        raise _fail("--legal-name, --github-org, --code-leaks and --self apply only with --org")
    if axfr and not active:
        raise _fail("--axfr asks the target's own name servers for its zone: add --active to confirm you may do that")
    if active and not axfr:
        raise _fail("--active confirms an active-ish lookup, and none was asked for (--axfr)")
    if axfr:
        policy = policy.opt("axfr")
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
    watcher = _live_names(seed_entity, scope, policy, "The scan goes on with their addresses (registration, network, InternetDB); the report follows.") if _wants_live(live) else None

    async def within(awaitable):
        """What is left of the deadline, for the steps that come after collection."""
        if deadline is None:
            return await awaitable
        try:
            return await asyncio.wait_for(awaitable, deadline.remaining())
        except asyncio.TimeoutError:
            return None

    async def go():
        async with open_context() as ctx, ai_client() as ai_http, _web_client(brand, scope, packs) as web:
            if ctx is not None:  # a test may stand in for the whole context
                ctx.web = web
            runtime, used = await build_runtime(
                config, cli_mode=mode, model=model, consent_cloud=True, redact=redact,
                client=ai_http, apex_domains=apexes,
            )
            scan_id, stats = await run_scan(
                seed_entity, scope, store, ctx, ai=runtime,
                max_steps=max_steps or config.max_steps, max_entities=max_entities, packs=packs,
                attribution=attribute, max_candidates=max_candidates, playbooks=playbooks,
                deadline=deadline, breaker_threshold=breaker, source_policy=policy,
                listeners=[watcher] if watcher is not None else None, allow_active=active,
                org=org_config,
            )
            if watcher is not None:
                watcher.on_names_settled()  # the planner's rounds do not signal it; said once either way
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
    report, written, bundle_path, manifest, bundle_problem = _write_outputs(store, scan_id, out, wanted, signing_key)

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
    if brand:
        _echo(_brand_line(report.get("brand")))
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
        noisy = ", ".join(f"{name} {count}" for name, count in sorted(capped.get("dropped_by_source", {}).items(), key=lambda kv: -kv[1])[:3])
        _echo(
            f"Entity cap of {capped['cap']} reached: {capped['dropped']} name(s) the sources gave were not recorded"
            + (f" (most from {noisy})" if noisy else "") + " and nothing past them was looked up."
            + (f" Sources that only list names were held to {capped['list_sources_limit']}, so the rest of the cap stayed"
               " free for what DNS and certificates vouch for." if capped.get("list_sources_limit") else "")
            + " Raise --max-entities to keep them."
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
    if bundle_problem:
        _echo(f"error: no proof bundle was written: {bundle_problem}", err=True)
        raise typer.Exit(2)


def _write_outputs(store: Store, scan_id: int, out: Path, wanted: set[str], signing_key):
    """Build the report from the store, write the formats asked for and, with a key, the signed bundle; closes the
    store. Returns (report, files written, bundle path or None, manifest or None, bundle problem or "")."""
    report = build_report(store, scan_id)
    written = []
    if "json" in wanted:
        (out / "report.json").write_text(render_json(report), encoding="utf-8")
        written.append("report.json")
    if "html" in wanted:
        (out / "report.html").write_text(render_html(report), encoding="utf-8")
        written.append("report.html")
    bundle_path, manifest, bundle_problem = None, None, ""
    if signing_key is not None:
        try:
            manifest = create_bundle(store, scan_id, signing_key, out / "proof.scrutator")
            bundle_path = out / "proof.scrutator"
        except BundleTooLarge as exc:
            bundle_problem = str(exc)
    store.close()
    return report, written, bundle_path, manifest, bundle_problem


# What `scrutator quick` asks: the sources that list names under a domain, and DNS (with the wildcard probe). Never the
# address enrichment (registration, network, InternetDB), the DNS history of the apex or anything opt-in.
QUICK_LEAVES_OUT = frozenset({"rdap", "asn", "ripestat", "internetdb", "mnemonic"})
QUICK_BUDGET_S = 7.0
QUICK_LOOKUP_CAP_S = 5.0


def _quick_sources(exclude_sources: Optional[str], no_noncommercial: bool) -> SourcePolicy:
    modules = load_builtin_modules()
    names = sorted(
        m.name for m in modules
        if EntityType.DOMAIN in m.accepts and m.opt_in is None and m.name not in QUICK_LEAVES_OUT
        and (m.needs_key is None or os.environ.get(m.needs_key))
    )
    try:
        return SourcePolicy.parse(",".join(names), exclude_sources, no_noncommercial, modules)
    except SourceError as exc:
        raise _fail(str(exc)) from exc


@app.command()
def quick(
    seed: str = typer.Argument(..., help="Domain to list names for."),
    out: Path = typer.Option(Path("scrutator-out"), "--out", help="Output directory."),
    db: Optional[Path] = typer.Option(None, "--db", help="SQLite database path (default: <out>/scrutator.db)."),
    formats: str = typer.Option("json", "--format", help="Comma-separated: json, html."),
    budget: float = typer.Option(QUICK_BUDGET_S, "--budget", min=1.0, help="Seconds the lookups may take in all (start-up and writing the report come on top)."),
    bundle: bool = typer.Option(False, "--bundle/--no-bundle", help="Also write a signed proof bundle to <out>/proof.scrutator."),
    key_dir: Optional[Path] = typer.Option(None, "--key-dir", help="Directory with signing.key (default: ~/.config/scrutator)."),
    exclude_sources: Optional[str] = typer.Option(None, "--exclude-sources", help="Do not use these sources (comma-separated)."),
    noncommercial: bool = typer.Option(True, "--noncommercial/--no-noncommercial", help="--no-noncommercial: leave out sources whose free tier is for non-commercial use only."),
) -> None:
    """Names only, in seconds: the name sources and DNS, nothing about the addresses. Prints live names as DNS confirms
    them, then the verified list; the report (and with --bundle the signed bundle) is evidence-backed like a scan's."""
    started = __import__("time").monotonic()
    wanted = {f.strip() for f in formats.split(",") if f.strip()}
    if not wanted or not wanted <= _FORMATS:
        raise _fail(f"--format must be a comma-separated subset of {sorted(_FORMATS)}")
    try:
        seed_entity = _parse_seed(seed)
    except ValueError as exc:
        raise _fail(f"invalid seed {seed!r}: give a bare domain") from exc
    if seed_entity.type is not EntityType.DOMAIN:
        raise _fail("quick lists the names under a domain: give a domain, not an address")
    policy = _quick_sources(exclude_sources, not noncommercial)
    signing_key = _signing_key(key_dir) if bundle else None
    scope = _default_scope(seed_entity)
    out.mkdir(parents=True, exist_ok=True)
    store = Store(db or out / "scrutator.db")
    from scrutator.livenames import LiveNames

    chosen, _ = policy.select(load_builtin_modules())
    _echo(f"Quick: names under {seed_entity.value} from {', '.join(m.name for m in chosen)}; nothing about their addresses.")
    watcher = LiveNames(
        scope, {seed_entity.value}, lambda line: _echo(line), probes_expected=any(m.name == "wildcard" for m in chosen),
        started=started,
    )

    async def go():
        async with open_context() as ctx:
            return await run_scan(
                seed_entity, scope, store, ctx, ai=None, max_steps=2000, packs=load_packs(),
                deadline=Deadline(budget), source_policy=policy, listeners=[watcher], timeout_cap=min(QUICK_LOOKUP_CAP_S, budget),
            )

    try:
        scan_id, stats = asyncio.run(go())
    except ValueError as exc:
        raise _fail(str(exc)) from exc
    watcher.on_names_settled()
    report, written, bundle_path, manifest, bundle_problem = _write_outputs(store, scan_id, out, wanted, signing_key)
    verified = [row for row in report["names"] if row["tier"] == "verified"]
    late = [row for row in verified if row["name"] not in watcher.printed]
    for row in late:
        _echo(f"  verified  {row['name']:<36} {row['tier_reason']}")
    _echo(f"Quick scan #{scan_id} of {seed_entity.value}: {report['summary']['headline']}.")
    failed = sorted(m for m, h in report["sources"].items() if h["error"] or h.get("down"))
    if failed:
        _echo(f"Sources that did not answer in time or failed: {', '.join(failed)} (see Source coverage in the report).")
    if stats.deadline_hit:
        _echo(f"Budget of {budget:g} s reached: lookups still running were cut and are listed as gaps in the report.")
    _echo(f"Wrote {', '.join(written)} to {out} in {__import__('time').monotonic() - started:.1f} s. "
          "For registration, network and exposure data run `scrutator scan`.")
    if bundle_path is not None:
        _echo(f"Proof bundle: {bundle_path} (signing key {manifest['key_fingerprint']})")
    if bundle_problem:
        _echo(f"error: no proof bundle was written: {bundle_problem}", err=True)
        raise typer.Exit(2)


def _wants_live(flag: Optional[bool]) -> bool:
    """--live / --no-live, or by default: on when the output is a terminal (a pipe gets the summary only)."""
    if flag is not None:
        return flag
    try:
        return sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def _live_names(seed: Entity, scope: ScopePolicy, policy: SourcePolicy, note: str):
    """The live name list (scrutator.livenames) for a scan of `seed`, or None for an address seed."""
    from scrutator.livenames import LiveNames

    if seed.type is not EntityType.DOMAIN:
        return None
    chosen, _ = policy.select(load_builtin_modules())
    roots = {seed.value, *scope.to_dict()["domains"]}
    _echo(f"Live names under {seed.value} as DNS confirms them:")
    return LiveNames(
        scope, roots, lambda line: _echo(line), probes_expected=any(m.name == "wildcard" for m in chosen),
        settled_note=note,
    )


def _web_client(wanted: bool, scope: ScopePolicy, packs):
    """The guarded client of the opt-in modules (scrutator.web), or nothing when they were not asked for."""
    from contextlib import nullcontext

    from scrutator.web import open_web, scope_guard

    return open_web(scope_guard(scope, packs or load_packs())) if wanted else nullcontext(None)


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
    except (KeyError, BundleTooLarge) as exc:
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
    replay_limit: int = typer.Option(MAX_RECORDS, "--replay-limit", min=1, help="With --replay: replay at most this many records (a bundle is untrusted input; the rest are reported as skipped)."),
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
        # the source hosts, and the fixed profile hosts of brand presence (bundle/replay.py)
        async with open_context(egress=EgressGuard(SOURCE_HOSTS | PROFILE_HOSTS)) as ctx:
            return await replay_evidence(records, ctx.http, ctx.resolver, subject=subject, max_records=replay_limit)

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
    out: Path = typer.Option(Path("scrutator-watch"), "--out", help="Output directory (one per client: it holds the baseline, alerts and digests)."),
    db: Optional[Path] = typer.Option(None, "--db", help="SQLite database (default: <out>/scrutator.db)."),
    webhook: Optional[str] = typer.Option(None, "--webhook", help="POST a JSON summary of changes and the new alerts (https only, or localhost)."),
    max_runs: int = typer.Option(0, "--max-runs", help="Stop after N scans (0 = run until interrupted)."),
    max_steps: int = typer.Option(1000, "--max-steps", help="Cap on module runs per scan."),
    deadline_s: float = typer.Option(DEFAULT_DEADLINE_S, "--deadline", min=0, help="Seconds each scan may take (0: no limit)."),
    sources: Optional[str] = typer.Option(None, "--sources", help="Use only these sources (comma-separated)."),
    exclude_sources: Optional[str] = typer.Option(None, "--exclude-sources", help="Do not use these sources (comma-separated).", rich_help_panel="Source policy"),
    noncommercial: bool = typer.Option(True, "--noncommercial/--no-noncommercial", help="--no-noncommercial: leave out sources whose free tier is for non-commercial use only.", rich_help_panel="Source policy"),
    client: Optional[str] = typer.Option(None, "--client", help="Client name for alerts and digests (default: the seed).", rich_help_panel="Alerts"),
    min_severity: str = typer.Option("low", "--min-severity", help="Announce alerts at or above: info, low, medium or high (all are kept in the state and the digest data).", rich_help_panel="Alerts"),
    email_to: list[str] = typer.Option([], "--email-to", help="Also e-mail each run's alerts here (repeatable). Server and credentials only from SCRUTATOR_SMTP_HOST/PORT/USER/PASSWORD/FROM, never from the command line.", rich_help_panel="Alerts"),
    lang: str = typer.Option("en", "--lang", help="Language of the 'why this matters' line and the digest: en or tr.", rich_help_panel="Alerts"),
    ai: str = typer.Option("off", "--ai", help="off (default), or local, cloud, hybrid: a model rewords each English 'why this matters' line; kept only when the deterministic floor and the verifier pass it.", rich_help_panel="Alerts"),
    model: Optional[str] = typer.Option(None, "--model", help="Model name for every AI role.", rich_help_panel="Alerts"),
    yes_cloud: bool = typer.Option(False, "--yes-cloud", help="Consent to cloud AI without a prompt.", rich_help_panel="Alerts"),
    config_path: Optional[Path] = typer.Option(None, "--config", help="AI config file.", rich_help_panel="Alerts"),
) -> None:
    """Re-scan on a schedule and report what changed. On top of the full diff, each run turns what is new into
    severity-ranked alerts (new names, findings, takeover candidates, certificates, open services), announced once,
    each citing its evidence; a weekly digest (digest-<year>-W<week>.md) collects them for the client."""
    from scrutator.monitor import SEVERITIES, SmtpConfig, at_least, current_keys, dedupe, diff_snapshots, explain, load_state, render_digest, save_state, send_email, snapshot, write_digest

    policy = _source_policy(sources, exclude_sources, not noncommercial)
    if min_severity not in SEVERITIES:
        raise _fail(f"--min-severity must be one of {list(SEVERITIES)}")
    if lang not in ("en", "tr"):
        raise _fail("--lang must be en or tr")
    mode = _mode(ai)
    try:
        interval = parse_interval(every)
        if webhook is not None:
            validate_webhook(webhook)
        seed_entity = _parse_seed(seed)
        scope = ScopePolicy.from_file(scope_file) if scope_file else _default_scope(seed_entity)
        smtp = SmtpConfig.from_env() if email_to else None
        for address in email_to:
            if "@" not in address or any(c in address for c in "\r\n,;<>"):
                raise ValueError(f"not an e-mail address: {address!r}")
    except (OSError, ValueError) as exc:
        raise _fail(str(exc)) from exc
    label = client or seed_entity.value
    out.mkdir(parents=True, exist_ok=True)
    store = Store(db or out / "scrutator.db")
    try:
        state = load_state(out)
    except ValueError as exc:
        raise _fail(str(exc)) from exc
    runtime_holder: dict = {}
    latest: dict = {"alerts": []}

    def in_scope(host: str) -> bool:
        try:
            return scope.decide_entity(Entity(type=EntityType.DOMAIN, value=host)).allowed
        except ValueError:
            return False

    def report_run(scan_id: int, previous: Optional[int], result) -> None:
        _echo(f"Run {scan_id}: scan #{scan_id} of {seed_entity.value} finished.")
        if result is None:
            _echo("  first scan for this seed; nothing to compare yet")
        else:
            _echo(render_diff(result, f"scan {previous}", f"scan {scan_id}"))
            if not result.empty:
                (out / f"diff-{scan_id}.json").write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
        shown = latest["alerts"]
        if shown:
            _echo(f"Alerts for {label} ({len(shown)}, at or above {min_severity}):")
            for alert in shown:
                _echo(f"  [{alert['severity'].upper():<6}] {alert['title']}")
                _echo(f"           why it matters{' (AI, verified)' if alert['why_source'] == 'ai-verified' else ''}: {alert['why']}")
                _echo(f"           evidence: {', '.join(i[:12] for i in alert['evidence_ids'][:4])}")

    async def alerts_for(scan_id: int) -> None:
        report = build_report(store, scan_id)
        snap = snapshot(report, in_scope)
        found = diff_snapshots(state["snapshot"], snap, lang=lang)
        fresh, remembered = dedupe(found, set(state["alerted"]), current_keys(snap))
        announced = at_least(fresh, min_severity)
        if runtime_holder.get("ai") is not None and lang == "en":
            await explain(runtime_holder["ai"], announced, {i: r["payload"] for i, r in report["evidence"].items()})
        stamp = datetime_now()
        rows = [{**a.to_dict(), "at": stamp, "scan_id": scan_id} for a in fresh]
        state.update(snapshot=snap, alerted=sorted(remembered))
        state["history"] = (state.get("history") or [])[-5000:] + rows
        state["runs"] = (state.get("runs") or [])[-500:] + [{"at": stamp, "scan_id": scan_id, "alerts": len(fresh)}]
        save_state(out, state)
        write_digest(out, label, [r for r in state["history"] if r["severity"] in SEVERITIES[SEVERITIES.index(min_severity):]], lang=lang)
        latest["alerts"] = [r for r in rows if r["key"] in {a.key for a in announced}]
        for row, alert in zip([r for r in rows if r["key"] in {a.key for a in announced}], announced):
            row["why"], row["why_source"] = alert.why, alert.why_source
        if latest["alerts"] and smtp is not None:
            body = render_digest(label, latest["alerts"], period=f"scan #{scan_id}, {stamp}", lang=lang)
            counts = ", ".join(f"{sum(1 for a in latest['alerts'] if a['severity'] == s)} {s}" for s in reversed(SEVERITIES) if any(a["severity"] == s for a in latest["alerts"]))
            problem = send_email(smtp, list(email_to), f"[Scrutator] {label}: {len(latest['alerts'])} new alert(s) ({counts})", body)
            _echo(problem or f"E-mailed {len(latest['alerts'])} alert(s) to {', '.join(email_to)}.")

    async def run_once() -> int:
        async with open_context() as ctx:
            scan_id, _ = await run_scan(
                seed_entity, scope, store, ctx, max_steps=max_steps,
                deadline=Deadline(deadline_s) if deadline_s > 0 else None, source_policy=policy,
            )
        await alerts_for(scan_id)
        return scan_id

    async def go():
        async with make_webhook_client() as http_client:
            notify = make_webhook_notifier(webhook, http_client, extra=lambda: {"client": label, "alerts": latest["alerts"]}) if webhook else None
            if mode is not AIMode.OFF:
                config = _config(config_path)
                _consent(config, mode, yes_cloud)
                async with ai_client() as ai_http:
                    runtime_holder["ai"], _used = await build_runtime(config, cli_mode=mode, model=model, consent_cloud=True, redact=None,
                                                                      client=ai_http, apex_domains=[seed_entity.value])
                    await watch_loop(run_once=run_once, store=store, seed=seed_entity.value, interval=interval,
                                     max_runs=max_runs, notify=notify, sleep=lambda seconds: _sleep(seconds), on_run=report_run)
                    return
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


def _brand_line(section: dict | None) -> str:
    if not section:
        return "Brand: no result (the site could not be read, or robots.txt does not allow it); see Source coverage."
    total = section["summary"]
    linked = total["official"]
    if not linked:
        return "Brand: the home page links to no known platform account, so no platform was asked about."
    return (
        f"Brand: {linked} account(s) linked from the site ({total['official_absent']} answer as not existing), "
        f"{total['brand_unregistered']} unregistered brand handle(s), {total['lookalikes_existing']} of "
        f"{total['lookalikes_checked']} look-alike handle(s) exist, {total['unverifiable']} unverifiable."
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
    compliance: bool = typer.Option(False, "--compliance", help="Also show the informational compliance mapping of each rule (ISO/IEC 27001 Annex A, NIS2 Art. 21(2), CIS Controls, OWASP, KVKK). Not a certification or a legal conclusion."),
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
    mapping = _compliance_rows(risks) if compliance else None
    if as_json:
        shown = [{**r, **({"basis": basis(r["evidence_ids"], report["evidence"])} if basis(r["evidence_ids"], report["evidence"]) else {})} for r in risks]
        _echo(json.dumps({"risks": shown, "dependencies": report["dependencies"], **({"compliance": mapping} if mapping is not None else {})}, indent=2, sort_keys=True))
    else:
        _echo(f"{label} of {report['scan']['seed']}. {_risk_line(risks)}")
        if report.get("summary", {}).get("names"):
            _echo(_names_line(report["summary"]["names"]))
        for item in risks:
            _echo(f"[{item['severity'].upper():<6}] {item['rule_id']}  {', '.join(item['entity_ids'][:3])}")
            _echo(f"         {item['title']}. {item['explanation']}")
            how = basis_text(basis(item["evidence_ids"], report["evidence"]))
            if how:
                _echo(f"         how established: {how}")
            _echo(f"         evidence: {len(item['evidence_ids'])} record(s), fingerprint {item['fingerprint']}")
            _echo(f"         fix: {item['remediation']}")
            if mapping is not None and mapping.get(item["rule_id"]):
                _echo("         informational mapping: " + "; ".join(
                    f"{m['ref']}{'' if m['verified'] else ' (unverified)'}" for m in mapping[item["rule_id"]]))
        if mapping is not None:
            _echo("Compliance references are an informational mapping, not a certification or a legal conclusion; "
                  "'unverified' ones (all of ISO/IEC 27001) could not be read at an authoritative public source.")
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


def _compliance_rows(risks: list[dict]) -> dict[str, list[dict]]:
    """The informational compliance mapping (packs/data/compliance.yaml) of the rules these risks come from."""
    packs = load_packs()
    out: dict[str, list[dict]] = {}
    for rule_id in sorted({r["rule_id"] for r in risks}):
        entry = packs.compliance_for(rule_id)
        out[rule_id] = [m.model_dump(mode="json") for m in entry.mappings] if entry is not None else []
    return out


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


@app.command("exposure")
def exposure_cmd(
    seed: str = typer.Argument(..., help="The organisation's domain (one of the engagement's domains). A person is never a seed."),
    engagement_file: Path = typer.Option(..., "--engagement", help="The engagement file that authorises the assessment (organisation, domains, authorised_by, start, end, purpose)."),
    detail: bool = typer.Option(False, "--detail", help="Also write the person-like work addresses found to exposure-detail.json (never into the report or the bundle). Logged in the audit log."),
    yes: bool = typer.Option(False, "--yes", help="Confirm the attestation without a prompt (recorded as such)."),
    out: Path = typer.Option(Path("scrutator-out"), "--out", help="Output directory."),
    db: Optional[Path] = typer.Option(None, "--db", help="SQLite database path (default: <out>/scrutator.db)."),
    bundle: bool = typer.Option(False, "--bundle/--no-bundle", help="Also write a signed proof bundle (minimised data only)."),
    key_dir: Optional[Path] = typer.Option(None, "--key-dir", help="Directory with signing.key (default: ~/.config/scrutator)."),
    deadline_s: float = typer.Option(300, "--deadline", min=0, help="Seconds the assessment may take (0: no limit)."),
) -> None:
    """Organisation exposure (off by default; needs an engagement file): how many work addresses the organisation itself
    publishes, their naming pattern, which functions are visible, and what an attacker could infer. Aggregate only,
    unless --detail."""
    from scrutator.engagement import EngagementError, check_seed, load_engagement
    from scrutator.exposure_scan import PREVIEW_VARIABLE, exposure_scope, run_exposure, write_detail

    if os.environ.get(PREVIEW_VARIABLE) != "1":
        # the design's release gate: a legal and ethics review before this ships. Until then it is a preview that
        # runs only when asked for twice: this variable, and an engagement file.
        raise _fail(
            "organisation exposure is a preview: it has not had the legal and ethics review its design requires "
            f"(docs/security.md). Set {PREVIEW_VARIABLE}=1 to run it, with an engagement file."
        )
    from scrutator.web import open_web, scope_guard

    try:
        loaded = load_engagement(engagement_file)
        host = check_seed(seed, loaded.engagement)
    except EngagementError as exc:
        raise _fail(f"refused: {exc}") from exc
    record = loaded.engagement.record()
    _echo("Engagement (written to the audit log before any lookup):")
    _echo(f"  organisation: {record['organisation']}")
    _echo(f"  domains: {', '.join(record['domains'])}")
    _echo(f"  authorised by: {record['authorised_by']['name']} ({record['authorised_by']['role']})")
    _echo(f"  in force: {record['start']} to {record['end']}")
    _echo(f"  purpose: {record['purpose']}")
    _echo(f"  file sha256: {loaded.sha256}")
    if yes:
        confirmed = "--yes"
    elif sys.stdin is not None and sys.stdin.isatty():
        if not typer.confirm("I confirm this engagement authorises the assessment of these domains", default=False):
            raise _fail("not confirmed: nothing was looked up")
        confirmed = "prompt"
    else:
        raise _fail("the attestation must be confirmed: run in a terminal, or pass --yes")
    signing_key = _signing_key(key_dir) if bundle else None
    out.mkdir(parents=True, exist_ok=True)
    store = Store(db or out / "scrutator.db")

    async def go():
        async with open_context() as ctx, open_web(scope_guard(exposure_scope(loaded.engagement))) as web:
            ctx.web = web
            return await run_exposure(loaded, host, store, ctx, confirmed=confirmed, detail=detail, deadline_s=deadline_s or None)

    scan_id, run = asyncio.run(go())
    detail_rows = []
    if detail:
        _, detail_rows = write_detail(store, scan_id, run, loaded, out)
    report = build_report(store, scan_id)
    (out / "report.json").write_text(render_json(report), encoding="utf-8")
    (out / "report.html").write_text(render_html(report), encoding="utf-8")
    manifest = create_bundle(store, scan_id, signing_key, out / "proof.scrutator") if signing_key is not None else None
    store.close()
    org = report.get("org_exposure") or {}
    counts = org.get("addresses") or {}
    _echo(f"Exposure #{scan_id} of {record['organisation']}: {counts.get('distinct', 0)} work address(es) found "
          f"({counts.get('role', 0)} role mailboxes, {counts.get('person_like', 0)} person-like), "
          f"{counts.get('outside_engagement_dropped', 0)} outside the engagement dropped.")
    if org.get("naming_patterns"):
        _echo("Naming patterns of person-like addresses: " + ", ".join(f"{p['shape']} {p['count']}" for p in org["naming_patterns"]) + ".")
    if org.get("functions"):
        _echo("Functions with a published mailbox: " + ", ".join(f"{k} {v}" for k, v in org["functions"].items()) + ".")
    for item in org.get("inferences", []):
        _echo(f"- {item['text']}")
    failed = sum(h["error"] for h in report["sources"].values())
    if failed:
        _echo(f"{failed} lookup(s) failed; see Source coverage in the report.")
    _echo(f"Wrote report.json, report.html to {out}")
    if detail:
        _echo(f"Per-person detail: {len(detail_rows)} address(es) in {out / 'exposure-detail.json'} (logged in the audit log; not in the report or the bundle).")
    if manifest is not None:
        _echo(f"Proof bundle: {out / 'proof.scrutator'} (signing key {manifest['key_fingerprint']})")


# ------------------------------------------------------------------------------------------- audit (R7)


def _authorise_audit(engagement_file: Optional[Path], self_mode: bool, yes: bool, *, today=None, active: bool = False):
    """The loaded engagement (client mode) or None (self mode), confirmed on the terminal or with --yes. With `active`, the
    authorisation must also cover active testing: an engagement with `active_testing: true`, or a self-attestation that names
    the systems the domains point at."""
    from scrutator.engagement import EngagementError, load_engagement

    if bool(engagement_file) == bool(self_mode):
        raise _fail("an audit needs exactly one of --engagement FILE (a client's signed authorisation) or --self (your own domains)")
    if self_mode:
        question = "I confirm I own or control the domains in scope (self-assessment)"
        if active:
            question = (
                "I confirm I own or control the domains in scope AND the systems their names resolve to, and I authorise active "
                "connection checks of those systems (TCP connect, TLS handshake, one HTTP request; no login, no exploit)"
            )
        loaded = None
    else:
        try:
            loaded = load_engagement(engagement_file, today=today)
        except EngagementError as exc:
            raise _fail(f"refused: {exc}") from exc
        record = loaded.engagement.record()
        _echo("Engagement:")
        _echo(f"  organisation: {record['organisation']}")
        _echo(f"  domains: {', '.join(record['domains'])}")
        _echo(f"  authorised by: {record['authorised_by']['name']} ({record['authorised_by']['role']})")
        _echo(f"  in force: {record['start']} to {record['end']}")
        _echo(f"  file sha256: {loaded.sha256}")
        question = "I confirm this engagement authorises a passive review of these domains"
        if active:
            if not loaded.engagement.active_testing:
                raise _fail("refused: this engagement does not authorise active testing. The signed letter must allow it and the engagement file must say `active_testing: true`. Nothing was sent.")
            _echo("  active testing: authorised (connection checks of the systems the domains resolve to)")
            question = "I confirm this engagement authorises active connection checks of the systems these domains point at"
    if yes:
        return loaded, "--yes"
    if sys.stdin is not None and sys.stdin.isatty():
        if not typer.confirm(question, default=False):
            raise _fail("not confirmed: nothing was looked up")
        return loaded, "prompt"
    raise _fail("the authorisation must be confirmed: run in a terminal, or pass --yes")


@app.command("audit")
def audit_cmd(
    seed: Optional[str] = typer.Argument(None, help="The domain to review (a new passive scan). Leave out with --from-bundle."),
    from_bundle: Optional[Path] = typer.Option(None, "--from-bundle", help="Make the audit from an existing signed bundle instead of scanning."),
    engagement_file: Optional[Path] = typer.Option(None, "--engagement", help="Client mode: the engagement file of the signed authorisation (see `scrutator audit-letter`)."),
    self_mode: bool = typer.Option(False, "--self", help="Self mode: a review of domains you own or control (attested, recorded in the audit log)."),
    branding: Optional[Path] = typer.Option(None, "--branding", help="audit.yaml: auditor name, contact, logo, colours, language."),
    lang: Optional[str] = typer.Option(None, "--lang", help="en or tr (default: the branding file's, else en)."),
    out: Path = typer.Option(Path("audit-out"), "--out", help="Output directory."),
    key_dir: Optional[Path] = typer.Option(None, "--key-dir", help="Directory with signing.key (a new scan's bundle is signed with it)."),
    pin: Optional[str] = typer.Option(None, "--pin", help="With --from-bundle: require this signer (fingerprint or signing.pub)."),
    pdf: bool = typer.Option(True, "--pdf/--no-pdf", help="Also print audit.pdf with an installed Chromium-based browser (Edge, Chrome, Chromium, Brave), if one is found."),
    ai: str = typer.Option("off", "--ai", help="off (default: deterministic text), or local, cloud, hybrid: offer the English executive sentences to a writer model for plainer wording, kept only when the verifier passes them."),
    model: Optional[str] = typer.Option(None, "--model", help="Model name for every AI role."),
    yes_cloud: bool = typer.Option(False, "--yes-cloud", help="Consent to cloud AI without a prompt."),
    config_path: Optional[Path] = typer.Option(None, "--config", help="AI config file."),
    yes: bool = typer.Option(False, "--yes", help="Confirm the authorisation without a prompt (recorded as such)."),
    deadline_s: float = typer.Option(DEFAULT_DEADLINE_S, "--deadline", min=0, help="Seconds the scan may take (0: no limit)."),
    max_entities: int = typer.Option(5000, "--max-entities", min=1, help="Cap on the entities the scan records."),
    exclude_sources: Optional[str] = typer.Option(None, "--exclude-sources", help="Do not use these sources (comma-separated)."),
    noncommercial: bool = typer.Option(True, "--noncommercial/--no-noncommercial", help="--no-noncommercial: leave out sources whose free tier is for non-commercial use only (advisable for paid work; see docs/sources.md)."),
    active: bool = typer.Option(False, "--active", help="After the passive scan, confirm what third parties reported with a few authorised connections to the addresses the domains resolve to: TCP connect and banner, TLS handshake, one HTTP request. Needs an engagement with active_testing: true, or --self (which then attests the systems too). Never probes shared platforms or non-public addresses. See docs/active.md."),
    max_connections: int = typer.Option(60, "--max-connections", min=1, max=500, help="With --active: the most connections the whole active phase may open."),
) -> None:
    """Turn a passive scan (or an existing signed bundle) into a client deliverable: audit.html (print-ready), audit.pdf
    when a browser is installed, the interactive report as technical-annex.html, and the signed bundle. Refuses to run
    without an authorisation: --engagement (client) or --self (your own domains)."""
    import time

    from scrutator.audit.branding import BrandingError, load_branding
    from scrutator.audit.content import AuditError, authorisation_from_log, authorisation_late, build_audit, engagement_event, self_event
    from scrutator.audit.make import append_log, load_bundle, now, polish_facts, write_audit

    started = time.monotonic()
    if (seed is None) == (from_bundle is None):
        raise _fail("give a domain to scan, or --from-bundle FILE, not both")
    try:
        brand = load_branding(branding, language=lang)
    except BrandingError as exc:
        raise _fail(str(exc)) from exc
    mode = _mode(ai)
    out.mkdir(parents=True, exist_ok=True)
    timing: dict = {}

    if active and from_bundle is not None:
        raise _fail("--active runs during a new scan and never re-probes from a bundle: give a domain to scan instead of --from-bundle")
    if from_bundle is not None:
        try:
            loaded_bundle = load_bundle(from_bundle, pin=_pinned(pin))
        except AuditError as exc:
            raise _fail(str(exc)) from exc
        report = loaded_bundle.report
        from datetime import date as _date

        scan_day = _date.fromisoformat(str(report["scan"]["started_at"])[:10])
        loaded, confirmed = _authorise_audit(engagement_file, self_mode, yes, today=scan_day)
        signed = authorisation_from_log(loaded_bundle.audit_records)
        if loaded is not None and signed is not None and signed["mode"] == "client" and signed["sha256"] != loaded.sha256:
            raise _fail("the bundle's signed log records another engagement than this file (sha256 differs)")
        wanted_mode = "self" if loaded is None else "client"
        if signed is not None and signed["mode"] == wanted_mode:
            authorisation = signed
        elif loaded is not None:
            authorisation = authorisation_late(loaded)
        else:
            authorisation = authorisation_late(domains=list((report.get("scope") or {}).get("domains") or [report["scan"]["seed"]]), organisation=brand.client)
        target = out / "proof.scrutator"
        if from_bundle.resolve() != target.resolve():
            import shutil

            shutil.copyfile(from_bundle, target)
    else:
        loaded, confirmed = _authorise_audit(engagement_file, self_mode, yes, active=active)
        try:
            seed_entity = _parse_seed(seed)
        except ValueError as exc:
            raise _fail(f"invalid seed {seed!r}: give a bare domain") from exc
        if seed_entity.type is not EntityType.DOMAIN:
            raise _fail("an audit is of an organisation's domain: give a domain")
        if loaded is not None and not loaded.engagement.covers(seed_entity.value):
            raise _fail(f"{seed_entity.value} is not one of the engagement's domains ({', '.join(loaded.engagement.domains)})")
        event = engagement_event(loaded, confirmed) if loaded is not None else self_event([seed_entity.value], brand.client, confirmed, active=active)
        policy = _source_policy(None, exclude_sources, not noncommercial)
        signing_key = _signing_key(key_dir)
        scope = _default_scope(seed_entity)
        store = Store(out / "scrutator.db")
        from scrutator.active.gate import ActiveRefused
        from scrutator.active.guard import Limits
        from scrutator.active.run import ActiveConfig

        _echo(f"Scanning {seed_entity.value} (passive" + (", then authorised active confirmation" if active else "") + "); the authorisation is written to the audit log before any lookup ...")
        active_config = ActiveConfig(limits=Limits(max_connections=max_connections)) if active else None

        async def go():
            async with open_context() as ctx:
                return await run_scan(
                    seed_entity, scope, store, ctx, max_steps=1000, max_entities=max_entities,
                    deadline=Deadline(deadline_s) if deadline_s > 0 else None, source_policy=policy, pre_audit=[event],
                    active=active_config,
                )

        try:
            scan_id, _stats = asyncio.run(go())
        except ActiveRefused as exc:
            raise _fail(f"refused: {exc}") from exc
        except ValueError as exc:
            raise _fail(str(exc)) from exc
        except KeyboardInterrupt:
            # what was collected is already stored: the audit is made from it, and says the run was interrupted
            scan_id = store.latest_scan(seed_entity.value)
            if scan_id is None:
                raise _fail("interrupted before the scan started") from None
            store.append_audit(scan_id, {"event": "interrupted"})
            _echo("Interrupted: the audit covers what was collected so far (partial).")
        timing["scan_s"] = round(time.monotonic() - started, 1)
        _report, _written, bundle_path, _manifest, problem = _write_outputs(store, scan_id, out, set(), signing_key)
        if problem or bundle_path is None:
            raise _fail(f"no proof bundle was written: {problem}")
        pub = public_key_path(key_dir or private_key_path().parent)
        if pub.exists():
            (out / "signing.pub").write_bytes(pub.read_bytes())
        loaded_bundle = load_bundle(bundle_path)
        report = loaded_bundle.report
        authorisation = authorisation_from_log(loaded_bundle.audit_records)
        if authorisation is None:
            raise _fail("the scan's audit log does not hold the authorisation before its first lookup")

    build_started = time.monotonic()
    try:
        facts = build_audit(report, authorisation=authorisation, bundle=loaded_bundle.info, lang=brand.language,
                            auditor=brand.auditor, client=brand.client, generated_at=now())
    except AuditError as exc:
        raise _fail(f"refused: {exc}") from exc
    (out / "technical-annex.html").write_text(render_html(report), encoding="utf-8")
    if mode is not AIMode.OFF:
        config = _config(config_path)
        _consent(config, mode, yes_cloud)

        async def polish():
            async with ai_client() as ai_http:
                runtime, _used = await build_runtime(config, cli_mode=mode, model=model, consent_cloud=True, redact=None,
                                                     client=ai_http, apex_domains=list(authorisation["domains"]))
                return await polish_facts(runtime, facts, loaded_bundle.payloads)

        try:
            facts["polish"] = asyncio.run(polish())
        except AIError as exc:
            _echo(f"AI rewording skipped ({exc}); the deterministic text is used.")
    written = write_audit(out, facts, brand, pdf=pdf)
    timing["audit_s"] = round(time.monotonic() - build_started, 1)
    timing["total_s"] = round(time.monotonic() - started, 1)
    info = loaded_bundle.info
    append_log(out, {"event": "audit", "at": facts["generated_at"], "mode": authorisation["mode"], "recorded": authorisation["recorded"],
                     "authorisation_sha256": authorisation.get("sha256", ""), "bundle_sha256": info["sha256"],
                     "lang": facts["lang"], "pdf": written.pdf is not None, "ai": facts["polish"] is not None, "timing": timing})
    summary = facts["summary"]
    _echo(f"Audit of {facts['who']['client']} ({', '.join(authorisation['domains'])}): {summary['verified']} verified name(s), "
          f"{summary['claimed']} unconfirmed, {summary['risks']} finding(s).")
    _echo(f"Authorisation: {authorisation['mode']}, " + ("in the signed audit log before the first lookup." if authorisation["recorded"] == "signed"
                                                       else "recorded now in audit-log.jsonl (the scan predates it)."))
    if facts["polish"] is not None:
        kept = sum(1 for s in facts["polish"]["statements"] if s["verdict"] == "verified")
        _echo(f"AI: {kept} of {len(facts['polish']['statements'])} executive sentence(s) reworded and verified; the rest kept as written.")
    if facts.get("active"):
        shown = facts["active"]
        s = shown["summary"]
        _echo(f"Active confirmation: {s['checks']} connection check(s) on {s['addresses']} address(es): {s['open']} open, {s['closed']} closed, {s['filtered']} unanswered; {s['skipped']} address(es) not probed.")
        for row in shown["addresses"]:
            opened = ", ".join(f"{o['port']}" + (f" ({o['banner']})" if o["banner"] else "") for o in row["open"]) or "none"
            _echo(f"  {row['ip']} ({', '.join(row['names'])}): open {opened}")
        for row in shown["skipped"]:
            _echo(f"  {row['ip']} ({', '.join(row['names'])}): not probed, {row['reason']}")
    _echo(f"Wrote {', '.join(written.files)}, technical-annex.html and proof.scrutator to {out}")
    if written.pdf is None:
        _echo(f"No PDF: {written.pdf_problem}.")
    _echo(f"Bundle sha256 {info['sha256']}, signing key {info['key_fingerprint']}.")
    _echo(f"Time: {timing.get('scan_s', 0):g} s scan, {timing['audit_s']:g} s audit, {timing['total_s']:g} s in all.")
    _echo(f"Check it as the client will: scrutator audit-check {out / 'audit.html'} {out / 'proof.scrutator'}")


@app.command("active-plan")
def active_plan_cmd(
    scan_ref: str = typer.Argument(..., metavar="SCAN", help="A scan id in --db, or a .scrutator bundle."),
    db: Path = typer.Option(Path("scrutator-out/scrutator.db"), "--db", help="SQLite database for scan ids."),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Show, offline, which addresses and ports `scrutator audit --active` would probe for a scan, and which addresses it would
    refuse or skip (private ranges, shared platforms) and why. Nothing is sent: it reads a passive scan or bundle."""
    from scrutator.active.guard import Limits
    from scrutator.active.plan import plan_active

    report, label = _load_report(scan_ref, db)
    plan = plan_active(report, load_packs(), Limits()).to_dict()
    if as_json:
        _echo(json.dumps(plan, indent=2, sort_keys=True))
        return
    _echo(f"{label} of {report['scan']['seed']}: active plan (nothing is sent by this command).")
    for target in plan["targets"]:
        ports = ", ".join(str(p["port"]) for p in target["ports"])
        _echo(f"  probe {target['ip']} ({', '.join(target['names'][:4])}): {len(target['ports'])} connect check(s): {ports}")
        _echo(f"        passive source lists open: {', '.join(str(p) for p in target['passive_ports']) or 'nothing'}")
    for skip in plan["skipped"]:
        _echo(f"  skip  {skip['ip']} ({', '.join(skip['names'][:4])}): {skip['reason']}")
    if plan["over_cap"]:
        _echo(f"  {len(plan['over_cap'])} port(s) left out because of the connection cap.")
    if not plan["targets"]:
        _echo("  no address would be probed.")


@app.command("audit-check")
def audit_check_cmd(
    page: Path = typer.Argument(..., help="audit.html"),
    bundle: Path = typer.Argument(..., help="The proof bundle the audit names (proof.scrutator)."),
    pin: Optional[str] = typer.Option(None, "--pin", help="Require this signer (fingerprint or signing.pub)."),
) -> None:
    """Check an audit against its signed bundle, offline: the bundle verifies and is the one the audit names, every
    number, finding and sentence follows from it, and the page was not edited. Exit status 1 on any failure."""
    from scrutator.audit.make import check_audit

    checks = check_audit(page, bundle, pin=_pinned(pin))
    for check in checks:
        _echo(f"{'PASS' if check.ok else 'FAIL'}  {check.name}" + (f"  ({check.detail})" if check.detail else ""))
    if not all(c.ok for c in checks):
        _echo("Audit check FAILED: do not rely on this report.")
        raise typer.Exit(1)
    _echo("Audit check passed: the report is what the signed evidence implies.")


@app.command("audit-letter")
def audit_letter_cmd(
    out: Path = typer.Option(Path("authorisation"), "--out", help="Directory for the letter and the engagement file."),
    lang: str = typer.Option("en", "--lang", help="en or tr."),
    client: Optional[str] = typer.Option(None, "--client", help="The client's legal name."),
    domains: Optional[str] = typer.Option(None, "--domains", help="Comma-separated domains in scope."),
    start: Optional[str] = typer.Option(None, "--start", help="First day, YYYY-MM-DD."),
    end: Optional[str] = typer.Option(None, "--end", help="Last day, YYYY-MM-DD."),
    auditor: Optional[str] = typer.Option(None, "--auditor", help="Your name or company."),
    auditor_contact: Optional[str] = typer.Option(None, "--auditor-contact", help="Your contact."),
    client_contact: Optional[str] = typer.Option(None, "--client-contact", help="The client's contact for the review."),
    signatory: Optional[str] = typer.Option(None, "--signatory", help="Who signs for the client."),
    signatory_role: Optional[str] = typer.Option(None, "--signatory-role", help="Their role (must be entitled to authorise testing)."),
    reference: Optional[str] = typer.Option(None, "--reference", help="Engagement reference."),
    retention: Optional[str] = typer.Option(None, "--retention", help="How long you keep the data after delivery, e.g. '90 days'."),
) -> None:
    """Write a fill-in authorisation letter (passive review only) and the engagement file `scrutator audit --engagement`
    reads. A template, not legal advice. Unfilled fields stay as <fill in: ...>, which `audit` refuses."""
    from datetime import date as _date

    from scrutator.audit.letter import make_letter
    from scrutator.engagement import refuse_person

    try:
        start_day = _date.fromisoformat(start) if start else None
        end_day = _date.fromisoformat(end) if end else None
    except ValueError as exc:
        raise _fail("--start and --end are YYYY-MM-DD") from exc
    if start_day and end_day and start_day > end_day:
        raise _fail("--start is after --end")
    listed = [d.strip().lower() for d in (domains or "").split(",") if d.strip()]
    for domain in listed:
        problem = refuse_person(domain)
        if problem:
            raise _fail(f"{domain!r}: {problem}")
    try:
        letter, engagement = make_letter(lang=lang, client=client, domains=listed, start=start_day, end=end_day, auditor=auditor,
                                         auditor_contact=auditor_contact, client_contact=client_contact, signatory=signatory,
                                         signatory_role=signatory_role, reference=reference, retention=retention)
    except ValueError as exc:
        raise _fail(str(exc)) from exc
    out.mkdir(parents=True, exist_ok=True)
    name = "yetki-belgesi.txt" if lang == "tr" else "authorisation-letter.txt"
    (out / name).write_text(letter, encoding="utf-8")
    (out / "engagement.yaml").write_text(engagement, encoding="utf-8")
    _echo(f"Wrote {out / name} and {out / 'engagement.yaml'}.")
    _echo("This is a template, not legal advice: have it reviewed by counsel before use. Get it signed by someone entitled "
          "to authorise testing, then copy the signed values into engagement.yaml (scrutator refuses any <fill in: ...> left).")


# ------------------------------------------------------------------------------------------- bug bounty (R7)

bounty_app = typer.Typer(no_args_is_help=True, help="Bug-bounty mode: import a programme's scope, watch it for new assets and takeover candidates (passive).")
app.add_typer(bounty_app, name="bounty")
BOUNTY_KINDS = ("new_name", "new_takeover", "new_cert", "new_service", "resolved_risk")


@bounty_app.command("import")
def bounty_import(
    source: str = typer.Argument(..., help="The scope export: a HackerOne scope CSV, Bugcrowd or bounty-targets JSON, or a plain list; - reads standard input."),
    program: str = typer.Option("", "--program", help="Programme name (shown in alerts and finding drafts)."),
    out: Path = typer.Option(Path("bounty-scope.yaml"), "--out", help="The scope file to write."),
) -> None:
    """Parse a programme's scope into a deny-by-default scope file. Wildcards that are too broad, odd schemes, user-info
    URLs, private ranges and hidden characters are refused and listed, never guessed."""
    from scrutator.bounty import BountyScope, ScopeError, parse_scope

    try:
        data = sys.stdin.buffer.read(10 * 1024 * 1024) if source == "-" else Path(source).read_bytes()
        parsed = parse_scope(data, source)
    except (OSError, ScopeError) as exc:
        raise _fail(str(exc)) from exc
    scope = BountyScope.from_parsed(parsed, program=program, data=data, name=source)
    if not scope.roots() and not scope.include["cidr"]:
        for item in parsed.refused[:10]:
            _echo(f"  refused {item['input']!r}: {item['reason']}")
        raise _fail("nothing in scope could be used: no scope file written")
    out.write_text(yaml.safe_dump(scope.to_dict(), sort_keys=False, allow_unicode=False), encoding="utf-8")
    inc, exc_ = scope.include, scope.exclude
    _echo(f"In scope: {len(inc['host'])} host(s), {len(inc['wildcard'])} wildcard(s), {len(inc['cidr'])} range(s). "
          f"Out of scope: {len(exc_['host'])} host(s), {len(exc_['wildcard'])} wildcard(s), {len(exc_['cidr'])} range(s).")
    for item in parsed.refused[:20]:
        _echo(f"  refused {item['input']!r}: {item['reason']}")
    if len(parsed.refused) > 20:
        _echo(f"  ... and {len(parsed.refused) - 20} more refused (all listed in {out})")
    for item in parsed.notes[:10]:
        _echo(f"  note {item['input']!r}: {item['reason']}")
    _echo(f"Wrote {out}. Anything not listed in it is out of scope. Scan roots: {', '.join(scope.roots()) or 'none'}.")


def _bounty_policy(noncommercial: bool) -> SourcePolicy:
    modules = load_builtin_modules()
    names = sorted(
        m.name for m in modules
        if m.opt_in is None and m.name not in (QUICK_LEAVES_OUT - {"internetdb"}) and (m.needs_key is None or os.environ.get(m.needs_key))
    )
    try:
        return SourcePolicy.parse(",".join(names), None, not noncommercial, modules)
    except SourceError as exc:
        raise _fail(str(exc)) from exc


@bounty_app.command("watch")
def bounty_watch(
    scope_file: Path = typer.Option(..., "--scope", help="The scope file `scrutator bounty import` wrote."),
    out: Path = typer.Option(Path("bounty-watch"), "--out", help="Baseline, alerts and finding drafts go here."),
    every: str = typer.Option("6h", "--every", help="Interval: 30m, 6h, 1d."),
    max_runs: int = typer.Option(0, "--max-runs", help="Stop after N rounds (0 = until interrupted)."),
    budget: float = typer.Option(30.0, "--budget", min=1.0, help="Seconds each scan root may take."),
    webhook: Optional[str] = typer.Option(None, "--webhook", help="POST the new alerts as JSON (https only, or localhost)."),
    as_json: bool = typer.Option(False, "--json", help="Print the alerts of each round as JSON."),
    key_dir: Optional[Path] = typer.Option(None, "--key-dir", help="Sign each round's scans into bundles (cited by the finding drafts)."),
    noncommercial: bool = typer.Option(True, "--noncommercial/--no-noncommercial", help="--no-noncommercial: leave out sources whose free tier is for non-commercial use only."),
) -> None:
    """Scheduled passive scans of a programme's scope. The first round is the baseline; after it only what is new and in
    scope is announced, once: verified names, takeover candidates (and their resolution), certificates and open
    services Shodan's InternetDB lists. No active probing. Each takeover candidate gets a ready-to-paste Markdown draft."""
    from scrutator.bounty import BountyScope, ScopeError, finding_snippet
    from scrutator.monitor import TAKEOVER_RULES, current_keys, dedupe, diff_snapshots, load_state, save_state, snapshot

    try:
        scope = BountyScope.load(scope_file)
        interval = parse_interval(every)
        if webhook is not None:
            validate_webhook(webhook)
    except (OSError, ValueError, ScopeError) as exc:
        raise _fail(str(exc)) from exc
    policy = _bounty_policy(noncommercial)
    signing_key = _signing_key(key_dir) if key_dir is not None else None
    out.mkdir(parents=True, exist_ok=True)
    (out / "findings").mkdir(exist_ok=True)
    try:
        state = load_state(out)
    except ValueError as exc:
        raise _fail(str(exc)) from exc
    roots = scope.roots()
    if not roots:
        raise _fail("the scope has no domain to start from (ranges alone are not watched)")
    _echo(f"Watching {scope.program or scope_file.name}: {len(roots)} root(s), every {every}; first round is the baseline." if state["snapshot"] is None
          else f"Watching {scope.program or scope_file.name}: {len(roots)} root(s), every {every}; baseline from an earlier run.")

    async def one_round(number: int) -> None:
        stamp = datetime_now()
        merged = {"names": {}, "risks": {}, "certs": {}, "services": {}}
        evidence: dict = {}
        bundles: dict[str, tuple[str, str]] = {}
        store = Store(out / "bounty.db")
        try:
            for root in roots:
                seed_entity = Entity(type=EntityType.DOMAIN, value=root)
                async with open_context() as ctx:
                    scan_id, _ = await run_scan(seed_entity, ScopePolicy(domains=[root]), store, ctx, ai=None, max_steps=2000,
                                                deadline=Deadline(budget), source_policy=policy, timeout_cap=min(15.0, budget))
                report = build_report(store, scan_id)
                part = snapshot(report, scope.contains)
                for key in merged:
                    merged[key].update(part[key])
                evidence.update(report["evidence"])
                if signing_key is not None:
                    (out / "bundles").mkdir(exist_ok=True)
                    path = out / "bundles" / f"{root}-{stamp[:19].replace(':', '')}.scrutator"
                    manifest = create_bundle(store, scan_id, signing_key, path)
                    bundles[root] = (str(path), manifest["key_fingerprint"])
        finally:
            store.close()
        alerts = [a for a in diff_snapshots(state["snapshot"], merged, kinds=BOUNTY_KINDS)
                  if a.kind != "resolved_risk" or a.rule_id in TAKEOVER_RULES]
        fresh, remembered = dedupe(alerts, set(state["alerted"]), current_keys(merged))
        first = state["snapshot"] is None
        state.update(snapshot=merged, alerted=sorted(remembered))
        state["runs"] = (state.get("runs") or [])[-200:] + [{"at": stamp, "names": len(merged["names"]), "alerts": len(fresh)}]
        save_state(out, state)
        if first:
            _echo(f"Round {number} ({stamp}): baseline of {len(merged['names'])} in-scope verified name(s), "
                  f"{sum(1 for r in merged['risks'].values() if r['rule_id'] in TAKEOVER_RULES)} takeover candidate(s), "
                  f"{len(merged['certs'])} certificate(s), {len(merged['services'])} open service(s). Nothing announced on a baseline.")
            return
        payload = [{**a.to_dict(), "at": stamp} for a in fresh]
        for alert in payload:
            if alert["kind"] == "new_takeover":
                root = next((r for r in roots if any(e == r or e.endswith("." + r) for e in alert["entities"])), "")
                bundle, fingerprint_ = bundles.get(root, ("", ""))
                draft = finding_snippet(alert, evidence, program=scope.program, bundle=bundle, key_fingerprint=fingerprint_)
                target = out / "findings" / f"{alert['key'].replace(':', '-')}.md"
                target.write_text(draft, encoding="utf-8")
                alert["draft"] = str(target)
        if payload:
            (out / f"alerts-{stamp[:19].replace(':', '')}.json").write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        if as_json:
            _echo(json.dumps(payload, indent=2, sort_keys=True))
        else:
            _echo(f"Round {number} ({stamp}): {len(payload)} new alert(s).")
            for alert in payload:
                _echo(f"  [{alert['severity'].upper():<6}] {alert['title']}  (evidence {', '.join(i[:12] for i in alert['evidence_ids'][:3])})"
                      + (f"\n           draft: {alert['draft']}" if alert.get("draft") else ""))
        if payload and webhook:
            async with make_webhook_client() as client:
                try:
                    await client.post(webhook, json={"tool": "scrutator", "program": scope.program, "generated_at": stamp, "alerts": payload}, timeout=15.0)
                except httpx.HTTPError:
                    _echo("Webhook did not answer; the alerts are on disk.")

    async def go():
        runs = 0
        while True:
            runs += 1
            await one_round(runs)
            if max_runs and runs >= max_runs:
                return
            await _sleep(interval)

    try:
        asyncio.run(go())
    except KeyboardInterrupt:
        _echo("Stopped.")


def datetime_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


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


@app.command("bench")
def bench_cmd(
    out: Path = typer.Option(Path("scrutator-bench"), "--out", help="Where the lab scans, the bundle and bench.json/bench.md go."),
    key_dir: Optional[Path] = typer.Option(None, "--key-dir", help="Sign the lab bundle with this key (default: a key made for the bench in <out>/keys)."),
    verifier_model: Optional[str] = typer.Option(None, "--verifier-model", help="Also run the Hallucination Test with this Ollama model as the verifier (loopback only)."),
    ollama_url: str = typer.Option("http://127.0.0.1:11434", "--ollama-url", help="Where Ollama answers; must be this machine."),
    as_json: bool = typer.Option(False, "--json", help="Print bench.json instead of the table."),
) -> None:
    """OSINT-Bench v0, offline: planted risk lab, attribution lab, name tiers, bundle tamper and replay, scope
    safety and the Hallucination Test. Exit status 1 when a threshold fails."""
    from scrutator.benchlab.run import render_table, run_bench

    key = _signing_key(key_dir) if key_dir is not None else None
    try:
        result = asyncio.run(run_bench(out, key=key, model=verifier_model, ollama_url=ollama_url))
    except ValueError as exc:
        raise _fail(str(exc)) from exc
    _echo(json.dumps(result, indent=2, sort_keys=True) if as_json else render_table(result))
    if not as_json:
        _echo(f"Wrote {out / 'bench.json'} and {out / 'bench.md'}; the lab report and bundle are in {out / 'lab'}.")
    if not result["pass"]:
        raise typer.Exit(1)


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
    # LF on every platform: the file is committed, and a CRLF copy written on Windows would show as a change
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
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
