"""Active confirmation, task 5: the rules, the report, `verify`, replay, the audit, SARIF, `risk` and the guardrail refusals,
on the active lab (local listeners; benchlab/activelab.py)."""

import asyncio
import copy
import hashlib
import json
from datetime import date, timedelta

import httpx
import pytest
from typer.testing import CliRunner

from activefix import self_authorisation
from bundlefix import forge
from scrutator import cli
from scrutator.active import SOURCES
from scrutator.active.records import active_records
from scrutator.active.section import active_problems, active_section
from scrutator.audit.make import check_audit
from scrutator.benchlab.activelab import ACTIVE_RULES, NEVER, TRUTH_ACTIVE_RULES, active_lab
from scrutator.bundle.keys import generate_keypair, load_private_key, private_key_path
from scrutator.bundle.reader import read_raw
from scrutator.bundle.replay import replay_evidence
from scrutator.bundle.verify import verify_bundle
from scrutator.bundle.writer import create_bundle
from scrutator.packs import load_packs
from scrutator.report import render_html
from scrutator.report.sarif import to_sarif
from scrutator.risk.basis import basis, basis_text
from scrutator.risk.engine import analyze, comparable

runner = CliRunner()


@pytest.fixture(scope="module")
def lab():
    async def go():
        async with active_lab() as made:
            return made

    return asyncio.run(go())


@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    folder = tmp_path_factory.mktemp("keys")
    generate_keypair(folder)
    return load_private_key(private_key_path(folder))


@pytest.fixture(scope="module")
def bundle(lab, keys, tmp_path_factory):
    path = tmp_path_factory.mktemp("bundle") / "proof.scrutator"
    create_bundle(lab.store, lab.scan_id, keys, path)
    return path


def by_rule(report):
    found: dict[str, set] = {}
    for risk in report["risks"]:
        found.setdefault(risk["rule_id"], set()).update(risk["entity_ids"])
    return found


# ------------------------------------------------------------------------------------------------ rules


def test_every_planted_issue_is_found_and_only_those(lab):
    found = by_rule(lab.report)
    for rule, entities in lab.truth.items():
        assert rule in found and entities <= found[rule], (rule, found.get(rule))
    active_found = {r for r in found if r in ACTIVE_RULES}
    assert active_found == set(lab.truth)
    assert lab.report["summary"]["risks"] == len(lab.report["risks"])


def test_the_tls_and_http_findings_are_about_the_right_names(lab):
    found = by_rule(lab.report)
    assert found["tls-cert-expired"] == {"ip:127.0.0.1", "domain:example.com"}
    assert found["tls-cert-expiring"] == {"ip:127.0.0.1", "domain:www.example.com"}
    assert found["tls-hostname-mismatch"] == {"ip:127.0.0.1", "domain:mail.example.com"}
    # www sends every header and HSTS: no header finding for it
    assert "domain:www.example.com" not in found["http-missing-hsts"] | found["http-missing-security-headers"]
    assert {"domain:example.com", "domain:mail.example.com"} <= found["http-missing-hsts"]


def test_confirmed_exposure_is_high_confidence_and_says_open_now_and_stale_data_is_shown_beside_it(lab):
    risks = {r["rule_id"]: r for r in lab.report["risks"]}
    exposed, stale = risks["exposed-risky-service"], risks["stale-exposure-data"]
    assert exposed["confidence"] == "high" and exposed["severity"] == "high"
    assert f"127.0.0.1:{lab.ports['open']}" in exposed["explanation"] and "open now" in exposed["explanation"]
    assert "ProFTPD 1.3.5" in exposed["explanation"] and "Shodan InternetDB had also listed" in exposed["explanation"]
    assert stale["severity"] == "info" and str(lab.ports["stale"]) in stale["explanation"] and "A connection check made at" in stale["explanation"]
    assert "closed" in stale["explanation"] and "may be out of date" in stale["explanation"]
    # both findings cite a check made now and Shodan's earlier report
    sources = lambda risk: {lab.report["evidence"][i]["source"] for i in risk["evidence_ids"]}  # noqa: E731
    assert {"tcp", "internetdb"} <= sources(exposed) and {"tcp", "internetdb"} <= sources(stale)
    assert basis_text(basis(stale["evidence_ids"], lab.report["evidence"])).startswith("Checked now (")


def test_a_passive_finding_still_says_it_was_reported_earlier_and_not_checked(lab):
    report = copy.deepcopy(lab.report)
    report["evidence"] = {k: v for k, v in report["evidence"].items() if v["source"] not in SOURCES}
    risk = next(r for r in analyze(report, load_packs())["risks"] if r["rule_id"] == "exposed-risky-service")
    assert risk["confidence"] == "low" and "not a check made now" in risk["explanation"]
    assert basis_text(basis(risk["evidence_ids"], report["evidence"])) == "Reported earlier by a third party (Shodan InternetDB); not checked now."


def test_the_catalog_rules_have_fixed_remediation_and_the_risks_use_it(lab):
    from scrutator.risk.catalog import RULES

    for risk in lab.report["risks"]:
        if risk["rule_id"] in ACTIVE_RULES:
            assert risk["remediation"] == RULES[risk["rule_id"]].remediation and risk["remediation"]


def test_nothing_is_probed_but_the_planted_server(lab):
    assert {ip for ip, _ in lab.attempts} == {"127.0.0.1"} and lab.attempts
    plan = json.loads(lab.report["evidence"][lab.report["active"]["plan"]["evidence_id"]]["payload"])
    skipped = {s["ip"]: s for s in plan["skipped"]}
    assert set(skipped) == set(NEVER)
    assert skipped["104.16.9.9"]["kind"] == "shared-platform" and skipped["104.16.9.9"]["platform"] == "Cloudflare"
    assert skipped["10.0.0.7"]["kind"] == "refused-address" and "private" in skipped["10.0.0.7"]["reason"]
    assert "link-local" in skipped["169.254.169.254"]["reason"]
    assert not [e for e in lab.report["evidence"].values() if e["source"] in ("tcp", "tls", "http") and any(ip in e["request"] for ip in NEVER)]


def test_the_page_and_headers_are_requested_before_certificates_and_legacy_attempts_when_the_cap_may_bite(lab):
    log = [r["module"] for r in lab.store.audit_log(lab.scan_id) if r.get("module") in ("http", "tls") and r.get("event") == "ok"]
    assert "http" in log and "tls" in log and log.index("tls") > max(i for i, m in enumerate(log) if m == "http")


def test_a_port_that_answers_with_another_protocol_is_named_for_what_speaks_and_not_rated_as_the_port_number():
    from scrutator.risk.services import exposed_services

    def report_with(banner, port):
        ev = {"source": "tcp", "request": f"TCP CONNECT 198.51.100.7:{port}", "payload": json.dumps({"state": "open", "banner": banner}), "collected_at": "2026-11-07T12:00:00"}
        ident = hashlib.sha256(("tcp" + chr(10) + ev["request"] + chr(10) + ev["payload"]).encode()).hexdigest()
        return {"entities": [{"id": "ip:198.51.100.7", "type": "ip", "value": "198.51.100.7", "state": "linked"}], "edges": [], "evidence": {ident: ev}, "scope": {"domains": ["example.com"], "cidrs": [], "asns": []}}

    ssh = exposed_services(report_with("SSH-2.0-mod_sftp", 23))
    assert len(ssh) == 1 and ssh[0].severity.value == "medium" and "SSH service on the usual Telnet port" in ssh[0].explanation
    telnet = exposed_services(report_with("Welcome to the router", 23))
    assert telnet[0].severity.value == "high" and "(Telnet)" in telnet[0].explanation
    mysql = exposed_services(report_with("MySQL/MariaDB handshake: server 8.0.35", 3306))
    assert mysql[0].severity.value == "high" and "(MySQL)" in mysql[0].explanation  # the port and the protocol agree


def test_versions_in_mysql_and_ssh_greetings_are_recognised():
    from scrutator.risk.active import _version_in

    assert _version_in("MySQL/MariaDB handshake: server 5.5.5-10.6.20-MariaDB-cll-lve") == "MariaDB 10.6.20"
    assert _version_in("MySQL/MariaDB handshake: server 8.0.35") == "MySQL 8.0.35"
    assert _version_in("SSH-2.0-OpenSSH_9.6 Ubuntu") == "OpenSSH 9.6" and _version_in("SSH-2.0-mod_sftp") is None
    assert _version_in("220 mail ESMTP Exim 4.100.1") == "Exim 4.100.1"


def test_the_connection_cap_held(lab):
    log = lab.store.audit_log(lab.scan_id)
    cap = next(r for r in log if r.get("event") == "active_confirmation_authorised")["limits"]["max_connections"]
    assert lab.summary["connections"] <= cap and len(lab.attempts) == lab.summary["connections"]


# ------------------------------------------------------------------------------------------------ the report


def test_the_report_carries_the_active_section_and_it_follows_from_the_evidence(lab):
    section = lab.report["active"]
    assert section == active_section(lab.report)
    assert any(c["ip"] == "127.0.0.1" and c["port"] == lab.ports["open"] and c["state"] == "open" for c in section["checks"])
    assert any(c["port"] == lab.ports["stale"] and c["state"] in ("closed", "filtered") for c in section["checks"])
    assert {t["sni"] for t in section["tls"]} >= {"example.com", "www.example.com", "mail.example.com"}


def test_the_html_report_shows_the_active_section_the_basis_line_and_the_not_replayed_note(lab):
    page = render_html(lab.report)
    assert "Active confirmation (authorised, checked now)" in page and "Checked now" in page and "never replayed" in page
    assert "function renderActive" in page


def test_sarif_carries_the_new_rules_and_how_each_finding_was_established(lab):
    sarif = to_sarif(lab.report)
    rules = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert ACTIVE_RULES <= rules
    results = {r["ruleId"]: r for r in sarif["runs"][0]["results"]}
    assert results["tls-cert-expired"]["properties"]["basis"].startswith("Checked now")
    assert "also reported earlier by a third party" in results["stale-exposure-data"]["properties"]["basis"]


def test_the_risk_command_says_checked_now_or_reported_earlier(lab, bundle):
    result = runner.invoke(cli.app, ["risk", str(bundle)])
    assert result.exit_code == 0, result.output
    assert "how established: Checked now" in result.output and "tls-cert-expired" in result.output
    as_json = json.loads(runner.invoke(cli.app, ["risk", str(bundle), "--json"]).output)
    assert any(r.get("basis", {}).get("checked_at") for r in as_json["risks"])


# ------------------------------------------------------------------------------------------------ verify and replay


def test_a_genuine_active_bundle_verifies_with_the_test_mode_warning(bundle):
    result = verify_bundle(bundle)
    assert result.ok, [c for c in result.checks if not c.ok]
    names = {c.name for c in result.checks}
    assert {"active section derivable", "active checks authorised and within the plan", "risks derivable"} <= names
    assert any("test mode" in w for w in result.warnings)


def rewrite_evidence(bundle, keys, tmp_path, change, name="forged.scrutator", rehash=False):
    """Change an evidence record in a re-signed bundle (manifest hashes rebuilt, signed with the genuine key)."""
    raw = read_raw(bundle).files

    def evidence(data):
        rows = [json.loads(line) for line in data.decode().splitlines() if line.strip()]
        for row in rows:
            change(row)
            if rehash:
                row["id"] = hashlib.sha256(f"{row['source']}\n{row['request']}\n{row['payload']}".encode()).hexdigest()
        return ("\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n").encode()

    return forge(bundle, tmp_path / name, keys, {"evidence.jsonl": evidence})


def flip_open_to_closed(row):
    if row["source"] == "tcp" and json.loads(row["payload"]).get("state") == "open":
        data = json.loads(row["payload"])
        row["payload"] = json.dumps({"state": "closed", "detail": "refused"}, sort_keys=True) if data["state"] == "open" else row["payload"]


def test_flipping_an_open_port_to_closed_in_a_re_signed_bundle_fails_verification(bundle, keys, tmp_path):
    forged = rewrite_evidence(bundle, keys, tmp_path, flip_open_to_closed)
    result = verify_bundle(forged)
    assert next(c for c in result.checks if c.name == "signature valid").ok  # genuine key, rebuilt manifest
    assert not result.ok and "evidence hashes" in [c.name for c in result.checks if not c.ok]


def test_flipping_it_and_fixing_the_record_ids_still_fails_because_the_findings_no_longer_follow(bundle, keys, tmp_path):
    raw = read_raw(bundle).files
    report = json.loads(raw["report.json"])
    flipped: dict[str, str] = {}

    def change(row):
        old = row["id"]
        flip_open_to_closed(row)
        row["id"] = hashlib.sha256(f"{row['source']}\n{row['request']}\n{row['payload']}".encode()).hexdigest()
        flipped[old] = row["id"]

    def evidence(data):
        rows = [json.loads(line) for line in data.decode().splitlines() if line.strip()]
        for row in rows:
            change(row)
        return ("\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n").encode()

    def new_report(data):
        text = data.decode()
        for old, new in flipped.items():
            text = text.replace(old, new)
        value = json.loads(text)
        for ident, row in value["evidence"].items():
            if row["source"] == "tcp":
                row["payload"] = next(r["payload"] for r in (json.loads(l) for l in forged_evidence.splitlines() if l.strip()) if r["id"] == ident)
        return json.dumps(value, sort_keys=True).encode()

    forged_evidence = evidence(raw["evidence.jsonl"]).decode()
    forged = forge(bundle, tmp_path / "f2.scrutator", keys, {"evidence.jsonl": forged_evidence.encode(), "report.json": new_report})
    result = verify_bundle(forged)
    failed = [c.name for c in result.checks if not c.ok]
    assert not result.ok and failed, failed


def problems(report, audit, rows, **changes):
    audit = copy.deepcopy(audit)
    report = copy.deepcopy(report)
    for fn in changes.values():
        fn(report, audit, rows)
    return active_problems(report, audit, rows, load_packs(), [])


@pytest.fixture(scope="module")
def parts(lab, bundle):
    raw = read_raw(bundle).files
    audit = lab.store.audit_log(lab.scan_id)
    rows = [json.loads(line) for line in raw["evidence.jsonl"].decode().splitlines() if line.strip()]
    return lab.report, audit, rows


def test_the_guardrail_audit_accepts_the_lab_and_names_every_way_a_bundle_can_break_them(parts):
    report, audit, rows = parts
    assert active_problems(report, audit, rows, load_packs(), []) == ""

    def drop_test_mode(report, audit, rows):
        for r in audit:
            r.pop("test_mode", None)

    assert "loopback" in problems(report, audit, rows, a=drop_test_mode)  # a public name that pointed at 127.0.0.1 was probed

    def drop_authorisation(report, audit, rows):
        audit[:] = [r for r in audit if r.get("event") != "active_confirmation_authorised"]

    assert "no active authorisation" in problems(report, audit, rows, a=drop_authorisation)

    def drop_attestation(report, audit, rows):
        audit[:] = [r for r in audit if r.get("event") != "self_attestation"]

    assert "covers active testing" in problems(report, audit, rows, a=drop_attestation)

    def late_authorisation(report, audit, rows):
        record = next(r for r in audit if r.get("event") == "active_confirmation_authorised")
        audit.remove(record)
        audit.insert(0, {"event": "ok", "module": "dns", "entity": "domain:example.com", "evidence_ids": []})
        audit.append(record)

    assert "only after the first lookup" in problems(report, audit, rows, a=late_authorisation)

    def tiny_cap(report, audit, rows):
        next(r for r in audit if r.get("event") == "active_confirmation_authorised")["limits"]["max_connections"] = 2

    assert "exceed the recorded cap" in problems(report, audit, rows, a=tiny_cap)

    def probe_shared_platform(report, audit, rows):
        ev = {"source": "tcp", "request": "TCP CONNECT 104.16.9.9:80", "payload": json.dumps({"state": "open", "banner": ""}), "collected_at": "2026-01-01T00:00:00"}
        ident = hashlib.sha256(f"{ev['source']}\n{ev['request']}\n{ev['payload']}".encode()).hexdigest()
        report["evidence"][ident] = ev
        rows.append({"id": ident, **ev})

    msg = problems(report, audit, rows, a=probe_shared_platform)
    assert "104.16.9.9" in msg and "Cloudflare" in msg and "outside the plan" in msg

    def unlogged_probe(report, audit, rows):
        for r in audit:
            if r.get("module") == "tcp" and r.get("evidence_ids"):
                r["evidence_ids"] = []
                break

    assert "not accounted for in the signed audit log" in problems(report, audit, rows, a=unlogged_probe)

    def unplanned_port(report, audit, rows):
        ev = {"source": "tcp", "request": "TCP CONNECT 127.0.0.1:31337", "payload": json.dumps({"state": "open", "banner": ""}), "collected_at": "2026-01-01T00:00:00"}
        ident = hashlib.sha256(f"{ev['source']}\n{ev['request']}\n{ev['payload']}".encode()).hexdigest()
        report["evidence"][ident] = ev
        rows.append({"id": ident, **ev})
        audit.append({"event": "ok", "module": "tcp", "entity": "ip:127.0.0.1", "evidence_ids": [ident]})

    assert "neither the passive port list nor the fixed list" in problems(report, audit, rows, a=unplanned_port)


def test_a_replay_never_contacts_the_target_and_says_why(lab):
    rows = [{"id": i, "source": e["source"], "request": e["request"], "payload": e["payload"]} for i, e in lab.report["evidence"].items() if e["source"] in SOURCES]
    assert rows
    connections = []

    async def handle(reader, writer):
        connections.append(1)
        writer.close()

    class Resolver:
        async def lookup(self, name, rtype):
            return []

    async def go():
        server = await asyncio.start_server(handle, "127.0.0.1", lab.ports["open"])  # the planted address, port now ours
        try:
            async with httpx.AsyncClient() as http:
                return await replay_evidence(rows, http, Resolver())
        finally:
            server.close()

    try:
        results = asyncio.run(go())
    except OSError:
        pytest.skip("the lab's port is taken")
    assert len(results) == len(rows) and {r.status for r in results} == {"skipped"}
    assert {r.detail for r in results} == {"active evidence is not replayed"} and connections == []


def test_an_old_report_without_active_evidence_stays_comparable(lab):
    plain = {"evidence": {"a": {"source": "dns"}}}
    assert comparable(3, plain) and comparable(2, plain) and not comparable(3, lab.report) and comparable(4, lab.report)


# ------------------------------------------------------------------------------------------------ the audit


def audit_of(bundle, tmp_path, *extra):
    out = tmp_path / "audit"
    result = runner.invoke(cli.app, ["audit", "--from-bundle", str(bundle), "--self", "--yes", "--no-pdf", "--out", str(out), *extra])
    assert result.exit_code == 0, result.output
    return out, result


def test_the_audit_of_an_active_scan_separates_checked_now_from_reported_earlier(bundle, tmp_path):
    out, result = audit_of(bundle, tmp_path)
    page = (out / "audit.html").read_text(encoding="utf-8")
    facts = json.loads((out / "audit.json").read_text(encoding="utf-8"))
    assert "Active confirmation" in page and "Checked now" in page and "also reported earlier by a third party" in page
    assert "no scanning" not in page.split('id="auth"')[0] and "limited set of connection checks" in page
    assert "This review was passive except for the authorised active confirmation" in page
    assert facts["active"]["summary"]["open"] >= 1 and facts["active"]["skipped"]
    assert any("not probed" in line or "Cloudflare" in line for line in [s["reason"] for s in facts["active"]["skipped"]])
    checks = check_audit(out / "audit.html", out / "proof.scrutator")
    assert all(c.ok for c in checks), [c for c in checks if not c.ok]


def test_an_edited_active_number_in_the_audit_is_caught(bundle, tmp_path):
    out, _ = audit_of(bundle, tmp_path)
    page = (out / "audit.html").read_text(encoding="utf-8")
    facts = json.loads((out / "audit.json").read_text(encoding="utf-8"))
    forged = page.replace(f'"open": {facts["active"]["summary"]["open"]},', '"open": 0,', 1)
    assert forged != page
    (out / "forged.html").write_text(forged, encoding="utf-8")
    assert not all(c.ok for c in check_audit(out / "forged.html", out / "proof.scrutator"))


def test_a_passive_audit_has_no_active_text_or_facts():
    from pathlib import Path

    folder = Path(__file__).resolve().parent.parent / "docs" / "examples" / "lab-zone"
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "a"
        result = runner.invoke(cli.app, ["audit", "--from-bundle", str(folder / "proof.scrutator"), "--self", "--yes", "--no-pdf", "--out", str(out)])
        assert result.exit_code == 0, result.output
        facts = json.loads((out / "audit.json").read_text(encoding="utf-8"))
        assert "active" not in facts and "Active confirmation" not in (out / "audit.html").read_text(encoding="utf-8")


# ------------------------------------------------------------------------------------------------ the CLI gate


def eng(tmp_path, *, active=None, name="eng.yaml"):
    today = date.today()
    lines = ["organisation: Example Corp", "domains: [example.com]", "authorised_by: {name: A. Signatory, role: CISO}",
             f"start: {(today - timedelta(days=1)).isoformat()}", f"end: {(today + timedelta(days=30)).isoformat()}",
             "purpose: Authorised external exposure review, engagement EX-1", "reference: EX-1"]
    if active is not None:
        lines.append(f"active_testing: {'true' if active else 'false'}")
    path = tmp_path / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def no_lookups(monkeypatch):
    """Any lookup or scan at all fails the test: the refusals must come first."""
    def boom(*a, **k):
        raise AssertionError("a scan was started")

    monkeypatch.setattr(cli, "run_scan", boom)
    monkeypatch.setattr(cli, "open_context", boom)


def test_active_without_an_authorisation_is_refused_before_anything_happens(tmp_path, no_lookups):
    result = runner.invoke(cli.app, ["audit", "example.com", "--active", "--yes", "--out", str(tmp_path / "a")])
    assert result.exit_code == 2 and "--engagement" in result.output and "--self" in result.output


def test_active_with_an_engagement_that_does_not_allow_it_is_refused(tmp_path, no_lookups):
    for active in (None, False):
        result = runner.invoke(cli.app, ["audit", "example.com", "--active", "--engagement", str(eng(tmp_path, active=active)), "--yes", "--out", str(tmp_path / "a")])
        assert result.exit_code == 2 and "does not authorise active testing" in result.output and "active_testing: true" in result.output


def test_active_never_runs_from_a_bundle(tmp_path, bundle, no_lookups):
    result = runner.invoke(cli.app, ["audit", "--from-bundle", str(bundle), "--active", "--self", "--yes", "--out", str(tmp_path / "a")])
    assert result.exit_code == 2 and "never re-probes from a bundle" in result.output


def test_active_must_be_confirmed_like_the_authorisation(tmp_path, no_lookups):
    result = runner.invoke(cli.app, ["audit", "example.com", "--active", "--self", "--out", str(tmp_path / "a")])  # no terminal, no --yes
    assert result.exit_code == 2 and "--yes" in result.output


def test_a_public_name_that_resolves_to_an_internal_address_is_never_probed_through_the_whole_cli(tmp_path, monkeypatch):
    """The SSRF-through-DNS case end to end: an `audit --active --self` of a name whose A record is 127.0.0.1."""
    from contextlib import asynccontextmanager

    from scrutator.modules.base import ModuleContext
    from scrutator.modules.registry import load_builtin_modules
    from scrutator.resolver import DnsAnswer
    from scrutator.scan import run_scan

    hits = []  # every connection attempt of the run (the proxy-aware opener is the only way a probe connects)
    from scrutator import proxy

    real_open = proxy.open_tcp

    async def counting_open(host, port, **kwargs):
        hits.append((host, port))
        return await real_open(host, port, **kwargs)

    monkeypatch.setattr(proxy, "open_tcp", counting_open)

    class Resolver:
        async def query(self, name, rtype):
            if rtype == "A" and name == "example.com":
                return DnsAnswer("answer", ("127.0.0.1",))
            return DnsAnswer("nxdomain")

        async def lookup(self, name, rtype):
            return list((await self.query(name, rtype)).records)

    @asynccontextmanager
    async def context():
        async with httpx.AsyncClient() as http:
            yield ModuleContext(http=http, resolver=Resolver())

    async def scan_with_dns(seed, scope, store, ctx, **kwargs):
        dns = next(m for m in load_builtin_modules() if m.name == "dns")
        return await run_scan(seed, scope, store, ctx, modules=[dns], max_steps=50, pre_audit=kwargs["pre_audit"], active=kwargs["active"])

    monkeypatch.setattr(cli, "open_context", context)
    monkeypatch.setattr(cli, "run_scan", scan_with_dns)
    generate_keypair(tmp_path / "keys")

    out = tmp_path / "audit"
    result = runner.invoke(cli.app, ["audit", "example.com", "--self", "--active", "--yes", "--no-pdf", "--key-dir", str(tmp_path / "keys"), "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert "not probed" in result.output and "loopback" in result.output and hits == []
    facts = json.loads((out / "audit.json").read_text(encoding="utf-8"))
    assert facts["authorisation"]["active"] is True and facts["active"]["summary"]["checks"] == 0
    assert facts["active"]["skipped"][0]["ip"] == "127.0.0.1"
    assert verify_bundle(out / "proof.scrutator").ok and all(c.ok for c in check_audit(out / "audit.html", out / "proof.scrutator"))


def test_active_plan_shows_the_plan_offline(tmp_path, bundle):
    result = runner.invoke(cli.app, ["active-plan", str(bundle)])
    assert result.exit_code == 0, result.output
    assert "nothing is sent" in result.output and "skip  127.0.0.1" in result.output and "loopback" in result.output
    parsed = json.loads(runner.invoke(cli.app, ["active-plan", str(bundle), "--json"]).output)
    assert parsed["targets"] == [] and {s["ip"] for s in parsed["skipped"]} >= {"127.0.0.1", "104.16.9.9"}
