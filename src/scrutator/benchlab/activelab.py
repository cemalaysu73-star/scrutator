"""The active-confirmation lab: a "server" made of local listeners, and addresses a scan must never touch. No network.

example.com resolves to 127.0.0.1 (the lab's allowance for loopback, `relax`), where the lab runs

- a risky-service port that answers with a version banner and is listed open by a passive source (Shodan InternetDB),
- a second risky port the passive source lists but nothing listens on (stale third-party data),
- a TLS port whose certificate depends on the name asked for (SNI): expired for `example.com`, expiring in ten days for
  `www.example.com`, valid but for another name for `mail.example.com`, also answering HTTP over TLS (full security headers for
  `www`, none for the others),
- a plain HTTP port that answers 200 with a `Server` version and no redirect,
- when this machine's TLS library can offer it, a port that still completes a TLS 1.0 handshake.

Three more names resolve to addresses that must never be probed: a Cloudflare address (shared platform), a private address and
the link-local cloud-metadata address. The lab wraps the connection function and records every (address, port) a probe tried, so
a bench can prove that nothing but 127.0.0.1 was touched.

The loopback and the web-port allowance exist only here: they are what the audit log marks as test mode, which `verify` shows
as a warning and no command-line option can set.
"""

from __future__ import annotations

import asyncio
import datetime
import json
import os
import socket
import ssl
import tempfile
import warnings
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from scrutator import active, proxy
from scrutator.active.gate import authorised_event
from scrutator.active.guard import Limits
from scrutator.active.run import ActiveConfig, run_active
from scrutator.model import Entity, EntityType, Evidence, ScopeState
from scrutator.packs import load_packs
from scrutator.store import Store

RELAX = frozenset({"loopback", "documentation"})
LAB_LIMITS = Limits(concurrency=8, connect_timeout=2.6, banner_timeout=0.4, handshake_timeout=2.0, http_timeout=2.0, rate_per_second=50.0, deadline_s=60.0, max_connections=200)
CANDIDATE_PORTS = (5984, 2375, 1521, 27017, 11211, 9200, 6379, 5432, 3306, 1433)  # risky ports with no usual listener
NEVER = {"104.16.9.9": "shared platform (Cloudflare)", "10.0.0.7": "private address", "169.254.169.254": "link-local cloud-metadata address"}

# what the lab must report (entity, by rule): the bench and the tests compare against it
TRUTH_ACTIVE_RULES = {
    "exposed-risky-service": {"ip:127.0.0.1"},
    "stale-exposure-data": {"ip:127.0.0.1"},
    "tls-cert-expired": {"domain:example.com"},
    "tls-cert-expiring": {"domain:www.example.com"},
    "tls-hostname-mismatch": {"domain:mail.example.com"},
    "http-no-https-redirect": {"domain:example.com", "domain:www.example.com", "domain:mail.example.com"},
    "http-missing-hsts": {"domain:example.com", "domain:mail.example.com"},
    "http-missing-security-headers": {"domain:example.com", "domain:mail.example.com"},
    "server-banner-discloses-version": {"ip:127.0.0.1"},
}
TRUTH_LEGACY = {"tls-legacy-protocol": {"ip:127.0.0.1"}}  # only when the platform can serve and offer TLS 1.0
ACTIVE_RULES = frozenset(TRUTH_ACTIVE_RULES) | frozenset(TRUTH_LEGACY)


def make_cert(common_name: str, sans, *, not_before_days=-30, not_after_days=90) -> tuple[bytes, bytes]:
    """(certificate PEM, key PEM): a throwaway certificate signed by its own key."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now + datetime.timedelta(days=not_before_days)).not_valid_after(now + datetime.timedelta(days=not_after_days))
    )
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    cert = builder.sign(key, hashes.SHA256())
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
    )


def server_context(cert_key, *, legacy: ssl.TLSVersion | None = None) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if legacy is not None:
        context.set_ciphers("ALL:@SECLEVEL=0")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = context.maximum_version = legacy
    with tempfile.TemporaryDirectory() as folder:
        cert_path, key_path = os.path.join(folder, "c.pem"), os.path.join(folder, "k.pem")
        with open(cert_path, "wb") as handle:
            handle.write(cert_key[0])
        with open(key_path, "wb") as handle:
            handle.write(cert_key[1])
        context.load_cert_chain(cert_path, key_path)
    return context


def free_port(avoid=()) -> int:
    for _ in range(50):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        if port not in avoid:
            return port
    raise OSError("no free port")


def _bindable(port: int) -> bool:
    with socket.socket() as sock:
        try:
            sock.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def make_active_store(names: dict[str, list[str]], *, ports=None, asns=None, cnames=None, netnames=None, hostnames=None,
                      authorisation=True, path=":memory:", domain="example.com"):
    """A scan built by hand: in-scope names that resolve to addresses, with the passive evidence the plan reads.
    `names`: name -> addresses. `ports`: address -> ports InternetDB lists. `asns`: address -> AS number. `cnames`: name -> CNAME
    target. `netnames`: address -> RIPEstat network name. `hostnames`: address -> reverse names InternetDB saw."""
    store = Store(path)
    sid = store.create_scan(domain)
    store.set_meta(sid, "scope", json.dumps({"domains": [domain], "cidrs": [], "asns": []}))
    root = Entity(type=EntityType.DOMAIN, value=domain)
    store.upsert_entity(sid, root, ScopeState.IN)
    seen_ips: set[str] = set()
    for name, ips in names.items():
        entity = Entity(type=EntityType.DOMAIN, value=name)
        store.upsert_entity(sid, entity, ScopeState.IN)
        for ip in ips:
            ip_entity = Entity(type=EntityType.IP, value=ip)
            store.upsert_entity(sid, ip_entity, ScopeState.LINKED)
            evidence = Evidence.create("dns", f"DNS A {name}", "\n".join(sorted(ips)))
            store.add_evidence(evidence)
            store.add_edge(sid, entity.id, "resolves_to", ip_entity.id, [evidence.id])
            seen_ips.add(ip)
    for name, target in (cnames or {}).items():
        evidence = Evidence.create("dns", f"DNS CNAME {name}", target + ".")
        store.add_evidence(evidence)
        store.add_scan_evidence(sid, evidence.id)
    for ip in sorted(seen_ips):
        listed = (ports or {}).get(ip)
        if listed is not None:
            evidence = Evidence.create("internetdb", f"GET https://internetdb.shodan.io/{ip}", json.dumps([{"ip": ip, "ports": sorted(listed)}], sort_keys=True))
            store.add_evidence(evidence)
            store.add_scan_evidence(sid, evidence.id)
        if (hostnames or {}).get(ip):
            evidence = Evidence.create("internetdb", f"GET https://internetdb.shodan.io/{ip}", json.dumps([{"ip": ip, "hostnames": hostnames[ip]}], sort_keys=True))
            store.add_evidence(evidence)
            store.add_scan_evidence(sid, evidence.id)
        if (asns or {}).get(ip):
            asn = Entity(type=EntityType.ASN, value=str(asns[ip]))
            store.upsert_entity(sid, asn, ScopeState.LINKED)
            evidence = Evidence.create("asn", f"ASN of {ip}", str(asns[ip]))
            store.add_evidence(evidence)
            store.add_edge(sid, Entity(type=EntityType.IP, value=ip).id, "announced_by", asn.id, [evidence.id])
        if (netnames or {}).get(ip):
            evidence = Evidence.create(
                "ripestat", f"GET https://stat.ripe.net/data/whois/data.json?resource={ip}",
                json.dumps([{"key": "netname", "value": netnames[ip]}], sort_keys=True),
            )
            store.add_evidence(evidence)
            store.add_scan_evidence(sid, evidence.id)
    if authorisation:
        store.append_audit(sid, {"event": "self_attestation", "domains": [domain], "organisation": "", "confirmed": "--yes", "active": True})
    return store, sid


HEAD_FULL = (
    b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nStrict-Transport-Security: max-age=31536000\r\n"
    b"Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n"
    b"Content-Length: 0\r\n\r\n"
)
HEAD_BARE = b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Length: 0\r\n\r\n"


@dataclass
class ActiveLab:
    store: Store
    scan_id: int
    report: dict
    ports: dict
    attempts: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    legacy: bool = False

    @property
    def truth(self) -> dict:
        return {**TRUTH_ACTIVE_RULES, **(TRUTH_LEGACY if self.legacy else {})}


@asynccontextmanager
async def active_lab(*, limits: Limits = LAB_LIMITS, store_path=":memory:"):
    """Start the listeners, rebind the web ports for the run, run the active phase against the planted scan and yield the lab
    (with its report built). Everything is restored and closed on the way out, whatever happens."""
    from scrutator.report.build import build_report
    from scrutator.active.tlscheck import can_offer

    servers: list = []
    originals = (active.HTTP_PORT, active.HTTPS_PORT, active.TLS_PORTS, proxy.open_tcp)
    attempts: list = []
    try:
        free = [p for p in CANDIDATE_PORTS if _bindable(p)]
        if len(free) < 2:
            raise OSError("the lab needs two free risky ports; none of " + ", ".join(map(str, CANDIDATE_PORTS)) + " are free")
        open_port, stale_port = free[0], free[1]

        async def greeting(reader, writer):
            writer.write(b"220 ProFTPD 1.3.5 Server (lab) ready\r\n")
            await writer.drain()
            await asyncio.sleep(0.1)
            writer.close()

        servers.append(await asyncio.start_server(greeting, "127.0.0.1", open_port))

        async def plain(reader, writer):
            try:
                await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
                writer.write(HEAD_BARE)
                await writer.drain()
            except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
                pass
            writer.close()

        http_port = free_port()
        servers.append(await asyncio.start_server(plain, "127.0.0.1", http_port))

        by_name = {
            "example.com": make_cert("example.com", ["example.com"], not_before_days=-400, not_after_days=-5),
            "www.example.com": make_cert("www.example.com", ["www.example.com"], not_after_days=10),
            "mail.example.com": make_cert("other.example.org", ["other.example.org"]),
        }
        contexts = {name: server_context(cert) for name, cert in by_name.items()}
        default = contexts["example.com"]

        def choose(sock, name, _context):
            sock.context = contexts.get((name or "").lower(), default)

        default.sni_callback = choose

        async def tls_web(reader, writer):
            try:
                head = (await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)).decode("latin-1").lower()
                writer.write(HEAD_FULL if "host: www.example.com" in head else HEAD_BARE)
                await writer.drain()
            except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
                pass
            writer.close()

        tls_port = free_port(avoid={http_port})
        servers.append(await asyncio.start_server(tls_web, "127.0.0.1", tls_port, ssl=default))
        listed = {open_port, stale_port, http_port, tls_port}
        tls_ports = [tls_port]
        legacy_ok = await can_offer("TLSv1")
        if legacy_ok:
            async def drop(reader, writer):
                writer.close()

            legacy_port = free_port(avoid=listed)
            context = server_context(make_cert("example.com", ["example.com"]), legacy=ssl.TLSVersion.TLSv1)
            servers.append(await asyncio.start_server(drop, "127.0.0.1", legacy_port, ssl=context))
            tls_ports.append(legacy_port)
            listed.add(legacy_port)

        names = {n: ["127.0.0.1"] for n in ("example.com", "www.example.com", "mail.example.com")}
        names.update({"cdn.example.com": ["104.16.9.9"], "internal.example.com": ["10.0.0.7"], "meta.example.com": ["169.254.169.254"]})
        store, sid = make_active_store(names, ports={"127.0.0.1": sorted(listed | {stale_port})}, path=store_path)

        real_open = proxy.open_tcp

        async def recording_open(host, port, **kwargs):
            attempts.append((host, port))
            return await real_open(host, port, **kwargs)

        active.HTTP_PORT, active.HTTPS_PORT, active.TLS_PORTS = http_port, tls_port, tuple(tls_ports)
        proxy.open_tcp = recording_open
        # what run_scan writes before the first lookup of a real scan (the lab builds its scan by hand)
        store.append_audit(sid, authorised_event(limits, fixed_ports=[*active.RISKY_PORTS, *active.WEB_PORTS], proxy=None, relax=RELAX))
        summary = await run_active(store, sid, load_packs(), ActiveConfig(limits=limits, relax=RELAX))
        proxy.open_tcp = real_open
        yield ActiveLab(store, sid, build_report(store, sid), {"open": open_port, "stale": stale_port, "http": http_port, "tls": tls_port}, attempts, summary, legacy_ok)
    finally:
        active.HTTP_PORT, active.HTTPS_PORT, active.TLS_PORTS, proxy.open_tcp = originals
        for server in servers:
            server.close()


async def bench_metrics(work, key) -> tuple[dict, list[str]]:
    """The metrics of the `active` bench section (see scrutator bench): the planted issues found and nothing else, the
    guardrails, the signed bundle, and the forgeries `verify` must catch. Returns (metrics, notes)."""
    import copy
    import hashlib
    from pathlib import Path

    import httpx

    from scrutator.active.gate import ActiveRefused, active_authorisation
    from scrutator.active.section import active_problems
    from scrutator.audit.content import authorisation_from_log, build_audit
    from scrutator.benchlab.run import _forge, _jsonl, _metric, _rows
    from scrutator.bundle.keys import fingerprint, public_raw_from_private
    from scrutator.bundle.reader import read_raw
    from scrutator.bundle.replay import replay_evidence
    from scrutator.bundle.verify import verify_bundle
    from scrutator.bundle.writer import create_bundle

    folder = Path(work) / "active"
    folder.mkdir(parents=True, exist_ok=True)
    async with active_lab() as lab:
        report, attempts, summary = lab.report, lab.attempts, lab.summary
        store, scan_id, legacy = lab.store, lab.scan_id, lab.legacy
        truth = lab.truth
        path = folder / "proof.scrutator"
        create_bundle(store, scan_id, key, path)
        audit = store.audit_log(scan_id)
    found: dict[str, set] = {}
    for risk in report["risks"]:
        found.setdefault(risk["rule_id"], set()).update(risk["entity_ids"])
    planted_found = sum(1 for rule, entities in truth.items() if entities <= found.get(rule, set()))
    unexpected = sorted(r for r in found if r in ACTIVE_RULES and r not in truth)
    risks = {r["rule_id"]: r for r in report["risks"]}
    exposed, stale = risks.get("exposed-risky-service", {}), risks.get("stale-exposure-data", {})

    def sources(risk):
        return {report["evidence"][i]["source"] for i in risk.get("evidence_ids", [])}

    plan = json.loads(report["evidence"][report["active"]["plan"]["evidence_id"]]["payload"])
    skipped = {s["ip"]: s for s in plan["skipped"]}
    pin = fingerprint(public_raw_from_private(key))
    genuine = verify_bundle(path, pinned_fingerprint=pin)

    def flip_open(data: bytes) -> bytes:
        rows = _rows(data)
        for row in rows:
            if row["source"] == "tcp" and json.loads(row["payload"]).get("state") == "open":
                row["payload"] = json.dumps({"detail": "refused", "state": "closed"}, sort_keys=True)  # the record id is left as it was
        return _jsonl(rows)

    flipped = verify_bundle(_forge(path, folder / "flipped.scrutator", key, {"evidence.jsonl": flip_open}), pinned_fingerprint=pin)
    rows = _rows(read_raw(path).files["evidence.jsonl"])
    packs = load_packs()

    def broken(change) -> str:
        audit_copy, report_copy, rows_copy = copy.deepcopy(audit), copy.deepcopy(report), copy.deepcopy(rows)
        change(report_copy, audit_copy, rows_copy)
        return active_problems(report_copy, audit_copy, rows_copy, packs, [])

    def add_probe(report_copy, audit_copy, rows_copy, request):
        row = {"source": "tcp", "request": request, "payload": json.dumps({"banner": "", "state": "open"}), "collected_at": "2026-01-01T00:00:00"}
        row["id"] = hashlib.sha256(f"{row['source']}\n{row['request']}\n{row['payload']}".encode()).hexdigest()
        report_copy["evidence"][row["id"]] = {k: v for k, v in row.items() if k != "id"}
        rows_copy.append(row)
        audit_copy.append({"event": "ok", "module": "tcp", "entity": "ip:x", "evidence_ids": [row["id"]]})

    def drop_test_mode(report_copy, audit_copy, rows_copy):
        for record in audit_copy:
            record.pop("test_mode", None)

    def drop_authorisation(report_copy, audit_copy, rows_copy):
        audit_copy[:] = [r for r in audit_copy if r.get("event") != "active_confirmation_authorised"]

    cases = {
        "loopback probe without test mode": drop_test_mode,
        "probe of a shared platform": lambda r, a, w: add_probe(r, a, w, "TCP CONNECT 104.16.9.9:80"),
        "probe of a private address": lambda r, a, w: add_probe(r, a, w, "TCP CONNECT 10.0.0.7:80"),
        "no authorisation recorded": drop_authorisation,
        "port outside the plan": lambda r, a, w: add_probe(r, a, w, "TCP CONNECT 127.0.0.1:31337"),
    }
    caught = {name: bool(broken(change)) for name, change in cases.items()}

    refusals = 0
    for events in (None, [], [{"event": "self_attestation", "domains": ["example.com"]}], [{"event": "engagement", "active_testing": False}]):
        try:
            active_authorisation(events)
        except ActiveRefused:
            refusals += 1

    class Quiet:
        async def lookup(self, name, rtype):
            return []

    def refuse_http(request):
        raise AssertionError("a replay sent an HTTP request")

    records = [{"id": i, "source": e["source"], "request": e["request"], "payload": e["payload"]} for i, e in report["evidence"].items() if e["source"] in active.SOURCES]
    async with httpx.AsyncClient(transport=httpx.MockTransport(refuse_http)) as http:
        replayed = await replay_evidence(records, http, Quiet())
    skipped_replays = sum(r.status == "skipped" and r.detail == "active evidence is not replayed" for r in replayed)

    facts = build_audit(
        report, authorisation=authorisation_from_log(audit),
        bundle={"file": "proof.scrutator", "sha256": "0" * 64, "key_fingerprint": pin, "records": len(report["evidence"])},
        generated_at="2026-01-01T00:00:00+00:00", packs=packs,
    )
    basis_rows = [r for r in facts["risks"] if r.get("basis")]
    limits = next(r for r in audit if r.get("event") == "active_confirmation_authorised")["limits"]
    checks = {c.name: c.ok for c in genuine.checks}
    confirmed_ok = exposed.get("confidence") == "high" and "open now" in exposed.get("explanation", "")
    beside_ok = {"tcp", "internetdb"} <= sources(stale) and bool(exposed)
    never = [a for a in attempts if a[0] in NEVER]
    elsewhere = [a for a in attempts if a[0] != "127.0.0.1"]
    cloudflare = skipped.get("104.16.9.9", {}).get("platform") == "Cloudflare"
    refused = skipped.get("10.0.0.7", {}).get("kind") == "refused-address" and skipped.get("169.254.169.254", {}).get("kind") == "refused-address"
    bundle_ok = genuine.ok and checks.get("active checks authorised and within the plan", False)
    audit_ok = bool(basis_rows) and bool(facts.get("active"))

    def metric(value, threshold, ok):
        return _metric(value, threshold, ok)

    metrics = {
        "active_rules_planted": _metric(len(truth)),
        "active_rules_found": metric(planted_found, f"= {len(truth)}", planted_found == len(truth)),
        "active_rules_not_planted": metric(len(unexpected), "= 0", not unexpected),
        "confirmed_exposure_high_confidence": metric(confirmed_ok, "= true", confirmed_ok),
        "stale_data_shown_beside_confirmed": metric(beside_ok, "= true", beside_ok),
        "connections_to_addresses_not_to_probe": metric(len(never), "= 0", not never),
        "connections_outside_the_planted_server": metric(len(elsewhere), "= 0", not elsewhere),
        "shared_platform_skipped_with_reason": metric(cloudflare, "= true", cloudflare),
        "private_and_metadata_addresses_refused": metric(refused, "= true", refused),
        "connections_within_cap": metric(f"{summary['connections']} of {limits['max_connections']}", "<= cap", summary["connections"] <= limits["max_connections"]),
        "authorisation_refusals_tested": metric(refusals, "= 4", refusals == 4),
        "active_evidence_not_replayed": metric(f"{skipped_replays} of {len(records)}", "= all", bool(records) and skipped_replays == len(records)),
        "bundle_verifies": metric(bundle_ok, "= true", bundle_ok),
        "flipped_open_to_closed_detected": metric(not flipped.ok, "= true", not flipped.ok),
        "guardrail_forgeries_detected": metric(f"{sum(caught.values())} of {len(caught)}", "= all", all(caught.values())),
        "audit_separates_checked_from_reported": metric(audit_ok, "= true", audit_ok),
    }
    notes = [
        "a lab of local listeners written by the author of the module (the loopback allowance is test mode: marked in the signed log, shown by verify as a warning)",
        "TLS 1.0 handshakes are planted only where this machine's TLS library can serve and offer them" + ("" if legacy else " (it cannot here: skipped)"),
    ]
    return metrics, notes
