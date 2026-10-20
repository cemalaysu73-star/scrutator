"""v0.7 task 4: keyed sources (VirusTotal, SecurityTrails, Shodan DNS). Off by default, keys only from the
environment and never written anywhere, redacted in errors, scope-gated like every other source. Tested with
fake HTTP answers in the documented shapes; not live-verified (no keys were available)."""

import json
import zipfile

import httpx
import pytest
import respx
from typer.testing import CliRunner

from scrutator import cli
from scrutator.bundle.replay import parse_request
from scrutator.keys import redact
from scrutator.model import Entity, EntityType
from scrutator.modules.base import ModuleContext, ModuleError, SourceUnavailable
from scrutator.modules.keyed.securitytrails import SecurityTrails
from scrutator.modules.keyed.shodan import ShodanDns
from scrutator.modules.keyed.virustotal import VirusTotal
from scrutator.modules.registry import load_builtin_modules
from scrutator.sources import SourceError, SourcePolicy, describe

KEY = "SENTINEL-KEY-0123456789"
SEED = Entity(type=EntityType.DOMAIN, value="example.com")
VARS = {VirusTotal: "SCRUTATOR_VIRUSTOTAL_KEY", SecurityTrails: "SCRUTATOR_SECURITYTRAILS_KEY", ShodanDns: "SCRUTATOR_SHODAN_KEY"}


@pytest.fixture(autouse=True)
def keys(monkeypatch):
    for name in VARS.values():
        monkeypatch.setenv(name, KEY)


def names(observations):
    return sorted(o.entity.value for o in observations)


# ------------------------------------------------------------------------------------------ the modules


async def test_virustotal_reads_the_documented_shape_and_follows_the_cursor(make_ctx):
    page1 = {"data": [{"id": "www.example.com", "type": "domain", "attributes": {"last_dns_records_date": 1700000000, "junk": 1}}, {"id": "evil.net", "type": "domain"}], "meta": {"cursor": "abc"}, "links": {}}
    page2 = {"data": [{"id": "api.example.com", "type": "domain", "attributes": {}}], "meta": {}}
    with respx.mock() as router:
        route = router.get("https://www.virustotal.com/api/v3/domains/example.com/subdomains").mock(
            side_effect=[httpx.Response(200, json=page1), httpx.Response(200, json=page2)]
        )
        out = await VirusTotal().run(SEED, make_ctx())
    assert names(out) == ["api.example.com", "www.example.com"]  # a name outside the domain is dropped
    assert route.calls[0].request.headers["x-apikey"] == KEY and "cursor=abc" in str(route.calls[1].request.url)
    www = next(o for o in out if o.entity.value == "www.example.com")
    assert json.loads(www.evidence.payload) == {"id": "www.example.com", "last_dns_records_date": 1700000000}
    assert all(KEY not in o.evidence.request and KEY not in o.evidence.payload for o in out)


async def test_securitytrails_joins_labels_to_the_domain(make_ctx):
    with respx.mock() as router:
        route = router.get("https://api.securitytrails.com/v1/domain/example.com/subdomains").mock(
            return_value=httpx.Response(200, json={"endpoint": "/v1/domain/example.com/subdomains", "subdomains": ["www", "api", ""], "subdomain_count": 3})
        )
        out = await SecurityTrails().run(SEED, make_ctx())
    assert names(out) == ["api.example.com", "www.example.com"]
    assert route.calls[0].request.headers["APIKEY"] == KEY
    assert all(KEY not in o.evidence.request for o in out)


async def test_shodan_sends_the_key_as_a_parameter_but_never_records_it(make_ctx):
    body = {"domain": "example.com", "subdomains": ["www", "mail"], "data": [{"subdomain": "www", "type": "A", "value": "192.0.2.1", "last_seen": "2026-10-01T00:00:00"}, {"subdomain": "", "type": "MX", "value": "mail.example.com"}], "more": False}
    with respx.mock() as router:
        route = router.get("https://api.shodan.io/dns/domain/example.com").mock(return_value=httpx.Response(200, json=body))
        out = await ShodanDns().run(SEED, make_ctx())
    assert names(out) == ["mail.example.com", "www.example.com"]
    assert route.calls[0].request.url.params["key"] == KEY  # what the service requires...
    for o in out:  # ...and nowhere it could be read back
        assert KEY not in o.evidence.request and KEY not in o.evidence.payload
        assert o.evidence.request == "GET https://api.shodan.io/dns/domain/example.com"
    www = next(o for o in out if o.entity.value == "www.example.com")
    assert json.loads(www.evidence.payload) == [{"type": "A", "value": "192.0.2.1", "last_seen": "2026-10-01T00:00:00"}]


async def test_shodan_asks_for_the_next_page_only_when_there_is_one(make_ctx):
    with respx.mock() as router:
        route = router.get("https://api.shodan.io/dns/domain/example.com").mock(
            side_effect=[httpx.Response(200, json={"subdomains": ["a"], "data": [], "more": True}), httpx.Response(200, json={"subdomains": ["b"], "data": [], "more": True})]
        )
        out = await ShodanDns().run(SEED, make_ctx())
    assert names(out) == ["a.example.com", "b.example.com"] and route.call_count == 2  # two pages at most: each costs a credit
    assert out[1].evidence.request.endswith("?page=2") and KEY not in out[1].evidence.request


@pytest.mark.parametrize("cls, url", [(VirusTotal, "https://www.virustotal.com/api/v3/domains/example.com/subdomains"), (SecurityTrails, "https://api.securitytrails.com/v1/domain/example.com/subdomains"), (ShodanDns, "https://api.shodan.io/dns/domain/example.com")])
async def test_a_rejected_key_is_an_error_about_the_key_and_a_quota_is_a_source_that_is_down(cls, url, make_ctx):
    with respx.mock() as router:
        router.get(url).mock(return_value=httpx.Response(401))
        with pytest.raises(ModuleError) as rejected:
            await cls().run(SEED, make_ctx())
        router.get(url).mock(return_value=httpx.Response(429))
        with pytest.raises(SourceUnavailable):
            await cls().run(SEED, make_ctx())
    assert not isinstance(rejected.value, SourceUnavailable) and KEY not in str(rejected.value) and "rejected the key" in str(rejected.value)


@pytest.mark.parametrize("cls", [VirusTotal, SecurityTrails, ShodanDns])
async def test_without_the_variable_the_module_refuses_by_name_not_value(cls, make_ctx, monkeypatch):
    monkeypatch.delenv(VARS[cls])
    with pytest.raises(ModuleError, match=VARS[cls]):
        await cls().run(SEED, make_ctx())


@pytest.mark.parametrize("cls", [VirusTotal, SecurityTrails, ShodanDns])
def test_each_keyed_source_is_apex_only_passive_documented_and_says_it_is_not_live_verified(cls):
    import inspect

    module = cls()
    assert module.apex_only and module.mode.value == "passive" and module.needs_key == VARS[cls] and module.licence_note
    assert "not live-verified" in inspect.getdoc(cls)


def test_the_keyed_hosts_are_not_replayable():
    for host in ("www.virustotal.com", "api.securitytrails.com", "api.shodan.io"):
        assert parse_request(f"GET https://{host}/x") is None  # a replay would need the key


# ------------------------------------------------------------------------------------------ the key rules


def test_redact_removes_the_key_in_every_form_a_message_can_carry_it():
    assert redact(f"GET https://api.shodan.io/dns/domain/x?key={KEY}&page=2 failed") == "GET https://api.shodan.io/dns/domain/x?key=[redacted]&page=2 failed"
    assert redact("nothing to hide") == "nothing to hide"
    assert redact("key=a%2Fb%2Bc%3D", {"SCRUTATOR_SHODAN_KEY": "a/b+c="}) == "key=[redacted]"
    assert redact("short", {"SCRUTATOR_SHODAN_KEY": "short"}) == "short"  # not a key: leave the text alone


async def test_an_error_that_quotes_the_url_is_redacted_in_the_audit_log():
    from scrutator.engine import Engine
    from scrutator.modules.base import Module
    from scrutator.scope import ScopePolicy
    from scrutator.store import Store

    class Leaky(Module):
        name = "leaky"
        accepts = frozenset({EntityType.DOMAIN})

        async def run(self, entity, ctx):
            raise httpx.ConnectError(f"cannot reach https://api.shodan.io/dns/domain/example.com?key={KEY}")

    store = Store(":memory:")
    scan = store.create_scan("example.com")
    store.upsert_entity(scan, SEED, __import__("scrutator.model", fromlist=["ScopeState"]).ScopeState.IN)
    engine = Engine(store, ScopePolicy(domains=["example.com"]), ctx=None, breaker_threshold=1)
    await engine.run_module(scan, Leaky(), SEED)
    dump = json.dumps(store.audit_log(scan))
    assert KEY not in dump and "[redacted]" in dump


def test_there_is_no_command_line_option_that_takes_a_key():
    for command in ("scan", "watch", "sources"):
        text = CliRunner().invoke(cli.app, [command, "--help"]).output.lower()
        assert "api-key" not in text and "apikey" not in text and "--key " not in text and "--token" not in text


# ------------------------------------------------------------------------------------------ the policy


def test_keyed_sources_are_off_by_default_and_the_reason_names_the_variable_only(monkeypatch):
    for name in VARS.values():
        monkeypatch.delenv(name)
    chosen, disabled = SourcePolicy().select(load_builtin_modules())
    assert {"virustotal", "securitytrails", "shodan"} <= set(disabled) and not {m.name for m in chosen} & set(disabled)
    assert disabled["shodan"] == "needs a key: set SCRUTATOR_SHODAN_KEY"


def test_setting_the_variable_turns_the_source_on_and_the_policy_can_still_exclude_it():
    chosen, _ = SourcePolicy().select(load_builtin_modules())
    assert {"virustotal", "securitytrails", "shodan"} <= {m.name for m in chosen}
    chosen, disabled = SourcePolicy(exclude=("shodan",)).select(load_builtin_modules())
    assert "shodan" not in {m.name for m in chosen} and "excluded" in disabled["shodan"]


def test_asking_for_a_keyed_source_by_name_without_its_key_is_an_error(monkeypatch):
    monkeypatch.delenv("SCRUTATOR_VIRUSTOTAL_KEY")
    modules = load_builtin_modules()
    policy = SourcePolicy.parse("crtsh,virustotal", None, False, modules)
    assert policy.missing_keys(modules) and "SCRUTATOR_VIRUSTOTAL_KEY" in policy.missing_keys(modules)[0]
    assert SourcePolicy.parse("crtsh", None, False, modules).missing_keys(modules) == []
    result = CliRunner().invoke(cli.app, ["scan", "example.com", "--sources", "virustotal"])
    assert result.exit_code == 2 and "SCRUTATOR_VIRUSTOTAL_KEY" in result.output


# ------------------------------------------------------------------------------------------ in a scan


async def test_a_scan_with_keys_collects_from_the_keyed_sources_and_writes_no_key_anywhere(tmp_path):
    from scrutator.bundle.keys import generate_keypair, load_private_key, private_key_path
    from scrutator.bundle.verify import verify_bundle
    from scrutator.bundle.writer import create_bundle
    from scrutator.report import build_report, render_html, render_json
    from scrutator.scan import run_scan
    from scrutator.scope import ScopePolicy
    from scrutator.store import Store

    class Resolver:
        async def lookup(self, name, rtype):
            return []

    db = tmp_path / "s.db"
    store = Store(db)
    modules = [m for m in load_builtin_modules() if m.name in {"virustotal", "securitytrails", "shodan", "dns"}]
    async with httpx.AsyncClient() as http:
        with respx.mock() as router:
            router.get("https://www.virustotal.com/api/v3/domains/example.com/subdomains").mock(return_value=httpx.Response(200, json={"data": [{"id": "vt.example.com"}]}))
            router.get("https://api.securitytrails.com/v1/domain/example.com/subdomains").mock(return_value=httpx.Response(401))
            router.get("https://api.shodan.io/dns/domain/example.com").mock(return_value=httpx.Response(200, json={"subdomains": ["sh"], "data": [], "more": False}))
            scan_id, _ = await run_scan(SEED, ScopePolicy(domains=["example.com"]), store, ModuleContext(http=http, resolver=Resolver()), modules=modules)
    report = build_report(store, scan_id)
    found = {e["value"] for e in report["entities"]}
    assert {"vt.example.com", "sh.example.com"} <= found
    assert report["sources"]["securitytrails"]["error"] == 1 and "rejected the key" in report["sources"]["securitytrails"]["errors"][0]
    key_dir = tmp_path / "keys"
    generate_keypair(key_dir)
    bundle = tmp_path / "proof.scrutator"
    create_bundle(store, scan_id, load_private_key(private_key_path(key_dir)), bundle)
    store.close()
    blobs = [render_json(report), render_html(report), db.read_bytes().decode("latin-1")]
    with zipfile.ZipFile(bundle) as archive:
        blobs += [archive.read(name).decode("utf-8") for name in archive.namelist()]
    assert all(KEY not in blob for blob in blobs)
    assert verify_bundle(bundle).ok


# ------------------------------------------------------------------------------------------ `scrutator sources`


def test_the_sources_command_lists_every_source_with_access_state_terms_and_last_health(tmp_path, monkeypatch):
    from scrutator.model import ScopeState
    from scrutator.store import Store

    for name in VARS.values():
        monkeypatch.delenv(name)
    db = tmp_path / "s.db"
    store = Store(db)
    scan = store.create_scan("example.com")
    store.upsert_entity(scan, SEED, ScopeState.IN)
    store.append_audit(scan, {"event": "ok", "module": "crtsh", "entity": "domain:example.com", "evidence_ids": []})
    store.append_audit(scan, {"event": "error", "module": "certspotter", "entity": "domain:example.com", "error": "SourceUnavailable: certspotter returned HTTP 429"})
    store.append_audit(scan, {"event": "breaker", "module": "rdap", "entity": "domain:example.com", "after": 3, "last_error": "x", "group": "rdap"})
    store.close()
    result = CliRunner().invoke(cli.app, ["sources", "--db", str(db)])
    assert result.exit_code == 0, result.output
    lines = {line.split()[0]: line for line in result.output.splitlines() if line and not line.startswith(" ")}
    assert "keyless" in lines["crtsh"] and "on" in lines["crtsh"] and "answered in scan #1" in lines["crtsh"]
    assert "yes" in lines["certspotter"] and "failing in scan #1" in lines["certspotter"]
    assert "down in scan #1" in lines["rdap"] and "not run in scan #1" in lines["dns"]
    assert "keyed (SCRUTATOR_SHODAN_KEY)" in lines["shodan"] and " off " in lines["shodan"]
    assert "needs a key: set SCRUTATOR_SHODAN_KEY" in result.output and KEY not in result.output
    assert "not live-verified" in result.output


def test_the_sources_command_previews_a_policy_and_speaks_json(tmp_path):
    result = CliRunner().invoke(cli.app, ["sources", "--db", str(tmp_path / "none.db"), "--no-noncommercial", "--json"])
    rows = {row["source"]: row for row in json.loads(result.output)}
    assert rows["certspotter"]["enabled"] is False and "non-commercial" in rows["certspotter"]["why_disabled"]
    assert rows["crtsh"]["enabled"] is True and rows["crtsh"]["last_scan"] == "no scan yet"
    assert rows["shodan"]["replayable"] is False and rows["crtsh"]["replayable"] is True
    assert CliRunner().invoke(cli.app, ["sources", "--sources", "nope"]).exit_code == 2


def test_describe_reports_a_source_that_was_not_part_of_the_last_scan():
    rows = describe(load_builtin_modules(), SourcePolicy(), {"crtsh": {"ok": 2, "error": 1, "down": False, "errors": []}}, "scan #4")
    by = {r["source"]: r for r in rows}
    assert by["crtsh"]["last_scan"] == "answered in scan #4 (2 ok, 1 failed)" and by["dns"]["last_scan"] == "not run in scan #4"
