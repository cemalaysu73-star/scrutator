"""R4 A3: the data-source client connects only to the source hosts, and nothing a response says can widen that.

The guard is installed by `open_context`, the client every scan, every MCP scan and `verify --replay` use."""

import re
from pathlib import Path

import httpx
import pytest
import respx

from scrutator.bundle.replay import ALLOWED_HTTP_HOSTS, replay_evidence
from scrutator.context import open_context
from scrutator.egress import SOURCE_HOSTS, EgressDenied, EgressGuard
from scrutator.engine import Engine
from scrutator.model import Entity, EntityType, ScopeState
from scrutator.modules.commoncrawl import CommonCrawl
from scrutator.scope import ScopePolicy
from scrutator.store import Store

MODULES = Path(__file__).resolve().parents[1] / "src" / "scrutator" / "modules"


async def fake_resolve(host):
    table = {
        "rdap.verisign.com": ["93.184.215.14"], "rdap.arin.net": ["199.43.0.44"], "rdap.db.ripe.net": ["193.0.6.1"],
        "internal.example.net": ["10.0.0.5"], "mixed.example.net": ["93.184.215.14", "127.0.0.1"],
        "metadata.example.net": ["169.254.169.254"], "v6local.example.net": ["fe80::1"],
    }
    if host not in table:
        raise OSError("no such host")
    return table[host]


def guard():
    return EgressGuard(resolve=fake_resolve)


def test_every_host_the_modules_name_is_a_source_host_and_replay_stays_inside_them():
    named = set()
    for path in MODULES.rglob("*.py"):
        named |= set(re.findall(r"https://([a-z0-9.-]+)", path.read_text(encoding="utf-8")))
    assert named and named <= SOURCE_HOSTS, named - SOURCE_HOSTS
    assert ALLOWED_HTTP_HOSTS <= SOURCE_HOSTS


@pytest.mark.parametrize("url", [
    "http://crt.sh/", "https://crt.sh:8443/", "https://user:pw@crt.sh/", "https://93.184.215.14/", "https://[::1]/",
    "https://localhost/", "https://intranet/", "https://printer.local/", "https://evil.example.net/",
    "https://crt.sh\\@evil.example.net/", "https://example.com/",  # the target itself is never a source
])
async def test_a_request_outside_the_policy_is_refused_before_it_is_sent(url):
    async with open_context(egress=guard()) as ctx:
        with respx.mock(assert_all_called=False) as router:
            route = router.route().mock(return_value=httpx.Response(200))
            with pytest.raises(EgressDenied):
                await ctx.http.get(url)
    assert route.call_count == 0


async def test_a_source_host_is_allowed():
    async with open_context(egress=guard()) as ctx:
        with respx.mock() as router:
            router.get("https://crt.sh/x").mock(return_value=httpx.Response(200, text="ok"))
            assert (await ctx.http.get("https://crt.sh/x")).text == "ok"


@pytest.mark.parametrize("location", [
    "https://evil.example.net/x", "https://example.com/", "http://web.archive.org/x", "https://10.0.0.1/",
    "https://169.254.169.254/latest/meta-data",
])
async def test_a_source_cannot_redirect_the_client_anywhere_else(location):
    async with open_context(egress=guard()) as ctx:
        with respx.mock(assert_all_called=False) as router:
            router.get("https://crt.sh/x").mock(return_value=httpx.Response(302, headers={"Location": location}))
            elsewhere = router.route(host__regex=r"^(?!crt\.sh$).*").mock(return_value=httpx.Response(200))
            with pytest.raises(EgressDenied):
                await ctx.http.get("https://crt.sh/x")
    assert elsewhere.call_count == 0


async def test_rdap_org_may_refer_to_public_rdap_servers_which_may_refer_on():
    async with open_context(egress=guard()) as ctx:
        with respx.mock() as router:
            router.get("https://rdap.org/ip/192.0.2.1").mock(return_value=httpx.Response(302, headers={"Location": "https://rdap.arin.net/registry/ip/192.0.2.1"}))
            router.get("https://rdap.arin.net/registry/ip/192.0.2.1").mock(return_value=httpx.Response(301, headers={"Location": "https://rdap.db.ripe.net/ip/192.0.2.1"}))
            router.get("https://rdap.db.ripe.net/ip/192.0.2.1").mock(return_value=httpx.Response(200, json={"name": "NET"}))
            assert (await ctx.http.get("https://rdap.org/ip/192.0.2.1")).json() == {"name": "NET"}


@pytest.mark.parametrize("location", [
    "https://internal.example.net/x", "https://mixed.example.net/x", "https://metadata.example.net/",
    "https://v6local.example.net/", "https://unknown.example.net/", "https://10.1.2.3/", "http://rdap.verisign.com/x",
    "https://rdap.verisign.com:8443/x",
])
async def test_an_rdap_referral_to_a_private_local_or_unresolvable_server_is_refused(location):
    async with open_context(egress=guard()) as ctx:
        with respx.mock(assert_all_called=False) as router:
            router.get("https://rdap.org/domain/example.com").mock(return_value=httpx.Response(302, headers={"Location": location}))
            elsewhere = router.route(host__regex=r"^(?!rdap\.org$).*").mock(return_value=httpx.Response(200, json={}))
            with pytest.raises(EgressDenied):
                await ctx.http.get("https://rdap.org/domain/example.com")
    assert elsewhere.call_count == 0


async def test_a_source_that_names_a_url_cannot_send_the_scan_there():
    """Common Crawl's index list names the URL of its search API: a hostile list must not become a request to an
    internal service or to the target."""
    store = Store(":memory:")
    scan = store.create_scan("example.com")
    root = Entity(type=EntityType.DOMAIN, value="example.com")
    store.upsert_entity(scan, root, ScopeState.IN)
    async with open_context(egress=guard()) as ctx:
        engine = Engine(store, ScopePolicy(domains=["example.com"]), ctx, breaker_threshold=0)
        with respx.mock(assert_all_called=False) as router:
            router.get("https://index.commoncrawl.org/collinfo.json").mock(
                return_value=httpx.Response(200, json=[{"cdx-api": "http://169.254.169.254/latest/meta-data/iam"}])
            )
            internal = router.route(host="169.254.169.254").mock(return_value=httpx.Response(200, text="secret"))
            assert await engine.run_module(scan, CommonCrawl(), root) == []
    assert internal.call_count == 0
    error = [r for r in store.audit_log(scan) if r.get("event") == "error"][0]["error"]
    assert "EgressDenied" in error and "http is not allowed" in error


async def test_replay_goes_through_the_same_guard():
    records = [{"id": "a", "source": "crtsh", "request": "GET https://crt.sh/?q=example.com", "payload": "[]"}]
    async with open_context(egress=guard()) as ctx:
        with respx.mock(assert_all_called=False) as router:
            router.get(url__regex=r"https://crt\.sh/.*").mock(return_value=httpx.Response(302, headers={"Location": "https://evil.example.net/"}))
            evil = router.route(host="evil.example.net").mock(return_value=httpx.Response(200, text="[]"))
            results = await replay_evidence(records, ctx.http, ctx.resolver)
    assert evil.call_count == 0 and results[0].status == "unavailable" and results[0].detail == "EgressDenied"


# ------------------------------------------------------------------------------------------ replay, MCP, webhooks


async def test_replay_looks_up_only_names_inside_the_bundles_own_subject():
    from scrutator.bundle.replay import subject_names

    report = {"scope": {"domains": ["example.com"]}, "entities": [
        {"type": "domain", "value": "partner.test", "state": "candidate"}, {"type": "domain", "value": "x.out.test", "state": "out"}]}
    subject = subject_names(report)
    records = [
        {"id": n, "source": "dns", "request": f"DNS A {n}", "payload": "NXDOMAIN"}
        for n in ("www.example.com", "_dmarc.partner.test", "tracking-id-42.attacker.test", "x.out.test")
    ]

    class Resolver:
        def __init__(self):
            self.asked = []

        async def lookup(self, name, rtype):
            self.asked.append(name)
            return []

    resolver = Resolver()
    async with httpx.AsyncClient() as http:
        results = await replay_evidence(records, http, resolver, subject=subject)
    assert sorted(resolver.asked) == ["_dmarc.partner.test", "www.example.com"]
    skipped = {r.evidence_id for r in results if r.status == "skipped"}
    assert skipped == {"tracking-id-42.attacker.test", "x.out.test"}


@pytest.mark.parametrize("path", [
    r"\\evil.example.net\share\proof.scrutator", "//evil.example.net/share/proof.scrutator",
    r"\\?\UNC\evil.example.net\share\proof.scrutator", r"\\.\pipe\proof.scrutator",
])
def test_the_mcp_verify_tool_refuses_network_and_device_paths_before_touching_them(path, monkeypatch, tmp_path):
    from scrutator.mcp_tools import ToolError, ToolSet

    touched = []
    monkeypatch.setattr(Path, "is_file", lambda self: touched.append(self) or False)
    monkeypatch.setattr(Path, "exists", lambda self: touched.append(self) or False)
    with pytest.raises(ToolError, match="local"):
        ToolSet(tmp_path / "db").verify_bundle(path)
    assert touched == []


@pytest.mark.parametrize("seed", [
    "exаmple.com",  # Cyrillic a
    "example.com.evil.net", "evil.net/example.com", "example.com@evil.net", "evil.net#example.com", "*.example.com",
    "192.0.2.1", "xn--exmple-cua.com", "example.com\x00.evil.net", "example.com evil.net",
])
async def test_the_mcp_scan_tool_refuses_seeds_outside_the_scope_before_any_lookup(seed, tmp_path):
    from scrutator.mcp_tools import ToolError, ToolSet

    scope = tmp_path / "scope.yaml"
    scope.write_text("domains:\n  - example.com\n", encoding="utf-8")

    def no_context():
        raise AssertionError("a lookup was about to start")

    tools = ToolSet(tmp_path / "s.db", scope_file=scope, allow_scan=True, context=no_context)
    with pytest.raises(ToolError):
        await tools.scan(seed)
    assert not (tmp_path / "s.db").exists()


async def test_a_webhook_redirect_is_not_followed():
    from scrutator.diff import Diff
    from scrutator.watch import make_webhook_client, make_webhook_notifier

    async with make_webhook_client() as client:
        notify = make_webhook_notifier("https://hooks.example.test/x", client)
        with respx.mock(assert_all_called=False) as router:
            router.post("https://hooks.example.test/x").mock(return_value=httpx.Response(307, headers={"Location": "http://127.0.0.1:8080/steal"}))
            local = router.route(host="127.0.0.1").mock(return_value=httpx.Response(200))
            await notify("example.com", 2, 1, Diff(added_entities=[{"id": "domain:a.example.com", "value": "a.example.com"}]))
    assert local.call_count == 0


async def test_a_referral_host_is_checked_once_not_before_every_request():
    """Twenty RDAP lookups of one scan are referred to the same few registry hosts; resolving each host before each
    request cost a scan two to three seconds on Windows (R4 timing: 29.5 s against 31.9 s on owasp.org)."""
    asked = []

    async def counting_resolve(host):
        asked.append(host)
        return await fake_resolve(host)

    egress = EgressGuard(resolve=counting_resolve)
    async with open_context(egress=egress) as ctx:
        with respx.mock(assert_all_called=False) as router:
            router.get(url__regex=r"https://rdap\.org/.*").mock(
                return_value=httpx.Response(302, headers={"Location": "https://rdap.arin.net/registry/ip/1"}))
            router.get(url__regex=r"https://rdap\.arin\.net/.*").mock(return_value=httpx.Response(200, json={}))
            for n in range(5):
                assert (await ctx.http.get(f"https://rdap.org/ip/192.0.2.{n}")).status_code == 200
    assert asked == ["rdap.arin.net"]


async def test_a_cached_host_is_still_refused_when_it_was_not_public():
    egress = EgressGuard(resolve=fake_resolve)
    egress._redirect_targets.add("internal.example.net")
    for _ in range(2):
        with pytest.raises(EgressDenied, match="non-public"):
            await egress.on_request(httpx.Request("GET", "https://internal.example.net/x"))
