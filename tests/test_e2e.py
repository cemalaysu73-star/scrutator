import httpx
import respx

from scrutator.model import Confidence, Entity, EntityType, ScopeState
from scrutator.modules.registry import load_builtin_modules
from scrutator.report import build_report
from scrutator.scan import run_scan
from scrutator.scope import ScopePolicy
from scrutator.store import Store

CRT_ROWS = [
    {
        "id": 1,
        "issuer_name": "LE",
        "name_value": "example.com\nwww.example.com\nexample.com.evil.net",
        "not_before": "2026-01-01",
        "not_after": "2026-04-01",
    }
]
RECORDS = {
    ("example.com", "A"): ["93.184.216.34"],
    ("www.example.com", "CNAME"): ["cdn.thirdparty.net."],
}
WAYBACK = [["original"], ["http://www.example.com/"]]
COLLINFO = [{"id": "CC-MAIN-2026-10", "cdx-api": "https://index.commoncrawl.org/CC-MAIN-2026-10-index"}]


def mock_internet(router):
    router.get("https://crt.sh/").mock(return_value=httpx.Response(200, json=CRT_ROWS))
    router.get(url__regex=r"https://rdap\.org/domain/.*").mock(return_value=httpx.Response(404))
    router.get("https://rdap.org/ip/93.184.216.34").mock(
        return_value=httpx.Response(200, json={"name": "EDGECAST-NETBLK-03"})
    )
    router.get("https://stat.ripe.net/data/prefix-overview/data.json").mock(
        return_value=httpx.Response(200, json={"data": {"asns": [{"asn": 15133, "holder": "EDGECAST"}]}})
    )
    router.get("https://web.archive.org/cdx/search/cdx").mock(return_value=httpx.Response(200, json=WAYBACK))
    router.get("https://index.commoncrawl.org/collinfo.json").mock(return_value=httpx.Response(200, json=COLLINFO))
    router.get("https://index.commoncrawl.org/CC-MAIN-2026-10-index").mock(return_value=httpx.Response(404))


async def test_full_passive_scan(make_ctx):
    ctx = make_ctx(RECORDS)
    store = Store(":memory:")
    seed = Entity(type=EntityType.DOMAIN, value="example.com")

    with respx.mock() as router:
        mock_internet(router)
        scan_id, stats = await run_scan(seed, ScopePolicy(domains=["example.com"]), store, ctx)
        requested = [str(call.request.url) for call in router.calls]

    states = {s.entity.id: s.state for s in store.entities(scan_id)}
    assert states["domain:example.com"] is ScopeState.IN
    assert states["domain:www.example.com"] is ScopeState.IN
    assert states["ip:93.184.216.34"] is ScopeState.LINKED
    assert states["asn:AS15133"] is ScopeState.OUT
    assert states["domain:example.com.evil.net"] is ScopeState.OUT
    assert states["domain:cdn.thirdparty.net"] is ScopeState.OUT
    assert stats.rounds >= 2

    # out-of-scope hosts were recorded but never queried
    assert not any("evil.net" in url or "thirdparty" in url for url in requested)
    assert not any("thirdparty" in name or "evil.net" in name for name, _ in ctx.resolver.calls)

    assert store.verify_audit(scan_id)
    report = build_report(store, scan_id)
    by_claim = {f["claim"]: f for f in report["findings"]}
    corroborated = by_claim["example.com has subdomain www.example.com"]
    assert corroborated["confidence"] == Confidence.MEDIUM.value
    assert by_claim["www.example.com is an alias (CNAME) of cdn.thirdparty.net"]["confidence"] == "low"
    assert by_claim["93.184.216.34 is announced by AS15133"]["confidence"] == "low"
    for finding in report["findings"]:
        assert all(i in report["evidence"] for i in finding["evidence_ids"])


def test_builtin_modules_are_discovered():
    names = {m.name for m in load_builtin_modules()}
    assert {"crtsh", "dns", "rdap", "asn", "wayback", "commoncrawl"} <= names
