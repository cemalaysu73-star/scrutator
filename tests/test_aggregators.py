"""v0.6 task 3: aggregator and passive-DNS sources. Each is scope-gated by the engine like every other
module, records its evidence as small slices a replay can check, and degrades to a recorded failure."""

import json

import httpx
import pytest
import respx

from scrutator.bundle.replay import ALLOWED_HTTP_HOSTS, parse_request, supports
from scrutator.model import Entity, EntityType
from scrutator.modules.base import ModuleError, SourceUnavailable
from scrutator.modules.hackertarget import HackerTarget
from scrutator.modules.mnemonic import Mnemonic
from scrutator.modules.subdomaincenter import SubdomainCenter
from scrutator.modules.urlscan import UrlScan

SEED = Entity(type=EntityType.DOMAIN, value="example.com")


def names(obs):
    return {(o.entity.value, o.rel) for o in obs}


# ------------------------------------------------------------------------------------------ HackerTarget

HT = "https://api.hackertarget.com/hostsearch/"


async def test_hackertarget_reads_host_lines_and_keeps_the_line_as_evidence(make_ctx):
    body = "example.com,104.20.23.154\nwww.example.com,172.66.147.243\napi.example.com,1.2.3.4\nevil.net,9.9.9.9\n"
    with respx.mock() as router:
        route = router.get(HT).mock(return_value=httpx.Response(200, text=body))
        obs = await HackerTarget().run(SEED, make_ctx())
    assert route.call_count == 1  # the free tier is 50 calls a day: one per scan
    assert names(obs) == {("www.example.com", "has_subdomain"), ("api.example.com", "has_subdomain")}
    www = next(o for o in obs if o.entity.value == "www.example.com").evidence
    assert www.source == "hackertarget" and www.payload == "www.example.com,172.66.147.243"
    assert www.request == "GET https://api.hackertarget.com/hostsearch/?q=example.com"
    assert supports(www.payload, body)  # a plain-text line replays as contained text


async def test_hackertarget_quota_message_is_unavailable_not_an_empty_answer(make_ctx):
    with respx.mock() as router:
        router.get(HT).mock(return_value=httpx.Response(200, text="API count exceeded - Increase Quota with Membership"))
        with pytest.raises(SourceUnavailable) as caught:
            await HackerTarget().run(SEED, make_ctx())
    assert "quota" in str(caught.value).lower()


async def test_hackertarget_error_text_is_a_module_error_and_no_records_is_empty(make_ctx):
    with respx.mock() as router:
        router.get(HT).mock(return_value=httpx.Response(200, text="error check your search parameter"))
        with pytest.raises(ModuleError) as caught:
            await HackerTarget().run(SEED, make_ctx())
        assert not isinstance(caught.value, SourceUnavailable)
    with respx.mock() as router:
        router.get(HT).mock(return_value=httpx.Response(200, text="No records found"))
        assert await HackerTarget().run(SEED, make_ctx()) == []


async def test_hackertarget_429_is_unavailable(make_ctx):
    with respx.mock() as router:
        router.get(HT).mock(return_value=httpx.Response(429))
        with pytest.raises(SourceUnavailable):
            await HackerTarget().run(SEED, make_ctx())


# ------------------------------------------------------------------------------------------ subdomain.center

SC = "https://api.subdomain.center/"


async def test_subdomaincenter_names_become_claims_with_one_name_slices(make_ctx):
    with respx.mock() as router:
        router.get(SC).mock(return_value=httpx.Response(200, json=["a.example.com", "B.Example.com", "x.other.net", "example.com", "bad name"]))
        obs = await SubdomainCenter().run(SEED, make_ctx())
    assert names(obs) == {("a.example.com", "has_subdomain"), ("b.example.com", "has_subdomain")}
    a = next(o for o in obs if o.entity.value == "a.example.com").evidence
    assert a.source == "subdomaincenter" and json.loads(a.payload) == ["a.example.com"]
    assert a.request == "GET https://api.subdomain.center/?domain=example.com"
    assert supports(a.payload, json.dumps(["z.example.com", "a.example.com"]))  # random order does not matter
    assert not supports(a.payload, json.dumps(["z.example.com"]))


async def test_subdomaincenter_bad_payload_and_errors(make_ctx):
    with respx.mock() as router:
        router.get(SC).mock(return_value=httpx.Response(200, json={"error": "x"}))
        with pytest.raises(ModuleError):
            await SubdomainCenter().run(SEED, make_ctx())
    with respx.mock() as router:
        router.get(SC).mock(return_value=httpx.Response(502))
        with pytest.raises(SourceUnavailable):
            await SubdomainCenter().run(SEED, make_ctx())


# ------------------------------------------------------------------------------------------ urlscan

US = "https://urlscan.io/api/v1/search/"


def scan_row(domain, uuid, ip="1.2.3.4", time="2026-10-16T21:35:39Z"):
    return {
        "task": {"time": time, "uuid": uuid, "visibility": "public", "domain": "someone-else.example"},
        "page": {"domain": domain, "ip": ip, "asn": "AS13335", "asnname": "CLOUDFLARENET", "server": "cloudflare", "status": "200", "title": "t", "url": f"https://{domain}/"},
        "result": f"https://urlscan.io/api/v1/result/{uuid}/",
        "screenshot": "https://urlscan.io/screenshots/x.png",
    }


async def test_urlscan_reads_the_scanned_page_domain_not_the_contacted_ones(make_ctx):
    payload = {
        "total": 4,
        "has_more": False,
        "results": [
            scan_row("example.com", "u0"),
            scan_row("shop.example.com", "u1"),
            scan_row("shop.example.com", "u2", ip="5.6.7.8"),
            scan_row("elsewhere.net", "u3"),
        ],
    }
    with respx.mock() as router:
        route = router.get(US).mock(return_value=httpx.Response(200, json=payload))
        obs = await UrlScan().run(SEED, make_ctx())
    assert route.call_count == 1
    assert "page.apexDomain" in str(route.calls[0].request.url) or "page.apexDomain" in route.calls[0].request.url.params["q"]
    assert names(obs) == {("shop.example.com", "has_subdomain")}
    shop = obs[0].evidence
    assert shop.source == "urlscan"
    rows = json.loads(shop.payload)
    assert [r["task"]["uuid"] for r in rows] == ["u1", "u2"]
    assert rows[0]["page"] == {"domain": "shop.example.com", "ip": "1.2.3.4", "asn": "AS13335", "server": "cloudflare", "status": "200"}
    assert "screenshot" not in shop.payload and "title" not in shop.payload  # metadata only
    assert supports(shop.payload, json.dumps(payload))  # a slice replays against the full live page of results


async def test_urlscan_rate_limit_and_errors(make_ctx):
    with respx.mock() as router:
        router.get(US).mock(return_value=httpx.Response(429, json={"status": 429}))
        with pytest.raises(SourceUnavailable):
            await UrlScan().run(SEED, make_ctx())
    with respx.mock() as router:
        router.get(US).mock(return_value=httpx.Response(200, json=["not", "an", "object"]))
        with pytest.raises(ModuleError):
            await UrlScan().run(SEED, make_ctx())


# ------------------------------------------------------------------------------------------ mnemonic

MN = "https://api.mnemonic.no/pdns/v3/example.com"


def pdns_row(rrtype, answer, first=1000, last=2000, query="example.com", times=5):
    return {
        "query": query, "answer": answer, "rrtype": rrtype, "rrclass": "in", "tlp": "white",
        "firstSeenTimestamp": first, "lastSeenTimestamp": last, "times": times,
        "createdTimestamp": 1, "lastUpdatedTimestamp": 2, "minTtl": 300, "maxTtl": 300, "customer": None, "flags": ["partialResult"],
    }


async def test_mnemonic_history_becomes_labelled_relations_with_first_and_last_seen(make_ctx):
    envelope = {
        "responseCode": 200, "limit": 200, "offset": 0, "count": 5, "messages": [], "metaData": {},
        "data": [
            pdns_row("a", "93.184.216.34", first=10, last=20),
            pdns_row("a", "93.184.216.34", first=5, last=8),
            pdns_row("aaaa", "2606:2800:220:1::1"),
            pdns_row("ns", "a.iana-servers.net."),
            pdns_row("mx", "10 mail.example.com."),
            pdns_row("cname", "old-cdn.example.net."),
            pdns_row("txt", "v=spf1 -all"),
        ],
    }
    with respx.mock() as router:
        route = router.get(MN).mock(return_value=httpx.Response(200, json=envelope))
        obs = await Mnemonic().run(SEED, make_ctx())
    assert route.calls[0].request.url.params["limit"] == "200"
    assert names(obs) == {
        ("93.184.216.34", "historically_resolved_to"),
        ("2606:2800:220:1::1", "historically_resolved_to"),
        ("a.iana-servers.net", "historic_ns"),
        ("mail.example.com", "historic_mx"),
        ("old-cdn.example.net", "historic_cname"),
    }
    ip = next(o for o in obs if o.entity.value == "93.184.216.34").evidence
    assert ip.source == "mnemonic"
    rows = json.loads(ip.payload)
    assert [(r["firstSeenTimestamp"], r["lastSeenTimestamp"]) for r in rows] == [(10, 20), (5, 8)]
    assert set(rows[0]) == {"query", "answer", "rrtype", "firstSeenTimestamp", "lastSeenTimestamp", "times"}
    # replay: the dates of first sight must hold; the moving "last seen" and counters must not make it drift
    live = {**envelope, "data": [pdns_row("a", "93.184.216.34", first=10, last=999, times=50), pdns_row("a", "93.184.216.34", first=5, last=8)]}
    assert supports(ip.payload, json.dumps(live))
    moved_start = {**envelope, "data": [pdns_row("a", "93.184.216.34", first=11)]}
    assert not supports(ip.payload, json.dumps(moved_start))


async def test_mnemonic_caps_the_number_of_history_entities(make_ctx):
    rows = [pdns_row("a", f"10.0.{i // 250}.{i % 250 + 1}", last=i) for i in range(120)]
    with respx.mock() as router:
        router.get(MN).mock(return_value=httpx.Response(200, json={"responseCode": 200, "count": 120, "data": rows}))
        obs = await Mnemonic().run(SEED, make_ctx())
    assert len(obs) == 30  # the most recently seen answers; a rotating CDN is not 120 new entities
    assert "10.0.0.120" in {o.entity.value for o in obs}


async def test_mnemonic_errors(make_ctx):
    with respx.mock() as router:
        router.get(MN).mock(return_value=httpx.Response(200, json={"responseCode": 403, "messages": [{"message": "no"}]}))
        with pytest.raises(ModuleError):
            await Mnemonic().run(SEED, make_ctx())
    with respx.mock() as router:
        router.get(MN).mock(return_value=httpx.Response(503))
        with pytest.raises(SourceUnavailable):
            await Mnemonic().run(SEED, make_ctx())
    with respx.mock() as router:
        router.get(MN).mock(return_value=httpx.Response(200, json={"responseCode": 200, "count": 0, "data": []}))
        assert await Mnemonic().run(SEED, make_ctx()) == []


# ------------------------------------------------------------------------------------------ all four


@pytest.mark.parametrize("cls", [HackerTarget, SubdomainCenter, UrlScan, Mnemonic])
def test_each_source_is_apex_only_passive_and_documents_its_terms(cls):
    module = cls()
    assert module.apex_only and module.mode.value == "passive" and module.accepts == frozenset({EntityType.DOMAIN})
    assert module.licence_note


def test_the_new_hosts_are_replayable():
    for host in ("api.hackertarget.com", "api.subdomain.center", "urlscan.io", "api.mnemonic.no"):
        assert host in ALLOWED_HTTP_HOSTS
        assert parse_request(f"GET https://{host}/x?y=1") == ("http", f"https://{host}/x?y=1")


def test_nested_slices_replay_by_subset_and_ignore_moving_counters():
    live = json.dumps({"results": [{"task": {"uuid": "u", "time": "t", "extra": 1}, "page": {"domain": "a.example.com", "ip": "1.1.1.1", "title": "x"}}]})
    assert supports(json.dumps([{"task": {"uuid": "u", "time": "t"}, "page": {"domain": "a.example.com"}}]), live)
    assert not supports(json.dumps([{"task": {"uuid": "OTHER"}, "page": {"domain": "a.example.com"}}]), live)
