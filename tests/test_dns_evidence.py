from dnsfakes import StatusResolver

from scrutator.engine import Engine
from scrutator.model import Entity, EntityType, ScopeState
from scrutator.modules.base import Fact, ModuleContext, Observation
from scrutator.modules.dns import Dns
from scrutator.scope import ScopePolicy
from scrutator.store import Store


def dom(value):
    return Entity(type=EntityType.DOMAIN, value=value)


def ctx(zone, http=None, boom=None):
    return ModuleContext(http=http, resolver=StatusResolver(zone, boom))


def facts(items):
    return {f.evidence.request: f.evidence.payload for f in items if isinstance(f, Fact)}


def observations(items):
    return [o for o in items if isinstance(o, Observation)]


async def test_a_name_that_does_not_exist_is_recorded_as_a_fact():
    items = await Dns().run(dom("ghost.example.com"), ctx({("example.com", "A"): ["192.0.2.1"]}))
    assert observations(items) == []
    assert facts(items) == {"DNS A ghost.example.com": "NXDOMAIN"}


async def test_a_name_that_exists_without_an_address_records_nothing():
    zone = {("mail.example.com", "MX"): ["10 mx.example.net."]}
    items = await Dns().run(dom("mail.example.com"), ctx(zone))
    assert "DNS A mail.example.com" not in facts(items)


async def test_a_dangling_cname_keeps_its_relation_and_gains_the_nxdomain_fact():
    zone = {("shop.example.com", "CNAME"): ["shop-demo.azurewebsites.net."], ("shop.example.com", "A"): "NXDOMAIN"}
    items = await Dns().run(dom("shop.example.com"), ctx(zone))
    assert [(o.rel, o.entity.value) for o in observations(items)] == [("cname_to", "shop-demo.azurewebsites.net")]
    assert facts(items) == {"DNS A shop.example.com": "NXDOMAIN"}


async def test_a_mail_domain_is_asked_for_dmarc_and_the_absence_is_recorded():
    zone = {("example.com", "MX"): ["10 mail.example.com."], ("mail.example.com", "A"): ["192.0.2.25"]}
    resolver_ctx = ctx(zone)
    items = await Dns().run(dom("example.com"), resolver_ctx)
    assert ("_dmarc.example.com", "TXT") in resolver_ctx.resolver.calls
    assert facts(items)["DNS TXT _dmarc.example.com"] in ("NXDOMAIN", "NODATA")
    assert ("example.com", "CAA") not in resolver_ctx.resolver.calls  # not a zone apex: no NS answer


async def test_an_existing_dmarc_record_is_recorded_too():
    record = '"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"'
    zone = {("example.com", "MX"): ["10 mail.example.com."], ("_dmarc.example.com", "TXT"): [record]}
    items = await Dns().run(dom("example.com"), ctx(zone))
    assert facts(items)["DNS TXT _dmarc.example.com"] == record


async def test_a_zone_apex_is_asked_for_caa_and_dmarc():
    zone = {("example.com", "NS"): ["ns1.dns.example.net."], ("example.com", "CAA"): ['0 issue "letsencrypt.org"']}
    resolver_ctx = ctx(zone)
    items = await Dns().run(dom("example.com"), resolver_ctx)
    assert facts(items)["DNS CAA example.com"] == '0 issue "letsencrypt.org"'
    assert "DNS TXT _dmarc.example.com" in facts(items)
    bare = await Dns().run(dom("example.com"), ctx({("example.com", "NS"): ["ns1.dns.example.net."]}))
    assert facts(bare)["DNS CAA example.com"] == "NODATA"


async def test_a_name_with_neither_mail_nor_ns_is_not_asked_for_dmarc_or_caa():
    zone = {("www.example.com", "A"): ["192.0.2.10"]}
    resolver_ctx = ctx(zone)
    items = await Dns().run(dom("www.example.com"), resolver_ctx)
    assert facts(items) == {}
    assert not any(name.startswith("_dmarc.") or rtype == "CAA" for name, rtype in resolver_ctx.resolver.calls)


async def test_an_spf_record_without_includes_is_still_evidence():
    zone = {("example.com", "TXT"): ['"v=spf1 -all"', '"_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9"']}
    items = await Dns().run(dom("example.com"), ctx(zone))
    assert observations(items) == []
    assert facts(items)["DNS TXT example.com"] == '"v=spf1 -all"\n"_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9"'


async def test_an_spf_record_with_includes_is_cited_by_its_relation_not_duplicated_as_a_fact():
    zone = {("example.com", "TXT"): ['"v=spf1 include:spf.dns.example.net -all"']}
    items = await Dns().run(dom("example.com"), ctx(zone))
    assert [o.rel for o in observations(items)] == ["spf_include"]
    assert "DNS TXT example.com" not in facts(items)


async def test_txt_records_that_are_not_spf_are_not_stored():
    zone = {("example.com", "TXT"): ['"google-site-verification=abc"']}
    assert await Dns().run(dom("example.com"), ctx(zone)) == []


async def test_a_failing_auxiliary_lookup_does_not_discard_the_main_answers():
    zone = {("example.com", "NS"): ["ns1.dns.example.net."]}
    boom = {("example.com", "CAA"): TimeoutError("slow")}
    items = await Dns().run(dom("example.com"), ctx(zone, boom=boom))
    assert [o.rel for o in observations(items)] == ["ns"]
    assert "DNS CAA example.com" not in facts(items)


async def test_every_name_queried_stays_under_the_scope():
    zone = {
        ("example.com", "MX"): ["10 mail.example.com."],
        ("example.com", "NS"): ["ns1.dns.example.net."],
        ("api.eu.example.com", "CNAME"): ["edge.example.net."],
    }
    scope = ScopePolicy(domains=["example.com"])
    for name in ("example.com", "api.eu.example.com"):
        resolver_ctx = ctx(zone)
        await Dns().run(dom(name), resolver_ctx)
        for queried, _ in resolver_ctx.resolver.calls:
            assert scope.decide(queried).allowed, queried
    assert not any("example.net" in queried for queried, _ in resolver_ctx.resolver.calls)


async def test_facts_reach_the_store_through_the_engine():
    store = Store(":memory:")
    engine = Engine(store, ScopePolicy(domains=["example.com"]), ctx(None))
    sid = store.create_scan("example.com")
    store.upsert_entity(sid, dom("ghost.example.com"), ScopeState.IN)
    await engine.run_module(sid, Dns(), dom("ghost.example.com"))
    stored = {e.request: e.payload for e in store.evidence_for_scan(sid)}
    assert stored == {"DNS A ghost.example.com": "NXDOMAIN"}
    assert store.edges(sid) == []
