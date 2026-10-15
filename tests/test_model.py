import pytest

from scrutator.model import (
    Confidence,
    Edge,
    Entity,
    EntityType,
    Evidence,
    Finding,
    ScopeState,
)


def test_domain_is_canonicalized():
    e = Entity(type=EntityType.DOMAIN, value="WWW.Example.COM.")
    assert e.value == "www.example.com"
    assert e.id == "domain:www.example.com"


def test_idn_domain_becomes_punycode():
    e = Entity(type=EntityType.DOMAIN, value="bücher.example")
    assert e.value == "xn--bcher-kva.example"


@pytest.mark.parametrize(
    "bad",
    ["", " ", "a..b.com", "exa mple.com", "-bad.com", "a" * 64 + ".com", "ex/ample.com", "user@example.com"],
)
def test_invalid_domain_rejected(bad):
    with pytest.raises(ValueError):
        Entity(type=EntityType.DOMAIN, value=bad)


def test_ip_is_canonicalized():
    assert Entity(type=EntityType.IP, value="2001:0DB8:0:0:0:0:0:1").value == "2001:db8::1"


def test_invalid_ip_rejected():
    with pytest.raises(ValueError):
        Entity(type=EntityType.IP, value="999.1.1.1")


def test_asn_is_canonicalized():
    assert Entity(type=EntityType.ASN, value="as13335").value == "AS13335"
    assert Entity(type=EntityType.ASN, value="13335").value == "AS13335"


def test_invalid_asn_rejected():
    with pytest.raises(ValueError):
        Entity(type=EntityType.ASN, value="ASX")


def test_org_whitespace_collapsed():
    assert Entity(type=EntityType.ORG, value="  Cloudflare,   Inc. ").value == "Cloudflare, Inc."


def test_empty_org_rejected():
    with pytest.raises(ValueError):
        Entity(type=EntityType.ORG, value="   ")


def test_entity_is_hashable_and_frozen():
    a = Entity(type=EntityType.DOMAIN, value="a.com")
    assert len({a, Entity(type=EntityType.DOMAIN, value="A.com")}) == 1
    with pytest.raises(ValueError):
        a.value = "b.com"


def test_scope_state_ranking():
    assert ScopeState.OUT.rank < ScopeState.LINKED.rank < ScopeState.IN.rank


def test_edge_holds_evidence_ids():
    edge = Edge(src="domain:a.com", rel="resolves_to", dst="ip:1.2.3.4", evidence_ids=("x",))
    assert edge.evidence_ids == ("x",)


def test_evidence_id_is_content_addressed():
    a = Evidence.create("dns", "DNS A x", "1.2.3.4", collected_at="2026-01-01T00:00:00+00:00")
    b = Evidence.create("dns", "DNS A x", "1.2.3.4", collected_at="2030-01-01T00:00:00+00:00")
    c = Evidence.create("dns", "DNS A x", "1.2.3.5")
    assert a.id == b.id
    assert a.id != c.id
    assert len(a.id) == 64


def test_finding_requires_evidence():
    with pytest.raises(ValueError):
        Finding(claim="x", entity_ids=("domain:a.com",), evidence_ids=(), confidence=Confidence.LOW)
    ok = Finding(claim="x", entity_ids=("domain:a.com",), evidence_ids=("e1",), confidence=Confidence.LOW)
    assert ok.confidence is Confidence.LOW
