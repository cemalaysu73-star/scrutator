import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from scrutator.model import Entity, EntityType
from scrutator.scope import ScopePolicy


@pytest.fixture
def policy():
    return ScopePolicy(
        domains=["example.com"], cidrs=["203.0.113.0/24", "2001:db8::/32"], asns=[64500]
    )


ALLOWED = [
    "example.com",
    "EXAMPLE.com.",
    "www.example.com",
    "a.b.example.com",
    "https://www.example.com/x?y=1",
    "http://example.com:8080/",
    "203.0.113.7",
    "2001:db8::1",
    "https://[2001:db8::1]/",
    "bücher.example.com",
]

DENIED = [
    "example.org",
    "evil.com",
    "example.com.evil.com",
    "evilexample.com",
    "notexample.com",
    "example.com@evil.com",
    "https://example.com@evil.com/",
    "https://evil.com\\@example.com/",
    "http://evil.com#@example.com/",
    "https://evil.com/?example.com",
    "ftp://example.com/",
    "//evil.com",
    "",
    "  ",
    "example.com/",
    "example.com:443",
    "203.0.114.1",
    "2130706433",
    "0x7f.1",
    "127.0.0.1",
    "::ffff:203.0.113.7",
    "2001:db9::1",
    "example.com\x00.evil.com",
    "example.com .evil.com",
    "example.com。evil.com",
    "example..com",
    "-.example.com",
]


@pytest.mark.parametrize("target", ALLOWED)
def test_allowed_targets(policy, target):
    decision = policy.decide(target)
    assert decision.allowed, decision.reason


@pytest.mark.parametrize("target", DENIED)
def test_denied_targets(policy, target):
    assert not policy.decide(target).allowed


def test_decide_entity(policy):
    assert policy.decide_entity(Entity(type=EntityType.DOMAIN, value="www.example.com")).allowed
    assert not policy.decide_entity(Entity(type=EntityType.DOMAIN, value="other.net")).allowed
    assert policy.decide_entity(Entity(type=EntityType.IP, value="203.0.113.9")).allowed
    assert policy.decide_entity(Entity(type=EntityType.ASN, value="AS64500")).allowed
    assert not policy.decide_entity(Entity(type=EntityType.ASN, value="AS13335")).allowed
    assert policy.decide_entity(Entity(type=EntityType.ORG, value="Anything Inc")).allowed


def test_from_file(tmp_path):
    f = tmp_path / "scope.yaml"
    f.write_text("domains:\n  - example.com\ncidrs:\n  - 198.51.100.0/24\nasns:\n  - AS64501\n")
    p = ScopePolicy.from_file(f)
    assert p.decide("api.example.com").allowed
    assert p.decide("198.51.100.5").allowed
    assert p.decide_entity(Entity(type=EntityType.ASN, value="64501")).allowed


def test_from_file_rejects_unknown_keys_and_empty_scope(tmp_path):
    f = tmp_path / "bad.yaml"
    f.write_text("domain: example.com\n")
    with pytest.raises(ValueError):
        ScopePolicy.from_file(f)
    g = tmp_path / "empty.yaml"
    g.write_text("domains: []\n")
    with pytest.raises(ValueError):
        ScopePolicy.from_file(g)


_label = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-", min_size=1, max_size=12).filter(
    lambda s: not s.startswith("-") and not s.endswith("-")
)
_hosts = st.lists(_label, min_size=1, max_size=5).map(".".join)


@settings(max_examples=300, deadline=None)
@given(_hosts)
def test_decision_matches_reference_oracle(host):
    p = ScopePolicy(domains=["example.com"])
    expected = host == "example.com" or host.endswith(".example.com")
    assert p.decide(host).allowed is expected
    assert p.decide(f"https://{host}/path").allowed is expected


@settings(max_examples=200, deadline=None)
@given(_hosts)
def test_userinfo_never_allowed(host):
    p = ScopePolicy(domains=["example.com"])
    assert not p.decide(f"https://{host}@example.com/").allowed
    assert not p.decide(f"https://example.com@{host}/").allowed


@settings(max_examples=300, deadline=None)
@given(st.text())
def test_decide_never_raises(text):
    ScopePolicy(domains=["example.com"], cidrs=["10.0.0.0/8"]).decide(text)
