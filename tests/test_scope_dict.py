from scrutator.scope import ScopePolicy


def test_to_dict_uses_canonical_forms():
    policy = ScopePolicy(domains=["Example.COM.", "bücher.example"], cidrs=["10.0.0.5/8"], asns=[64500, "as64501"])
    assert policy.to_dict() == {
        "domains": ["example.com", "xn--bcher-kva.example"],
        "cidrs": ["10.0.0.0/8"],
        "asns": ["AS64500", "AS64501"],
    }


def test_round_trip_keeps_decisions():
    original = ScopePolicy(domains=["example.com"], cidrs=["203.0.113.0/24"], asns=[64500])
    clone = ScopePolicy(**original.to_dict())
    for target in ("www.example.com", "203.0.113.9", "evil.net", "203.0.114.1"):
        assert clone.decide(target).allowed == original.decide(target).allowed
