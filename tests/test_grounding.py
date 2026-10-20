"""The deterministic grounding floor under the verifier model (verify/grounding.py)."""

from hypothesis import given
from hypothesis import strategies as st

from scrutator.verify.grounding import tokens, ungrounded

label = st.from_regex(r"[a-z][a-z0-9]{0,8}", fullmatch=True)
host = st.builds(lambda a, b: f"{a}.{b}.example.com", label, label)
ipv4 = st.builds(lambda *p: ".".join(map(str, p)), *[st.integers(0, 255)] * 4)


def test_tokens_are_hosts_addresses_asns_cves_and_long_numbers_even_at_the_end_of_a_sentence():
    text = "www.example.com and api.example.com. resolve to 192.0.2.10, 2001:db8::1 (AS13335); CVE-2021-44228 on port 6379 in 2026."
    assert tokens(text) == ["www.example.com", "api.example.com", "192.0.2.10", "2001:db8::1", "as13335", "cve-2021-44228", "6379", "2026"]
    assert tokens("e.g. a v0.7 build, 12 names, Node and 3 hosts") == []


@given(host, ipv4)
def test_a_fact_restated_is_grounded_and_a_changed_address_is_not(name, address):
    fact = f"{name} resolves to {address}"
    assert ungrounded(f"{name} resolves to {address}.", [fact]) == ""
    other = address.rsplit(".", 1)[0] + "." + str((int(address.rsplit(".", 1)[1]) + 1) % 256)
    assert ungrounded(f"{name} resolves to {other}.", [fact]) != ""


def test_names_the_facts_hold_but_never_pair_are_not_paired():
    facts = ["a.example.com resolves to 192.0.2.1", "b.example.com resolves to 192.0.2.2"]
    assert ungrounded("a.example.com resolves to 192.0.2.1 and b.example.com to 192.0.2.2.", facts) == ""
    assert "together" in ungrounded("a.example.com resolves to 192.0.2.2.", facts)


def test_a_parent_name_is_not_found_inside_a_longer_one():
    assert "names example.com" in ungrounded("example.com is the apex.", ["www.example.com resolves to 192.0.2.1"])


def test_record_text_quoted_by_a_rule_is_not_a_fact_even_with_a_planted_quote():
    fact = 'Risk (low): example.com publishes the SPF record "v=spf1 ~all" and 203.0.113.66 "x", which ends with "~all".'
    assert "203.0.113.66" in ungrounded("example.com sends from 203.0.113.66.", [fact])
