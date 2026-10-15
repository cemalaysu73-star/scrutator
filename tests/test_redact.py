from hypothesis import given, settings
from hypothesis import strategies as st

from scrutator.ai.redact import Redactor


def make():
    return Redactor(apex_domains=["acme.com"], orgs=["Acme Corp"])


def test_apex_ip_and_org_are_pseudonymised_and_restorable():
    r = make()
    text = "www.acme.com resolves to 192.0.2.10, owned by Acme Corp"
    out = r.redact(text)
    assert out == "www.d1.example resolves to ip-1, owned by org-1"
    for secret in ("acme", "192.0.2.10", "Acme"):
        assert secret not in out
    assert r.restore(out) == text


def test_subdomain_labels_are_kept_and_lookalikes_untouched():
    r = make()
    out = r.redact("dev.staging.acme.com and evilacme.com and acme.com.evil.net")
    assert out.startswith("dev.staging.d1.example and ")
    assert "evilacme.com" in out


def test_same_ip_gets_the_same_alias_and_distinct_ips_differ():
    r = make()
    out = r.redact("192.0.2.1 192.0.2.2 192.0.2.1 2001:db8::1")
    assert out == "ip-1 ip-2 ip-1 ip-3"


def test_invalid_addresses_and_times_are_left_alone():
    r = make()
    text = "999.1.1.1 at 12:30:45 and version 1.2.3"
    assert r.redact(text) == text


def test_restore_prefers_longer_aliases():
    r = Redactor()
    ips = [f"198.51.100.{n}" for n in range(1, 12)]
    out = r.redact(" ".join(ips))
    assert "ip-10" in out and "ip-11" in out
    assert r.restore(out) == " ".join(ips)


def test_apex_added_later_is_used():
    r = Redactor()
    r.add_apex("Other.NET")
    assert r.redact("mail.other.net") == "mail.d1.example"


_PIECES = ["www.acme.com", "198.51.100.7", "Acme Corp", "plain words", "2001:db8::5", "api.dev.acme.com"]


@settings(max_examples=200, deadline=None)
@given(st.lists(st.sampled_from(_PIECES), min_size=1, max_size=8))
def test_round_trip_property(pieces):
    r = make()
    text = " | ".join(pieces)
    redacted = r.redact(text)
    assert "acme.com" not in redacted.lower()
    assert "198.51.100.7" not in redacted
    assert r.restore(redacted) == text
