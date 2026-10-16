import dns.resolver
import pytest

from scrutator.resolver import DnsAnswer, DnsResolver, lookup_status, parse_payload


class _Rdata:
    def __init__(self, text):
        self._text = text

    def to_text(self):
        return self._text


def test_payload_is_the_records_one_per_line_or_a_single_negative_word():
    assert DnsAnswer("answer", ("192.0.2.1", "192.0.2.2")).payload() == "192.0.2.1\n192.0.2.2"
    assert DnsAnswer("nxdomain").payload() == "NXDOMAIN"
    assert DnsAnswer("nodata").payload() == "NODATA"
    assert DnsAnswer("empty").payload() == "" and DnsAnswer("servfail").payload() == ""


@pytest.mark.parametrize(
    "answer",
    [DnsAnswer("answer", ("192.0.2.1", "192.0.2.2")), DnsAnswer("nxdomain"), DnsAnswer("nodata"), DnsAnswer("empty")],
)
def test_payload_round_trips(answer):
    assert parse_payload(answer.payload()) == answer


def test_only_nxdomain_and_nodata_are_definite_negatives():
    assert DnsAnswer("nxdomain").negative and DnsAnswer("nodata").negative
    assert not DnsAnswer("empty").negative and not DnsAnswer("servfail").negative
    assert not DnsAnswer("answer", ("x",)).negative


def test_a_txt_record_that_says_nxdomain_is_not_a_negative():
    # TXT text is quoted by dnspython, so it cannot collide with the bare word
    assert parse_payload('"NXDOMAIN"') == DnsAnswer("answer", ('"NXDOMAIN"',))


async def test_query_tells_nxdomain_from_nodata_from_servfail(monkeypatch):
    resolver = DnsResolver()

    async def ok(name, rtype):
        return [_Rdata("192.0.2.1")]

    monkeypatch.setattr(resolver._resolver, "resolve", ok)
    assert await resolver.query("www.example.com", "A") == DnsAnswer("answer", ("192.0.2.1",))

    for raised, status in (
        (dns.resolver.NXDOMAIN(), "nxdomain"),
        (dns.resolver.NoAnswer(), "nodata"),
        (dns.resolver.NoNameservers(), "servfail"),
    ):

        async def boom(name, rtype, _raised=raised):
            raise _raised

        monkeypatch.setattr(resolver._resolver, "resolve", boom)
        assert (await resolver.query("x.example.com", "A")).status == status
        assert await resolver.lookup("x.example.com", "A") == []  # the older contract is unchanged


async def test_a_timeout_is_still_an_error_not_a_negative(monkeypatch):
    resolver = DnsResolver()

    async def slow(name, rtype):
        raise dns.resolver.LifetimeTimeout()

    monkeypatch.setattr(resolver._resolver, "resolve", slow)
    with pytest.raises(dns.resolver.LifetimeTimeout):
        await resolver.query("x.example.com", "A")


class OldStyle:
    def __init__(self, records):
        self.records = records

    async def lookup(self, name, rtype):
        return self.records.get((name, rtype), [])


class NewStyle:
    async def query(self, name, rtype):
        return DnsAnswer("nxdomain")


async def test_lookup_status_works_with_old_and_new_resolvers():
    old = OldStyle({("a.example.com", "A"): ["192.0.2.1"]})
    assert await lookup_status(old, "a.example.com", "A") == DnsAnswer("answer", ("192.0.2.1",))
    assert await lookup_status(old, "b.example.com", "A") == DnsAnswer("empty")  # unknown why: never a negative
    assert await lookup_status(NewStyle(), "b.example.com", "A") == DnsAnswer("nxdomain")
