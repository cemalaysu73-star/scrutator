import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.resolver
import dns.rrset
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


def _empty_noerror(*authority):
    """A NOERROR response with an empty answer section and the given authority records,
    each given as (owner, type, rdata text)."""
    query = dns.message.make_query("dev.example.com.", "A")
    response = dns.message.make_response(query)
    response.set_rcode(dns.rcode.NOERROR)
    for owner, rtype, rdata in authority:
        response.authority.append(dns.rrset.from_text(owner, 300, "IN", rtype, rdata))
    return response


async def _query_with(monkeypatch, response):
    resolver = DnsResolver()

    async def boom(name, rtype):
        raise dns.resolver.NoAnswer(response=response)

    monkeypatch.setattr(resolver._resolver, "resolve", boom)
    return await resolver.query("dev.example.com", "A")


NXNAME_NSEC = ("dev.example.com.", "NSEC", "\000.dev.example.com. RRSIG NSEC TYPE128")
PLAIN_NSEC = ("example.com.", "NSEC", "www.example.com. A NS SOA MX TXT AAAA RRSIG NSEC DNSKEY")
SOA = ("example.com.", "SOA", "ns.example.com. host.example.com. 1 7200 3600 1209600 300")


async def test_compact_denial_of_existence_is_nxdomain(monkeypatch):
    # NOERROR, empty answer, NSEC whose bitmap carries the NXNAME pseudo-type (128)
    answer = await _query_with(monkeypatch, _empty_noerror(NXNAME_NSEC))
    assert answer == DnsAnswer("nxdomain")
    assert answer.negative and answer.payload() == "NXDOMAIN"


async def test_nodata_for_an_existing_name_stays_nodata(monkeypatch):
    # the NSEC proves the type is absent from an existing name: its bitmap has no NXNAME
    assert (await _query_with(monkeypatch, _empty_noerror(PLAIN_NSEC))).status == "nodata"


async def test_noerror_empty_without_nsec_is_nodata(monkeypatch):
    assert (await _query_with(monkeypatch, _empty_noerror())).status == "nodata"
    assert (await _query_with(monkeypatch, _empty_noerror(SOA))).status == "nodata"


async def test_a_real_nxdomain_rcode_is_still_nxdomain(monkeypatch):
    resolver = DnsResolver()

    async def boom(name, rtype):
        raise dns.resolver.NXDOMAIN(qnames=[dns.name.from_text("dev.example.com.")], responses={})

    monkeypatch.setattr(resolver._resolver, "resolve", boom)
    assert await resolver.query("dev.example.com", "A") == DnsAnswer("nxdomain")


def test_the_resolver_sets_the_dnssec_ok_bit():
    # recursive resolvers send the NSEC proof (and so the NXNAME marker) only to DO queries
    resolver = DnsResolver()
    assert resolver._resolver.ednsflags & dns.flags.DO
