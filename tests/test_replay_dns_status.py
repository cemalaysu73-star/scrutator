import pytest

from scrutator.bundle.replay import parse_request, replay_evidence
from scrutator.resolver import DnsAnswer


@pytest.mark.parametrize(
    "request_text, expected",
    [
        ("DNS CAA example.com", ("dns", "CAA", "example.com")),
        ("DNS TXT _dmarc.Example.COM.", ("dns", "TXT", "_dmarc.example.com")),
    ],
)
def test_caa_and_underscore_names_are_replayable(request_text, expected):
    assert parse_request(request_text) == expected


@pytest.mark.parametrize("request_text", ["DNS SOA example.com", "DNS ANY example.com", "DNS AXFR example.com", "DNS CAA "])
def test_other_record_types_are_still_refused(request_text):
    assert parse_request(request_text) is None


class Resolver:
    def __init__(self, answer):
        self.answer, self.calls = answer, []

    async def query(self, name, rtype):
        self.calls.append((name, rtype))
        return self.answer


def record(request, payload):
    return {"id": "x" * 64, "source": "dns", "request": request, "payload": payload, "collected_at": "t"}


async def test_a_recorded_nxdomain_is_unchanged_while_the_name_still_does_not_exist(http):
    rec = record("DNS A ghost.example.com", "NXDOMAIN")
    same = (await replay_evidence([rec], http, Resolver(DnsAnswer("nxdomain"))))[0]
    assert same.status == "unchanged"
    appeared = (await replay_evidence([rec], http, Resolver(DnsAnswer("answer", ("192.0.2.9",)))))[0]
    assert appeared.status == "changed"


async def test_a_recorded_answer_changes_when_the_name_disappears(http):
    rec = record("DNS A www.example.com", "192.0.2.1")
    gone = (await replay_evidence([rec], http, Resolver(DnsAnswer("nxdomain"))))[0]
    assert gone.status == "changed"


async def test_nodata_and_caa_replay(http):
    rec = record("DNS CAA example.com", "NODATA")
    resolver = Resolver(DnsAnswer("nodata"))
    assert (await replay_evidence([rec], http, resolver))[0].status == "unchanged"
    assert resolver.calls == [("example.com", "CAA")]
