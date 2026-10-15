import httpx
import pytest
import respx

from scrutator.bundle.replay import ALLOWED_HTTP_HOSTS, parse_request, replay_evidence


@pytest.mark.parametrize(
    "request_text, expected",
    [
        ("GET https://crt.sh/?q=%25.example.com&output=json", ("http", "https://crt.sh/?q=%25.example.com&output=json")),
        ("GET https://rdap.org/domain/example.com", ("http", "https://rdap.org/domain/example.com")),
        ("DNS A www.example.com", ("dns", "A", "www.example.com")),
        ("DNS TXT Example.COM.", ("dns", "TXT", "example.com")),
    ],
)
def test_parse_request_accepts_known_shapes(request_text, expected):
    assert parse_request(request_text) == expected


@pytest.mark.parametrize(
    "request_text",
    [
        "GET http://crt.sh/",  # not https
        "GET https://evil.example/steal",  # not an allowlisted source
        "GET https://crt.sh.evil.example/",  # look-alike host
        "GET https://user:pw@crt.sh/",  # userinfo
        "GET https://crt.sh:8443/",  # unexpected port
        "GET http://169.254.169.254/latest/meta-data/",
        "GET https://localhost/",
        "GET file:///etc/passwd",
        "POST https://crt.sh/",
        "DNS AXFR example.com",
        "DNS A not a host",
        "DNS A ",
        "",
    ],
)
def test_parse_request_refuses_everything_else(request_text):
    assert parse_request(request_text) is None


def test_allowlist_is_exactly_the_sources_the_modules_use():
    assert ALLOWED_HTTP_HOSTS == {"crt.sh", "rdap.org", "stat.ripe.net", "web.archive.org", "index.commoncrawl.org"}


class Resolver:
    def __init__(self, answers=None, boom=None):
        self.answers, self.boom, self.calls = answers or {}, boom, []

    async def lookup(self, name, rtype):
        self.calls.append((name, rtype))
        if self.boom:
            raise self.boom
        return self.answers.get((name, rtype), [])


def record(request, payload, source="crtsh"):
    return {"id": "x" * 64, "source": source, "request": request, "payload": payload, "collected_at": "t"}


async def test_http_records_are_unchanged_changed_or_unavailable(http):
    records = [
        record("GET https://crt.sh/a", '[{"x": 1}]'),
        record("GET https://crt.sh/b", '[{"x": 1}]'),
        record("GET https://crt.sh/c", "old"),
        record("GET https://crt.sh/d", "old"),
    ]
    with respx.mock() as router:
        router.get("https://crt.sh/a").mock(return_value=httpx.Response(200, text='[{"x": 1}]'))
        router.get("https://crt.sh/b").mock(return_value=httpx.Response(200, text='[ {"x":1} ]'))  # same JSON
        router.get("https://crt.sh/c").mock(return_value=httpx.Response(200, text="new"))
        router.get("https://crt.sh/d").mock(return_value=httpx.Response(503))
        results = await replay_evidence(records, http, Resolver())
    assert [r.status for r in results] == ["unchanged", "unchanged", "changed", "unavailable"]
    assert "503" in results[3].detail


async def test_dns_records_compare_as_sets_and_errors_are_unavailable(http):
    same = Resolver({("www.example.com", "A"): ["192.0.2.2", "192.0.2.1"]})
    rec = record("DNS A www.example.com", "192.0.2.1\n192.0.2.2", source="dns")
    assert (await replay_evidence([rec], http, same))[0].status == "unchanged"
    moved = Resolver({("www.example.com", "A"): ["192.0.2.9"]})
    assert (await replay_evidence([rec], http, moved))[0].status == "changed"
    gone = Resolver({})
    assert (await replay_evidence([rec], http, gone))[0].status == "changed"
    broken = Resolver(boom=TimeoutError("slow"))
    result = (await replay_evidence([rec], http, broken))[0]
    assert result.status == "unavailable" and "TimeoutError" in result.detail


async def test_hostile_requests_are_skipped_and_never_sent(http):
    records = [
        record("GET http://169.254.169.254/latest/meta-data/", "x"),
        record("GET https://evil.example/", "x"),
        record("DNS AXFR example.com", "x", source="dns"),
    ]
    resolver = Resolver()
    with respx.mock(assert_all_mocked=True) as router:
        results = await replay_evidence(records, http, resolver)
        assert not router.calls
    assert [r.status for r in results] == ["skipped"] * 3
    assert resolver.calls == []
