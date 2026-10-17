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
    assert ALLOWED_HTTP_HOSTS == {
        "crt.sh", "rdap.org", "stat.ripe.net", "web.archive.org", "index.commoncrawl.org", "api.certspotter.com",
        "api.hackertarget.com", "api.subdomain.center", "urlscan.io", "api.mnemonic.no", "internetdb.shodan.io",
    }


def test_every_host_a_module_contacts_is_replayable_and_nothing_else_is():
    """Read the modules' own source: a module added without an allowlist entry cannot be replayed,
    and an entry no module uses is a hole a hostile bundle could use."""
    import re
    from pathlib import Path

    import scrutator.modules as package

    hosts = set()
    for path in Path(package.__file__).parent.glob("*.py"):
        hosts.update(re.findall(r"https://([a-z0-9.-]+)", path.read_text(encoding="utf-8")))
    # the Common Crawl module gets its index URL from the collection list, not from a literal
    assert hosts | {"index.commoncrawl.org"} == ALLOWED_HTTP_HOSTS


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


async def test_one_request_shared_by_many_records_is_sent_once(http):
    """A name-listing source stores one evidence record per name, all with the same request. Replaying
    them must not send that request once per name (hundreds of identical calls to a free service)."""
    body = '["a.example.com", "b.example.com", "c.example.com"]'
    records = [record("GET https://api.subdomain.center/?domain=example.com", f'["{n}.example.com"]', source="subdomaincenter") for n in "abcx"]
    with respx.mock() as router:
        route = router.get("https://api.subdomain.center/").mock(return_value=httpx.Response(200, text=body))
        results = await replay_evidence(records, http, Resolver())
    assert route.call_count == 1
    assert [r.status for r in results] == ["unchanged", "unchanged", "unchanged", "changed"]


async def test_a_failed_request_is_not_retried_for_every_record_that_shares_it(http):
    records = [record("GET https://crt.sh/z", "[]") for _ in range(5)]
    with respx.mock() as router:
        route = router.get("https://crt.sh/z").mock(return_value=httpx.Response(502))
        results = await replay_evidence(records, http, Resolver())
    assert route.call_count == 1 and {r.status for r in results} == {"unavailable"}
