"""R4 A3: a bundle is untrusted, and `verify --replay` acts on what it holds. The scope and the host lists bound *where*
a replay may go; these tests bound *how much*: a hostile bundle with a million records must not turn the verifier into
an hours-long request loop against the public sources or the resolver."""

import httpx
import respx

from scrutator.bundle.replay import MAX_HTTP_REQUESTS, MAX_RECORDS, replay_evidence


class Resolver:
    def __init__(self):
        self.asked = []

    async def lookup(self, name, rtype):
        self.asked.append(name)
        return []


async def test_a_replay_looks_up_at_most_the_record_limit_and_says_what_it_left_out():
    records = [{"id": str(i), "source": "dns", "request": f"DNS A h{i}.example.com", "payload": "NXDOMAIN"} for i in range(50)]
    resolver = Resolver()
    async with httpx.AsyncClient() as http:
        results = await replay_evidence(records, http, resolver, subject={"example.com"}, max_records=10)
    assert len(resolver.asked) == 10
    assert [r.status for r in results].count("skipped") == 40
    assert all("replay limit" in r.detail for r in results if r.status == "skipped")


async def test_a_replay_sends_at_most_the_http_limit_of_distinct_requests():
    records = [{"id": str(i), "source": "crtsh", "request": f"GET https://crt.sh/?q=h{i}.example.com&output=json", "payload": "[]"} for i in range(30)]
    with respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=r"https://crt\.sh/.*").mock(return_value=httpx.Response(200, text="[]"))
        async with httpx.AsyncClient() as http:
            results = await replay_evidence(records, http, Resolver(), max_http=5)
    assert route.call_count == 5
    assert [r.status for r in results].count("skipped") == 25


async def test_the_default_limits_are_large_enough_for_a_big_honest_scan_and_finite():
    assert 5000 <= MAX_RECORDS <= 100_000 and 500 <= MAX_HTTP_REQUESTS <= 10_000
