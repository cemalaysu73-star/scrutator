import json

import httpx
import pytest
import respx

from scrutator.bundle.replay import replay_evidence, supports


def test_equal_text_and_equal_json_are_supported():
    assert supports("abc", "abc")
    assert supports('[{"x": 1}]', '[ {"x":1} ]')
    assert not supports("abc", "abd")


def test_a_dict_response_ignores_volatile_envelope_fields_only():
    old = json.dumps({"data": {"asns": [{"asn": 13335}]}, "time": "t1", "query_id": "q1", "process_time": 113, "server_id": "app1"})
    same_answer = json.dumps({"data": {"asns": [{"asn": 13335}]}, "time": "t2", "query_id": "q2", "process_time": 97, "server_id": "app9"})
    other_answer = json.dumps({"data": {"asns": [{"asn": 64500}]}, "time": "t2", "query_id": "q2", "process_time": 97, "server_id": "app9"})
    assert supports(old, same_answer)
    assert not supports(old, other_answer)


def test_a_recorded_subset_of_a_longer_live_list_is_still_supported():
    # crt.sh evidence keeps only the certificates that mention one hostname
    recorded = json.dumps([{"id": 7, "name_value": "www.example.com", "issuer_name": "LE"}])
    live = json.dumps(
        [
            {"id": 1, "name_value": "a.example.com", "issuer_name": "LE", "serial_number": "x"},
            {"id": 7, "name_value": "www.example.com", "issuer_name": "LE", "serial_number": "y"},
        ]
    )
    assert supports(recorded, live)
    gone = json.dumps([{"id": 1, "name_value": "a.example.com", "issuer_name": "LE"}])
    assert not supports(recorded, gone)
    changed = json.dumps([{"id": 7, "name_value": "www.example.com", "issuer_name": "Other CA"}])
    assert not supports(recorded, changed)


def test_recorded_urls_match_wayback_rows_and_common_crawl_lines():
    recorded = json.dumps(["http://shop.example.com/p"])
    wayback = json.dumps([["original"], ["http://shop.example.com/p"], ["http://shop.example.com/q"]])
    crawl = '{"url": "http://shop.example.com/p"}\n{"url": "http://shop.example.com/q"}\n'
    assert supports(recorded, wayback)
    assert supports(recorded, crawl)
    assert not supports(recorded, json.dumps([["original"], ["http://other.example.com/"]]))
    assert not supports(recorded, '{"url": "http://other.example.com/"}\n')


def test_plain_text_is_supported_when_still_contained_and_empty_lists_need_empty_lists():
    assert supports("192.0.2.1", "answer: 192.0.2.1 ok")
    assert not supports("192.0.2.1", "answer: 192.0.2.9")
    assert not supports("[]", json.dumps([{"id": 1}]))
    assert supports("[]", "[]")


class Resolver:
    async def lookup(self, name, rtype):
        return []


async def test_replay_reports_a_still_supported_subset_as_unchanged(http):
    recorded = json.dumps([{"id": 7, "name_value": "www.example.com"}])
    record = {"id": "x" * 64, "source": "crtsh", "request": "GET https://crt.sh/?q=%25.example.com", "payload": recorded, "collected_at": "t"}
    live = [{"id": n, "name_value": f"h{n}.example.com"} for n in range(5)] + [{"id": 7, "name_value": "www.example.com"}]
    with respx.mock() as router:
        router.get("https://crt.sh/").mock(return_value=httpx.Response(200, json=live))
        (result,) = await replay_evidence([record], http, Resolver())
    assert result.status == "unchanged"
    with respx.mock() as router:
        router.get("https://crt.sh/").mock(return_value=httpx.Response(200, json=live[:3]))
        (result,) = await replay_evidence([record], http, Resolver())
    assert result.status == "changed"
