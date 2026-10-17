import json

import httpx
import pytest
import respx

from scrutator.bundle.replay import parse_request, supports
from scrutator.model import Entity, EntityType
from scrutator.modules.base import ModuleError, SourceUnavailable
from scrutator.modules.certspotter import CertSpotter

SEED = Entity(type=EntityType.DOMAIN, value="example.com")
URL = "https://api.certspotter.com/v1/issuances"

ROW_A = {
    "id": "100",
    "tbs_sha256": "aa",
    "cert_sha256": "4973b4",
    "dns_names": ["example.com", "www.example.com", "*.example.com", "other.net", "user@example.com"],
    "pubkey_sha256": "54d187",
    "issuer": {"friendly_name": "Sectigo", "name": "C=GB, O=Sectigo Limited, CN=Sectigo RSA"},
    "not_before": "2025-11-20T00:00:00Z",
    "not_after": "2026-11-20T23:59:59Z",
    "revoked": False,
}
ROW_B = {
    "id": "101",
    "cert_sha256": "beef01",
    "dns_names": ["api.example.com", "www.example.com"],
    "pubkey_sha256": "99aa",
    "issuer": {"friendly_name": "Let's Encrypt", "name": "C=US, O=Let's Encrypt, CN=R11"},
    "not_before": "2026-01-01T00:00:00Z",
    "not_after": "2026-04-01T00:00:00Z",
    "revoked": True,
}


async def test_names_relations_and_small_evidence_slices(make_ctx):
    with respx.mock() as router:
        router.get(URL).mock(return_value=httpx.Response(200, json=[ROW_A, ROW_B]))
        obs = await CertSpotter().run(SEED, make_ctx())

    assert {(o.entity.value, o.rel) for o in obs} == {
        ("www.example.com", "has_subdomain"),
        ("api.example.com", "has_subdomain"),
        ("other.net", "related_host"),
    }
    www = next(o for o in obs if o.entity.value == "www.example.com")
    assert www.evidence.source == "certspotter"
    assert "api.certspotter.com/v1/issuances" in www.evidence.request and "include_subdomains=true" in www.evidence.request
    rows = json.loads(www.evidence.payload)
    assert [r["id"] for r in rows] == ["100", "101"]  # both certificates name www
    assert all("dns_names" not in r for r in rows)  # the slice, not the certificate's whole name list
    assert rows[1]["revoked"] is True and rows[0]["pubkey_sha256"] == "54d187"
    api = next(o for o in obs if o.entity.value == "api.example.com")
    assert [r["id"] for r in json.loads(api.evidence.payload)] == ["101"]


async def test_the_apex_itself_and_non_hostnames_are_not_reported(make_ctx):
    with respx.mock() as router:
        router.get(URL).mock(return_value=httpx.Response(200, json=[ROW_A]))
        obs = await CertSpotter().run(SEED, make_ctx())
    assert "example.com" not in {o.entity.value for o in obs}
    assert not any("@" in o.entity.value for o in obs)


async def test_a_second_page_is_read_after_the_last_id_and_no_further(make_ctx):
    pages = []

    def handler(request):
        pages.append(dict(request.url.params))
        if "after" not in request.url.params:
            return httpx.Response(200, json=[ROW_A], headers={"Link": '<https://api.certspotter.com/issuances?after=100>; rel="next"'})
        if request.url.params["after"] == "100":
            return httpx.Response(200, json=[ROW_B], headers={"Link": '<https://api.certspotter.com/issuances?after=101>; rel="next"'})
        raise AssertionError("a third page was requested")

    with respx.mock() as router:
        router.get(URL).mock(side_effect=handler)
        obs = await CertSpotter().run(SEED, make_ctx())
    assert [p.get("after") for p in pages] == [None, "100"]
    www_evidence = [o.evidence for o in obs if o.entity.value == "www.example.com"]
    assert len(www_evidence) == 2  # one slice per page it appeared on: each replays against its own request
    assert len({e.request for e in www_evidence}) == 2


async def test_a_page_without_a_next_link_ends_the_walk(make_ctx):
    calls = []
    with respx.mock() as router:
        router.get(URL).mock(side_effect=lambda r: calls.append(1) or httpx.Response(200, json=[ROW_A]))
        await CertSpotter().run(SEED, make_ctx())
    assert len(calls) == 1


async def test_rate_limit_and_server_errors_mean_the_source_is_unavailable(make_ctx):
    for status in (429, 503):
        with respx.mock() as router:
            router.get(URL).mock(return_value=httpx.Response(status))
            with pytest.raises(SourceUnavailable):
                await CertSpotter().run(SEED, make_ctx())


async def test_other_http_errors_and_bad_payloads_are_plain_module_errors(make_ctx):
    with respx.mock() as router:
        router.get(URL).mock(return_value=httpx.Response(400, json={"code": "bad"}))
        with pytest.raises(ModuleError) as caught:
            await CertSpotter().run(SEED, make_ctx())
        assert not isinstance(caught.value, SourceUnavailable)
    for body in (httpx.Response(200, text="<html>"), httpx.Response(200, json={"not": "a list"})):
        with respx.mock() as router:
            router.get(URL).mock(return_value=body)
            with pytest.raises(ModuleError):
                await CertSpotter().run(SEED, make_ctx())


async def test_a_name_that_is_not_in_the_live_answer_any_more_is_not_supported(make_ctx):
    """Replay: the recorded slice must still be present in the live page."""
    with respx.mock() as router:
        router.get(URL).mock(return_value=httpx.Response(200, json=[ROW_A, ROW_B]))
        obs = await CertSpotter().run(SEED, make_ctx())
    www = next(o for o in obs if o.entity.value == "www.example.com").evidence
    live = json.dumps([ROW_A, ROW_B])
    assert supports(www.payload, live)
    assert supports(www.payload, json.dumps([ROW_B, ROW_A]))
    revoked_later = json.dumps([{**ROW_A, "revoked": True}, ROW_B])
    assert not supports(www.payload, revoked_later)  # drift in a recorded fact is reported
    assert parse_request(www.request) == ("http", www.request.removeprefix("GET "))


def test_the_source_is_registered_apex_only_and_documents_its_terms():
    module = CertSpotter()
    assert module.apex_only and module.mode.value == "passive"
    assert "personal" in (module.licence_note or "").lower()
