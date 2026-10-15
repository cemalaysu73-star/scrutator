import httpx
import pytest
import respx

from scrutator.model import Entity, EntityType
from scrutator.modules.base import ModuleError
from scrutator.modules.crtsh import CrtSh

ROWS = [
    {
        "id": 1,
        "issuer_name": "C=US, O=Let's Encrypt",
        "name_value": "example.com\nwww.example.com",
        "not_before": "2026-01-01T00:00:00",
        "not_after": "2026-04-01T00:00:00",
    },
    {
        "id": 2,
        "issuer_name": "C=US, O=Let's Encrypt",
        "name_value": "*.example.com\napi.example.com\nother.net\nuser@example.com",
        "not_before": "2026-02-01T00:00:00",
        "not_after": "2026-05-01T00:00:00",
    },
]

SEED = Entity(type=EntityType.DOMAIN, value="example.com")


async def test_extracts_names_with_relations_and_evidence(make_ctx):
    with respx.mock() as router:
        router.get("https://crt.sh/").mock(return_value=httpx.Response(200, json=ROWS))
        obs = await CrtSh().run(SEED, make_ctx())

    pairs = {(o.entity.value, o.rel) for o in obs}
    assert pairs == {
        ("www.example.com", "has_subdomain"),
        ("api.example.com", "has_subdomain"),
        ("other.net", "related_host"),
    }
    www = next(o for o in obs if o.entity.value == "www.example.com")
    assert www.evidence.source == "crtsh"
    assert '"id": 1' in www.evidence.payload
    assert "crt.sh" in www.evidence.request


async def test_http_error_raises_module_error(make_ctx):
    with respx.mock() as router:
        router.get("https://crt.sh/").mock(return_value=httpx.Response(503))
        with pytest.raises(ModuleError):
            await CrtSh().run(SEED, make_ctx())


async def test_invalid_json_raises_module_error(make_ctx):
    with respx.mock() as router:
        router.get("https://crt.sh/").mock(return_value=httpx.Response(200, text="<html>busy</html>"))
        with pytest.raises(ModuleError):
            await CrtSh().run(SEED, make_ctx())
