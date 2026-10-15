import httpx
import pytest
import respx

from scrutator.model import Entity, EntityType
from scrutator.modules.base import ModuleError
from scrutator.modules.wayback import Wayback

URL = "https://web.archive.org/cdx/search/cdx"
SEED = Entity(type=EntityType.DOMAIN, value="example.com")


async def test_extracts_archived_hosts(make_ctx):
    rows = [
        ["original"],
        ["http://blog.example.com/a"],
        ["https://blog.example.com/b"],
        ["http://old.example.com/"],
        ["http://1.2.3.4/x"],
        ["http://example.com/"],
    ]
    with respx.mock() as router:
        router.get(URL).mock(return_value=httpx.Response(200, json=rows))
        obs = await Wayback().run(SEED, make_ctx())
    assert [(o.entity.value, o.rel) for o in obs] == [
        ("blog.example.com", "has_subdomain"),
        ("old.example.com", "has_subdomain"),
    ]
    blog = obs[0]
    assert "http://blog.example.com/a" in blog.evidence.payload
    assert "https://blog.example.com/b" in blog.evidence.payload
    assert blog.evidence.source == "wayback"


async def test_empty_result(make_ctx):
    with respx.mock() as router:
        router.get(URL).mock(return_value=httpx.Response(200, json=[]))
        assert await Wayback().run(SEED, make_ctx()) == []


async def test_http_error_raises(make_ctx):
    with respx.mock() as router:
        router.get(URL).mock(return_value=httpx.Response(503))
        with pytest.raises(ModuleError):
            await Wayback().run(SEED, make_ctx())
