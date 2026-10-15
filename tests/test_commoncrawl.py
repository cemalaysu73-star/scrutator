import httpx
import pytest
import respx

from scrutator.model import Entity, EntityType
from scrutator.modules.base import ModuleError
from scrutator.modules.commoncrawl import CommonCrawl

COLLINFO = "https://index.commoncrawl.org/collinfo.json"
CDX = "https://index.commoncrawl.org/CC-MAIN-2026-10-index"
SEED = Entity(type=EntityType.DOMAIN, value="example.com")
INDEXES = [
    {"id": "CC-MAIN-2026-10", "cdx-api": CDX},
    {"id": "CC-MAIN-2025-50", "cdx-api": "https://index.commoncrawl.org/CC-MAIN-2025-50-index"},
]


async def test_extracts_hosts_from_latest_index(make_ctx):
    body = (
        '{"url": "http://shop.example.com/p"}\n'
        "this line is not json\n"
        '{"url": "https://shop.example.com/q"}\n'
        '{"url": "http://example.com/"}\n'
    )
    with respx.mock() as router:
        router.get(COLLINFO).mock(return_value=httpx.Response(200, json=INDEXES))
        router.get(CDX).mock(return_value=httpx.Response(200, text=body))
        obs = await CommonCrawl().run(SEED, make_ctx())
    assert [(o.entity.value, o.rel) for o in obs] == [("shop.example.com", "has_subdomain")]
    assert "http://shop.example.com/p" in obs[0].evidence.payload
    assert obs[0].evidence.source == "commoncrawl"


async def test_no_captures_is_empty(make_ctx):
    with respx.mock() as router:
        router.get(COLLINFO).mock(return_value=httpx.Response(200, json=INDEXES))
        router.get(CDX).mock(return_value=httpx.Response(404, text="No Captures found"))
        assert await CommonCrawl().run(SEED, make_ctx()) == []


async def test_missing_index_list_raises(make_ctx):
    with respx.mock() as router:
        router.get(COLLINFO).mock(return_value=httpx.Response(200, json=[]))
        with pytest.raises(ModuleError):
            await CommonCrawl().run(SEED, make_ctx())
