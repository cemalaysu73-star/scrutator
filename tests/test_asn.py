import httpx
import pytest
import respx

from scrutator.model import Entity, EntityType
from scrutator.modules.asn import Asn
from scrutator.modules.base import ModuleError

URL = "https://stat.ripe.net/data/prefix-overview/data.json"
IP = Entity(type=EntityType.IP, value="93.184.216.34")


async def test_maps_ip_to_announcing_asns(make_ctx):
    payload = {"data": {"resource": "93.184.216.0/24", "asns": [{"asn": 15133, "holder": "EDGECAST"}]}}
    with respx.mock() as router:
        router.get(URL).mock(return_value=httpx.Response(200, json=payload))
        obs = await Asn().run(IP, make_ctx())
    assert [(o.rel, o.entity.type.value, o.entity.value) for o in obs] == [("announced_by", "asn", "AS15133")]
    assert "EDGECAST" in obs[0].evidence.payload
    assert obs[0].evidence.source == "asn"


async def test_unannounced_space_is_empty(make_ctx):
    with respx.mock() as router:
        router.get(URL).mock(return_value=httpx.Response(200, json={"data": {"asns": []}}))
        assert await Asn().run(IP, make_ctx()) == []


async def test_http_error_raises(make_ctx):
    with respx.mock() as router:
        router.get(URL).mock(return_value=httpx.Response(500))
        with pytest.raises(ModuleError):
            await Asn().run(IP, make_ctx())
