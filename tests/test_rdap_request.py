import httpx
import respx

from scrutator.bundle.replay import parse_request
from scrutator.model import Entity, EntityType
from scrutator.modules.rdap import Rdap


async def test_the_recorded_request_is_the_one_made_not_the_redirect_target(make_ctx):
    entity = Entity(type=EntityType.DOMAIN, value="example.com")
    with respx.mock() as router:
        router.get("https://rdap.org/domain/example.com").mock(
            return_value=httpx.Response(302, headers={"location": "https://rdap.verisign.com/com/v1/domain/example.com"})
        )
        router.get("https://rdap.verisign.com/com/v1/domain/example.com").mock(
            return_value=httpx.Response(200, json={"ldhName": "EXAMPLE.COM", "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}]})
        )
        observations = await Rdap().run(entity, make_ctx())
    assert observations
    request = observations[0].evidence.request
    assert request == "GET https://rdap.org/domain/example.com"
    assert parse_request(request) == ("http", "https://rdap.org/domain/example.com")
