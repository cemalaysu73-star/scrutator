import httpx
import respx

from scrutator.model import Entity, EntityType
from scrutator.modules.base import Fact, Observation
from scrutator.modules.rdap import Rdap

EVENTS_ONLY = {"ldhName": "EXAMPLE.COM", "events": [{"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"}]}
WITH_NAME_SERVERS = {**EVENTS_ONLY, "nameservers": [{"ldhName": "NS1.DNS.EXAMPLE.NET"}]}
DOMAIN = Entity(type=EntityType.DOMAIN, value="example.com")


async def run(payload, make_ctx, entity=DOMAIN, url="https://rdap.org/domain/example.com"):
    with respx.mock() as router:
        router.get(url).mock(return_value=httpx.Response(200, json=payload))
        return await Rdap().run(entity, make_ctx())


async def test_registration_dates_are_kept_even_when_there_is_no_relation_to_record(make_ctx):
    (item,) = await run(EVENTS_ONLY, make_ctx)
    assert isinstance(item, Fact)
    assert item.evidence.request == "GET https://rdap.org/domain/example.com"
    assert "2027-08-13T04:00:00Z" in item.evidence.payload


async def test_a_response_that_yields_relations_is_cited_by_them_not_duplicated_as_a_fact(make_ctx):
    items = await run(WITH_NAME_SERVERS, make_ctx)
    assert [type(i) for i in items] == [Observation]


async def test_an_ip_without_an_owner_still_yields_nothing(make_ctx):
    ip = Entity(type=EntityType.IP, value="192.0.2.1")
    assert await run({"handle": "NET-1"}, make_ctx, ip, "https://rdap.org/ip/192.0.2.1") == []
