import httpx
import pytest
import respx

from scrutator.model import Entity, EntityType
from scrutator.modules.base import ModuleError
from scrutator.modules.rdap import Rdap

DOMAIN_RDAP = {
    "ldhName": "EXAMPLE.COM",
    "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}, {"ldhName": "B.IANA-SERVERS.NET"}],
    "entities": [
        {
            "roles": ["registrar"],
            "vcardArray": [
                "vcard",
                [["version", {}, "text", "4.0"], ["fn", {}, "text", "RESERVED-Internet Assigned Numbers Authority"]],
            ],
        },
        {"roles": ["abuse"], "vcardArray": ["vcard", [["fn", {}, "text", "Abuse Desk"]]]},
    ],
}
IP_RDAP = {"handle": "NET-93-184-216-0-1", "name": "EDGECAST-NETBLK-03", "country": "EU"}


def pairs(observations):
    return {(o.rel, o.entity.type.value, o.entity.value) for o in observations}


async def test_domain_registration(make_ctx):
    with respx.mock() as router:
        router.get("https://rdap.org/domain/example.com").mock(return_value=httpx.Response(200, json=DOMAIN_RDAP))
        obs = await Rdap().run(Entity(type=EntityType.DOMAIN, value="example.com"), make_ctx())
    assert pairs(obs) == {
        ("ns", "domain", "a.iana-servers.net"),
        ("ns", "domain", "b.iana-servers.net"),
        ("registrar", "org", "RESERVED-Internet Assigned Numbers Authority"),
    }
    assert all(o.evidence.source == "rdap" for o in obs)


async def test_ip_network_owner(make_ctx):
    with respx.mock() as router:
        # R6: a public address is asked of the registry that holds it (93/8 is RIPE NCC's), not through rdap.org
        router.get("https://rdap.db.ripe.net/ip/93.184.216.34").mock(return_value=httpx.Response(200, json=IP_RDAP))
        obs = await Rdap().run(Entity(type=EntityType.IP, value="93.184.216.34"), make_ctx())
    assert pairs(obs) == {("netblock_owner", "org", "EDGECAST-NETBLK-03")}


async def test_not_found_is_empty(make_ctx):
    with respx.mock() as router:
        router.get("https://rdap.org/domain/www.example.com").mock(return_value=httpx.Response(404))
        obs = await Rdap().run(Entity(type=EntityType.DOMAIN, value="www.example.com"), make_ctx())
    assert obs == []


async def test_server_error_raises(make_ctx):
    with respx.mock() as router:
        router.get("https://rdap.org/domain/example.com").mock(return_value=httpx.Response(500))
        with pytest.raises(ModuleError):
            await Rdap().run(Entity(type=EntityType.DOMAIN, value="example.com"), make_ctx())
