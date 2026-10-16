import httpx
import pytest
import respx

from scrutator.model import Entity, EntityType
from scrutator.modules._names import usable_org
from scrutator.modules.rdap import Rdap


def card(*items):
    return ["vcard", [["version", {}, "text", "4.0"], *[[name, {}, "text", value] for name, value in items]]]


def body(*entities):
    return {"ldhName": "EXAMPLE.COM", "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}], "entities": list(entities)}


def pairs(observations):
    return {(o.rel, o.entity.type.value, o.entity.value) for o in observations}


async def lookup(make_ctx, payload):
    with respx.mock() as router:
        router.get("https://rdap.org/domain/example.com").mock(return_value=httpx.Response(200, json=payload))
        return await Rdap().run(Entity(type=EntityType.DOMAIN, value="example.com"), make_ctx())


async def test_a_published_registrant_organisation_becomes_a_relation(make_ctx):
    obs = await lookup(make_ctx, body({"roles": ["registrant"], "vcardArray": card(("fn", "Example Holdings Ltd"))}))
    assert ("registrant", "org", "Example Holdings Ltd") in pairs(obs)
    assert all(o.evidence.source == "rdap" for o in obs)


async def test_the_org_property_is_used_when_there_is_no_name(make_ctx):
    obs = await lookup(make_ctx, body({"roles": ["registrant"], "vcardArray": card(("org", "Example Holdings Ltd"))}))
    assert ("registrant", "org", "Example Holdings Ltd") in pairs(obs)


@pytest.mark.parametrize(
    "value",
    ["REDACTED FOR PRIVACY", "Data Protected", "Domains By Proxy, LLC", "WhoisGuard Protected", "Contact Privacy Inc.", "withheld for privacy", "N/A", "", "x"],
)
async def test_redacted_and_placeholder_registrants_are_not_recorded(make_ctx, value):
    obs = await lookup(make_ctx, body({"roles": ["registrant"], "vcardArray": card(("fn", value))}))
    assert not [o for o in obs if o.rel == "registrant"]
    assert ("ns", "domain", "ns1.example.com") in pairs(obs)


async def test_only_the_registrant_role_counts(make_ctx):
    obs = await lookup(make_ctx, body({"roles": ["technical"], "vcardArray": card(("fn", "Example Holdings Ltd"))}))
    assert not [o for o in obs if o.rel == "registrant"]


def test_usable_org_cleans_whitespace_and_rejects_placeholders():
    assert usable_org("  Example   Holdings  Ltd ") == "Example Holdings Ltd"
    assert usable_org("REDACTED FOR PRIVACY") is None
    assert usable_org(None) is None and usable_org(42) is None
