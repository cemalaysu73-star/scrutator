import asyncio

from scrutator.model import Entity, EntityType
from scrutator.modules.base import ModuleContext
from scrutator.modules.dns import Dns

RECORDS = {
    ("www.example.com", "A"): ["93.184.216.34"],
    ("www.example.com", "AAAA"): ["2606:2800:220:1:248:1893:25c8:1946"],
    ("www.example.com", "CNAME"): ["cdn.example.net."],
    ("example.com", "MX"): ["10 mail.example.com."],
    ("example.com", "NS"): ["a.iana-servers.net.", "b.iana-servers.net."],
    ("example.com", "TXT"): ['"v=spf1 include:_spf.example.net -all"', '"google-site-verification=abc"'],
}


def dom(value):
    return Entity(type=EntityType.DOMAIN, value=value)


def pairs(observations):
    return {(o.rel, o.entity.type.value, o.entity.value) for o in observations}


async def test_address_and_alias_records(make_ctx):
    obs = await Dns().run(dom("www.example.com"), make_ctx(RECORDS))
    assert pairs(obs) == {
        ("resolves_to", "ip", "93.184.216.34"),
        ("resolves_to", "ip", "2606:2800:220:1:248:1893:25c8:1946"),
        ("cname_to", "domain", "cdn.example.net"),
    }
    a = next(o for o in obs if o.entity.value == "93.184.216.34")
    assert a.evidence.request == "DNS A www.example.com"
    assert a.evidence.payload == "93.184.216.34"


async def test_mail_name_server_and_spf_records(make_ctx):
    obs = await Dns().run(dom("example.com"), make_ctx(RECORDS))
    assert pairs(obs) == {
        ("mx", "domain", "mail.example.com"),
        ("ns", "domain", "a.iana-servers.net"),
        ("ns", "domain", "b.iana-servers.net"),
        ("spf_include", "domain", "_spf.example.net"),
    }


async def test_junk_answers_are_ignored(make_ctx):
    records = {
        ("example.com", "A"): ["not-an-ip"],
        ("example.com", "CNAME"): ["."],
        ("example.com", "MX"): ["0 ."],
    }
    assert await Dns().run(dom("example.com"), make_ctx(records)) == []


async def test_no_records_yield_nothing(make_ctx):
    assert await Dns().run(dom("empty.example.com"), make_ctx({})) == []


async def test_the_queries_for_one_name_are_asked_together():
    import time

    from scrutator.resolver import DnsAnswer

    class SlowResolver:
        async def query(self, name, rtype):
            await asyncio.sleep(0.2)
            return DnsAnswer("answer", ("192.0.2.1",)) if rtype == "A" else DnsAnswer("nodata")

    ctx = ModuleContext(http=None, resolver=SlowResolver())
    started = time.monotonic()
    obs = await Dns().run(Entity(type=EntityType.DOMAIN, value="www.example.com"), ctx)
    assert time.monotonic() - started < 0.6  # six queries one after the other would take 1.2 s
    assert [o.entity.value for o in obs if o.rel == "resolves_to"] == ["192.0.2.1"]


def test_the_server_that_answered_is_tried_first_next_time():
    from scrutator.resolver import DnsResolver

    resolver = DnsResolver(["10.255.255.1", "1.1.1.1", "8.8.8.8"])
    resolver._prefer("1.1.1.1")
    assert resolver._resolver.nameservers == ["1.1.1.1", "10.255.255.1", "8.8.8.8"]
    resolver._prefer("1.1.1.1")  # already first: unchanged
    resolver._prefer(None)  # no answering server known: unchanged
    resolver._prefer("9.9.9.9")  # not one of ours: unchanged
    assert resolver._resolver.nameservers == ["1.1.1.1", "10.255.255.1", "8.8.8.8"]
