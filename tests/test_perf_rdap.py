"""v0.7 task 2: RDAP answers about a whole network, so an address inside a network already looked up in
this scan cites that record instead of asking again. 50 addresses of owasp.org are in 20 networks."""

import httpx
import respx

from scrutator.model import Entity, EntityType
from scrutator.modules.base import ModuleContext
from scrutator.modules.rdap import Rdap


def ip(value):
    return Entity(type=EntityType.IP, value=value)


def network(start, end, name="NET-EXAMPLE", handle="NET-1"):
    return {"handle": handle, "name": name, "startAddress": start, "endAddress": end, "ipVersion": "v4" if "." in start else "v6", "country": "US"}


async def test_an_address_inside_a_network_already_looked_up_cites_that_record(http):
    ctx = ModuleContext(http=http, resolver=None)
    with respx.mock(assert_all_called=False) as router:
        first = router.get("https://rdap.org/ip/198.51.100.7").mock(return_value=httpx.Response(200, json=network("198.51.100.0", "198.51.100.255")))
        other = router.get("https://rdap.org/ip/198.51.100.200").mock(return_value=httpx.Response(500))
        a = await Rdap().run(ip("198.51.100.7"), ctx)
        b = await Rdap().run(ip("198.51.100.200"), ctx)
    assert first.call_count == 1 and other.call_count == 0
    assert [(o.rel, o.entity.value) for o in a] == [(o.rel, o.entity.value) for o in b] == [("netblock_owner", "NET-EXAMPLE")]
    assert a[0].evidence.id == b[0].evidence.id  # the second edge rests on the record that contains its address
    assert a[0].evidence.request == "GET https://rdap.org/ip/198.51.100.7"


async def test_an_address_outside_every_known_network_is_looked_up(http):
    ctx = ModuleContext(http=http, resolver=None)
    with respx.mock(assert_all_called=False) as router:
        router.get("https://rdap.org/ip/198.51.100.7").mock(return_value=httpx.Response(200, json=network("198.51.100.0", "198.51.100.255")))
        second = router.get("https://rdap.org/ip/203.0.113.9").mock(return_value=httpx.Response(200, json=network("203.0.113.0", "203.0.113.255", "NET-TWO", "NET-2")))
        await Rdap().run(ip("198.51.100.7"), ctx)
        out = await Rdap().run(ip("203.0.113.9"), ctx)
    assert second.call_count == 1 and out[0].entity.value == "NET-TWO"


async def test_ipv6_networks_are_covered_too_and_versions_never_mix(http):
    ctx = ModuleContext(http=http, resolver=None)
    with respx.mock(assert_all_called=False) as router:
        router.get("https://rdap.org/ip/2001:db8::1").mock(return_value=httpx.Response(200, json=network("2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "NET6")))
        v4 = router.get("https://rdap.org/ip/192.0.2.1").mock(return_value=httpx.Response(200, json=network("192.0.2.0", "192.0.2.255", "NET4", "N4")))
        inside = router.get("https://rdap.org/ip/2001:db8:0:5::9").mock(return_value=httpx.Response(500))
        await Rdap().run(ip("2001:db8::1"), ctx)
        covered = await Rdap().run(ip("2001:db8:0:5::9"), ctx)
        other = await Rdap().run(ip("192.0.2.1"), ctx)
    assert inside.call_count == 0 and covered[0].entity.value == "NET6"
    assert v4.call_count == 1 and other[0].entity.value == "NET4"


async def test_a_record_without_a_usable_range_covers_nothing(http):
    ctx = ModuleContext(http=http, resolver=None)
    with respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=r"https://rdap.org/ip/.*").mock(return_value=httpx.Response(200, json={"name": "NO-RANGE", "startAddress": "garbage", "endAddress": "198.51.100.255"}))
        await Rdap().run(ip("198.51.100.7"), ctx)
        await Rdap().run(ip("198.51.100.8"), ctx)
    assert route.call_count == 2


async def test_a_network_without_an_owner_name_is_remembered_as_empty(http):
    ctx = ModuleContext(http=http, resolver=None)
    with respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=r"https://rdap.org/ip/.*").mock(return_value=httpx.Response(200, json={"startAddress": "198.51.100.0", "endAddress": "198.51.100.255"}))
        assert await Rdap().run(ip("198.51.100.7"), ctx) == []
        assert await Rdap().run(ip("198.51.100.8"), ctx) == []
    assert route.call_count == 1


async def test_a_failed_lookup_is_not_remembered(http):
    ctx = ModuleContext(http=http, resolver=None)
    with respx.mock(assert_all_called=False) as router:
        router.get("https://rdap.org/ip/198.51.100.7").mock(side_effect=[httpx.Response(404), httpx.Response(200, json=network("198.51.100.0", "198.51.100.255"))])
        assert await Rdap().run(ip("198.51.100.7"), ctx) == []
        again = await Rdap().run(ip("198.51.100.7"), ctx)
    assert again and again[0].entity.value == "NET-EXAMPLE"


def test_the_scan_context_has_a_place_for_in_scan_memory():
    ctx = ModuleContext(http=None, resolver=None)
    assert ctx.cache == {} and ModuleContext(http=None, resolver=None).cache is not ctx.cache


def test_the_rate_limited_services_are_asked_within_their_documented_limits():
    from scrutator.modules.asn import Asn
    from scrutator.modules.ripestat import RipeStat

    assert Asn.concurrency == RipeStat.concurrency == 8 and Asn.rate_group == RipeStat.rate_group
    assert Rdap.concurrency == 4  # rdap.org throttles harder than that


async def test_neighbouring_addresses_asked_at_the_same_moment_still_share_one_lookup(http):
    import asyncio

    ctx = ModuleContext(http=http, resolver=None)
    with respx.mock(assert_all_called=False) as router:
        async def slow(request):
            await asyncio.sleep(0.05)
            return httpx.Response(200, json=network("198.51.100.0", "198.51.100.255"))

        route = router.get(url__regex=r"https://rdap.org/ip/198\.51\.100\..*").mock(side_effect=slow)
        outcomes = await asyncio.gather(*(Rdap().run(ip(f"198.51.100.{n}"), ctx) for n in range(1, 9)))
    assert route.call_count == 1  # seven of the eight waited for the first answer and cited it
    assert all(o[0].entity.value == "NET-EXAMPLE" for o in outcomes)


async def test_addresses_in_different_ranges_are_not_held_up_by_each_other(http):
    import asyncio
    import time

    ctx = ModuleContext(http=http, resolver=None)
    with respx.mock(assert_all_called=False) as router:
        async def slow(request):
            await asyncio.sleep(0.2)
            start = request.url.path.rsplit("/", 1)[1]
            return httpx.Response(200, json=network(start, start, f"NET-{start}", start))

        router.get(url__regex=r"https://rdap.org/ip/.*").mock(side_effect=slow)
        begun = time.monotonic()
        await asyncio.gather(*(Rdap().run(ip(f"10.{n}.0.1"), ctx) for n in range(1, 7)))
    assert time.monotonic() - begun < 0.6  # six lookups in parallel, not 1.2 s one after the other
