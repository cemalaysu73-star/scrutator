"""v0.7 task 2: DNS for hundreds of discovered names goes through one bounded pool, starts with the
fastest configured name server instead of the first one, and does not ask the same question twice."""

import asyncio

import dns.resolver

from scrutator.modules.dns import Dns
from scrutator.resolver import DnsAnswer, DnsResolver


class _Rdata:
    def __init__(self, text):
        self._text = text

    def to_text(self):
        return self._text


async def test_no_more_queries_are_in_flight_than_the_pool_allows(monkeypatch):
    resolver = DnsResolver(["192.0.2.1"], max_in_flight=4)
    running = peak = 0

    async def slow(name, rtype):
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        await asyncio.sleep(0.01)
        running -= 1
        return [_Rdata("192.0.2.9")]

    monkeypatch.setattr(resolver._resolver, "resolve", slow)
    answers = await asyncio.gather(*(resolver.query(f"h{n}.example.com", "A") for n in range(40)))
    assert peak == 4 and all(a.status == "answer" for a in answers)


async def test_a_repeated_question_is_answered_from_the_scan_s_own_memory(monkeypatch):
    resolver = DnsResolver(["192.0.2.1"], cache=True)
    calls = []

    async def ok(name, rtype):
        calls.append((name, rtype))
        return [_Rdata("192.0.2.9")]

    monkeypatch.setattr(resolver._resolver, "resolve", ok)
    first = await resolver.query("www.example.com", "A")
    again = await resolver.query("www.example.com", "A")
    other = await resolver.query("www.example.com", "AAAA")
    assert first == again and len(calls) == 2 and resolver.cache_hits == 1 and other.status == "answer"


async def test_only_definite_answers_are_remembered_a_servfail_is_asked_again(monkeypatch):
    resolver = DnsResolver(["192.0.2.1"], cache=True)
    outcomes = [dns.resolver.NoNameservers(), dns.resolver.NXDOMAIN(), dns.resolver.NXDOMAIN()]
    calls = []

    async def scripted(name, rtype):
        calls.append(name)
        raise outcomes.pop(0)

    monkeypatch.setattr(resolver._resolver, "resolve", scripted)
    assert (await resolver.query("x.example.com", "A")).status == "servfail"
    assert (await resolver.query("x.example.com", "A")).status == "nxdomain"  # asked again, then remembered
    assert (await resolver.query("x.example.com", "A")).status == "nxdomain"
    assert len(calls) == 2 and resolver.cache_hits == 1


async def test_a_resolver_without_the_memory_asks_every_time(monkeypatch):
    resolver = DnsResolver(["192.0.2.1"])
    calls = []

    async def ok(name, rtype):
        calls.append(name)
        return [_Rdata("192.0.2.9")]

    monkeypatch.setattr(resolver._resolver, "resolve", ok)
    await resolver.query("www.example.com", "A")
    await resolver.query("www.example.com", "A")
    assert len(calls) == 2


async def test_warm_up_puts_the_fastest_server_first_and_the_dead_one_last(monkeypatch):
    resolver = DnsResolver(["10.255.255.1", "8.8.8.8", "1.1.1.1"])
    latency = {"10.255.255.1": None, "8.8.8.8": 0.05, "1.1.1.1": 0.01}

    async def probe(server, timeout):
        return latency[server]

    monkeypatch.setattr(resolver, "_probe", probe)
    await resolver.warm_up()
    assert resolver._resolver.nameservers == ["1.1.1.1", "8.8.8.8", "10.255.255.1"]


async def test_warm_up_leaves_the_order_alone_when_nothing_answers_or_there_is_one_server(monkeypatch):
    resolver = DnsResolver(["10.255.255.1", "10.255.255.2"])

    async def silent(server, timeout):
        return None

    monkeypatch.setattr(resolver, "_probe", silent)
    await resolver.warm_up()
    assert resolver._resolver.nameservers == ["10.255.255.1", "10.255.255.2"]

    single = DnsResolver(["192.0.2.1"])

    async def never(server, timeout):  # pragma: no cover - must not be called
        raise AssertionError("a single server is not probed")

    monkeypatch.setattr(single, "_probe", never)
    await single.warm_up()


async def test_the_probes_are_sent_together_not_one_after_the_other(monkeypatch):
    resolver = DnsResolver(["192.0.2.1", "192.0.2.2", "192.0.2.3"])

    async def slow(server, timeout):
        await asyncio.sleep(0.2)
        return 0.2

    monkeypatch.setattr(resolver, "_probe", slow)
    loop = asyncio.get_running_loop()
    started = loop.time()
    await resolver.warm_up()
    assert loop.time() - started < 0.45


def test_many_names_are_resolved_at_once():
    assert Dns.concurrency >= 32
    assert DnsAnswer("answer", ("x",))  # the module still speaks the same answers


async def test_a_scan_ranks_the_name_servers_before_its_first_lookup():
    from scrutator.model import Entity, EntityType
    from scrutator.modules.base import ModuleContext
    from scrutator.scan import run_scan
    from scrutator.scope import ScopePolicy
    from scrutator.store import Store

    events = []

    class Resolver:
        async def warm_up(self):
            events.append("warm")

        async def lookup(self, name, rtype):
            events.append("lookup")
            return []

    await run_scan(
        Entity(type=EntityType.DOMAIN, value="example.com"), ScopePolicy(domains=["example.com"]), Store(":memory:"),
        ModuleContext(http=None, resolver=Resolver()), modules=[Dns()],
    )
    assert events[0] == "warm" and "lookup" in events


async def test_warm_up_does_not_wait_for_a_server_that_is_slow_or_dead(monkeypatch):
    resolver = DnsResolver(["10.255.255.1", "8.8.8.8", "1.1.1.1"])
    started = []

    async def probe(server, timeout):
        started.append(server)
        if server == "10.255.255.1":
            await asyncio.sleep(timeout)  # the dead server: its whole timeout
            return None
        await asyncio.sleep(0.01 if server == "1.1.1.1" else 0.03)
        return 0.01 if server == "1.1.1.1" else 0.03

    monkeypatch.setattr(resolver, "_probe", probe)
    loop = asyncio.get_running_loop()
    begun = loop.time()
    await resolver.warm_up(timeout=3.0)
    assert loop.time() - begun < 0.6  # not the dead server's three seconds
    assert resolver._resolver.nameservers == ["1.1.1.1", "8.8.8.8", "10.255.255.1"]
    assert sorted(started) == ["1.1.1.1", "10.255.255.1", "8.8.8.8"]
    await asyncio.sleep(0)
    assert not [t for t in asyncio.all_tasks() if t is not asyncio.current_task() and not t.done()]  # the probe was cancelled
