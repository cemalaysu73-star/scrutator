import dns.resolver
import pytest

from scrutator.model import EntityType
from scrutator.modules import registry
from scrutator.modules.base import Mode, Module
from scrutator.resolver import DnsResolver


def test_register_and_select(monkeypatch):
    monkeypatch.setattr(registry, "_REGISTRY", {})

    @registry.register
    class Passive(Module):
        name = "t_passive"
        accepts = frozenset({EntityType.DOMAIN})

        async def run(self, entity, ctx):
            return []

    @registry.register
    class Active(Module):
        name = "t_active"
        accepts = frozenset({EntityType.DOMAIN})
        mode = Mode.ACTIVE

        async def run(self, entity, ctx):
            return []

    mods = registry.registered()
    assert {m.name for m in mods} == {"t_passive", "t_active"}
    assert [m.name for m in registry.select_modules(mods, EntityType.DOMAIN)] == ["t_passive"]
    both = registry.select_modules(mods, EntityType.DOMAIN, allow_active=True)
    assert {m.name for m in both} == {"t_passive", "t_active"}
    assert registry.select_modules(mods, EntityType.IP) == []


def test_duplicate_module_name_rejected(monkeypatch):
    monkeypatch.setattr(registry, "_REGISTRY", {})

    class One(Module):
        name = "dup"
        accepts = frozenset({EntityType.DOMAIN})

        async def run(self, entity, ctx):
            return []

    registry.register(One)
    with pytest.raises(ValueError):
        registry.register(One)


class _Rdata:
    def __init__(self, text):
        self._text = text

    def to_text(self):
        return self._text


async def test_dns_resolver_returns_text_and_swallows_nxdomain(monkeypatch):
    resolver = DnsResolver()

    async def ok(name, rtype):
        return [_Rdata("1.2.3.4"), _Rdata("5.6.7.8")]

    monkeypatch.setattr(resolver._resolver, "resolve", ok)
    assert await resolver.lookup("example.com", "A") == ["1.2.3.4", "5.6.7.8"]

    async def nxdomain(name, rtype):
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(resolver._resolver, "resolve", nxdomain)
    assert await resolver.lookup("nope.example", "A") == []

    async def no_answer(name, rtype):
        raise dns.resolver.NoAnswer()

    monkeypatch.setattr(resolver._resolver, "resolve", no_answer)
    assert await resolver.lookup("example.com", "CNAME") == []
