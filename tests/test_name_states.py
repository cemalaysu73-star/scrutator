"""v0.6 task 5: every in-scope hostname gets a resolution state derived from evidence the scan holds:
live, stale (NXDOMAIN), wildcard-covered, or unresolved. Wildcard DNS is detected with a random-label
probe that is recorded as evidence like any other lookup."""

import json

import pytest
from dnsfakes import StatusResolver
from riskfix import Zone

from scrutator.bundle.verify import verify_bundle
from scrutator.model import Entity, EntityType
from scrutator.modules import wildcard as wildcard_module
from scrutator.modules.base import Fact, ModuleContext
from scrutator.modules.wildcard import PROBE_PREFIX, Wildcard
from scrutator.names import name_states, summarise_states
from scrutator.resolver import DnsAnswer
from scrutator.scan import run_scan
from scrutator.scope import ScopePolicy
from scrutator.store import Store


def dom(value):
    return Entity(type=EntityType.DOMAIN, value=value)


# ------------------------------------------------------------------------------------------ the probe


class WildResolver(StatusResolver):
    """Every name under `wild` answers with `addresses`, like a zone with *.example.com."""

    def __init__(self, zone, wild=None, addresses=("203.0.113.5",)):
        super().__init__(zone)
        self.wild, self.addresses = wild, tuple(addresses)

    async def query(self, name, rtype):
        self.calls.append((name, rtype))
        if (name, rtype) in self.zone:
            return await StatusResolver.query(self, name, rtype)
        if self.wild and name.endswith("." + self.wild) and rtype == "A":
            return DnsAnswer("answer", self.addresses)
        return await StatusResolver.query(self, name, rtype)


async def test_the_probe_asks_for_a_random_label_under_the_apex_and_records_the_answer(monkeypatch):
    monkeypatch.setattr(wildcard_module.secrets, "token_hex", lambda n: "0123456789ab")
    resolver = StatusResolver({("example.com", "A"): ["192.0.2.1"]})
    out = await Wildcard().run(dom("example.com"), ModuleContext(http=None, resolver=resolver))
    name = f"{PROBE_PREFIX}0123456789ab.example.com"
    assert resolver.calls == [(name, "A"), (name, "AAAA")]  # nothing outside the apex is ever asked
    assert {f.evidence.request: f.evidence.payload for f in out} == {f"DNS A {name}": "NXDOMAIN", f"DNS AAAA {name}": "NXDOMAIN"}
    assert all(isinstance(f, Fact) and f.evidence.source == "dns" for f in out)


async def test_a_wildcard_zone_answers_the_probe_and_the_addresses_are_the_evidence():
    resolver = WildResolver({("example.com", "A"): ["192.0.2.1"]}, wild="example.com")
    out = await Wildcard().run(dom("example.com"), ModuleContext(http=None, resolver=resolver))
    a = next(f for f in out if " A " in f.evidence.request)
    assert a.evidence.payload == "203.0.113.5"


async def test_a_failed_probe_is_silence_not_evidence():
    class Broken:
        async def query(self, name, rtype):
            raise TimeoutError("slow")

    assert await Wildcard().run(dom("example.com"), ModuleContext(http=None, resolver=Broken())) == []

    class Servfail:
        async def query(self, name, rtype):
            return DnsAnswer("servfail")

    assert await Wildcard().run(dom("example.com"), ModuleContext(http=None, resolver=Servfail())) == []


def test_the_probe_runs_once_per_apex_and_is_passive():
    assert Wildcard.apex_only and Wildcard.mode.value == "passive"


# ------------------------------------------------------------------------------------------ the states


def zone():
    z = Zone()
    z.host("live.example.com", ["192.0.2.10"])
    z.name("gone.example.com")
    z.dns("A", "gone.example.com", "NXDOMAIN")
    z.name("quiet.example.com")  # no DNS evidence at all
    z.name("nodata.example.com")
    z.dns("A", "nodata.example.com", "NODATA")
    z.name("v6.example.com")
    z.dns("AAAA", "v6.example.com", ["2001:db8::1"])
    z.name("example.com")
    z.dns("A", "example.com", ["192.0.2.1"])
    return z


def by_name(report):
    return {row["name"]: row for row in name_states(report)}


def test_each_name_gets_a_state_a_reason_and_the_evidence_for_it():
    z = zone()
    rows = by_name(z.report())
    assert {n: r["state"] for n, r in rows.items()} == {
        "example.com": "live",
        "live.example.com": "live",
        "gone.example.com": "stale",
        "quiet.example.com": "unresolved",
        "nodata.example.com": "unresolved",
        "v6.example.com": "live",
    }
    live = rows["live.example.com"]
    assert live["addresses"] == ["192.0.2.10"] and "resolves to 192.0.2.10" in live["reason"]
    assert len(live["evidence_ids"]) == 1
    assert "NXDOMAIN" in rows["gone.example.com"]["reason"]
    assert rows["quiet.example.com"]["evidence_ids"] == [] and "no" in rows["quiet.example.com"]["reason"].lower()
    assert rows["v6.example.com"]["addresses"] == ["2001:db8::1"]


def test_a_name_that_resolves_only_to_what_a_random_label_resolves_to_is_wildcard_covered():
    z = Zone()
    z.host("www.example.com", ["203.0.113.5"])
    z.host("real.example.com", ["192.0.2.77"])
    z.host("mixed.example.com", ["203.0.113.5", "192.0.2.78"])
    probe = z.dns("A", f"{PROBE_PREFIX}0123456789ab.example.com", ["203.0.113.5"])
    rows = by_name(z.report())
    assert rows["www.example.com"]["state"] == "wildcard"
    assert probe in rows["www.example.com"]["evidence_ids"] and "random label" in rows["www.example.com"]["reason"]
    assert rows["real.example.com"]["state"] == "live"
    assert rows["mixed.example.com"]["state"] == "live"  # one address no wildcard explains


def test_a_probe_that_found_no_wildcard_changes_nothing():
    z = Zone()
    z.host("www.example.com", ["203.0.113.5"])
    z.dns("A", f"{PROBE_PREFIX}0123456789ab.example.com", "NXDOMAIN")
    assert by_name(z.report())["www.example.com"]["state"] == "live"


def test_a_probe_only_covers_the_zone_it_was_asked_in():
    z = Zone(domains=("example.com", "example.net"))
    z.host("www.example.net", ["203.0.113.5"])
    z.dns("A", f"{PROBE_PREFIX}0123456789ab.example.com", ["203.0.113.5"])
    assert by_name(z.report())["www.example.net"]["state"] == "live"


def test_who_names_a_name_is_listed_so_a_certificate_can_vouch_for_a_wildcard_name():
    z = Zone()
    z.host("www.example.com", ["203.0.113.5"])
    z.dns("A", f"{PROBE_PREFIX}0123456789ab.example.com", ["203.0.113.5"])
    z.found("www.example.com", source="crtsh")
    z.found("www.example.com", source="wayback")
    row = by_name(z.report())["www.example.com"]
    assert row["state"] == "wildcard" and row["named_by"] == ["crtsh", "wayback"]


def test_only_in_scope_names_are_described_and_hostile_evidence_is_ignored():
    z = Zone()
    z.host("www.example.com", ["192.0.2.10"])
    z.name("elsewhere.example.org", state="out")
    z.dns("A", "elsewhere.example.org", ["192.0.2.99"])
    z.entity("domain", "cand.example.net", "candidate")
    assert list(by_name(z.report())) == ["www.example.com"]


def test_the_summary_counts_the_four_states():
    rows = name_states(zone().report())
    assert summarise_states(rows) == {"live": 3, "stale": 1, "wildcard": 0, "unresolved": 2}


# ------------------------------------------------------------------------------------------ in a scan


async def test_a_scan_resolves_every_name_and_marks_the_wildcard_ones(monkeypatch):
    from scrutator.model import Evidence
    from scrutator.modules.base import Module, Observation

    class Names(Module):
        name = "names"
        accepts = frozenset({EntityType.DOMAIN})
        apex_only = True

        async def run(self, entity, ctx):
            return [
                Observation(dom(f"{label}.example.com"), "has_subdomain", Evidence.create("names", "names", label))
                for label in ("www", "real", "gone")
            ]

    from scrutator.modules.dns import Dns

    zone = {
        ("example.com", "A"): ["192.0.2.1"],
        ("real.example.com", "A"): ["192.0.2.77"],
        ("www.example.com", "A"): ["203.0.113.5"],
    }
    resolver = WildResolver(zone, wild="example.com")
    store = Store(":memory:")
    scan_id, _ = await run_scan(
        dom("example.com"), ScopePolicy(domains=["example.com"]), store, ModuleContext(http=None, resolver=resolver),
        modules=[Names(), Dns(), Wildcard()],
    )
    from scrutator.report import build_report

    report = build_report(store, scan_id)
    states = {r["name"]: r["state"] for r in report["names"]}
    assert states["real.example.com"] == "live" and states["www.example.com"] == "wildcard"
    # "gone" has no explicit record but the wildcard answers for it: it is not stale, it is covered
    assert states["gone.example.com"] == "wildcard"
    assert report["summary"]["names"] == summarise_states(report["names"])
    assert any(r["request"].startswith(f"DNS A {PROBE_PREFIX}") for r in report["evidence"].values())


# ------------------------------------------------------------------------------------------ bundles


def test_a_bundle_checks_the_name_states_against_its_evidence(tmp_path):
    from riskbundlefix import forge_report, make_risky_bundle

    fx = make_risky_bundle(tmp_path)
    genuine = verify_bundle(fx.path)
    assert genuine.ok and any(c.name == "name states derivable" and c.ok for c in genuine.checks)

    def flatter(report):
        for row in report["names"]:
            if row["state"] == "stale":
                row["state"] = "live"

    forged = verify_bundle(forge_report(fx.path, tmp_path / "f.scrutator", fx.private, flatter))
    assert next(c for c in forged.checks if c.name == "signature valid").ok
    assert [c.name for c in forged.checks if not c.ok] == ["name states derivable"]


def test_the_html_report_shows_the_state_of_each_name():
    from scrutator.report.html import render_html

    page = render_html({"names": [], "summary": {}})
    assert "name states" in page.lower() or "resolution" in page.lower()


async def test_a_probe_that_timed_out_once_is_asked_again():
    class Flaky(StatusResolver):
        async def query(self, name, rtype):
            self.calls.append((name, rtype))
            if self.calls.count((name, rtype)) == 1:
                raise TimeoutError("first try")
            return DnsAnswer("answer", ("203.0.113.5",))

    out = await Wildcard().run(dom("example.com"), ModuleContext(http=None, resolver=Flaky({})))
    assert len(out) == 2 and all(f.evidence.payload == "203.0.113.5" for f in out)
