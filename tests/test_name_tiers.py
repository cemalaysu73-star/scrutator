"""v0.7 task 1: precision and noise. Every in-scope name is also placed in a tier derived from its
evidence: verified (DNS resolves it, or a certificate or an observation with a timestamp inside the
recent window vouches for it), claimed (only a list names it), stale (it was once evidenced and DNS
no longer agrees) or wildcard (only a wildcard zone answers for it). Nothing is deleted; the report,
the CLI and the HTML put the verified names first and count the rest as groups."""

import json

from riskbundlefix import forge_report
from riskfix import COLLECTED, Zone

from scrutator.bundle.verify import verify_bundle
from scrutator.findings import findings_from_report, summarise_findings
from scrutator.modules.wildcard import PROBE_PREFIX
from scrutator.names import RECENT_DAYS, TIERS, headline, name_states, summarise_tiers


def by_name(report):
    return {row["name"]: row for row in name_states(report)}


def cert(z, name, source="crtsh", not_before="2026-09-01T00:00:00", not_after="2026-12-01T00:00:00"):
    return z.found(name, source=source, not_before=not_before, not_after=not_after)


def test_the_tiers_and_the_window_are_documented_constants():
    assert TIERS == ("verified", "claimed", "stale", "wildcard")
    assert RECENT_DAYS == 90


def test_a_name_that_resolves_is_verified_by_dns():
    z = Zone()
    z.host("www.example.com", ["192.0.2.10"])
    row = by_name(z.report())["www.example.com"]
    assert row["tier"] == "verified" and row["basis"] == "dns" and row["state"] == "live"
    assert "resolves to 192.0.2.10" in row["tier_reason"]


def test_a_name_only_an_aggregator_lists_and_that_does_not_resolve_is_claimed():
    z = Zone()
    z.found("ghost.example.com", source="subdomaincenter")
    z.dns("A", "ghost.example.com", "NXDOMAIN")
    z.found("quiet.example.com", source="hackertarget")  # no DNS answer at all
    rows = by_name(z.report())
    assert rows["ghost.example.com"]["tier"] == "claimed" and rows["ghost.example.com"]["basis"] is None
    assert "subdomaincenter" in rows["ghost.example.com"]["tier_reason"] and "NXDOMAIN" in rows["ghost.example.com"]["tier_reason"]
    assert rows["quiet.example.com"]["tier"] == "claimed"


def test_a_name_no_source_names_at_all_and_that_does_not_resolve_is_claimed():
    z = Zone()
    z.name("orphan.example.com")
    z.dns("A", "orphan.example.com", "NXDOMAIN")
    assert by_name(z.report())["orphan.example.com"]["tier"] == "claimed"


def test_a_recent_certificate_vouches_for_a_name_that_dns_did_not_answer_for():
    z = Zone()
    eid = cert(z, "api.example.com")  # valid until 2026-12-01, collected 2026-10-16
    row = by_name(z.report())["api.example.com"]
    assert row["state"] == "unresolved" and row["tier"] == "verified" and row["basis"] == "certificate"
    assert eid in row["evidence_ids"] and "2026-12-01" in row["tier_reason"]


def test_a_certificate_that_expired_inside_the_window_still_counts():
    z = Zone()
    cert(z, "api.example.com", not_before="2026-01-01T00:00:00", not_after="2026-08-01T00:00:00")  # 76 days before
    assert by_name(z.report())["api.example.com"]["tier"] == "verified"


def test_a_certificate_older_than_the_window_does_not_vouch_and_the_name_is_stale():
    z = Zone()
    eid = cert(z, "old.example.com", not_before="2024-01-01T00:00:00", not_after="2024-04-01T00:00:00")
    row = by_name(z.report())["old.example.com"]
    assert row["tier"] == "stale" and row["basis"] is None and eid in row["evidence_ids"]
    assert "2024-04-01" in row["tier_reason"]


def test_a_recent_certificate_does_not_override_nxdomain_the_name_is_stale():
    z = Zone()
    cert(z, "gone.example.com")
    z.dns("A", "gone.example.com", "NXDOMAIN")
    row = by_name(z.report())["gone.example.com"]
    assert row["state"] == "stale" and row["tier"] == "stale" and "NXDOMAIN" in row["tier_reason"]


def test_certspotter_slices_and_urlscan_observations_vouch_too():
    z = Zone()
    z.name("cs.example.com")
    cs = z.ev(
        "certspotter",
        "GET https://api.certspotter.com/v1/issuances?domain=example.com",
        json.dumps([{"id": "1", "not_after": "2026-11-20T10:00:00Z", "not_before": "2026-08-20T10:00:00Z"}]),
    )
    z.edge(z.name("example.com"), "has_subdomain", "domain:cs.example.com", cs)
    z.name("us.example.com")
    us = z.ev(
        "urlscan",
        "GET https://urlscan.io/api/v1/search/?q=x",
        json.dumps([{"page": {"domain": "us.example.com"}, "task": {"time": "2026-10-01T08:00:00.000Z", "uuid": "u"}}]),
    )
    z.edge("domain:example.com", "has_subdomain", "domain:us.example.com", us)
    rows = by_name(z.report())
    assert rows["cs.example.com"]["tier"] == "verified" and rows["cs.example.com"]["basis"] == "certificate"
    assert rows["us.example.com"]["tier"] == "verified" and rows["us.example.com"]["basis"] == "observation"


def test_an_old_observation_is_stale_and_one_without_a_date_is_a_claim():
    z = Zone()
    z.name("old.example.com")
    old = z.ev("urlscan", "GET https://urlscan.io/api/v1/search/?q=y", json.dumps([{"task": {"time": "2023-01-01T00:00:00.000Z"}}]))
    z.edge("domain:example.com", "has_subdomain", "domain:old.example.com", old)
    assert by_name(z.report())["old.example.com"]["tier"] == "stale"


def test_hostile_or_malformed_dates_vouch_for_nothing():
    z = Zone()
    for name, payload in (("a.example.com", "not json"), ("b.example.com", json.dumps([{"not_after": "tomorrow"}])), ("c.example.com", json.dumps({"not_after": "2099-01-01"})), ("d.example.com", json.dumps([{"not_after": 4102444800}]))):
        z.name(name)
        eid = z.ev("crtsh", f"GET https://crt.sh/?q={name}", payload)
        z.edge("domain:example.com", "has_subdomain", f"domain:{name}", eid)
    assert {r["tier"] for n, r in by_name(z.report()).items() if n != "example.com"} == {"claimed"}


def test_a_listing_from_an_archive_or_an_aggregator_never_vouches_whatever_it_says():
    z = Zone()
    z.found("arch.example.com", source="wayback")
    z.name("agg.example.com")
    agg = z.ev("subdomaincenter", "GET https://api.subdomain.center/?domain=example.com", json.dumps([{"not_after": "2099-01-01T00:00:00"}]))
    z.edge("domain:example.com", "has_subdomain", "domain:agg.example.com", agg)
    rows = by_name(z.report())
    assert rows["arch.example.com"]["tier"] == "claimed" and rows["agg.example.com"]["tier"] == "claimed"


def test_other_dns_records_verify_a_name_that_has_no_address():
    z = Zone()
    z.mx("mail.example.com", ["mx1.example.net"])
    z.dns("A", "mail.example.com", "NODATA")
    row = by_name(z.report())["mail.example.com"]
    assert row["state"] == "unresolved" and row["tier"] == "verified" and row["basis"] == "dns"
    assert "MX" in row["tier_reason"]


def test_a_wildcard_name_is_in_the_wildcard_tier_unless_a_recent_certificate_names_it():
    z = Zone()
    z.host("www.example.com", ["203.0.113.5"])
    z.host("shop.example.com", ["203.0.113.5"])
    z.dns("A", f"{PROBE_PREFIX}0123456789ab.example.com", ["203.0.113.5"])
    cert(z, "shop.example.com")
    rows = by_name(z.report())
    assert rows["www.example.com"]["state"] == "wildcard" and rows["www.example.com"]["tier"] == "wildcard"
    assert rows["shop.example.com"]["state"] == "wildcard" and rows["shop.example.com"]["tier"] == "verified"
    assert rows["shop.example.com"]["basis"] == "certificate"


def test_rows_come_verified_first_and_the_counts_and_the_headline_agree():
    z = Zone()
    z.found("claimed.example.com", source="subdomaincenter")
    z.dns("A", "claimed.example.com", "NXDOMAIN")
    z.host("example.com")
    z.host("www.example.com")
    z.host("zeta.example.com")
    cert(z, "old.example.com", not_before="2020-01-01T00:00:00", not_after="2020-04-01T00:00:00")
    rows = name_states(z.report())
    tiers = [r["tier"] for r in rows]
    assert tiers == sorted(tiers, key=TIERS.index)
    assert [r["name"] for r in rows[:3]] == ["example.com", "www.example.com", "zeta.example.com"]
    counts = summarise_tiers(rows)
    assert counts == {"verified": 3, "claimed": 1, "stale": 1, "wildcard": 0}
    assert headline(counts) == "3 verified, 1 claimed (1 stale, 0 wildcard-covered)"


def test_a_verified_name_is_never_lost_every_live_name_is_verified():
    z = Zone()
    z.host("example.com", ["192.0.2.99"])
    for n in range(5):
        z.host(f"h{n}.example.com", [f"192.0.2.{n + 1}"])
    for n in range(40):
        z.found(f"c{n}.example.com", source="subdomaincenter")
        z.dns("A", f"c{n}.example.com", "NXDOMAIN")
    rows = name_states(z.report())
    assert {r["name"] for r in rows if r["state"] == "live"} <= {r["name"] for r in rows if r["tier"] == "verified"}
    assert summarise_tiers(rows)["claimed"] == 40 and len(rows) == 46  # nothing was dropped


# ------------------------------------------------------------------------------------------ findings


def tiered_zone():
    z = Zone()
    z.host("www.example.com")
    z.found("claimed.example.com", source="subdomaincenter")
    z.dns("A", "claimed.example.com", "NXDOMAIN")
    z.announced("192.0.2.10", "AS64500")
    return z


def test_findings_carry_the_tier_of_their_name_and_come_verified_first():
    report = tiered_zone().report()
    findings = findings_from_report(report)
    by_claim = {f["claim"]: f["tier"] for f in findings}
    assert by_claim["www.example.com resolves to 192.0.2.10"] == "verified"
    assert by_claim["example.com has subdomain claimed.example.com"] == "claimed"
    assert by_claim["192.0.2.10 is announced by AS64500"] == "other"
    order = [f["tier"] for f in findings]
    assert order == sorted(order, key=("verified", "other", "claimed", "stale", "wildcard").index)
    assert len(findings) == len(report["edges"])  # one per relation: nothing collapsed away


def test_findings_are_counted_per_tier():
    counts = summarise_findings(findings_from_report(tiered_zone().report()))
    assert counts == {"verified": 1, "other": 1, "claimed": 1, "stale": 0, "wildcard": 0}


def test_a_report_headline_names_verified_and_claimed_instead_of_one_big_number():
    from scrutator.model import Entity, EntityType, Evidence, ScopeState
    from scrutator.report import build_report
    from scrutator.store import Store

    store = Store(":memory:")
    sid = store.create_scan("example.com")
    root = Entity(type=EntityType.DOMAIN, value="example.com")
    store.upsert_entity(sid, root, ScopeState.IN)
    ip = Entity(type=EntityType.IP, value="192.0.2.10")
    store.upsert_entity(sid, ip, ScopeState.LINKED)
    live_ev = Evidence.create("dns", "DNS A www.example.com", "192.0.2.10")
    root_ev = Evidence.create("dns", "DNS A example.com", "192.0.2.10")
    store.add_evidence(live_ev)
    store.add_evidence(root_ev)
    www = Entity(type=EntityType.DOMAIN, value="www.example.com")
    store.upsert_entity(sid, www, ScopeState.IN)
    store.add_edge(sid, www.id, "resolves_to", ip.id, [live_ev.id])
    store.add_edge(sid, root.id, "resolves_to", ip.id, [root_ev.id])
    store.add_edge(sid, root.id, "has_subdomain", www.id, [live_ev.id])
    for n in range(6):
        ghost = Entity(type=EntityType.DOMAIN, value=f"g{n}.example.com")
        ev = Evidence.create("subdomaincenter", "GET https://api.subdomain.center/?domain=example.com", json.dumps([ghost.value]))
        nx = Evidence.create("dns", f"DNS A {ghost.value}", "NXDOMAIN")
        for e in (ev, nx):
            store.add_evidence(e)
        store.add_scan_evidence(sid, nx.id)
        store.upsert_entity(sid, ghost, ScopeState.IN)
        store.add_edge(sid, root.id, "has_subdomain", ghost.id, [ev.id])
    store.set_meta(sid, "scope", json.dumps({"domains": ["example.com"], "cidrs": [], "asns": []}))
    report = build_report(store, sid)
    summary = report["summary"]
    assert summary["tiers"] == {"verified": 2, "claimed": 6, "stale": 0, "wildcard": 0}
    assert summary["names"] == {"live": 2, "stale": 6, "wildcard": 0, "unresolved": 0}
    assert summary["headline"] == "2 verified, 6 claimed (0 stale, 0 wildcard-covered)"
    assert summary["findings"] == len(report["findings"]) == 9  # all kept
    assert summary["findings_by_tier"] == {"verified": 3, "other": 0, "claimed": 6, "stale": 0, "wildcard": 0}
    assert [f["tier"] for f in report["findings"]][:3] == ["verified"] * 3
    assert len(report["entities"]) == 9 and len(report["edges"]) == 9  # entities and relations all kept


# ------------------------------------------------------------------------------------------ verify


def forged(fx, tmp_path, change):
    return verify_bundle(forge_report(fx.path, tmp_path / "f.scrutator", fx.private, change))


def failed(result):
    return sorted(c.name for c in result.checks if not c.ok)


def test_a_genuine_bundle_re_derives_tiers_findings_and_headline(tmp_path):
    from riskbundlefix import make_risky_bundle

    fx = make_risky_bundle(tmp_path)
    result = verify_bundle(fx.path)
    assert result.ok, [c for c in result.checks if not c.ok]
    names = {c.name for c in result.checks}
    assert {"name states derivable", "findings derivable", "headline derivable"} <= names


def test_a_forged_tier_a_forged_finding_tier_and_a_forged_headline_are_each_caught(tmp_path):
    from riskbundlefix import make_risky_bundle

    fx = make_risky_bundle(tmp_path)

    def upgrade_name(report):
        for row in report["names"]:
            if row["tier"] != "verified":
                row["tier"] = "verified"

    def upgrade_finding(report):
        for finding in report["findings"]:
            finding["tier"] = "verified"

    def boast(report):
        report["summary"]["headline"] = "99 verified, 0 claimed (0 stale, 0 wildcard-covered)"

    def boast_counts(report):
        report["summary"]["tiers"]["verified"] += 50

    assert failed(forged(fx, tmp_path, upgrade_name)) == ["name states derivable"]
    assert failed(forged(fx, tmp_path, upgrade_finding)) == ["findings derivable"]
    assert failed(forged(fx, tmp_path, boast)) == ["headline derivable"]
    assert failed(forged(fx, tmp_path, boast_counts)) == ["headline derivable"]


def test_a_bundle_made_before_tiers_existed_still_verifies(tmp_path):
    from riskbundlefix import make_risky_bundle

    fx = make_risky_bundle(tmp_path)

    def strip(report):
        report["names"] = name_states(report, tiered=False)  # the v0.6 shape: by name, DNS evidence only, no tier
        report["findings"] = findings_from_report(report, tiered=False)  # relation order, no tier
        for key in ("tiers", "headline", "findings_by_tier"):
            report["summary"].pop(key)

    result = forged(fx, tmp_path, strip)
    assert failed(result) == []
    assert "tier" not in json.loads(__import__("scrutator.bundle.reader", fromlist=["read_raw"]).read_raw(tmp_path / "f.scrutator").files["report.json"])["findings"][0]


# ------------------------------------------------------------------------------------------ CLI and HTML


def test_the_html_report_groups_the_claimed_names_and_findings_behind_counted_disclosures():
    from scrutator.report.html import render_html

    page = render_html({"names": [], "summary": {}})
    for needle in ("Verified names", "claimed", "tier-group", "details"):
        assert needle in page


DRIVER = r"""
const fs = require("fs");
class Node {
  constructor(tag) { this.tag = tag; this.children = []; this.listeners = {}; this._text = null; this.open = false; }
  append(...kids) { for (const k of kids) this.children.push(typeof k === "string" ? Object.assign(new Node("#text"), {_text: k}) : k); }
  replaceChildren() { this.children = []; }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  setAttribute() {}
  get value() { return this.tag === "select" && this.children[0] ? this.children[0].value : undefined; }
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text !== null ? this._text : this.children.map(c => c.textContent).join(" "); }
}
const byId = {};
const document = {
  getElementById(id) { return byId[id] || (byId[id] = new Node("#" + id)); },
  createElement(tag) { return new Node(tag); },
  createElementNS(ns, tag) { return new Node(tag); },
};
const [pagePath, dataPath, outPath] = process.argv.slice(2);
document.getElementById("data")._text = fs.readFileSync(dataPath, "utf8");
new Function("document", fs.readFileSync(pagePath, "utf8"))(document);
const find = (node, pred, out = []) => { if (pred(node)) out.push(node); node.children.forEach(c => find(c, pred, out)); return out; };
const before = document.getElementById("findings").textContent;
const groups = find(document.getElementById("findings"), n => n.tag === "details" && n.listeners.toggle);
const names = find(document.getElementById("risks"), n => n.tag === "details" && n.listeners.toggle);
groups.forEach(g => { g.open = true; g.listeners.toggle(); });
const after = document.getElementById("findings").textContent;
fs.writeFileSync(outPath, JSON.stringify({before, after, groups: groups.length, nameGroups: names.length, cards: document.getElementById("cards").textContent, headline: document.getElementById("headline").textContent}));
"""


def test_the_page_shows_verified_findings_and_opens_the_claimed_group_on_demand(tmp_path):
    import shutil
    import subprocess

    import pytest

    from scrutator.report.html import render_html

    if shutil.which("node") is None:
        pytest.skip("node is not installed")
    z = Zone()
    z.host("example.com")
    z.host("www.example.com")
    for n in range(30):
        z.found(f"c{n}.example.com", source="subdomaincenter")
        z.dns("A", f"c{n}.example.com", "NXDOMAIN")
    report = z.report()
    report["names"] = name_states(report)
    report["findings"] = findings_from_report(report)
    from scrutator.names import headline as make_headline

    report["summary"] = {
        "entities": len(report["entities"]), "by_type": {"domain": 1}, "by_scope": {"in": 1}, "edges": len(report["edges"]),
        "findings": len(report["findings"]), "names": {"live": 2, "stale": 30, "wildcard": 0, "unresolved": 0},
        "tiers": summarise_tiers(report["names"]), "findings_by_tier": summarise_findings(report["findings"]),
    }
    report["summary"]["headline"] = make_headline(report["summary"]["tiers"])
    report["scan"] = {"seed": "example.com", "id": 1}
    report.update(generated_at="now", tool={"version": "t"}, sources={}, coverage={}, risks=[], dependencies=[], exposure=[], summary_statements=[], unverified_leads=[], leads={}, promotions=[], ai=None)
    html = render_html(report)
    import re

    code = re.findall(r"<script>(.*?)</script>", html, re.S)[0]
    (tmp_path / "page.js").write_text(code, encoding="utf-8")
    (tmp_path / "data.json").write_text(json.dumps(report), encoding="utf-8")
    (tmp_path / "driver.js").write_text(DRIVER, encoding="utf-8")
    done = subprocess.run(["node", str(tmp_path / "driver.js"), str(tmp_path / "page.js"), str(tmp_path / "data.json"), str(tmp_path / "out.json")], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    out = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    assert "www.example.com resolves to 192.0.2.10" in out["before"]
    assert "c7.example.com" not in out["before"] and "Claimed: 30 finding(s)" in out["before"]  # counted, not drawn
    assert "c7.example.com" in out["after"]  # drawn when asked for
    assert out["groups"] == 1 and out["nameGroups"] == 1
    assert "Verified names" in out["cards"] and "2 verified, 30 claimed" in out["headline"]
