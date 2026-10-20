"""Brand presence (`scan --brand`): the planted lab (scrutator/benchlab/brandlab.py), the guard, robots.txt, the
derivation that `verify` repeats, the pack rules, and the opt-in."""

import io
import json
import zipfile

import httpx
import pytest

from scrutator.benchlab import brandlab
from scrutator.brand import MAX_LOOKALIKES, brand_presence, lookalikes, parse_link, plan, valid_handle
from scrutator.bundle.keys import fingerprint, generate_keypair, load_private_key, private_key_path, public_raw_from_private
from scrutator.bundle.replay import parse_request, replay_evidence
from scrutator.bundle.verify import verify_bundle
from scrutator.bundle.writer import create_bundle
from scrutator.egress import EgressDenied
from scrutator.model import Entity, EntityType
from scrutator.modules.base import ModuleContext
from scrutator.modules.registry import load_builtin_modules
from scrutator.packs import PackError, load_packs
from scrutator.packs.schema import PlatformEntry
from scrutator.report import build_report, render_html
from scrutator.report.sarif import to_sarif
from scrutator.scan import run_scan
from scrutator.scope import ScopePolicy
from scrutator.sources import SourcePolicy
from scrutator.store import Store
from scrutator.web import WebGuard, open_web, scope_guard

from conftest import FakeResolver

SEED = Entity(type=EntityType.DOMAIN, value="example.com")
PACKS = load_packs()


def brand_module():
    return next(m for m in load_builtin_modules() if m.name == "brand")


async def lab_scan(tmp_path, lab=None, *, policy=None, modules=None):
    lab = lab or brandlab.router()
    store = Store(tmp_path / "brand.db")
    scope = ScopePolicy(domains=["example.com"])
    async with httpx.AsyncClient(transport=lab.transport()) as http, open_web(
        scope_guard(scope, PACKS, resolve=brandlab.public_resolve), transport=lab.transport()
    ) as web:
        ctx = ModuleContext(http=http, resolver=FakeResolver(), web=web)
        scan_id, _ = await run_scan(
            SEED, scope, store, ctx, modules=modules or [brand_module()], packs=PACKS,
            source_policy=policy or SourcePolicy().opt("brand"),
        )
    return store, scan_id, lab


# ------------------------------------------------------------------------------------------- the lab


async def test_the_lab_finds_what_was_planted_and_nothing_else(tmp_path):
    store, scan_id, lab = await lab_scan(tmp_path)
    report = build_report(store, scan_id)
    site = report["brand"]["domains"][0]
    assert site["domain"] == "example.com" and site["brand"] == "example"
    official = {(o["platform"], o["handle"]): o["state"] for o in site["official"]}
    assert official == brandlab.TRUTH_OFFICIAL
    found = {(r["rule_id"], r["entity_ids"][1], r["severity"]) for r in report["risks"] if r["rule_id"].startswith("brand-")}
    assert found == brandlab.TRUTH_RISKS
    for risk in report["risks"]:
        if risk["rule_id"].startswith("brand-"):
            assert risk["confidence"] == "low"
            assert risk["evidence_ids"] and all(i in report["evidence"] for i in risk["evidence_ids"])


async def test_it_never_asks_where_it_may_not(tmp_path):
    store, scan_id, lab = await lab_scan(tmp_path)
    hosts = {request.url.host for request in lab.calls}
    assert hosts <= brandlab.ALLOWED_HOSTS
    assert not hosts & brandlab.NEVER_HOSTS  # X and LinkedIn are linked but never requested; unlinked platforms neither
    paths = [str(r.url) for r in lab.calls if r.url.host == "example.com"]
    assert paths == ["https://example.com/robots.txt", "https://example.com/"]  # robots.txt first, one page
    # bounded: per linked status platform, the official handles, the brand name and at most MAX_LOOKALIKES look-alikes
    per_host = {}
    for request in lab.calls:
        per_host[request.url.host] = per_host.get(request.url.host, 0) + 1
    assert all(count <= MAX_LOOKALIKES + 3 for host, count in per_host.items() if host != "example.com")


async def test_an_unverifiable_answer_is_never_absent(tmp_path):
    store, scan_id, _ = await lab_scan(tmp_path)
    report = build_report(store, scan_id)
    gitlab = [c for c in report["brand"]["domains"][0]["checks"] if c["platform"] == "gitlab"]
    assert gitlab and {c["state"] for c in gitlab} == {"unverifiable"}  # a redirect to sign-in says nothing
    assert not [r for r in report["risks"] if "gitlab" in " ".join(r["entity_ids"])]


async def test_robots_txt_that_forbids_the_home_page_stops_everything(tmp_path):
    store, scan_id, lab = await lab_scan(tmp_path, brandlab.router(robots="User-agent: *\nDisallow: /\n"))
    assert [str(r.url) for r in lab.calls] == ["https://example.com/robots.txt"]
    report = build_report(store, scan_id)
    assert report["brand"]["summary"]["official"] == 0
    assert report["brand"]["domains"][0]["robots"][0]["allows_home"] is False


async def test_robots_txt_for_another_agent_does_not_stop_it(tmp_path):
    store, scan_id, lab = await lab_scan(tmp_path, brandlab.router(robots="User-agent: otherbot\nDisallow: /\n"))
    assert "https://example.com/" in [str(r.url) for r in lab.calls]


async def test_an_unreadable_robots_txt_counts_as_disallow(tmp_path):
    lab = brandlab.router()
    lab.routes.insert(0, ("GET", "example.com", __import__("re").compile(r"/robots\.txt\Z"), lambda _r: httpx.Response(503)))
    store, scan_id, lab = await lab_scan(tmp_path, lab)
    assert [str(r.url) for r in lab.calls] == ["https://example.com/robots.txt"]


async def test_a_redirect_out_of_scope_is_not_followed(tmp_path):
    lab = brandlab.router(home=httpx.Response(301, headers={"location": "https://example.net/"}))
    store, scan_id, lab = await lab_scan(tmp_path, lab)
    assert "example.net" not in {r.url.host for r in lab.calls}
    page = build_report(store, scan_id)["brand"]["domains"][0]["pages"][0]
    assert page["status"] == 301 and page["links"] == 0


async def test_a_redirect_inside_the_scope_is_followed_with_its_own_robots(tmp_path):
    lab = brandlab.router(home=httpx.Response(301, headers={"location": "https://www.example.com/"}))
    store, scan_id, lab = await lab_scan(tmp_path, lab)
    urls = [str(r.url) for r in lab.calls if r.url.host.endswith("example.com")]
    assert urls[:4] == ["https://example.com/robots.txt", "https://example.com/", "https://www.example.com/robots.txt", "https://www.example.com/"]
    assert build_report(store, scan_id)["brand"]["summary"]["official"] == len(brandlab.TRUTH_OFFICIAL)


async def test_without_the_flag_the_module_never_runs(tmp_path):
    store, scan_id, lab = await lab_scan(tmp_path, policy=SourcePolicy())
    assert lab.calls == []
    report = build_report(store, scan_id)
    assert "brand" not in report
    assert report["source_policy"]["disabled"]["brand"] == "opt-in: only with --brand"


async def test_a_page_that_is_not_html_gives_no_links(tmp_path):
    lab = brandlab.router(home=httpx.Response(200, content=b"\x89PNG", headers={"content-type": "image/png"}))
    store, scan_id, lab = await lab_scan(tmp_path, lab)
    assert {r.url.host for r in lab.calls} == {"example.com"}


# ------------------------------------------------------------------------------------------- the guard


async def test_the_web_guard_allows_scope_and_status_platforms_only():
    guard = scope_guard(ScopePolicy(domains=["example.com"]), PACKS, resolve=brandlab.public_resolve)
    for url in ("https://example.com/", "https://www.example.com/robots.txt", "https://github.com/x", "https://mastodon.social/@x"):
        await guard.on_request(httpx.Request("GET", url))
    for url in ("https://x.com/example", "https://www.linkedin.com/company/x", "https://example.net/", "http://example.com/",
                "https://example.com:8443/", "https://93.184.215.14/", "https://user@example.com/", "https://localhost/"):
        with pytest.raises(EgressDenied):
            await guard.on_request(httpx.Request("GET", url))


async def test_an_in_scope_host_on_a_private_address_is_refused():
    async def private(host):
        return ["10.0.0.5"]

    guard = WebGuard(lambda host: host.endswith("example.com"), resolve=private)
    with pytest.raises(EgressDenied, match="non-public"):
        await guard.on_request(httpx.Request("GET", "https://intranet.example.com/"))


# ------------------------------------------------------------------------------------------- bundle and verify


async def signed_bundle(tmp_path):
    store, scan_id, _ = await lab_scan(tmp_path)
    generate_keypair(tmp_path / "keys")
    key = load_private_key(private_key_path(tmp_path / "keys"))
    create_bundle(store, scan_id, key, tmp_path / "proof.scrutator")
    return tmp_path / "proof.scrutator", fingerprint(public_raw_from_private(key)), store, scan_id


async def test_a_brand_bundle_verifies_and_rederives_the_section(tmp_path):
    path, pin, _, _ = await signed_bundle(tmp_path)
    result = verify_bundle(path, pinned_fingerprint=pin)
    checks = {c.name: c for c in result.checks}
    assert result.ok, [(c.name, c.detail) for c in result.checks if not c.ok]
    assert checks["brand derivable"].ok and checks["risks derivable"].ok


def rewrite(path, out, change):
    """Change report.json and re-sign nothing: the hashes break too, but the derivation check must name the change."""
    with zipfile.ZipFile(path) as src:
        files = {n: src.read(n) for n in src.namelist()}
    report = json.loads(files["report.json"])
    change(report)
    files["report.json"] = json.dumps(report).encode()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as dst:
        for name, data in files.items():
            dst.writestr(name, data)
    out.write_bytes(buffer.getvalue())
    return out


@pytest.mark.parametrize("change", [
    lambda r: r["brand"]["domains"][0]["official"][0].__setitem__("state", "exists" if r["brand"]["domains"][0]["official"][0]["state"] != "exists" else "absent"),
    lambda r: r.pop("brand"),
    lambda r: r["brand"]["domains"][0]["checks"].pop(),
    lambda r: r["packs"]["effective"].pop("platforms"),
])
async def test_a_changed_brand_section_fails_by_name(tmp_path, change):
    path, pin, _, _ = await signed_bundle(tmp_path)
    forged = rewrite(path, tmp_path / "forged.scrutator", change)
    result = verify_bundle(forged, pinned_fingerprint=pin)
    failed = {c.name for c in result.checks if not c.ok}
    assert not result.ok
    assert failed & {"brand derivable", "packs intact"}


async def test_the_html_and_sarif_carry_the_brand_risks_inertly(tmp_path):
    store, scan_id, _ = await lab_scan(tmp_path)
    report = build_report(store, scan_id)
    html = render_html(report)
    assert "\"brand\": {" in html and "renderBrand()" in html
    assert "<script>document.write" not in html  # nothing from the page is kept, let alone rendered
    sarif = to_sarif(report)
    rules = {r["ruleId"] for r in sarif["runs"][0]["results"]}
    assert {"brand-handle-unregistered", "brand-lookalike-handle"} <= rules


async def test_profile_records_replay_by_status(tmp_path):
    store, scan_id, _ = await lab_scan(tmp_path)
    report = build_report(store, scan_id)
    records = [{"id": i, **r} for i, r in report["evidence"].items()]
    profiles = [r for r in records if r["request"].startswith("PROFILE ")]
    pages = [r for r in records if r["request"].startswith(("PAGE ", "ROBOTS ", "SITE "))]
    assert profiles and all(parse_request(r["request"]) for r in profiles if "gitlab.com" not in r["request"] or True)
    assert all(parse_request(r["request"]) is None for r in pages)  # the organisation's own site is never replayed
    lab = brandlab.router()
    async with httpx.AsyncClient(transport=lab.transport()) as http:
        same = await replay_evidence(profiles, http, FakeResolver())
    assert {r.status for r in same} == {"unchanged"}
    brandlab.EXISTING["https://github.com/examp1e"] = 404
    try:
        lab = brandlab.router()
        async with httpx.AsyncClient(transport=lab.transport()) as http:
            drift = await replay_evidence(profiles, http, FakeResolver())
    finally:
        brandlab.EXISTING["https://github.com/examp1e"] = 200
    changed = [r for r in drift if r.status == "changed"]
    assert [r.request for r in changed] == ["PROFILE https://github.com/examp1e"]


# ------------------------------------------------------------------------------------------- pure parts


def test_lookalikes_are_deterministic_capped_by_class_and_never_the_brand():
    first = lookalikes("example")
    assert first == lookalikes("example")
    handles = [h for h, _ in first]
    assert "example" not in handles and len(handles) == len(set(handles))
    kinds = [how.split()[0] for _, how in first[:8]]
    assert {"homoglyph", "suffix", "separator", "keyboard"} & set(kinds) >= {"homoglyph", "suffix", "separator"}
    assert ("examp1e", "homoglyph l->1") in first


def test_every_bundled_platform_reads_its_own_examples():
    for entry in PACKS.platforms:
        assert entry.examples, entry.id
        for example in entry.examples:
            found = parse_link(PACKS, example)
            assert found is not None and found[0].id == entry.id, (entry.id, example)


def test_pages_and_reserved_paths_are_not_accounts():
    assert parse_link(PACKS, "https://github.com/features") is None
    assert parse_link(PACKS, "https://github.com/example/repo") is None
    assert parse_link(PACKS, "https://github.com/-bad") is None
    assert parse_link(PACKS, "https://www.linkedin.com/in/someone") is None  # personal profiles are not read
    assert parse_link(PACKS, "https://github.com/Example-Org/") == (next(e for e in PACKS.platforms if e.id == "github"), "example-org")


def test_platforms_the_site_does_not_link_are_never_planned():
    official, checks = plan(PACKS, "example", ["https://github.com/example-org", "https://twitter.com/example"])
    assert set(checks) == {"github"}  # X is linked but unverifiable; nothing else is linked
    assert [h for h, kind, _ in checks["github"] if kind != "lookalike"] == ["example-org", "example"]
    assert sum(1 for _, kind, _ in checks["github"] if kind == "lookalike") <= MAX_LOOKALIKES
    assert all(valid_handle(next(e for e in PACKS.platforms if e.id == "github"), h) for h, _, _ in checks["github"])


def entry(**over):
    data = {"id": "p", "source": "https://p.example/", "verified": False, "platform": "P", "profile": "https://p.example/{handle}",
            "link_hosts": ["p.example"], "link_paths": ["/{handle}"], "handle_min": 1, "handle_max": 20, "presence": "status",
            "exists": [200], "absent": [404]}
    data.update(over)
    return data


@pytest.mark.parametrize("bad", [
    {"presence": "status", "exists": []},
    {"presence": "unverifiable"},
    {"exists": [200], "absent": [200]},
    {"link_paths": ["/(.*)+{handle}"]},
    {"link_paths": ["/{handle}/{handle}"]},
    {"profile": "http://p.example/{handle}"},
    {"profile": "https://{handle}.p.example/"},
    {"profile": "https://p.example/?u={handle}"},
    {"handle_chars": "*"},
    {"handle_min": 30, "handle_max": 3},
])
def test_a_platform_entry_that_could_mislead_is_refused(bad):
    with pytest.raises(ValueError):
        PlatformEntry.model_validate(entry(**bad))


def test_no_brand_evidence_no_section():
    assert brand_presence({"evidence": {}, "scope": {"domains": ["example.com"]}}, PACKS) is None
