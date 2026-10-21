"""R7 T4: bug-bounty mode.

`bounty import` turns a programme's scope (HackerOne CSV, Bugcrowd or bounty-targets JSON, a plain list) into a
deny-by-default scope file and refuses what it cannot represent safely; `bounty watch` keeps a baseline and announces
only what is new and in scope, once, with a ready-to-paste draft for each takeover candidate. No active probing.
"""

import json
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from typer.testing import CliRunner

from scrutator import cli
from scrutator.benchlab.fakes import Router, StatusResolver
from scrutator.bounty import BountyScope, ScopeError, parse_scope, parse_target
from scrutator.modules.base import ModuleContext
from scrutator.modules.registry import load_builtin_modules
from scrutator.scan import run_scan

runner = CliRunner()


def scope_of(text: str) -> BountyScope:
    data = text.encode("utf-8")
    return BountyScope.from_parsed(parse_scope(data), program="p", data=data, name="s.txt")


# ------------------------------------------------------------------------------------------- hostile entries


@pytest.mark.parametrize("entry,reason", [
    ("*", "leftmost"),
    ("*.*", "leftmost"),
    ("*.com", "public suffix"),
    ("*.com.tr", "public suffix"),
    ("*.co.uk", "public suffix"),
    ("example.*", "leftmost"),
    ("api.*.example.com", "leftmost"),
    ("*example.com", "leftmost"),
    ("javascript:alert(1)", "scheme"),
    ("data:text/html,<script>alert(1)</script>", "scheme"),
    ("file:///etc/passwd", "scheme"),
    ("ftp://example.com", "scheme"),
    ("https://example.com@evil.example/", "user info"),
    ("http://user:pw@example.com", "user info"),
    ("10.0.0.0/8", "public"),
    ("192.168.1.1", "public"),
    ("1.0.0.0/4", "too wide"),
    ("exam​ple.com", "control"),
    ("ex‮ample.com", "control"),
    ("com.tr", "public suffix"),
    ("localhost", "public suffix"),
    ("not a host!", "valid host"),
])
def test_entries_that_cannot_be_represented_safely_are_refused(entry, reason):
    rule, why = parse_target(entry, True)
    assert rule is None and reason in why


@pytest.mark.parametrize("entry,kind,value", [
    ("*.example.com", "wildcard", "example.com"),
    ("https://*.example.com", "wildcard", "example.com"),
    ("*.EXAMPLE.com", "wildcard", "example.com"),
    ("https://www.example.com/app?x=1", "host", "www.example.com"),
    ("example.com:8443", "host", "example.com"),
    ("www.example.com.", "host", "www.example.com"),
    ("example。com", "host", "example.com"),
    ("1.1.1.0/24", "cidr", "1.1.1.0/24"),
    ("1.1.1.1", "cidr", "1.1.1.1/32"),
])
def test_ordinary_and_odd_but_safe_entries_are_normalised(entry, kind, value):
    rule, why = parse_target(entry, True)
    assert rule is not None, why
    assert (rule.kind, rule.value) == (kind, value)
    if not entry.isascii():
        assert "normalised" in rule.note


def test_a_huge_file_is_refused_before_parsing():
    with pytest.raises(ScopeError, match="MiB"):
        parse_scope(b"a.example.com\n" * 500_000)


def test_too_many_lines_or_rules_are_refused():
    with pytest.raises(ScopeError):
        parse_scope("\n".join(f"h{i}.example.com" for i in range(60_000)).encode())


def test_a_json_depth_bomb_neither_crashes_nor_includes_anything():
    data = ("[" * 5000 + "]" * 5000).encode()
    try:
        parsed = parse_scope(data)
    except ScopeError:
        return
    assert parsed.rules == []


# ------------------------------------------------------------------------------------------- formats


H1_CSV = """identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission,availability_requirement,confidentiality_requirement,integrity_requirement,max_severity,system_tags,created_at,updated_at
*.example.com,WILDCARD,,true,true,,,,critical,,,
"www.example.com, api.example.com",URL,,true,true,,,,critical,,,
legacy.example.com,URL,,false,false,,,,none,,,
com.example.app,GOOGLE_PLAY_APP_ID,,true,true,,,,critical,,,
*,WILDCARD,,true,true,,,,critical,,,
1.1.1.0/24,CIDR,,true,true,,,,critical,,,
"""


def test_hackerone_csv():
    parsed = parse_scope(H1_CSV.encode())
    scope = BountyScope.from_parsed(parsed, program="p", data=H1_CSV.encode(), name="h1.csv")
    assert scope.include["wildcard"] == ["example.com"] and scope.include["host"] == ["api.example.com", "www.example.com"]
    assert scope.exclude["host"] == ["legacy.example.com"] and scope.include["cidr"] == ["1.1.1.0/24"]
    assert any(r["input"] == "*" for r in parsed.refused)
    assert any("not a network asset" in n["reason"] for n in parsed.notes)
    assert scope.contains("a.b.example.com") and not scope.contains("legacy.example.com")


def test_bugcrowd_target_groups_and_bounty_targets_json():
    groups = {"groups": [
        {"name": "Core", "in_scope": True, "targets": [{"name": "*.example.com", "category": "website"}, {"name": "Example iOS app", "category": "ios"}]},
        {"name": "Not", "in_scope": False, "targets": [{"name": "status.example.com", "category": "website"}]},
    ]}
    parsed = parse_scope(json.dumps(groups).encode())
    scope = BountyScope.from_parsed(parsed, program="p", data=b"x", name="bc.json")
    assert scope.include["wildcard"] == ["example.com"] and scope.exclude["host"] == ["status.example.com"]
    data = [{"name": "Example", "targets": {"in_scope": [{"asset_identifier": "*.example.org", "asset_type": "WILDCARD", "eligible_for_submission": True}],
                                            "out_of_scope": [{"asset_identifier": "blog.example.org", "asset_type": "URL"}]}}]
    other = BountyScope.from_parsed(parse_scope(json.dumps(data).encode()), program="p", data=b"x", name="h1.json")
    assert other.include["wildcard"] == ["example.org"] and other.exclude["host"] == ["blog.example.org"]


def test_a_plain_list_with_sections_and_exclusion_marks():
    scope = scope_of("# programme scope\nIn scope:\n- *.example.com\n* www.example.net\nOut of scope:\n- *.out.example.com\nlegacy.example.com\n!old.example.net\n")
    assert scope.include == {"host": ["www.example.net"], "wildcard": ["example.com"], "cidr": []}
    assert scope.exclude["wildcard"] == ["out.example.com"] and set(scope.exclude["host"]) == {"legacy.example.com", "old.example.net"}


def test_membership_is_deny_by_default_and_exclusions_win():
    scope = scope_of("*.example.com\nwww.example.net\n!*.out.example.com\n!legacy.example.com\n")
    assert scope.contains("a.example.com") and scope.contains("www.example.net")
    assert not scope.contains("example.com")  # a wildcard does not include its apex
    assert not scope.contains("out.example.com") and not scope.contains("x.out.example.com")  # nor an excluded base
    assert not scope.contains("legacy.example.com") and not scope.contains("other.example.net")
    assert not scope.contains("example.com.evil.test") and not scope.contains("evilexample.com")
    assert scope.roots() == ["example.com", "www.example.net"]


def test_import_cli_reads_stdin_and_writes_a_scope_file_that_loads(tmp_path):
    out = tmp_path / "scope.yaml"
    result = runner.invoke(cli.app, ["bounty", "import", "-", "--program", "Example", "--out", str(out)], input="*.example.com\n*\njavascript:alert(1)\n")
    assert result.exit_code == 0, result.output
    assert "refused '*'" in result.output and "scheme javascript" in result.output
    loaded = BountyScope.load(out)
    assert loaded.include["wildcard"] == ["example.com"] and loaded.program == "Example"


def test_import_refuses_a_scope_with_nothing_usable(tmp_path):
    result = runner.invoke(cli.app, ["bounty", "import", "-", "--out", str(tmp_path / "s.yaml")], input="*\n*.com\n")
    assert result.exit_code == 2 and not (tmp_path / "s.yaml").exists()


def test_an_edited_scope_file_is_checked_again(tmp_path):
    out = tmp_path / "scope.yaml"
    runner.invoke(cli.app, ["bounty", "import", "-", "--out", str(out)], input="*.example.com\n")
    out.write_text(out.read_text(encoding="utf-8").replace("- example.com", "- com"), encoding="utf-8")
    with pytest.raises(ScopeError, match="not allowed"):
        BountyScope.load(out)


# ------------------------------------------------------------------------------------------- watch


def _crt_rows(names):
    now = datetime.now(timezone.utc)
    return [{"id": 1000 + i, "issuer_name": "C=US, O=Example CA", "name_value": name,
             "not_before": (now - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%S"), "not_after": (now + timedelta(days=80)).strftime("%Y-%m-%dT%H:%M:%S")}
            for i, name in enumerate(names)]


ROUNDS = [
    {"crt": ["www.example.com"], "zone": {("www.example.com", "A"): ["1.1.1.1"]}, "ports": {"1.1.1.1": [443]}},
    {"crt": ["www.example.com", "dev.example.com", "shop.example.com", "staging.out.example.com"],
     "zone": {("www.example.com", "A"): ["1.1.1.1"], ("dev.example.com", "A"): ["1.1.1.2"], ("staging.out.example.com", "A"): ["1.1.1.3"],
              ("shop.example.com", "CNAME"): ["shop-demo.azurewebsites.net."], ("shop.example.com", "A"): "NXDOMAIN"},
     "ports": {"1.1.1.1": [443, 6379], "1.1.1.2": [443], "1.1.1.3": [22]}},
]
ROUNDS.append(ROUNDS[1])  # the third round sees the same as the second: nothing is announced twice


@pytest.fixture
def watched(monkeypatch, tmp_path):
    state = {"round": -1}

    @asynccontextmanager
    async def context():
        plan = ROUNDS[state["round"]]
        router = Router()
        router.add("crt.sh", "/", httpx.Response(200, json=_crt_rows(plan["crt"])))
        router.add("internetdb.shodan.io", r"/(.+)", lambda r: httpx.Response(200, json={"ip": r.url.path[1:], "ports": plan["ports"].get(r.url.path[1:], []), "cpes": [], "vulns": [], "hostnames": [], "tags": []}), regex=True)
        async with httpx.AsyncClient(transport=router.transport()) as http:
            yield ModuleContext(http=http, resolver=StatusResolver(plan["zone"]))

    real = run_scan

    async def scan(seed, scope, store, ctx, **kwargs):
        modules = [m for m in load_builtin_modules() if m.name in ("crtsh", "dns", "internetdb")]
        return await real(seed, scope, store, ctx, modules=modules, max_steps=500)

    async def no_sleep(_seconds):
        state["round"] += 1

    monkeypatch.setattr(cli, "open_context", context)
    monkeypatch.setattr(cli, "run_scan", scan)
    monkeypatch.setattr(cli, "_sleep", no_sleep)
    state["round"] = 0
    scope = tmp_path / "scope.yaml"
    runner.invoke(cli.app, ["bounty", "import", "-", "--program", "Example", "--out", str(scope)], input="*.example.com\n!*.out.example.com\n")
    return scope, tmp_path / "watch"


def test_bounty_watch_announces_only_new_in_scope_things_once(watched):
    scope, out = watched
    result = runner.invoke(cli.app, ["bounty", "watch", "--scope", str(scope), "--out", str(out), "--max-runs", "3", "--every", "1h"])
    assert result.exit_code == 0, result.output
    assert "baseline of 1 in-scope verified name" in result.output
    alerts = json.loads(next(out.glob("alerts-*.json")).read_text(encoding="utf-8"))
    kinds = {a["kind"] for a in alerts}
    assert {"new_name", "new_takeover", "new_service", "new_cert"} <= kinds
    named = {e for a in alerts for e in a["entities"]}
    assert "dev.example.com" in named and "shop.example.com" in named
    assert not any("out.example.com" in e for e in named) and "1.1.1.3" not in named  # excluded, never announced
    assert any(a["kind"] == "new_service" and a["key"] == "svc:1.1.1.1:6379" for a in alerts)
    assert all(a["evidence_ids"] for a in alerts)
    assert result.output.count("new alert(s)") == 2 and "Round 3" in result.output and "0 new alert(s)" in result.output
    assert len(list(out.glob("alerts-*.json"))) == 1  # the third round announced nothing


def test_each_takeover_candidate_gets_a_ready_to_paste_draft(watched):
    scope, out = watched
    runner.invoke(cli.app, ["bounty", "watch", "--scope", str(scope), "--out", str(out), "--max-runs", "2", "--every", "1h"])
    drafts = list((out / "findings").glob("*.md"))
    assert len(drafts) == 1
    text = drafts[0].read_text(encoding="utf-8")
    assert "Subdomain takeover candidate: shop.example.com" in text and "dig +short CNAME shop.example.com" in text
    assert "Do not register or claim the resource" in text
    alerts = json.loads(next(out.glob("alerts-*.json")).read_text(encoding="utf-8"))
    takeover = next(a for a in alerts if a["kind"] == "new_takeover")
    assert all(i in text for i in takeover["evidence_ids"])


def test_a_restarted_watch_keeps_its_baseline(watched):
    scope, out = watched
    runner.invoke(cli.app, ["bounty", "watch", "--scope", str(scope), "--out", str(out), "--max-runs", "1"])
    result = runner.invoke(cli.app, ["bounty", "watch", "--scope", str(scope), "--out", str(out), "--max-runs", "1"])
    assert "baseline from an earlier run" in result.output and "Round 1" in result.output and "0 new alert(s)" in result.output
