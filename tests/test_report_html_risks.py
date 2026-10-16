import json
import re
import shutil
import subprocess

import pytest
from riskbundlefix import dom, make_risky_store

from scrutator.model import Evidence, ScopeState
from scrutator.report import build_report, render_html

HOSTILE = "</script><script>alert(1)</script><!--"


def page():
    store, sid = make_risky_store()
    return render_html(build_report(store, sid)), build_report(store, sid)


def data_of(html):
    return json.loads(re.search(r'<script type="application/json" id="data">(.*?)</script>', html, re.S).group(1))


def test_the_page_embeds_the_risks_and_the_dependencies():
    html, report = page()
    data = data_of(html)
    assert [r["rule_id"] for r in data["risks"]] == [r["rule_id"] for r in report["risks"]] and len(data["risks"]) == 3
    assert data["dependencies"] and data["summary"]["risks"] == 3
    assert 'id="risks"' in html and "renderRisks();" in html and "renderDependencies();" in html


def test_a_hostile_record_cited_by_a_risk_cannot_break_out_of_the_page():
    store, sid = make_risky_store()
    nasty = Evidence.create("dns", "DNS TXT mail.example.com", f'"v=spf1 {HOSTILE} +all"')
    store.upsert_entity(sid, dom("mail.example.com"), ScopeState.IN)
    store.add_evidence(nasty)
    store.add_scan_evidence(sid, nasty.id)
    html = render_html(build_report(store, sid))
    assert "<script>alert(1)" not in html
    assert html.count("<script") == 2 and html.count("</script>") == 2
    spf = [r for r in data_of(html)["risks"] if r["rule_id"] == "spf-allows-all" and r["entity_ids"] == ["domain:mail.example.com"]]
    assert spf and HOSTILE in spf[0]["explanation"]


def test_the_page_stays_self_contained():
    html, _ = page()
    scripts = re.sub(r'<script type="application/json" id="data">.*?</script>', "", html, flags=re.S)
    assert "https://" not in scripts and "innerHTML" not in scripts


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_the_page_script_is_valid_javascript(tmp_path):
    html, _ = page()
    code = re.findall(r"<script>(.*?)</script>", html, re.S)
    assert len(code) == 1
    target = tmp_path / "page.js"
    target.write_text(code[0], encoding="utf-8")
    done = subprocess.run(["node", "--check", str(target)], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
