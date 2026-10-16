import json
import re
import shutil
import subprocess

import pytest
from attrscan import scan

from scrutator.attribution.promote import promote
from scrutator.report import build_report, render_html

HOSTILE = "</script><script>alert(1)</script><!--"

DRIVER = r"""
const fs = require("fs");
class Node {
  constructor(tag) { this.tag = tag; this.children = []; this.listeners = {}; this.attrs = {}; this._text = null; }
  append(...kids) { for (const k of kids) this.children.push(typeof k === "string" ? Object.assign(new Node("#text"), {_text: k}) : k); }
  replaceChildren() { this.children = []; }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  setAttribute(k, v) { this.attrs[k] = v; }
  get value() { return this._value !== undefined ? this._value : (this.tag === "select" && this.children[0] ? this.children[0].value : undefined); }
  set value(v) { this._value = v; }
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
globalThis.document = document;
new Function("document", fs.readFileSync(pagePath, "utf8"))(document);
const texts = {};
for (const id of ["attribution", "risks", "extra-after", "entities", "cards"]) texts[id] = document.getElementById(id).textContent;
fs.writeFileSync(outPath, JSON.stringify(texts));
"""


def page(run=None, promote_to=None):
    report = build_report(run.store, run.scan_id)
    return render_html(report), report


def data_of(html):
    return json.loads(re.search(r'<script type="application/json" id="data">(.*?)</script>', html, re.S).group(1))


async def test_the_page_embeds_the_attribution_and_has_a_section_for_it(http):
    run = await scan(http, attribution=True)
    html, report = page(run)
    data = data_of(html)
    assert data["attribution"] == report["attribution"] and data["leads"] == {"verified": [], "rejected": []}
    assert 'id="attribution"' in html and "renderAttribution();" in html and "renderAnalystLeads();" in html
    assert '"candidate"' in html  # the scope filter and the graph know the fourth state


async def test_hostile_text_in_a_lead_or_in_evidence_cannot_break_out_of_the_page(http, tmp_path):
    run = await scan(http, attribution=True)
    evidence = build_report(run.store, run.scan_id)["attribution"]["candidates"][0]["evidence_ids"][0]
    run.store.add_lead(run.scan_id, kind="lead", claim=HOSTILE, entity_ids=["domain:partner.test"], evidence_ids=[evidence], status="verified")
    run.store.add_lead(run.scan_id, kind="lead", claim=HOSTILE + "rejected", entity_ids=["domain:partner.test"], evidence_ids=[evidence], status="rejected", reason=HOSTILE)
    html, _ = page(run)
    assert "<script>alert(1)" not in html
    assert html.count("<script") == 2 and html.count("</script>") == 2
    data = data_of(html)
    assert data["leads"]["verified"][0]["claim"] == HOSTILE


async def test_the_page_stays_self_contained(http):
    run = await scan(http, attribution=True)
    html, _ = page(run)
    scripts = re.sub(r'<script type="application/json" id="data">.*?</script>', "", html, flags=re.S)
    assert "https://" not in scripts and "innerHTML" not in scripts


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
async def test_the_page_script_is_valid_javascript(http, tmp_path):
    run = await scan(http, attribution=True)
    html, _ = page(run)
    code = re.findall(r"<script>(.*?)</script>", html, re.S)
    assert len(code) == 1
    target = tmp_path / "page.js"
    target.write_text(code[0], encoding="utf-8")
    done = subprocess.run(["node", "--check", str(target)], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
async def test_the_page_script_runs_against_a_dom_stub_and_draws_the_attribution(http, tmp_path):
    run = await scan(http, attribution=True)
    promote(run.store, run.scan_id, "domain:partner.test", scope_file=_scope(tmp_path), via="cli", now="2026-10-17T09:30:00+00:00")
    evidence = build_report(run.store, run.scan_id)["attribution"]["candidates"][0]["evidence_ids"][0]
    run.store.add_lead(run.scan_id, kind="premortem", claim="The only link is one certificate.", entity_ids=["domain:partner.test"], evidence_ids=[evidence], status="verified", check="dns on domain:partner.test")
    run.store.add_lead(run.scan_id, kind="lead", claim="An unsupported claim.", entity_ids=["domain:partner.test"], evidence_ids=[evidence], status="rejected", reason="not in the evidence")
    html, report = page(run)
    code = re.findall(r"<script>(.*?)</script>", html, re.S)[0]
    (tmp_path / "page.js").write_text(code, encoding="utf-8")
    (tmp_path / "data.json").write_text(json.dumps(report), encoding="utf-8")
    (tmp_path / "driver.js").write_text(DRIVER, encoding="utf-8")
    done = subprocess.run(["node", str(tmp_path / "driver.js"), str(tmp_path / "page.js"), str(tmp_path / "data.json"), str(tmp_path / "out.json")], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    texts = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    assert "Attribution (candidates for the scope)" in texts["attribution"] and "partner.test" in texts["attribution"]
    assert "confirmed" in texts["attribution"] and "promoted" in texts["attribution"] and "cert_san 0.60" in texts["attribution"]
    assert "Analyst leads" in texts["attribution"] and "Suggested check (not run): dns on domain:partner.test" in texts["attribution"]
    assert "t0.test" not in texts["attribution"]  # unlikely names are behind the filter
    assert "An unsupported claim." in texts["extra-after"] and "not in the evidence" in texts["extra-after"]
    assert "Candidates" in texts["cards"]


def _scope(tmp_path):
    path = tmp_path / "scope.yaml"
    path.write_text("domains:\n  - example.com\n", encoding="utf-8")
    return path
