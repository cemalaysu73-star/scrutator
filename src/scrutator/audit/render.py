"""The audit as one self-contained HTML file, made for the screen and for print (A4).

No script runs in it: the only <script> element is a JSON data block (type application/json, every `<` escaped) that
holds the facts and the branding, so `scrutator audit-check` can rebuild the page and compare it byte for byte. Every
piece of text, branding included, is escaped where it is placed; the style sheet takes nothing from the branding but the
two colours, which are validated as #rrggbb.
"""

from __future__ import annotations

import html
import json

from scrutator.audit.branding import Branding
from scrutator.audit.i18n import TEXT, plural

SEV_COLOURS = {"high": "#a1271b", "medium": "#9a5b00", "low": "#3d5a80", "info": "#59636e"}


def esc(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _css(brand: Branding) -> str:
    return """
:root{--primary:%s;--accent:%s;--ink:#1b1f24;--ink2:#4a525c;--line:#d9dde2;--soft:#f4f6f8;--paper:#fff}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%%}
body{margin:0;background:#e9ecef;color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans",Arial,sans-serif}
main{max-width:900px;margin:0 auto;background:var(--paper)}
.cover{min-height:100vh;display:flex;flex-direction:column;justify-content:space-between;padding:56px 56px 40px;
  border-top:14px solid var(--primary);background:var(--paper)}
.cover img{max-height:72px;max-width:260px;object-fit:contain}
.cover .kicker{color:var(--accent);font-weight:600;letter-spacing:.08em;text-transform:uppercase;font-size:13px}
.cover h1{font-size:40px;line-height:1.1;margin:10px 0 6px;color:var(--primary)}
.cover .client{font-size:24px;margin:0 0 28px}
.cover dl{display:grid;grid-template-columns:max-content 1fr;gap:6px 18px;margin:0}
.cover dt{color:var(--ink2)} .cover dd{margin:0;overflow-wrap:anywhere}
.cover .conf{margin-top:28px;font-size:12px;color:var(--ink2);border-top:1px solid var(--line);padding-top:10px}
section{padding:36px 56px;border-top:1px solid var(--line)}
h2{color:var(--primary);font-size:22px;margin:0 0 14px}
h3{font-size:16px;margin:22px 0 8px}
p{margin:0 0 10px}
.muted{color:var(--ink2);font-size:13px}
.toc ol{columns:2;margin:0;padding-left:20px}
.toc a{color:var(--ink);text-decoration:none}
table{width:100%%;border-collapse:collapse;font-size:13px;margin:8px 0 14px}
th,td{text-align:left;vertical-align:top;padding:7px 8px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}
th{background:var(--soft);font-weight:600;color:var(--ink2)}
thead{display:table-header-group}
tr{break-inside:avoid}
.mono,code,pre{font-family:ui-monospace,"Cascadia Mono",Consolas,"Liberation Mono",monospace;font-size:12px}
pre{background:var(--soft);border:1px solid var(--line);border-radius:6px;padding:10px 12px;white-space:pre-wrap;overflow-wrap:anywhere}
.sev{display:inline-block;padding:1px 8px;border-radius:999px;color:#fff;font-size:12px;font-weight:600;white-space:nowrap}
.exec li{margin:0 0 8px}
.refs{color:var(--ink2);font-size:12px;white-space:nowrap}
.refs a{color:var(--accent)}
.risk{border:1px solid var(--line);border-left:5px solid var(--ink2);border-radius:6px;padding:12px 16px;margin:12px 0;break-inside:avoid}
.risk h3{margin:0 0 6px}
.risk dl{display:grid;grid-template-columns:150px 1fr;gap:4px 14px;margin:8px 0 0;font-size:13px}
.risk dt{color:var(--ink2)} .risk dd{margin:0;overflow-wrap:anywhere}
.unverified{color:var(--ink2);font-style:italic}
.notice{background:var(--soft);border-left:4px solid var(--accent);padding:10px 14px;font-size:13px;margin:10px 0}
dl.gloss dt{font-weight:600;margin-top:8px} dl.gloss dd{margin:0 0 4px}
@media (max-width:640px){
  .cover,section{padding:24px 18px} .cover h1{font-size:30px} .toc ol{columns:1}
  .risk dl{grid-template-columns:1fr} .wide{display:block;overflow-x:auto}
}
@page{size:A4;margin:16mm 14mm 18mm;
  @bottom-right{content:counter(page);font:9pt system-ui,sans-serif;color:#59636e}}
@page:first{margin:0}
@media print{
  body{background:#fff;font-size:10.5pt}
  main{max-width:none}
  .cover{min-height:auto;height:297mm;padding:30mm 22mm 20mm;break-after:page}
  section{padding:0 0 6mm;border:0;break-before:page}
  section.flow{break-before:auto;padding-top:6mm}
  a{color:inherit;text-decoration:none}
  .risk,table,pre{break-inside:auto}
  .risk{break-inside:avoid}
}
""" % (brand.primary, brand.accent)


def _sev(t: dict, severity: str) -> str:
    return f'<span class="sev" style="background:{SEV_COLOURS.get(severity, "#59636e")}">{esc(t["sev"].get(severity, severity))}</span>'


def _short(evidence_id: str) -> str:
    return evidence_id[:12]


def render_audit(facts: dict, brand: Branding) -> str:
    """The audit page. Deterministic: the same facts and branding give the same bytes."""
    lang = facts["lang"]
    t = TEXT[lang]
    who = facts["who"]
    auth = facts["authorisation"]
    self_mode = auth["mode"] == "self"
    title = t["self_title"] if self_mode else t["doc_title"]
    out: list[str] = []
    w = out.append
    w("<!doctype html>")
    w(f'<html lang="{esc(lang)}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">')
    w(f"<title>{esc(title)} · {esc(who['client'])}</title>")
    w(f"<style>{_css(brand)}</style></head><body><main>")

    # cover
    w('<header class="cover"><div>')
    if brand.logo_data_uri:
        w(f'<img alt="{esc(who["auditor"] or "logo")}" src="{esc(brand.logo_data_uri)}">')
    w(f'<p class="kicker">{esc(t["confidential"])}</p><h1>{esc(title)}</h1><p class="client">{esc(who["client"])}</p>')
    w("<dl>")
    w(f"<dt>{esc(t['prepared_for'])}</dt><dd>{esc(who['client'])}</dd>")
    w(f"<dt>{esc(t['prepared_by'])}</dt><dd>{esc(who['auditor'] or '—')}</dd>")
    if brand.contact:
        w(f"<dt>{esc(t['contact'])}</dt><dd>{esc(brand.contact)}</dd>")
    w(f"<dt>{esc(t['date'])}</dt><dd>{esc(str(facts['generated_at'])[:10])}</dd>")
    if auth.get("reference"):
        w(f"<dt>{esc(t['reference'])}</dt><dd>{esc(auth['reference'])}</dd>")
    w(f"<dt>{esc(t['scope'])}</dt><dd>{esc(', '.join(auth['domains']))}</dd>")
    w(f"<dt>{esc(t['bundle_sha'])}</dt><dd class=\"mono\">{esc(facts['bundle']['sha256'])}</dd>")
    w("</dl></div>")
    w(f'<p class="conf">{esc(t["annex"])}</p></header>')

    sections = [("auth", t["s_auth"]), ("exec", t["s_exec"]), ("risks", t["s_risks"]), ("inventory", t["s_inventory"]),
                ("limits", t["s_limits"]), ("method", t["s_method"]), ("glossary", t["s_glossary"]), ("evidence", t["s_evidence"])]
    w(f'<section class="toc"><h2>{esc(t["toc"])}</h2><ol>')
    for anchor, label in sections:
        w(f'<li><a href="#{anchor}">{esc(label)}</a></li>')
    w("</ol></section>")

    # authorisation
    w(f'<section id="auth" class="flow"><h2>{esc(t["s_auth"])}</h2>')
    if self_mode:
        w(f"<p>{esc(t['auth_self'])}</p>")
        w(f"<p>{esc(t['auth_self_recorded'] if auth['recorded'] == 'signed' else t['auth_self_late'])}</p>")
    else:
        by = auth.get("authorised_by") or {}
        w("<p>" + esc(t["auth_client"].format(organisation=auth["organisation"], name=by.get("name", ""), role=by.get("role", ""),
                                               start=auth["start"], end=auth["end"], purpose=auth["purpose"])) + "</p>")
        w(f"<p>{esc((t['auth_recorded_signed'] if auth['recorded'] == 'signed' else t['auth_recorded_late']).format(sha=auth['sha256']))}</p>")
    w(f"<p>{esc(t['auth_passive'])}</p></section>")

    # executive summary
    w(f'<section id="exec"><h2>{esc(t["s_exec"])}</h2><ol class="exec">')
    polished = {p["index"]: p["text"] for p in (facts.get("polish") or {}).get("statements", []) if p.get("verdict") == "verified"}
    for index, sentence in enumerate(facts["executive"]):
        text = polished.get(index, sentence["text"])
        mark = "*" if index in polished else ""
        refs = ""
        if sentence["risk_refs"]:
            links = ", ".join(f'<a href="#{esc(r)}">{esc(r)}</a>' for r in sentence["risk_refs"][:6])
            refs += f' <span class="refs">[{links}{" …" if len(sentence["risk_refs"]) > 6 else ""}]</span>'
        if sentence["evidence_ids"]:
            count = len(sentence["evidence_ids"])
            refs += f' <span class="refs">({esc(t["record_1"] if count == 1 else t["records_n"].format(n=count))})</span>'
        w(f"<li>{esc(text)}{mark}{refs}</li>")
    w("</ol>")
    w(f'<p class="muted">{esc(t["exec_note"])}' + (f" {esc(t['exec_ai'])}" if polished else "") + "</p></section>")

    # risks
    w(f'<section id="risks"><h2>{esc(t["s_risks"])}</h2>')
    if not facts["risks"]:
        w(f"<p>{esc(t['no_risks'])}</p>")
    else:
        w('<div class="wide"><table><thead><tr>')
        for key in ("col_priority", "col_severity", "col_finding", "col_affected", "col_effort"):
            w(f"<th>{esc(t[key])}</th>")
        w("</tr></thead><tbody>")
        for row in facts["risks"]:
            w(f'<tr><td><a href="#{esc(row["ref"])}">{esc(row["ref"])}</a></td><td>{_sev(t, row["severity"])}</td>'
              f"<td>{esc(row['title'])}</td><td>{esc(', '.join(row['affected'][:4]))}{' …' if len(row['affected']) > 4 else ''}</td>"
              f"<td>{esc(t['effort'][row['effort']])}</td></tr>")
        w("</tbody></table></div>")
        w(f'<p class="muted">{esc(t["effort_note"])}</p>')
        for row in facts["risks"]:
            w(f'<div class="risk" id="{esc(row["ref"])}" style="border-left-color:{SEV_COLOURS.get(row["severity"], "#59636e")}">')
            w(f"<h3>{esc(row['ref'])} · {esc(row['title'])} {_sev(t, row['severity'])}</h3><dl>")
            w(f"<dt>{esc(t['col_affected'])}</dt><dd>{esc(', '.join(row['affected']))}</dd>")
            w(f"<dt>{esc(t['col_evidence_says'])}</dt><dd>{esc(row['explanation'])}</dd>")
            w(f"<dt>{esc(t['col_fix'])}</dt><dd>{esc(row['remediation'])}</dd>")
            w(f"<dt>{esc(t['col_effort'])}</dt><dd>{esc(t['effort'][row['effort']])}</dd>")
            if row["compliance"]:
                refs = "; ".join(
                    esc(m["ref"]) + ("" if m["verified"] else f' <span class="unverified">({"unverified" if lang == "en" else "doğrulanmadı"})</span>')
                    for m in row["compliance"])
                w(f"<dt>{esc(t['col_mapping'])}</dt><dd>{refs}</dd>")
            ids = ", ".join(f'<span class="mono">{esc(_short(i))}</span>' for i in row["evidence_ids"][:8])
            more = f" +{len(row['evidence_ids']) - 8}" if len(row["evidence_ids"]) > 8 else ""
            w(f"<dt>{esc(t['col_records'])}</dt><dd>{ids}{esc(more)}</dd></dl></div>")
        w(f'<p class="notice">{esc(t["mapping_note"])}</p>')
    w("</section>")

    # inventory
    summary = facts["summary"]
    w(f'<section id="inventory"><h2>{esc(t["s_inventory"])}</h2><p>{esc(t["inventory_note"])}</p>')
    w('<div class="wide"><table><thead><tr>')
    for key in ("col_name", "col_addresses", "col_providers", "col_networks", "col_records"):
        w(f"<th>{esc(t[key])}</th>")
    w("</tr></thead><tbody>")
    for row in facts["inventory"]:
        w(f"<tr><td class=\"mono\">{esc(row['name'])}</td><td class=\"mono\">{esc(', '.join(row['addresses'][:4]))}{' …' if len(row['addresses']) > 4 else ''}</td>"
          f"<td>{esc(', '.join(row['providers']))}</td><td>{esc(', '.join(row['networks']))}</td>"
          f"<td class=\"mono\">{esc(_short(row['evidence_ids'][0]) if row['evidence_ids'] else '')}{esc(' +' + str(len(row['evidence_ids']) - 1) if len(row['evidence_ids']) > 1 else '')}</td></tr>")
    w("</tbody></table></div>")
    if summary["inventory_total"] > len(facts["inventory"]):
        w(f"<p class=\"muted\">{esc(t['inventory_more'].format(n=summary['inventory_total'] - len(facts['inventory']), **plural(lang, summary['inventory_total'] - len(facts['inventory']))))}</p>")
    w(f"<p>{esc(t['claimed_line'].format(claimed=summary['claimed'], stale=summary['stale'], wildcard=summary['wildcard']))}</p></section>")

    # limits
    limits = facts["limits"]
    w(f'<section id="limits"><h2>{esc(t["s_limits"])}</h2><p>{esc(t["not_tested_intro"])}</p><ul>')
    for line in t["not_tested"]:
        w(f"<li>{esc(line)}</li>")
    w(f"</ul><h3>{esc(t['coverage_intro'])}</h3>")
    w(f'<div class="wide"><table><thead><tr><th>{esc(t["col_source"])}</th><th>{esc(t["col_state"])}</th></tr></thead><tbody>')
    labels = {"ok": t["src_ok"], "partial": t["src_ok"] + " / " + t["src_failed"], "failed": t["src_failed"], "down": t["src_down"], "idle": t["src_idle"]}
    for row in limits["sources"]:
        detail = f" — {'; '.join(row['errors'])}" if row["errors"] and row["outcome"] != "ok" else ""
        w(f"<tr><td class=\"mono\">{esc(row['source'])}</td><td>{esc(labels[row['outcome']])}{esc(detail)}</td></tr>")
    w("</tbody></table></div>")
    if not any(r["outcome"] in ("failed", "down", "partial") for r in limits["sources"]):
        w(f"<p>{esc(t['coverage_none_failed'])}</p>")
    if limits["disabled"]:
        w(f"<p>{esc(t['coverage_off'].format(list='; '.join(f'{k} ({v})' for k, v in limits['disabled'].items())))}</p>")
    if limits["deadline_hit"]:
        w(f"<p>{esc(t['coverage_deadline'])}</p>")
    if limits["entity_cap"]:
        w(f"<p>{esc(t['coverage_cap'].format(cap=limits['entity_cap']['cap'], dropped=limits['entity_cap']['dropped']))}</p>")
    w(f'<p class="notice">{esc(t["coverage_limit"])}</p></section>')

    # methodology
    method = facts["method"]
    w(f'<section id="method"><h2>{esc(t["s_method"])}</h2>')
    for para in t["method_paras"]:
        w(f"<p>{esc(para)}</p>")
    w(f"<p>{esc(t['method_sources'].format(list=', '.join(method['sources_used'])))}</p>")
    w("<p class=\"muted\">" + esc(t["method_facts"].format(tool=f"scrutator {facts['scan']['tool']}", ruleset=method["ruleset"], packs=method["packs"],
                                                          started=facts["scan"]["started_at"], generated=facts["generated_at"])) + "</p></section>")

    # glossary
    w(f'<section id="glossary"><h2>{esc(t["s_glossary"])}</h2><dl class="gloss">')
    for term, meaning in t["glossary"]:
        w(f"<dt>{esc(term)}</dt><dd>{esc(meaning)}</dd>")
    w("</dl></section>")

    # evidence appendix
    bundle = facts["bundle"]
    w(f'<section id="evidence"><h2>{esc(t["s_evidence"])}</h2><p>{esc(t["evidence_intro"])}</p>')
    w('<div class="wide"><table><tbody>')
    w(f"<tr><th>{esc(t['bundle_file'])}</th><td class=\"mono\">{esc(bundle['file'])}</td></tr>")
    w(f"<tr><th>{esc(t['bundle_sha'])}</th><td class=\"mono\">{esc(bundle['sha256'])}</td></tr>")
    w(f"<tr><th>{esc(t['bundle_key'])}</th><td class=\"mono\">{esc(bundle['key_fingerprint'])}</td></tr>")
    w(f"<tr><th>{esc(t['bundle_records'])}</th><td>{esc(bundle['records'])}</td></tr>")
    w("</tbody></table></div>")
    w(f"<h3>{esc(t['verify_title'])}</h3><ol>")
    commands = [
        f"sha256sum {bundle['file']}\n# {bundle['sha256']}",
        f"scrutator verify {bundle['file']} --pin {bundle['key_fingerprint']}",
        f"scrutator audit-check audit.html {bundle['file']}",
    ]
    for step, command in zip(t["verify_steps"], commands):
        w(f"<li><p>{esc(step)}</p><pre>{esc(command)}</pre></li>")
    w(f"</ol><p class=\"muted\">{esc(t['verify_install'])}</p>")
    w(f"<h3>{esc(t['cited_records'])}</h3>")
    w(f'<div class="wide"><table><thead><tr><th>{esc(t["col_id"])}</th><th>{esc(t["col_source"])}</th><th>{esc(t["col_request"])}</th><th>{esc(t["col_collected"])}</th></tr></thead><tbody>')
    for row in facts["evidence"]["cited"]:
        w(f"<tr><td class=\"mono\">{esc(_short(row['id']))}</td><td>{esc(row['source'])}</td><td class=\"mono\">{esc(row['request'])}</td><td class=\"mono\">{esc(row['collected_at'])}</td></tr>")
    w("</tbody></table></div>")
    if facts["evidence"]["cited_total"] > len(facts["evidence"]["cited"]):
        w(f"<p class=\"muted\">{esc(t['cited_more'].format(n=facts['evidence']['cited_total'] - len(facts['evidence']['cited']), **plural(lang, facts['evidence']['cited_total'] - len(facts['evidence']['cited']))))}</p>")
    w("</section></main>")
    data = json.dumps({"facts": facts, "branding": brand.to_dict()}, sort_keys=True, ensure_ascii=True).replace("<", "\\u003c")
    w(f'<script type="application/json" id="audit-facts">{data}</script>')
    w("</body></html>")
    return "\n".join(out) + "\n"


def read_embedded(page: str) -> dict:
    """The facts and branding a page embeds (for audit-check). Raises ValueError when there is no single data block."""
    start_tag = '<script type="application/json" id="audit-facts">'
    if page.count(start_tag) != 1:
        raise ValueError("the page does not hold exactly one audit data block")
    body = page.split(start_tag, 1)[1]
    if "</script>" not in body:
        raise ValueError("the audit data block is not closed")
    return json.loads(body.split("</script>", 1)[0])
