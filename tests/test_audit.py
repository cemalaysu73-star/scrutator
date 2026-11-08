"""R7 T1+T2: `scrutator audit`, `audit-check` and `audit-letter`.

The audit is a client deliverable made from a signed bundle. It refuses to run without an authorisation (an engagement
file, or --self), records that authorisation in the signed audit log before the first lookup of a new scan, cites
evidence for every statement about the client, treats every branding field as hostile input, and can be checked
offline against its bundle, so an edited number, sentence or page is caught.
"""

import asyncio
import json
import re
import shutil
from contextlib import asynccontextmanager
from datetime import date, timedelta
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from llmfakes import ScriptedProvider
from scrutator import cli
from scrutator.ai.runtime import AIRuntime
from scrutator.audit.branding import BrandingError, load_branding
from scrutator.audit.content import evidence_problems
from scrutator.audit.make import check_audit, load_bundle, polish_facts
from scrutator.audit.pdf import find_browser
from scrutator.audit.render import read_embedded
from scrutator.bundle.keys import generate_keypair
from scrutator.bundle.verify import verify_bundle
from scrutator.engagement import EngagementError, load_engagement
from scrutator.model import Entity, EntityType, Evidence
from scrutator.modules.base import Module, ModuleContext, Observation
from scrutator.modules.registry import load_builtin_modules
from scrutator.resolver import DnsAnswer
from scrutator.scan import run_scan

runner = CliRunner()
LAB = Path(__file__).resolve().parent.parent / "docs" / "examples" / "lab-zone" / "proof.scrutator"
HOSTILE = '</style></script><script>alert(1)</script>"><img src=x onerror=alert(2)>'
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


def run(*args):
    return runner.invoke(cli.app, [str(a) for a in args])


def lab_audit(tmp_path, *extra):
    out = tmp_path / "audit"
    result = run("audit", "--from-bundle", LAB, "--self", "--yes", "--no-pdf", "--out", out, *extra)
    assert result.exit_code == 0, result.output
    return out


def engagement_file(tmp_path, *, domains=("example.com", "example.net"), start="2026-10-01", end="2026-12-31", name="eng.yaml", **extra):
    lines = [
        "organisation: Example Corp",
        f"domains: [{', '.join(domains)}]",
        "authorised_by: {name: A. Signatory, role: CISO}",
        f"start: {start}",
        f"end: {end}",
        "purpose: Passive external exposure review, engagement EX-1",
        "reference: EX-1",
        *[f"{k}: {v}" for k, v in extra.items()],
    ]
    path = tmp_path / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


# ------------------------------------------------------------------------------------------- authorisation


def test_an_audit_without_an_authorisation_is_refused(tmp_path):
    result = run("audit", "--from-bundle", LAB, "--yes", "--no-pdf", "--out", tmp_path / "a")
    assert result.exit_code == 2 and "--engagement" in result.output and "--self" in result.output
    both = run("audit", "--from-bundle", LAB, "--self", "--engagement", engagement_file(tmp_path), "--yes", "--out", tmp_path / "b")
    assert both.exit_code == 2
    assert not (tmp_path / "a" / "audit.html").exists()


def test_the_authorisation_must_be_confirmed(tmp_path):
    result = run("audit", "--from-bundle", LAB, "--self", "--no-pdf", "--out", tmp_path / "a")  # no terminal, no --yes
    assert result.exit_code == 2 and "--yes" in result.output


def test_an_engagement_that_does_not_cover_the_scope_or_the_scan_date_is_refused(tmp_path):
    narrow = run("audit", "--from-bundle", LAB, "--engagement", engagement_file(tmp_path, domains=("example.com",)), "--yes", "--no-pdf", "--out", tmp_path / "a")
    assert narrow.exit_code == 2 and "example.net" in narrow.output and "not in the authorisation" in narrow.output
    late = run("audit", "--from-bundle", LAB, "--engagement", engagement_file(tmp_path, start="2026-10-21", name="late.yaml"), "--yes", "--no-pdf", "--out", tmp_path / "b")
    assert late.exit_code == 2 and "not in force" in late.output


def test_a_client_audit_of_an_old_bundle_records_the_engagement_at_report_time(tmp_path):
    eng = engagement_file(tmp_path)
    out = tmp_path / "audit"
    result = run("audit", "--from-bundle", LAB, "--engagement", eng, "--yes", "--no-pdf", "--out", out)
    assert result.exit_code == 0, result.output
    facts = json.loads((out / "audit.json").read_text(encoding="utf-8"))
    assert facts["authorisation"]["mode"] == "client" and facts["authorisation"]["recorded"] == "report-time"
    assert facts["authorisation"]["sha256"] == load_engagement(eng, today=date(2026, 10, 20)).sha256
    log = [json.loads(line) for line in (out / "audit-log.jsonl").read_text(encoding="utf-8").splitlines()]
    assert log[-1]["authorisation_sha256"] == facts["authorisation"]["sha256"]
    page = (out / "audit.html").read_text(encoding="utf-8")
    assert "A. Signatory" in page and "EX-1" in page and "was recorded when this report was made" in page
    assert all(c.ok for c in check_audit(out / "audit.html", out / "proof.scrutator"))


# ------------------------------------------------------------------------------------------- a new scan, client mode


class Resolver:
    async def query(self, name, rtype):
        if rtype == "A" and name in ("example.com", "www.example.com"):
            return DnsAnswer("answer", ("192.0.2.1",))
        return DnsAnswer("nxdomain")

    async def lookup(self, name, rtype):
        return list((await self.query(name, rtype)).records)


class Certs(Module):
    name = "certs"
    name_weight = 3
    accepts = frozenset({EntityType.DOMAIN})
    apex_only = True

    async def run(self, entity, ctx):
        evidence = Evidence.create("certs", f"GET https://certs.test/{entity.value}", "www." + entity.value)
        return [Observation(Entity(type=EntityType.DOMAIN, value="www." + entity.value), "has_subdomain", evidence)]


@pytest.fixture
def fake_scan(monkeypatch):
    @asynccontextmanager
    async def context():
        async with httpx.AsyncClient() as http:
            yield ModuleContext(http=http, resolver=Resolver())

    seen = {}

    async def scan_with_modules(seed, scope, store, ctx, **kwargs):
        seen.update(kwargs)
        dns = next(m for m in load_builtin_modules() if m.name == "dns")
        return await run_scan(seed, scope, store, ctx, modules=[Certs(), dns], max_steps=100, pre_audit=kwargs["pre_audit"])

    monkeypatch.setattr(cli, "open_context", context)
    monkeypatch.setattr(cli, "run_scan", scan_with_modules)
    return seen


def test_a_new_client_audit_writes_the_engagement_to_the_signed_log_before_any_lookup(tmp_path, fake_scan):
    generate_keypair(tmp_path / "keys")
    today = date.today()
    eng = engagement_file(tmp_path, domains=("example.com",), start=(today - timedelta(days=1)).isoformat(), end=(today + timedelta(days=30)).isoformat())
    out = tmp_path / "audit"
    result = run("audit", "example.com", "--engagement", eng, "--yes", "--no-pdf", "--key-dir", tmp_path / "keys", "--out", out)
    assert result.exit_code == 0, result.output
    assert "in the signed audit log before the first lookup" in result.output
    bundle = out / "proof.scrutator"
    assert verify_bundle(bundle).ok  # includes the check "engagement recorded" (before the first lookup)
    loaded = load_bundle(bundle)
    events = [r.get("event") for r in loaded.audit_records]
    first_lookup = next(i for i, r in enumerate(loaded.audit_records) if r.get("module"))
    assert events.index("engagement") < first_lookup
    assert loaded.audit_records[events.index("engagement")]["sha256"] == load_engagement(eng).sha256
    facts = json.loads((out / "audit.json").read_text(encoding="utf-8"))
    assert facts["authorisation"]["recorded"] == "signed" and facts["authorisation"]["reference"] == "EX-1"
    checks = check_audit(out / "audit.html", bundle)
    assert all(c.ok for c in checks), [c for c in checks if not c.ok]
    assert any(c.name == "authorisation in the signed log" for c in checks)
    assert (out / "technical-annex.html").exists() and (out / "signing.pub").exists()


def test_a_new_audit_refuses_a_seed_outside_the_engagement(tmp_path, fake_scan):
    generate_keypair(tmp_path / "keys")
    today = date.today()
    eng = engagement_file(tmp_path, domains=("example.org",), start=today.isoformat(), end=today.isoformat())
    result = run("audit", "example.com", "--engagement", eng, "--yes", "--no-pdf", "--key-dir", tmp_path / "keys", "--out", tmp_path / "a")
    assert result.exit_code == 2 and "not one of the engagement's domains" in result.output
    assert "pre_audit" not in fake_scan  # nothing was scanned


def test_a_self_audit_records_the_attestation(tmp_path, fake_scan):
    generate_keypair(tmp_path / "keys")
    out = tmp_path / "audit"
    result = run("audit", "example.com", "--self", "--yes", "--no-pdf", "--key-dir", tmp_path / "keys", "--out", out)
    assert result.exit_code == 0, result.output
    loaded = load_bundle(out / "proof.scrutator")
    attest = next(r for r in loaded.audit_records if r.get("event") == "self_attestation")
    assert attest["domains"] == ["example.com"] and attest["confirmed"] == "--yes"
    assert all(c.ok for c in check_audit(out / "audit.html", out / "proof.scrutator"))


# ------------------------------------------------------------------------------------------- content


def test_every_claim_about_the_client_cites_evidence_in_the_bundle(tmp_path):
    out = lab_audit(tmp_path)
    facts = json.loads((out / "audit.json").read_text(encoding="utf-8"))
    loaded = load_bundle(out / "proof.scrutator")
    assert evidence_problems(facts, loaded.evidence_ids) == []
    assert [r["priority"] for r in facts["risks"]] == list(range(1, len(facts["risks"]) + 1))
    severities = [r["severity"] for r in facts["risks"]]
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    assert severities == sorted(severities, key=order.get)  # most severe first
    assert all(r["compliance"] for r in facts["risks"])  # every rule has its informational mapping
    page = (out / "audit.html").read_text(encoding="utf-8")
    for heading in ("Authorisation", "Executive summary", "What was not tested", "Methodology", "Glossary", "Evidence appendix"):
        assert heading in page
    assert "not a certification, an audit opinion or a legal conclusion" in page
    assert "scrutator audit-check audit.html proof.scrutator" in page and facts["bundle"]["sha256"] in page


def test_the_turkish_audit_is_turkish(tmp_path):
    out = lab_audit(tmp_path, "--lang", "tr")
    page = (out / "audit.html").read_text(encoding="utf-8")
    assert '<html lang="tr">' in page
    for text in ("Yönetici özeti", "Neler test edilmedi", "Kanıt eki", "Artık var olmayan, sahiplenilebilir bir servise işaret eden CNAME",
                 "sertifikasyon, denetim görüşü ya da hukuki sonuç değildir"):
        assert text in page
    assert all(c.ok for c in check_audit(out / "audit.html", out / "proof.scrutator"))


# ------------------------------------------------------------------------------------------- audit-check


def test_audit_check_passes_on_an_untouched_audit_and_from_the_cli(tmp_path):
    out = lab_audit(tmp_path)
    result = run("audit-check", out / "audit.html", out / "proof.scrutator")
    assert result.exit_code == 0, result.output
    assert "Audit check passed" in result.output


def test_an_edited_page_is_caught(tmp_path):
    out = lab_audit(tmp_path)
    page = (out / "audit.html").read_text(encoding="utf-8")
    edited = page.replace("3 high", "0 high", 1)
    assert edited != page
    (out / "audit.html").write_text(edited, encoding="utf-8", newline="\n")
    checks = {c.name: c for c in check_audit(out / "audit.html", out / "proof.scrutator")}
    assert not checks["page is what the facts render to"].ok
    assert run("audit-check", out / "audit.html", out / "proof.scrutator").exit_code == 1


def test_edited_facts_rendered_consistently_are_still_caught(tmp_path):
    from scrutator.audit.branding import Branding
    from scrutator.audit.render import render_audit

    out = lab_audit(tmp_path)
    embedded = read_embedded((out / "audit.html").read_text(encoding="utf-8"))
    facts = embedded["facts"]
    facts["risks"] = [r for r in facts["risks"] if r["severity"] != "high"]  # quietly drop the high risks
    (out / "audit.html").write_text(render_audit(facts, Branding.from_dict(embedded["branding"])), encoding="utf-8", newline="\n")
    checks = {c.name: c for c in check_audit(out / "audit.html", out / "proof.scrutator")}
    assert checks["page is what the facts render to"].ok  # the forger re-rendered the page ...
    assert not checks["content derivable"].ok  # ... but the bundle does not imply it


def test_another_or_a_tampered_bundle_is_caught(tmp_path):
    out = lab_audit(tmp_path)
    other = tmp_path / "other.scrutator"
    shutil.copyfile(Path(__file__).resolve().parent.parent / "docs" / "examples" / "example.com" / "proof.scrutator", other)
    checks = {c.name: c for c in check_audit(out / "audit.html", other)}
    assert not checks["names this bundle"].ok
    data = bytearray((out / "proof.scrutator").read_bytes())
    data[len(data) // 2] ^= 1
    (tmp_path / "bad.scrutator").write_bytes(bytes(data))
    first = check_audit(out / "audit.html", tmp_path / "bad.scrutator")[0]
    assert first.name == "bundle verifies" and not first.ok


# ------------------------------------------------------------------------------------------- branding is hostile input


def test_branding_text_is_inert_in_the_page(tmp_path):
    (tmp_path / "logo.png").write_bytes(PNG)
    brand = tmp_path / "audit.yaml"
    brand.write_text(json.dumps({"auditor": HOSTILE, "contact": HOSTILE, "client": HOSTILE, "logo": "logo.png",
                                 "colours": {"primary": "#112233", "accent": "#445566"}}), encoding="utf-8")
    out = lab_audit(tmp_path, "--branding", brand)
    page = (out / "audit.html").read_text(encoding="utf-8")
    assert "<script>alert(1)" not in page and "<img src=x" not in page and "</style></script>" not in page
    assert page.count("<script") == 1 and page.count("</script>") == 1  # only the JSON data block
    assert page.count("<style>") == 1 and page.count("</style>") == 1
    assert re.search(r"<script(?![^>]*application/json)", page) is None
    assert "data:image/png;base64," in page
    assert all(c.ok for c in check_audit(out / "audit.html", out / "proof.scrutator"))


@pytest.mark.parametrize("document,problem", [
    ({"colours": {"primary": "red;}</style><script>alert(1)</script>"}}, "colour"),
    ({"colours": {"accent": "#12345"}}, "colour"),
    ({"language": "de"}, "language"),
    ({"surprise": 1}, "surprise"),
    ({"logo": "logo.svg"}, "PNG or JPEG"),
    ({"logo": "missing.png"}, "cannot read"),
])
def test_bad_branding_is_refused(tmp_path, document, problem):
    (tmp_path / "logo.svg").write_text('<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>', encoding="utf-8")
    path = tmp_path / "audit.yaml"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(BrandingError, match=problem):
        load_branding(path)


def test_a_logo_larger_than_the_limit_is_refused(tmp_path):
    (tmp_path / "big.png").write_bytes(PNG + b"\x00" * (600 * 1024))
    path = tmp_path / "audit.yaml"
    path.write_text('logo: big.png\n', encoding="utf-8")
    with pytest.raises(BrandingError, match="512 KiB"):
        load_branding(path)


# ------------------------------------------------------------------------------------------- the letter


@pytest.mark.parametrize("lang,notice,name", [("en", "NOT LEGAL ADVICE", "authorisation-letter.txt"), ("tr", "HUKUKİ TAVSİYE DEĞİLDİR", "yetki-belgesi.txt")])
def test_the_letter_is_a_template_and_its_unfilled_engagement_is_refused(tmp_path, lang, notice, name):
    out = tmp_path / "letter"
    result = run("audit-letter", "--lang", lang, "--client", "Example Corp", "--domains", "example.com,example.net", "--out", out)
    assert result.exit_code == 0, result.output
    letter = (out / name).read_text(encoding="utf-8")
    assert notice in letter and "example.net" in letter and "<fill in:" in letter
    assert ("PASSIVE ONLY" in letter) if lang == "en" else ("YALNIZCA PASİF" in letter)
    with pytest.raises(EngagementError, match="placeholder"):
        load_engagement(out / "engagement.yaml")


def test_a_fully_filled_letter_gives_an_engagement_file_that_loads(tmp_path):
    today = date.today()
    out = tmp_path / "letter"
    result = run("audit-letter", "--client", "Example Corp", "--domains", "example.com", "--start", today.isoformat(),
                 "--end", (today + timedelta(days=10)).isoformat(), "--signatory", "A. Signatory", "--signatory-role", "CISO",
                 "--reference", "EX-2", "--auditor", "Me", "--auditor-contact", "me@example.org", "--client-contact", "it@example.com",
                 "--retention", "90 days", "--out", out)
    assert result.exit_code == 0, result.output
    loaded = load_engagement(out / "engagement.yaml")
    assert loaded.engagement.domains == ("example.com",) and loaded.engagement.reference == "EX-2"


def test_the_letter_refuses_a_person_as_a_domain(tmp_path):
    result = run("audit-letter", "--domains", "jane.doe@example.com", "--out", tmp_path / "l")
    assert result.exit_code == 2


# ------------------------------------------------------------------------------------------- AI rewording


def _facts(tmp_path):
    out = lab_audit(tmp_path)
    return json.loads((out / "audit.json").read_text(encoding="utf-8")), load_bundle(out / "proof.scrutator"), out


def test_an_invented_rewording_is_refused_and_the_original_kept(tmp_path):
    facts, loaded, _ = _facts(tmp_path)
    writer = ScriptedProvider(responder=lambda s, u, schema: {"text": "backup.example.com exposes a database at 203.0.113.66."})
    verifier = ScriptedProvider(responder=lambda s, u, schema: {"supported": True, "reason": "agrees with everything"}, model="other")
    result = asyncio.run(polish_facts(AIRuntime({"writer": writer, "verifier": verifier}), facts, loaded.payloads))
    assert result["statements"] and all(s["verdict"].startswith("ungrounded") for s in result["statements"])
    assert all(s["text"] == s["original"] for s in result["statements"])


def test_a_faithful_rewording_is_kept_and_audit_check_rechecks_it(tmp_path):
    from scrutator.audit.branding import Branding
    from scrutator.audit.render import render_audit

    facts, loaded, out = _facts(tmp_path)
    writer = ScriptedProvider(responder=lambda s, u, schema: {"text": re.search(r"<data>\s*(.*?)\s*</data>", u, re.S).group(1).replace("The review confirmed", "We confirmed")})
    verifier = ScriptedProvider(responder=lambda s, u, schema: {"supported": True, "reason": "same"}, model="other")
    facts["polish"] = asyncio.run(polish_facts(AIRuntime({"writer": writer, "verifier": verifier}), facts, loaded.payloads))
    kept = [s for s in facts["polish"]["statements"] if s["verdict"] == "verified"]
    assert kept and any(s["text"].startswith("We confirmed") for s in kept)
    brand = Branding.from_dict(read_embedded((out / "audit.html").read_text(encoding="utf-8"))["branding"])
    (out / "audit.html").write_text(render_audit(facts, brand), encoding="utf-8", newline="\n")
    assert all(c.ok for c in check_audit(out / "audit.html", out / "proof.scrutator"))
    # a forged "verified" rewording that names an invented host fails the floor that audit-check re-runs
    kept[0]["text"] = "We confirmed that evil.example.org serves the 17 names."
    (out / "audit.html").write_text(render_audit(facts, brand), encoding="utf-8", newline="\n")
    checks = {c.name: c for c in check_audit(out / "audit.html", out / "proof.scrutator")}
    assert not checks["AI rewordings pass the deterministic floor"].ok


# ------------------------------------------------------------------------------------------- PDF


@pytest.mark.skipif(find_browser() is None, reason="no Chromium-based browser installed")
def test_the_pdf_is_printed_with_an_installed_browser(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # a relative --out (the live run that found this: the browser resolves paths elsewhere)
    result = run("audit", "--from-bundle", LAB, "--self", "--yes", "--out", "audit")
    assert result.exit_code == 0, result.output
    if not (tmp_path / "audit" / "audit.pdf").exists() and "No PDF" in result.output:
        # A browser is installed but cannot print here (CI containers without a usable sandbox): the audit said how
        # to print by hand, which test_without_a_browser_the_audit_says_how_to_print covers.
        pytest.skip("the installed browser could not print a PDF in this environment")
    assert (tmp_path / "audit" / "audit.pdf").read_bytes()[:5] == b"%PDF-"


def test_without_a_browser_the_audit_says_how_to_print(tmp_path, monkeypatch):
    monkeypatch.setenv("SCRUTATOR_BROWSER", str(tmp_path / "no-such-browser.exe"))
    out = tmp_path / "audit"
    result = run("audit", "--from-bundle", LAB, "--self", "--yes", "--out", out)
    assert result.exit_code == 0, result.output
    assert "No PDF" in result.output and "print it to PDF" in result.output and not (out / "audit.pdf").exists()


@pytest.mark.parametrize("folder", ["audit", "audit/tr"])
def test_the_shipped_sample_audit_passes_audit_check_pinned(folder):
    from scrutator.bundle.keys import fingerprint, load_public_raw

    base = Path(__file__).resolve().parent.parent / "docs" / "examples" / folder
    pin = fingerprint(load_public_raw(base / "signing.pub"))
    checks = check_audit(base / "audit.html", base / "proof.scrutator", pin=pin)
    assert all(c.ok for c in checks), [c for c in checks if not c.ok]
