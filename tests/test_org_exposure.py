"""Organisation exposure (design D18, `scrutator exposure`): it refuses without a valid engagement file, refuses a person
as the seed, refuses domains outside the engagement, reports aggregates only by default, logs --detail in the audit
log, keeps personal data out of every output, and never leaves the engagement's scope."""

import json
import zipfile
from contextlib import asynccontextmanager
from datetime import date

import httpx
import pytest
from typer.testing import CliRunner

from scrutator import cli
from scrutator import web as web_module
from scrutator.benchlab import exposurelab
from scrutator.bundle.keys import fingerprint, generate_keypair, load_public_raw
from scrutator.bundle.verify import verify_bundle
from scrutator.engagement import EngagementError, check_seed, load_engagement, refuse_person
from scrutator.modules.base import ModuleContext
from scrutator.orgexposure import Minimiser, breach_counts, role_function, shape

runner = CliRunner()


@pytest.fixture
def lab(monkeypatch):
    """The CLI's network replaced by the planted lab; every request and DNS question recorded."""
    router = exposurelab.router()
    resolver = exposurelab.Resolver()

    @asynccontextmanager
    async def fake_context(**_):
        async with httpx.AsyncClient(transport=router.transport()) as http:
            yield ModuleContext(http=http, resolver=resolver)

    real_open_web = web_module.open_web

    def lab_web(guard, transport=None):
        guard._resolve = exposurelab.public_resolve
        return real_open_web(guard, transport=router.transport())

    monkeypatch.setattr(cli, "open_context", fake_context)
    monkeypatch.setattr(web_module, "open_web", lab_web)
    monkeypatch.setenv("SCRUTATOR_PREVIEW_EXPOSURE", "1")
    monkeypatch.setattr("scrutator.modules.exposure.PACE", 100_000.0)
    return router, resolver


@pytest.fixture
def engagement(tmp_path):
    path = tmp_path / "engagement.yaml"
    path.write_text(exposurelab.ENGAGEMENT_YAML, encoding="utf-8")
    return path


def run(tmp_path, engagement, *extra, seed="example.com"):
    return runner.invoke(cli.app, ["exposure", seed, "--engagement", str(engagement), "--yes", "--out", str(tmp_path / "out"), *extra])


# ------------------------------------------------------------------------------------------- refusals


def test_it_is_a_preview_that_needs_the_variable(tmp_path, lab, engagement, monkeypatch):
    monkeypatch.delenv("SCRUTATOR_PREVIEW_EXPOSURE")
    result = run(tmp_path, engagement)
    assert result.exit_code == 2 and "preview" in result.output and "legal and ethics review" in result.output
    assert lab[0].calls == [] and lab[1].calls == []


def test_it_refuses_without_an_engagement_file(tmp_path, lab):
    result = runner.invoke(cli.app, ["exposure", "example.com", "--yes", "--out", str(tmp_path / "out")])
    assert result.exit_code != 0
    result = run(tmp_path, tmp_path / "missing.yaml")
    assert result.exit_code == 2 and "refused" in result.output
    assert lab[0].calls == [] and lab[1].calls == []


@pytest.mark.parametrize("text, why", [
    ("organisation: X\n", "not valid"),
    (exposurelab.ENGAGEMENT_YAML.replace("start: 2026-01-01", "start: 2031-01-01"), "start is after end"),
    (exposurelab.ENGAGEMENT_YAML.replace("end: 2030-12-31", "end: 2026-01-02"), "not in force"),
    (exposurelab.ENGAGEMENT_YAML.replace("purpose: Planted", "purpose: x\nextra: 1\nnote: Planted"), "not valid"),
    (exposurelab.ENGAGEMENT_YAML.replace("domains: [example.com]", "domains: []"), "not valid"),
    (exposurelab.ENGAGEMENT_YAML.replace("{name: Lab Authoriser, role: CISO}", "{name: Lab Authoriser}"), "not valid"),
    ("- a list\n", "mapping"),
    (exposurelab.ENGAGEMENT_YAML.replace("domains: [example.com]", "domains: [example.com, gmail.com]"), "public mail provider"),
    (exposurelab.ENGAGEMENT_YAML.replace("domains: [example.com]", "domains: [gmx.de]"), "public mail provider"),
    ("\xff\xfe", "not readable"),
])
def test_an_invalid_engagement_file_is_refused_before_anything_is_looked_up(tmp_path, lab, text, why):
    path = tmp_path / "bad.yaml"
    path.write_bytes(text.encode("latin-1") if text.startswith("\xff") else text.encode())
    result = run(tmp_path, path)
    assert result.exit_code == 2 and why in result.output, result.output
    assert lab[0].calls == [] and lab[1].calls == []


@pytest.mark.parametrize("seed", ["Jane Doe", "jane.doe@example.com", "+31 20 555 0123", "0612345678", "@janedoe", "janedoe", "Doe"])
def test_a_person_is_refused_as_a_seed(tmp_path, lab, engagement, seed):
    result = run(tmp_path, engagement, seed=seed)
    assert result.exit_code == 2 and "refused" in result.output
    assert lab[0].calls == [] and lab[1].calls == []
    assert refuse_person(seed)


def test_a_domain_outside_the_engagement_is_refused(tmp_path, lab, engagement):
    result = run(tmp_path, engagement, seed="example.net")
    assert result.exit_code == 2 and "not one of the engagement's domains" in result.output
    assert lab[0].calls == []
    with pytest.raises(EngagementError):
        check_seed("evil-example.com", load_engagement(engagement).engagement)


def test_the_attestation_must_be_confirmed(tmp_path, lab, engagement):
    result = runner.invoke(cli.app, ["exposure", "example.com", "--engagement", str(engagement), "--out", str(tmp_path / "out")])
    assert result.exit_code == 2 and "confirmed" in result.output
    assert lab[0].calls == []


def test_an_ordinary_scan_never_runs_the_exposure_modules():
    from scrutator.modules.registry import load_builtin_modules
    from scrutator.sources import SourcePolicy

    modules = load_builtin_modules()
    chosen, disabled = SourcePolicy().select(modules)
    assert not {m.name for m in chosen} & {"exposure_site", "exposure_dns", "exposure_rdap", "exposure_repos"}
    named, _ = SourcePolicy(allow=("exposure_site", "dns")).select(modules)  # naming it is not opting in
    assert "exposure_site" not in {m.name for m in named}


# ------------------------------------------------------------------------------------------- the run


def outputs(out):
    """Every file the run wrote, as text (bundle members included)."""
    texts = {}
    for path in out.iterdir():
        if path.suffix == ".scrutator":
            with zipfile.ZipFile(path) as bundle:
                for name in bundle.namelist():
                    texts[f"{path.name}/{name}"] = bundle.read(name).decode("utf-8", "replace")
        elif path.suffix in (".json", ".html"):
            texts[path.name] = path.read_text(encoding="utf-8")
    return texts


def test_the_lab_aggregate_is_right_and_holds_no_personal_data(tmp_path, lab, engagement, monkeypatch):
    monkeypatch.setattr(cli, "_signing_key", lambda key_dir: __import__("scrutator.bundle.keys", fromlist=["x"]).load_private_key(
        __import__("scrutator.bundle.keys", fromlist=["x"]).private_key_path(tmp_path / "keys")))
    generate_keypair(tmp_path / "keys")
    result = run(tmp_path, engagement, "--bundle")
    assert result.exit_code == 0, result.output
    out = tmp_path / "out"
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    org = report["org_exposure"]
    assert org["addresses"]["role"] == exposurelab.TRUTH["role"]
    assert org["addresses"]["person_like"] == exposurelab.TRUTH["person_like"]
    assert org["addresses"]["outside_engagement_dropped"] == exposurelab.TRUTH["outside"]
    assert org["functions"] == exposurelab.TRUTH["functions"]
    assert org["naming_patterns"][0]["shape"] == exposurelab.TRUTH["top_shape"]
    assert {i["kind"] for i in org["inferences"]} >= {"pattern", "finance", "it", "hr", "repos"}
    assert not (out / "exposure-detail.json").exists()
    # no personal data anywhere: report, HTML, every bundle member (the authoriser's name is the engagement record)
    for name, text in outputs(out).items():
        for planted in exposurelab.PERSONAL_EXCEPT_ENGAGEMENT:
            assert planted not in text, (name, planted)
    for planted in exposurelab.PERSONAL_EXCEPT_ENGAGEMENT:
        assert planted not in result.output, planted
    # and the database holds only minimised records too
    db = (out / "scrutator.db").read_bytes()
    for planted in exposurelab.PERSONAL_EXCEPT_ENGAGEMENT:
        assert planted.encode() not in db, planted


def test_nothing_leaves_the_engagement(tmp_path, lab, engagement):
    router, resolver = lab
    assert run(tmp_path, engagement).exit_code == 0
    hosts = {r.url.host for r in router.calls}
    assert hosts <= exposurelab.ALLOWED_HOSTS
    assert all(r.url.path.startswith(("/orgs/example-lab/", "/repos/example-lab/")) for r in router.calls if r.url.host == "api.github.com")
    assert all(name == "example.com" or name.endswith(".example.com") for name, _ in resolver.calls)
    assert "/blog/2026/post" not in {r.url.path for r in router.calls}  # robots.txt forbids it (and it is not a contact page)


def test_detail_is_separate_and_logged(tmp_path, lab, engagement):
    result = run(tmp_path, engagement, "--detail")
    assert result.exit_code == 0, result.output
    out = tmp_path / "out"
    detail = json.loads((out / "exposure-detail.json").read_text(encoding="utf-8"))
    addresses = {row["address"] for row in detail["addresses"]}
    assert {"jane.doe@example.com", "john.smith@example.com", "a.berg@example.com", "m.ross@example.com", "p.kim@example.com"} <= addresses
    assert not any("gmail" in a or "othercompany" in a for a in addresses)  # outside the engagement: never kept
    detail_text = json.dumps(detail)
    for never in ("555 0123", "12345678", "Main Street", "@annaberg", "Jane Doe"):
        assert never not in detail_text  # only work addresses, never phones, places, handles or names
    from scrutator.store import Store

    store = Store(out / "scrutator.db")
    events = [r for r in store.audit_log(1) if r.get("event") == "exposure_detail"]
    assert events and events[0]["addresses"] == len(detail["addresses"])
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert "jane.doe" not in json.dumps(report)


def test_the_engagement_is_in_the_audit_log_before_any_lookup_and_the_bundle_verifies(tmp_path, lab, engagement, monkeypatch):
    generate_keypair(tmp_path / "keys")
    from scrutator.bundle import keys as keys_module

    monkeypatch.setattr(cli, "_signing_key", lambda key_dir: keys_module.load_private_key(keys_module.private_key_path(tmp_path / "keys")))
    assert run(tmp_path, engagement, "--bundle", "--detail").exit_code == 0
    out = tmp_path / "out"
    pin = fingerprint(load_public_raw(tmp_path / "keys" / "signing.pub"))
    result = verify_bundle(out / "proof.scrutator", pinned_fingerprint=pin)
    assert result.ok, [(c.name, c.detail) for c in result.checks if not c.ok]
    names = {c.name for c in result.checks}
    assert {"engagement recorded", "org exposure derivable"} <= names
    with zipfile.ZipFile(out / "proof.scrutator") as bundle:
        audit = [json.loads(json.loads(line)["record"]) for line in bundle.read("audit.jsonl").decode().splitlines() if line.strip()]
        assert "jane.doe" not in bundle.read("report.json").decode()
    events = [r.get("event") for r in audit]
    assert events.index("engagement") < next(i for i, r in enumerate(audit) if r.get("module"))
    assert "exposure_detail" in events  # --detail is on the signed record
    engaged = audit[events.index("engagement")]
    assert engaged["sha256"] == load_engagement(engagement).sha256 and engaged["confirmed"] == "--yes"


def test_a_forged_aggregate_or_engagement_fails(tmp_path, lab, engagement, monkeypatch):
    generate_keypair(tmp_path / "keys")
    from scrutator.bundle import keys as keys_module

    monkeypatch.setattr(cli, "_signing_key", lambda key_dir: keys_module.load_private_key(keys_module.private_key_path(tmp_path / "keys")))
    assert run(tmp_path, engagement, "--bundle").exit_code == 0
    source = tmp_path / "out" / "proof.scrutator"
    for change, check in (
        (lambda r: r["org_exposure"]["addresses"].__setitem__("person_like", 0), "org exposure derivable"),
        (lambda r: r["engagement"].__setitem__("domains", ["example.com", "example.org"]), "engagement recorded"),
        (lambda r: r.pop("engagement"), "engagement recorded"),
    ):
        with zipfile.ZipFile(source) as src:
            files = {n: src.read(n) for n in src.namelist()}
        report = json.loads(files["report.json"])
        change(report)
        files["report.json"] = json.dumps(report).encode()
        forged = tmp_path / "forged.scrutator"
        with zipfile.ZipFile(forged, "w") as dst:
            for name, data in files.items():
                dst.writestr(name, data)
        result = verify_bundle(forged)
        assert check in {c.name for c in result.checks if not c.ok}, check


# ------------------------------------------------------------------------------------------- pure parts


def test_roles_and_shapes():
    assert role_function("security") == "security" and role_function("dmarc-reports") == "automation"
    assert role_function("billing.de") == "finance" and role_function("security-team") == "security"
    assert role_function("billing.jane.doe") is None  # a role word followed by a name is a person's address
    assert role_function("jane.doe") is None and role_function("it") == "it"
    assert shape("jane.doe") == "word.word" and shape("a.berg") == "initial.word" and shape("jdoe2") == "word+digits"
    assert shape("jane_doe+news") == "word_word"


def test_the_minimiser_keeps_no_person_and_drops_outsiders():
    detail: list = []
    m = Minimiser(lambda d: d == "example.com" or d.endswith(".example.com"), b"k" * 32, detail)
    reduced = m.reduce(["Jane.Doe@Example.com", "jane.doe@example.com", "info@example.com", "x@gmail.com", "not an address"], "here")
    assert reduced["outside_engagement"] == 1
    kinds = sorted(a["kind"] for a in reduced["addresses"])
    assert kinds == ["person", "role"]  # one person (seen twice), one role
    assert "jane" not in json.dumps(reduced)
    assert [(d["address"], d["found_at"]) for d in detail] == [("jane.doe@example.com", ["here"])]  # one row per address
    person = next(a for a in reduced["addresses"] if a["kind"] == "person")
    other = Minimiser(lambda d: True, b"j" * 32).reduce(["jane.doe@example.com"], "here")
    assert other["addresses"][0]["ref"] != person["ref"]  # a new key, a new pseudonym: runs cannot be linked


def test_breach_counts_keep_numbers_only():
    counts = breach_counts({"jane.doe": ["Adobe", "LinkedIn"], "info": ["Adobe"], "x": []})
    assert counts == {"addresses": 2, "breaches": 2}
    assert breach_counts("garbage") == {"addresses": 0, "breaches": 0}


def test_engagement_dates_are_checked_against_today(engagement):
    assert load_engagement(engagement, today=date(2027, 1, 1)).engagement.organisation.startswith("Example")
    with pytest.raises(EngagementError, match="not in force"):
        load_engagement(engagement, today=date(2031, 1, 1))
