import base64
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from scrutator.attribution import RULESET_VERSION as ATTRIBUTION_RULESET
from scrutator.attribution import attribute
from scrutator.bundle.keys import fingerprint, verify_signature
from scrutator.bundle.reader import BundleError, read_raw
from scrutator.exposure import exposure
from scrutator.findings import findings_from_report, summarise_findings
from scrutator.names import headline, name_states, summarise_states, summarise_tiers
from scrutator.packs import KINDS, PackSet, load_packs
from scrutator.modules.registry import load_builtin_modules
from scrutator.report.build import promotions
from scrutator.risk.engine import RULESET_VERSION, analyze
from scrutator.sources import SourcePolicy
from scrutator.store import GENESIS_HASH, chain_hash

_DATA_FILES = {"report.json", "evidence.jsonl", "audit.jsonl"}


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class VerifyReport:
    checks: list[Check] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    key_fingerprint: str = ""

    @property
    def ok(self) -> bool:
        return bool(self.checks) and all(c.ok for c in self.checks)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _jsonl(data: bytes) -> list[dict]:
    rows = []
    for line in data.decode("utf-8").splitlines():
        if line.strip():
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError("a line is not a JSON object")
            rows.append(value)
    return rows


def _trusted_packs() -> PackSet:
    """This tool's own bundled packs, the reference a bundle's embedded packs are compared with."""
    return load_packs()


def _packs_problem(report: dict, warnings: list[str]) -> str:
    """Why the packs embedded in the report cannot be trusted, or an empty string.

    The embedded entries are what the risk rules ran on, so they are checked three ways: they
    must hash to what the report declares; bundled pack files must carry the content hash of
    this tool's copy of the same version; and without user packs the merged content must equal
    this tool's. With user packs the merged content cannot be matched to a trusted copy, but a
    bundled entry may still not be removed. A bundle made with other pack versions than this
    tool ships is accepted with a warning: there is nothing to compare it with."""
    declared = PackSet.from_dict(report["packs"])
    if declared.effective_sha256 != report["packs"]["effective_sha256"]:
        return "the pack entries do not match the hash the report declares for them"
    trusted = _trusted_packs()
    ours = {(f["name"], f["kind"]): f for f in trusted.files if f["origin"] == "bundled"}
    user_files, uncomparable = False, False
    for item in declared.files:
        if item["origin"] != "bundled":
            user_files = True
            continue
        mine = ours.get((item["name"], item["kind"]))
        if mine is None or mine["version"] != item["version"]:
            uncomparable = True
        elif mine["content_sha256"] != item["content_sha256"]:
            return f"{item['name']} differs from this tool's bundled pack of the same version"
    if uncomparable:
        warnings.append(
            "the bundle was made with other bundled pack versions than this tool ships, so its pack "
            "content could not be compared with a trusted copy."
        )
        return ""
    if user_files:
        have, want = declared.effective(), trusted.effective()
        for kind in KINDS:
            missing = {e["id"] for e in want[kind]} - {e["id"] for e in have[kind]}
            if missing:
                return f"bundled {kind} entries were removed: {sorted(missing)[:3]}"
        warnings.append("the bundle includes user packs, which cannot be compared with a trusted copy; the signer is vouching for them.")
    elif declared.effective_sha256 != trusted.effective_sha256:
        return "the pack content differs from this tool's bundled packs"
    return ""


def _analysis_problem(manifest: dict, report: dict, warnings: list[str]) -> tuple[str, bool]:
    """Does the manifest's record of the analysis match the report? Returns the problem (empty
    if none) and whether the risks can be re-derived by this tool. Re-deriving is attempted even
    when the record disagrees, so one forgery shows up in every check it breaks."""
    analysis = manifest.get("analysis")
    complete = all(key in report for key in ("risks", "dependencies", "packs"))
    if analysis is None:
        return "", complete
    if not complete:
        return "the manifest records a risk analysis but the report has none", False
    problem = ""
    recorded = [
        {k: item[k] for k in ("name", "kind", "version", "origin", "content_sha256")}
        for item in report["packs"]["files"]
    ]
    if analysis.get("packs") != recorded or analysis.get("effective_sha256") != report["packs"]["effective_sha256"]:
        problem = "the manifest and the report disagree about the packs used"
    elif analysis.get("risks") != len(report["risks"]):
        problem = "the manifest and the report disagree about the number of risks"
    if "attribution" in report:
        recorded_attribution = analysis.get("attribution")
        if not isinstance(recorded_attribution, dict):
            problem = problem or "the report has an attribution but the manifest records none"
        elif recorded_attribution.get("candidates") != len(report["attribution"]["candidates"]) or recorded_attribution.get("ruleset") != report["attribution"].get("ruleset"):
            problem = problem or "the manifest and the report disagree about the attribution"
    comparable = analysis.get("ruleset") == RULESET_VERSION
    if not comparable:
        warnings.append(
            f"the risks were made by rule set {analysis.get('ruleset')}; this tool implements "
            f"{RULESET_VERSION}, so they were not re-derived."
        )
    return problem, comparable


def _policy_problem(manifest: dict, report: dict, audit_records: list[dict], evidence_rows: list[dict]) -> str:
    """Does the bundle respect the source policy it records? The policy is in the report, the signed manifest and
    the first record of the signed audit log; the three must agree, and no lookup of a source the policy forbids
    may appear in the audit log or the evidence. What is forbidden is re-derived from the recorded flags with this
    tool's own module list (the recorded `disabled` list is trusted only to widen it, never to narrow it).
    A bundle with no policy anywhere predates v0.7 and is not checked."""
    recorded = [r for r in audit_records if r.get("event") == "source_policy"]
    in_report, in_manifest = report.get("source_policy"), manifest.get("source_policy")
    if not recorded and not in_report and not in_manifest:
        return ""
    if len(recorded) != 1 or audit_records.index(recorded[0]) != 0:
        return "the signed audit log does not open with exactly one source policy record"
    logged = {k: v for k, v in recorded[0].items() if k != "event"}
    if in_report != logged:
        return "the report's source policy is not the one in the signed audit log"
    if in_manifest != logged:
        return "the manifest's source policy is not the one in the signed audit log"
    policy = SourcePolicy.from_dict(logged)
    forbidden = policy.restricted(load_builtin_modules()) | set(logged.get("disabled", {}))
    ran = sorted({r["module"] for r in audit_records if r.get("module") in forbidden})
    # evidence of the DNS resolver and of the wildcard probe both carry the source name "dns"
    produced = sorted({row["source"] for row in evidence_rows if row.get("source") in forbidden - {"dns"}})
    if ran or produced:
        return "the scan used sources its own policy forbids: " + ", ".join(sorted({*ran, *produced}))
    return ""


def verify_bundle(path: str | Path, *, pinned_fingerprint: str | None = None) -> VerifyReport:
    """Check every layer of a bundle independently. A failure in one layer does not hide
    the others, so the output says exactly what was altered."""
    result = VerifyReport()

    def add(name: str, ok: bool, detail: str = "") -> None:
        result.checks.append(Check(name, ok, detail))

    try:
        raw = read_raw(path)
    except BundleError as exc:
        add("readable bundle", False, str(exc))
        return result
    add("readable bundle", True)

    try:
        manifest = json.loads(raw.files["manifest.json"])
        if not isinstance(manifest, dict):
            raise ValueError("manifest is not an object")
        add("manifest parses", True)
    except ValueError as exc:
        add("manifest parses", False, str(exc))
        return result

    problems = []
    declared = manifest.get("files")
    if not isinstance(declared, dict) or set(declared) != _DATA_FILES:
        problems.append("the manifest does not list exactly the three data files")
    else:
        for name, info in declared.items():
            data = raw.files[name]
            if not isinstance(info, dict) or info.get("sha256") != _sha256(data) or info.get("bytes") != len(data):
                problems.append(f"{name} does not match the manifest")
    add("file hashes", not problems, "; ".join(problems))

    public = b""
    try:
        public = base64.b64decode(manifest["public_key"], validate=True)
        signature = base64.b64decode(raw.files["manifest.sig"].strip(), validate=True)
        valid = verify_signature(public, signature, raw.files["manifest.json"])
    except (KeyError, ValueError, TypeError):
        valid = False
    add("signature valid", valid, "" if valid else "manifest.sig does not match manifest.json and the embedded key")
    result.key_fingerprint = fingerprint(public) if len(public) == 32 else ""
    if manifest.get("key_fingerprint") != result.key_fingerprint:
        add("key fingerprint", False, "the manifest's key_fingerprint does not match its public key")

    if pinned_fingerprint is not None:
        wanted = pinned_fingerprint.strip().lower().removeprefix("sha256:")
        pinned_ok = valid and result.key_fingerprint == wanted
        add("signing key pinned", pinned_ok, "" if pinned_ok else f"signed by {result.key_fingerprint or 'an unreadable key'}, not {wanted}")
    else:
        result.warnings.append(
            "signing key is not pinned: a valid signature only proves the bundle matches the key inside "
            "it, and anyone can sign a forged bundle with their own key. Pin the signer with --pin."
        )

    # audit chain
    audit_records: list[dict] = []
    try:
        previous, expected, bad = GENESIS_HASH, 1, ""
        for row in _jsonl(raw.files["audit.jsonl"]):
            if row["seq"] != expected or row["prev_hash"] != previous:
                bad = f"record {expected} does not follow the previous one"
                break
            if chain_hash(previous, row["record"]) != row["hash"]:
                bad = f"record {expected} was altered"
                break
            audit_records.append(json.loads(row["record"]))
            previous, expected = row["hash"], expected + 1
        add("audit chain", not bad, bad)
    except (ValueError, KeyError, TypeError) as exc:
        add("audit chain", False, f"malformed audit log: {exc}")

    # evidence content addressing
    evidence_ids: set[str] = set()
    evidence_rows: list[dict] = []
    try:
        bad_ids = []
        for row in _jsonl(raw.files["evidence.jsonl"]):
            evidence_rows.append(row)
            expected_id = _sha256(f"{row['source']}\n{row['request']}\n{row['payload']}".encode())
            if row["id"] != expected_id:
                bad_ids.append(str(row["id"])[:12])
            evidence_ids.add(row["id"])
        add("evidence hashes", not bad_ids, f"altered records: {', '.join(bad_ids[:5])}" if bad_ids else "")
    except (ValueError, KeyError, TypeError) as exc:
        add("evidence hashes", False, f"malformed evidence: {exc}")

    # the report and what it cites
    try:
        report = json.loads(raw.files["report.json"])
        cited: set[str] = set()
        for finding in report["findings"]:
            cited.update(finding["evidence_ids"])
        for edge in report["edges"]:
            cited.update(edge["evidence_ids"])
        for statement in report["summary_statements"]:
            cited.update(statement["evidence_ids"])
        for risk in report.get("risks", []):
            cited.update(risk["evidence_ids"])
        for candidate in report.get("attribution", {}).get("candidates", []):
            cited.update(candidate["evidence_ids"])
            for signal in candidate["signals"]:
                cited.update(signal["evidence_ids"])
            for note in candidate["premortem"]:
                cited.update(note["evidence_ids"])
        for row in report.get("exposure", []):
            cited.update(row["evidence_ids"])
        for row in report.get("names", []):
            cited.update(row["evidence_ids"])
        leads = [*report.get("leads", {}).get("verified", []), *report.get("leads", {}).get("rejected", [])]
        unknown_entities = sorted({e for lead in leads for e in lead["entity_ids"]} - {e["id"] for e in report["entities"]})
        for lead in leads:
            cited.update(lead["evidence_ids"])
        missing = sorted(cited - evidence_ids)
        also_missing = sorted(cited - set(report["evidence"]))
        if missing or also_missing:
            detail = f"{len(set(missing + also_missing))} cited evidence record(s) are not in the bundle"
        elif unknown_entities:
            detail = f"a lead is about an entity the report does not have ({unknown_entities[0]})"
        else:
            detail = ""
        add("report references", not detail, detail)
        legacy = bool(report["findings"]) and "tier" not in report["findings"][0]  # made before v0.7
        try:
            derivable = findings_from_report(report, tiered=not legacy) == report["findings"]
            why = "" if derivable else "the findings are not what the cited evidence implies"
        except Exception as exc:  # noqa: BLE001 - the tiers read every DNS record in the bundle, which is untrusted
            derivable, why = False, f"malformed evidence: {type(exc).__name__}: {exc}"
        add("findings derivable", derivable, why)
        same_scan = report["scan"]["seed"] == manifest["scan"]["seed"]
        add("scan identity", same_scan, "" if same_scan else "the report is for a different scan than the manifest")
    except (ValueError, KeyError, TypeError) as exc:
        add("report references", False, f"malformed report: {exc}")
        return result

    # the risk analysis: recorded in the manifest, built on trusted packs, re-derivable from the report
    try:
        problem, derivable_here = _analysis_problem(manifest, report, result.warnings)
        add("analysis recorded", not problem, problem)
        if "packs" in report:
            problem = _packs_problem(report, result.warnings)
            add("packs intact", not problem, problem)
        if derivable_here and "packs" in report:
            same = analyze(report) == {"risks": report["risks"], "dependencies": report["dependencies"]}
            add("risks derivable", same, "" if same else "the risks are not what the cited evidence and the packs imply")
        elif manifest.get("analysis") is None and "risks" not in report:
            add("risks derivable", True, "bundle predates risk analysis")
    except Exception as exc:  # noqa: BLE001 - a bundle is untrusted input; whatever it breaks, the check fails
        add("risks derivable", False, f"malformed risk analysis: {type(exc).__name__}: {exc}")

    # what is known about the addresses: re-derived from the report's own evidence
    try:
        if "exposure" in report:
            same = exposure(report) == report["exposure"]
            add("exposure derivable", same, "" if same else "the address table is not what the cited evidence implies")
    except Exception as exc:  # noqa: BLE001
        add("exposure derivable", False, f"malformed exposure: {type(exc).__name__}: {exc}")

    # the resolution state and the tier of each name: re-derived from the report's own evidence
    try:
        if "names" in report:
            legacy = bool(report["names"]) and "tier" not in report["names"][0]  # made before v0.7
            same = name_states(report, tiered=not legacy) == report["names"]
            add("name states derivable", same, "" if same else "the name states and tiers are not what the cited evidence implies")
    except Exception as exc:  # noqa: BLE001
        add("name states derivable", False, f"malformed name states: {type(exc).__name__}: {exc}")

    # the numbers a reader quotes (verified and claimed names, findings per tier) are recounted, not trusted
    try:
        summary = report.get("summary", {})
        if "tiers" in summary:
            rows = name_states(report)
            tiers = summarise_tiers(rows)
            counted = summarise_findings(findings_from_report(report, names=rows))
            problems = []
            if summary.get("tiers") != tiers or summary.get("headline") != headline(tiers):
                problems.append("the headline counts of names")
            if summary.get("names") != summarise_states(rows):
                problems.append("the name state counts")
            if summary.get("findings_by_tier") != counted or summary.get("findings") != len(report["findings"]):
                problems.append("the finding counts")
            add("headline derivable", not problems, "" if not problems else "not what the evidence implies: " + ", ".join(problems))
    except Exception as exc:  # noqa: BLE001
        add("headline derivable", False, f"malformed summary: {type(exc).__name__}: {exc}")

    # the source policy: recorded three times, and the lookups and evidence must not contradict it
    try:
        problem = _policy_problem(manifest, report, audit_records, evidence_rows)
        if report.get("source_policy") or manifest.get("source_policy") or any(r.get("event") == "source_policy" for r in audit_records):
            add("source policy honoured", not problem, problem)
    except Exception as exc:  # noqa: BLE001
        add("source policy honoured", False, f"malformed source policy: {type(exc).__name__}: {exc}")

    # attribution: re-derived from the report's own evidence, like the risks
    try:
        if "attribution" in report and "packs" in report:
            recorded = (manifest.get("analysis") or {}).get("attribution") or {}
            if recorded.get("ruleset", ATTRIBUTION_RULESET) != ATTRIBUTION_RULESET:
                result.warnings.append(
                    f"the attribution was made by rule set {recorded.get('ruleset')}; this tool implements "
                    f"{ATTRIBUTION_RULESET}, so it was not re-derived."
                )
            else:
                same = attribute(report) == report["attribution"]
                add("attribution derivable", same, "" if same else "the attribution is not what the cited evidence and the packs imply")
        elif "attribution" not in report:
            add("attribution derivable", True, "bundle predates attribution")
        if "promotions" in report:
            problem = ""
            states = {e["id"]: e["state"] for e in report["entities"]}
            if report["promotions"] != promotions(audit_records):
                problem = "the report's promotions are not the ones recorded in the signed audit log"
            elif any(states.get(p["entity"]) != "in" for p in report["promotions"]):
                problem = "a promoted entity is not in scope in the report"
            add("promotions recorded", not problem, problem)
    except Exception as exc:  # noqa: BLE001
        add("attribution derivable", False, f"malformed attribution: {type(exc).__name__}: {exc}")
    return result
