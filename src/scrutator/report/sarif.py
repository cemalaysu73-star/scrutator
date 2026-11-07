"""SARIF 2.1.0 export of the risks in a report.

SARIF is built for findings in files. Scrutator's findings are about DNS names, so each entity is
a *logical* location (a name), not a file; results carry no physical location. Viewers that need
a file position (GitHub code scanning does) must be given one by the integration that uploads
the file; that belongs to the CI integration planned for a later version.

Each result has a stable `partialFingerprints` entry (rule plus entities, not wording or
evidence), so a later run can recognise the same finding and update its ticket instead of
opening a new one.
"""

import re

from scrutator.risk.basis import basis, basis_text
from scrutator.risk.catalog import RULES

SARIF_VERSION = "2.1.0"
SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
FINGERPRINT_KEY = "scrutatorRisk/v1"

_LEVEL = {"info": "note", "low": "note", "medium": "warning", "high": "error"}
# GitHub code scanning reads a numeric rating from this property to order results
_SECURITY_SEVERITY = {"info": "1.0", "low": "3.0", "medium": "5.5", "high": "8.0"}


def _camel(rule_id: str) -> str:
    return "".join(part.capitalize() for part in re.split(r"[-_]", rule_id))


def _rules() -> list[dict]:
    return [
        {
            "id": info.rule_id,
            "name": _camel(info.rule_id),
            "shortDescription": {"text": info.title},
            "fullDescription": {"text": info.description},
            "help": {"text": info.remediation},
            "defaultConfiguration": {"level": _LEVEL[info.severity.value]},
            "properties": {
                "category": info.category,
                "tags": ["scrutator", info.category],
                "security-severity": _SECURITY_SEVERITY[info.severity.value],
            },
        }
        for info in sorted(RULES.values(), key=lambda i: i.rule_id)
    ]


def _logical(entity_id: str) -> dict:
    kind, _, value = entity_id.partition(":")
    return {"name": value or entity_id, "fullyQualifiedName": entity_id, "kind": "resource", "properties": {"entityType": kind}}


def to_sarif(report: dict) -> dict:
    rules = _rules()
    index = {rule["id"]: n for n, rule in enumerate(rules)}
    evidence = report.get("evidence", {})
    results = []
    for risk in report.get("risks", []):
        entities = risk["entity_ids"]
        result = {
            "ruleId": risk["rule_id"],
            "ruleIndex": index[risk["rule_id"]],
            "level": _LEVEL[risk["severity"]],
            "message": {"text": f"{risk['title']}. {risk['explanation']}"},
            "partialFingerprints": {FINGERPRINT_KEY: risk["fingerprint"]},
            "properties": {
                "severity": risk["severity"],
                "confidence": risk["confidence"],
                "category": risk["category"],
                "remediation": risk["remediation"],
                "evidenceIds": list(risk["evidence_ids"]),
                "evidence": [
                    {"id": i, "source": evidence[i]["source"], "request": evidence[i]["request"]}
                    for i in risk["evidence_ids"]
                    if i in evidence
                ],
                "security-severity": _SECURITY_SEVERITY[risk["severity"]],
            },
        }
        found = basis(risk["evidence_ids"], evidence)
        if found:  # checked now by this tool, reported earlier by a third party, or both
            result["properties"]["basis"] = basis_text(found)
        if entities:
            result["locations"] = [{"logicalLocations": [_logical(entities[0])]}]
            if len(entities) > 1:
                result["relatedLocations"] = [
                    {"id": n, "logicalLocations": [_logical(entity)]} for n, entity in enumerate(entities[1:], start=1)
                ]
        results.append(result)
    return {
        "$schema": SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {"driver": {"name": "Scrutator", "version": report["tool"]["version"], "rules": rules}},
                "invocations": [{"executionSuccessful": True}],
                "properties": {
                    "scanId": report["scan"]["id"],
                    "seed": report["scan"]["seed"],
                    "packs": report.get("packs", {}).get("effective_sha256"),
                },
                "results": results,
            }
        ],
    }
