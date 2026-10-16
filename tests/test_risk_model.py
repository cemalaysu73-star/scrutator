import pytest
from pydantic import ValidationError

from scrutator.model import Confidence
from scrutator.risk.model import Risk, Severity, severity_at_least


def risk(**over):
    fields = dict(
        rule_id="dangling-cname",
        severity=Severity.HIGH,
        category="risk",
        title="Dangling CNAME",
        entity_ids=("domain:b.example.com", "domain:a.example.com"),
        evidence_ids=("e" * 64,),
        explanation="a.example.com is an alias of x, which does not exist.",
        remediation="Remove the record.",
        confidence=Confidence.HIGH,
    )
    fields.update(over)
    return Risk(**fields)


def test_a_risk_without_evidence_cannot_exist():
    with pytest.raises(ValidationError):
        risk(evidence_ids=())


def test_unknown_severity_and_category_are_rejected():
    with pytest.raises(ValidationError):
        risk(severity="urgent")
    with pytest.raises(ValidationError):
        risk(category="other")


def test_the_fingerprint_follows_the_rule_and_the_entities_only():
    base = risk()
    assert base.fingerprint == risk(entity_ids=("domain:a.example.com", "domain:b.example.com")).fingerprint
    assert base.fingerprint == risk(evidence_ids=("f" * 64,), explanation="other words", severity=Severity.LOW).fingerprint
    assert base.fingerprint != risk(rule_id="spf-allows-all").fingerprint
    assert base.fingerprint != risk(entity_ids=("domain:a.example.com",)).fingerprint
    assert len(base.fingerprint) == 32


def test_the_dictionary_form_is_complete_and_plain_json():
    data = risk().to_dict()
    assert data["severity"] == "high" and data["confidence"] == "high" and data["category"] == "risk"
    assert data["entity_ids"] == ["domain:b.example.com", "domain:a.example.com"]
    assert data["fingerprint"] == risk().fingerprint
    assert set(data) == {
        "rule_id", "severity", "category", "title", "entity_ids", "evidence_ids",
        "explanation", "remediation", "confidence", "fingerprint",
    }


def test_a_risk_becomes_a_finding_with_the_same_evidence():
    finding = risk().as_finding()
    assert finding.evidence_ids == ("e" * 64,)
    assert finding.claim.startswith("Risk (high): Dangling CNAME.")
    assert "does not exist" in finding.claim


def test_severities_order_and_compare():
    assert [s.rank for s in (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH)] == [0, 1, 2, 3]
    assert severity_at_least("high", "medium") and severity_at_least("medium", "medium")
    assert not severity_at_least("low", "medium")
    ordered = sorted([risk(severity=Severity.LOW), risk(severity=Severity.HIGH, rule_id="b"), risk(severity=Severity.HIGH, rule_id="a")], key=lambda r: r.sort_key)
    assert [(r.severity.value, r.rule_id) for r in ordered] == [("high", "a"), ("high", "b"), ("low", "dangling-cname")]
