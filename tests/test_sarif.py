import json

from riskbundlefix import make_risky_store

from scrutator.report import build_report
from scrutator.report.sarif import FINGERPRINT_KEY, SARIF_VERSION, to_sarif
from scrutator.risk.catalog import RULES
from scrutator.risk.engine import risk_from_dict


def sarif_of(store, sid):
    return to_sarif(build_report(store, sid))


def test_the_document_has_the_structure_sarif_2_1_0_requires():
    store, sid = make_risky_store()
    doc = sarif_of(store, sid)
    assert doc["version"] == SARIF_VERSION == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    (run,) = doc["runs"]
    driver = run["tool"]["driver"]
    assert driver["name"] == "Scrutator" and driver["version"]
    rule_ids = [rule["id"] for rule in driver["rules"]]
    assert rule_ids == sorted(set(rule_ids)) and set(rule_ids) == set(RULES)
    for rule in driver["rules"]:
        assert rule["shortDescription"]["text"] and rule["fullDescription"]["text"] and rule["help"]["text"]
        assert rule["defaultConfiguration"]["level"] in ("note", "warning", "error")
    assert json.loads(json.dumps(doc)) == doc  # plain JSON


def test_every_result_points_at_its_rule_and_names_its_entities_as_logical_locations():
    store, sid = make_risky_store()
    doc = sarif_of(store, sid)
    run = doc["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert len(run["results"]) == 3
    for result in run["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]
        assert result["message"]["text"]
        location = result["locations"][0]
        assert "physicalLocation" not in location
        assert location["logicalLocations"][0]["fullyQualifiedName"].startswith("domain:")
        assert result["properties"]["evidenceIds"] and result["properties"]["evidence"][0]["request"]
    claimable = next(r for r in run["results"] if r["ruleId"] == "dangling-cname-claimable")
    assert claimable["level"] == "error"
    assert claimable["locations"][0]["logicalLocations"][0]["name"] == "shop.example.com"
    assert claimable["relatedLocations"][0]["logicalLocations"][0]["name"] == "shop-demo.azurewebsites.net"
    levels = {r["ruleId"]: r["level"] for r in run["results"]}
    assert levels == {"dangling-cname-claimable": "error", "spf-allows-all": "error", "ghost-hostname": "note"}


def test_fingerprints_are_stable_across_scans_and_distinct_within_one():
    first = sarif_of(*make_risky_store())["runs"][0]["results"]
    second = sarif_of(*make_risky_store())["runs"][0]["results"]
    prints = [r["partialFingerprints"][FINGERPRINT_KEY] for r in first]
    assert prints == [r["partialFingerprints"][FINGERPRINT_KEY] for r in second]
    assert len(set(prints)) == len(prints) and all(len(p) == 32 for p in prints)


def test_the_fingerprint_survives_new_evidence_and_new_wording_but_not_a_new_entity():
    store, sid = make_risky_store()
    risks = build_report(store, sid)["risks"]
    reworded = [dict(r, explanation="different words", evidence_ids=["f" * 64]) for r in risks]
    base = {"tool": {"version": "x"}, "scan": {"id": 1, "seed": "example.com"}, "evidence": {}}
    again = to_sarif({**base, "risks": reworded})["runs"][0]["results"]
    assert [r["partialFingerprints"][FINGERPRINT_KEY] for r in again] == [r["fingerprint"] for r in risks]
    moved = risk_from_dict(dict(risks[0], entity_ids=["domain:other.example.com"]))
    assert moved.fingerprint != risks[0]["fingerprint"]


def test_a_report_without_risks_gives_an_empty_but_valid_run():
    doc = to_sarif({"tool": {"version": "x"}, "scan": {"id": 1, "seed": "example.com"}, "risks": []})
    assert doc["runs"][0]["results"] == [] and doc["runs"][0]["tool"]["driver"]["rules"]
