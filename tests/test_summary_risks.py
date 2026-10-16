import re

from llmfakes import ScriptedProvider
from riskbundlefix import make_risky_store

from scrutator.ai.runtime import AIRuntime
from scrutator.model import Confidence, Finding
from scrutator.report import build_report
from scrutator.verify.narrative import MAX_FINDINGS, MAX_RISKS, _select, summarise

CLAIMABLE = "Risk (high): CNAME to a claimable service that no longer exists."


def ref_for(user, text):
    return re.search(rf"(F\d+): {re.escape(text)}", user).group(1)


def runtime(writer, verifier):
    return AIRuntime(
        {
            "writer": ScriptedProvider(responder=writer, model="writer-model"),
            "verifier": ScriptedProvider(responder=verifier, model="verifier-model"),
        }
    )


async def test_risks_reach_the_writer_first_and_statements_about_them_are_verified():
    store, sid = make_risky_store()
    seen = {}

    def writer(system, user, schema):
        seen["user"] = user
        ref = ref_for(user, CLAIMABLE)
        return {
            "statements": [
                {"text": "shop.example.com points at an Azure host that does not exist.", "finding_refs": [ref]},
                {"text": "An attacker has already taken over shop.example.com.", "finding_refs": [ref]},
            ]
        }

    def verifier(system, user, schema):
        seen["verifier"] = user
        claim = user.split("Evidence:")[0]
        return {"supported": "already taken over" not in claim, "reason": "the evidence shows no takeover"}

    ai = runtime(writer, verifier)
    result = await summarise(ai, store, sid)

    assert [v.text for v in result.verified] == ["shop.example.com points at an Azure host that does not exist."]
    assert [r.text for r in result.rejected] == ["An attacker has already taken over shop.example.com."]
    listing = seen["user"]
    assert listing.index("Risk (high)") < listing.index("example.com has subdomain")  # risks lead the list
    assert "Risk (info): A certificate or archive names a host that DNS does not know." in listing
    assert "DNS A shop.example.com -> NXDOMAIN" in seen["verifier"]  # the verifier saw the evidence of absence

    report = build_report(store, sid)
    risk = next(r for r in report["risks"] if r["rule_id"] == "dangling-cname-claimable")
    (statement,) = report["summary_statements"]
    assert set(statement["evidence_ids"]) == set(risk["evidence_ids"])
    assert statement["confidence"] == risk["confidence"] == "high"
    assert [l["text"] for l in report["unverified_leads"]] == ["An attacker has already taken over shop.example.com."]


async def test_a_statement_citing_a_risk_that_does_not_exist_is_rejected():
    store, sid = make_risky_store()

    def writer(system, user, schema):
        return {"statements": [{"text": "Invented risk.", "finding_refs": ["F99"]}]}

    ai = runtime(writer, lambda s, u, sc: {"supported": True, "reason": ""})
    result = await summarise(ai, store, sid)
    assert result.verified == [] and "unknown finding F99" in result.rejected[0].reason


def finding(n, confidence=Confidence.LOW):
    return Finding(claim=f"claim {n:03d}", entity_ids=(), evidence_ids=("e" * 64,), confidence=confidence)


def test_selection_puts_risks_first_and_caps_both_groups():
    risks = [finding(n) for n in range(30)]
    relations = [finding(100 + n, Confidence.HIGH) for n in range(60)]
    chosen = _select(relations, risks)
    assert len(chosen) == MAX_FINDINGS
    assert chosen[:MAX_RISKS] == risks[:MAX_RISKS]
    assert all(f.claim.startswith("claim 1") for f in chosen[MAX_RISKS:])  # the high-confidence relations follow
    assert _select(relations) == _select(relations, None) and len(_select(relations)) == MAX_FINDINGS
