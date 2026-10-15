import re

import httpx
import respx
from llmfakes import ScriptedProvider
from test_e2e import RECORDS, mock_internet

from scrutator.ai.redact import Redactor
from scrutator.ai.runtime import AIRuntime
from scrutator.model import Entity, EntityType
from scrutator.report import build_report
from scrutator.scan import run_scan
from scrutator.scope import ScopePolicy
from scrutator.store import Store
from scrutator.verify.narrative import summarise

SEED = Entity(type=EntityType.DOMAIN, value="example.com")
SUB = "example.com has subdomain www.example.com"


def ref_for(user, claim):
    return re.search(rf"(F\d+): {re.escape(claim)}", user).group(1)


def planner(system, user, schema):
    return {"choices": [0], "hypothesis": "more names exist"} if schema["title"] == "Ranking" else {"settled": []}


def writer(system, user, schema):
    return {
        "statements": [
            {"text": "The root domain has a www subdomain, seen in two sources.", "finding_refs": [ref_for(user, SUB)]},
            {"text": "The company runs a secret data centre in Oslo.", "finding_refs": [ref_for(user, SUB)]},
            {"text": "An invented citation.", "finding_refs": ["F999"]},
        ]
    }


def verifier(system, user, schema):
    return {"supported": "Oslo" not in user, "reason": "the evidence says nothing about Oslo"}


async def test_scan_with_ai_produces_a_verified_summary_and_rejects_inventions(make_ctx):
    ctx = make_ctx(RECORDS)
    store = Store(":memory:")
    ai = AIRuntime(
        {
            "planner": ScriptedProvider(responder=planner, model="planner-model"),
            "writer": ScriptedProvider(responder=writer, model="writer-model"),
            "verifier": ScriptedProvider(responder=verifier, model="verifier-model"),
        }
    )
    with respx.mock() as router:
        mock_internet(router)
        scan_id, stats = await run_scan(SEED, ScopePolicy(domains=["example.com"]), store, ctx, ai=ai)
    result = await summarise(ai, store, scan_id)

    assert [v.text for v in result.verified] == ["The root domain has a www subdomain, seen in two sources."]
    assert result.verified[0].confidence.value == "medium"
    assert len(result.rejected) == 2
    report = build_report(store, scan_id, ai_info=ai.describe())
    assert [s["text"] for s in report["summary_statements"]] == [v.text for v in result.verified]
    assert {l["text"] for l in report["unverified_leads"]} == {"The company runs a secret data centre in Oslo.", "An invented citation."}
    assert report["ai"]["providers"]["planner"]["local"] is True
    assert report["egress"] == []
    assert report["sources"]["crtsh"]["ok"] >= 1
    assert store.verify_audit(scan_id)


async def test_cloud_run_pseudonymises_everything_that_leaves_and_logs_it(make_ctx):
    ctx = make_ctx(RECORDS)
    store = Store(":memory:")

    def cloud_writer(system, user, schema):
        ref = ref_for(user, "d1.example has subdomain www.d1.example")
        return {"statements": [{"text": "d1.example has the subdomain www.d1.example.", "finding_refs": [ref]}]}

    providers = {
        "planner": ScriptedProvider(responder=planner, is_local=False, name="anthropic"),
        "writer": ScriptedProvider(responder=cloud_writer, is_local=False, name="anthropic"),
        "verifier": ScriptedProvider(responder=lambda s, u, sc: {"supported": True, "reason": ""}, is_local=False, name="openai"),
    }
    ai = AIRuntime(providers, redactor=Redactor(["example.com"]))
    with respx.mock() as router:
        mock_internet(router)
        scan_id, _ = await run_scan(SEED, ScopePolicy(domains=["example.com"]), store, ctx, ai=ai)
    result = await summarise(ai, store, scan_id)

    assert result.verified[0].text == "example.com has the subdomain www.example.com."
    for provider in providers.values():
        for call in provider.calls:
            assert "example.com" not in call["system"] + call["user"]
    log = store.egress_log(scan_id)
    assert len(log) >= 2 and all(row["redacted"] for row in log)
    assert {row["role"] for row in log} >= {"writer", "verifier"}


async def test_scan_without_ai_still_works_and_reports_source_health(make_ctx):
    ctx = make_ctx(RECORDS)
    store = Store(":memory:")
    with respx.mock() as router:
        mock_internet(router)
        router.get("https://web.archive.org/cdx/search/cdx").mock(return_value=httpx.Response(503))
        scan_id, _ = await run_scan(SEED, ScopePolicy(domains=["example.com"]), store, ctx)
    report = build_report(store, scan_id)
    assert report["sources"]["wayback"]["error"] >= 1
    assert report["summary_statements"] == [] and report["ai"] is None
