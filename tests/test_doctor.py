import re

from llmfakes import ScriptedProvider

from scrutator.ai.doctor import render_doctor, run_doctor
from scrutator.ai.runtime import AIRuntime


def good(system, user, schema):
    title = schema["title"]
    if title == "Answer":
        return {"answer": 7}
    if title == "Ranking":
        match = re.search(r"(\d+): crtsh on", user)
        return {"choices": [int(match.group(1))], "hypothesis": "certificates reveal names"}
    if title == "Entailment":
        claim = re.search(r"Claim:\n<data>\n(.*?)\n</data>", user, re.S).group(1)
        evidence = re.search(r"Evidence:\n<data>\n(.*?)\n</data>", user, re.S).group(1)
        return {"supported": "192.0.2.10" in claim and "192.0.2.10" in evidence, "reason": "matches"}
    if title == "Narrative":
        return {"statements": [{"text": "www resolves.", "finding_refs": ["F1"]}]}
    raise AssertionError(title)


def runtime(responder):
    return AIRuntime({role: ScriptedProvider(responder=responder) for role in ("planner", "verifier", "writer")})


async def test_a_capable_model_passes_every_case():
    report = await run_doctor(runtime(good))
    assert report.passed
    assert set(report.results) == {"planner", "verifier", "writer"}
    assert all(r.passed for rs in report.results.values() for r in rs)
    text = render_doctor(report)
    assert "planner" in text and "verifier" in text and "writer" in text and "PASS" in text


async def test_a_gullible_verifier_fails_the_unsupported_and_injection_cases():
    def gullible(system, user, schema):
        if schema["title"] == "Entailment":
            return {"supported": True, "reason": "sure"}
        return good(system, user, schema)

    report = await run_doctor(runtime(gullible))
    assert not report.passed
    failed = [r.name for r in report.results["verifier"] if not r.passed]
    assert set(failed) == {"unsupported value", "unsupported extra detail", "injected instruction"}
    assert all(r.passed for r in report.results["planner"])
    assert "FAIL" in render_doctor(report)


async def test_unusable_output_fails_the_case_instead_of_crashing():
    def broken(system, user, schema):
        return {"nonsense": True}

    report = await run_doctor(runtime(broken))
    assert not report.passed
    assert all(not r.passed for rs in report.results.values() for r in rs)


async def test_only_configured_roles_are_tested():
    ai = AIRuntime({"planner": ScriptedProvider(responder=good)})
    report = await run_doctor(ai)
    assert set(report.results) == {"planner"}
    assert report.passed
