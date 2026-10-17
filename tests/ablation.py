"""The playbook ablation: the same investigation of the planted lab, with a stand-in planner, once
with the knowledge packs' playbooks in its prompt and once without.

The stand-in planner is deterministic and obeys guidance the way a model asked to would: it ranks
the options whose module the playbooks' `(lookups: ...)` lines name first, in the order named, and
leaves everything else in the listed order. Without guidance there is nothing to obey, so it
returns the listed order, which is what the deterministic fallback does. The difference between the
two runs therefore shows that retrieval reaches the prompt and changes what the agent does within a
fixed budget. It does not show that a real model benefits: that needs the real-model ablation the
v1.0 benchmark publishes.
"""

import re

from attrlab import run_lab
from llmfakes import ScriptedProvider

from scrutator.ai.runtime import AIRuntime

BUDGETS = (8, 10, 14, 24)
PUBLISHED = {
    # lookup budget: (names resolved, risks found) without playbooks, then with them
    8: ((1, 1), (6, 2)),
    10: ((1, 1), (8, 3)),
    14: ((4, 2), (8, 3)),
    24: ((8, 3), (8, 3)),
}
OPTION = re.compile(r"^(\d+): (\w+) on (\w+) (\S+)$", re.M)
LOOKUPS = re.compile(r"\(lookups: ([^)]*)\)")


def planner(system, user, schema):
    if schema["title"] != "Ranking":
        return {"settled": []}
    preferred: list[str] = []
    for line in LOOKUPS.findall(user):
        for module in (m.strip() for m in line.split(",")):
            if module not in preferred:
                preferred.append(module)
    options = [(int(index), module) for index, module, _, _ in OPTION.findall(user)]
    rank = lambda module: preferred.index(module) if module in preferred else len(preferred)  # noqa: E731
    order = sorted(options, key=lambda option: (rank(option[1]), option[0]))
    return {"choices": [index for index, _ in order], "hypothesis": ""}


async def investigate(http, tmp_path, *, playbooks: bool, max_steps: int) -> dict:
    """Run the agent on the lab for `max_steps` lookups, without attribution, and measure it."""
    ai = AIRuntime({"planner": ScriptedProvider(responder=planner, model="stand-in")})
    lab = await run_lab(http, tmp_path, attribution=False, ai=ai, playbooks=playbooks, max_steps=max_steps)
    audit = lab.store.audit_log(lab.scan_id)
    done = [r for r in audit if r["event"] == "ok"]
    return {
        "lookups": len(done),
        "names_resolved": len({r["entity"] for r in done if r["module"] == "dns"}),
        "rounds_with_playbooks": sum(1 for r in audit if r["event"] == "playbooks"),
        "risks": len(lab.report["risks"]),
        "risk_rules": sorted({r["rule_id"] for r in lab.report["risks"]}),
    }
