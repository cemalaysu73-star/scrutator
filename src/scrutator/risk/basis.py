"""How a finding was established: checked now by this tool, reported earlier by a third party, or both.

A pure function of the evidence a risk cites. It is shown beside every finding that rests on a connection check (`tcp`, `tls`,
`http` evidence) or on Shodan's earlier scan (`internetdb`), so a reader never mistakes a third party's old data for a check made
now, nor the reverse. It is derived at display time and is not part of the stored risk, so the risk records of earlier bundles
are unchanged.
"""

CHECKED_SOURCES = ("tcp", "tls", "http")
THIRD_PARTY = {"internetdb": "Shodan InternetDB"}


def basis(evidence_ids, evidence: dict) -> dict | None:
    """{"checked_at": ..., "third_party": [...]} (either key may be absent), or None for findings that rest on public records
    (DNS, registry, certificate logs) only."""
    checked = [evidence[i]["collected_at"] for i in evidence_ids if i in evidence and evidence[i].get("source") in CHECKED_SOURCES]
    third = sorted({THIRD_PARTY[evidence[i]["source"]] for i in evidence_ids if i in evidence and evidence[i].get("source") in THIRD_PARTY})
    found: dict = {}
    if checked:
        found["checked_at"] = max(checked)
    if third:
        found["third_party"] = third
    return found or None


def basis_text(found: dict | None) -> str:
    """The sentence shown to a reader (English; the audit has Turkish too, from its own text table)."""
    if not found:
        return ""
    who = ", ".join(found.get("third_party") or [])
    if "checked_at" in found and who:
        return f"Checked now ({found['checked_at']} UTC); also reported earlier by a third party ({who})."
    if "checked_at" in found:
        return f"Checked now: a connection check made by this tool at {found['checked_at']} UTC."
    return f"Reported earlier by a third party ({who}); not checked now."
