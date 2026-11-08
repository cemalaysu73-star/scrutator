"""Risks from the organisation phase (`scan --org`): pure functions of the report's organisation evidence and scope.

- `breach-history`: a public index names a breach of a service under the organisation's domain (info; low when the data
  is sensitive). Metadata only; it is history, not a live finding.
- `exposed-credential`: `--code-leaks` matched a credential format in the organisation's own public repository. High.
- `brand-namespace-unregistered`: the brand name is free on a public package registry (info; dependency-confusion note).
- `lookalike-package-exists`: a look-alike of the brand name exists on a registry and is not linked to the organisation
  (low).

The remediation text of each is fixed in the catalogue; the explanation states only what the cited evidence shows.
"""

from scrutator.model import Confidence
from scrutator.org.section import organisation
from scrutator.risk.catalog import make
from scrutator.risk.model import Risk, Severity


def org_risks(report: dict) -> list[Risk]:
    section = organisation(report)
    if section is None:
        return []
    seed = str(report.get("scan", {}).get("seed", "")) or "the organisation"
    risks: list[Risk] = []

    for breach in section["breaches"]:
        if not breach.get("evidence_id"):
            continue
        classes = ", ".join(breach.get("data_classes", [])[:8]) or "unlisted data"
        count = breach.get("pwn_count")
        risks.append(make(
            "breach-history", (f"domain:{breach.get('domain') or seed}", f"breach:{breach.get('name')}"), (breach["evidence_id"],),
            f"A public breach index lists the breach {breach.get('title') or breach.get('name')!r} affecting "
            f"{breach.get('domain') or seed}, dated {breach.get('breach_date')}"
            + (f", {count:,} records" if isinstance(count, int) else "")
            + f" ({classes}). This is third-party history about the breached service, not a live finding.",
            Confidence.LOW, severity=Severity.LOW if breach.get("is_sensitive") else Severity.INFO,
        ))

    for leak in section["github"].get("code_leaks", []):
        if not leak.get("evidence_id"):
            continue
        risks.append(make(
            "exposed-credential", (f"repo:{leak.get('repository')}", f"path:{leak.get('path')}"), (leak["evidence_id"],),
            f"A {leak.get('format')} credential format was found in the organisation's own public repository "
            f"{leak.get('repository')} at {leak.get('path')} (commit {str(leak.get('commit_sha'))[:12]}, value "
            f"{leak.get('mask')}, not stored). Possible exposed credential.",
            Confidence.MEDIUM, severity=Severity.HIGH,
        ))

    for pkg in section["packages"].get("lookalikes_existing", []):
        if not pkg.get("evidence_id"):
            continue
        risks.append(make(
            "lookalike-package-exists", (f"domain:{seed}", f"package:{pkg.get('registry')}/{pkg.get('name')}"), (pkg["evidence_id"],),
            f"A package named {pkg.get('name')!r} exists on {pkg.get('registry')} ({pkg.get('how')}); it looks like the "
            f"brand name and is not linked to an in-scope domain. Ownership is unknown.",
            Confidence.LOW,
        ))

    for pkg in section["packages"].get("unregistered_brand", []):
        if not pkg.get("evidence_id"):
            continue
        risks.append(make(
            "brand-namespace-unregistered", (f"domain:{seed}", f"package:{pkg.get('registry')}/{pkg.get('name')}"), (pkg["evidence_id"],),
            f"The brand name {pkg.get('name')!r} is not registered on {pkg.get('registry')}. If an internal build ever "
            f"installs a package by that name, an attacker who registers it first can run code (dependency confusion).",
            Confidence.LOW, severity=Severity.INFO,
        ))
    return risks
