"""Risks from brand presence (scrutator/brand.py): pure functions of the report's evidence and the packs.

- `brand-handle-unregistered`: a handle the organisation publishes on its site, or the brand name itself on a platform
  the site links to, answers "no such account". Whoever registers it can pose as the organisation; a published one
  sends the site's own visitors there (medium); the bare brand name is low.
- `brand-lookalike-handle`: a look-alike of the brand name exists on a platform the site links to. Ownership unknown:
  it may be the organisation's own, a fan, a reseller, or an impersonator. Low.

Both are low confidence: the status of a public profile page is all the evidence there is."""

from scrutator.brand import brand_presence
from scrutator.model import Confidence
from scrutator.packs import PackSet
from scrutator.risk.catalog import make
from scrutator.risk.model import Risk, Severity


def brand_risks(report: dict, packs: PackSet) -> list[Risk]:
    section = brand_presence(report, packs)
    if section is None:
        return []
    risks: list[Risk] = []
    for site in section["domains"]:
        domain_id = f"domain:{site['domain']}"
        for item in site["official"]:
            if item["state"] != "absent":
                continue
            risks.append(make(
                "brand-handle-unregistered", (domain_id, f"handle:{item['platform']}/{item['handle']}"), item["evidence_ids"],
                f"{site['domain']} links to {item['url']} on its home page, and that profile page answered as an account "
                f"that does not exist ({item['reason']}).",
                Confidence.LOW, severity=Severity.MEDIUM,
            ))
        for check in site["checks"]:
            if check["kind"] == "brand" and check["state"] == "absent":
                risks.append(make(
                    "brand-handle-unregistered", (domain_id, f"handle:{check['platform']}/{check['handle']}"), (check["evidence_id"],),
                    f"The brand name {check['handle']!r} of {site['domain']} is not a registered account on {check['platform']}, a "
                    f"platform the site links to ({check['reason']}).",
                    Confidence.LOW, severity=Severity.LOW,
                ))
            elif check["kind"] == "lookalike" and check["state"] == "exists":
                risks.append(make(
                    "brand-lookalike-handle", (domain_id, f"handle:{check['platform']}/{check['handle']}"), (check["evidence_id"],),
                    f"{check['url']} exists ({check['reason']}). Its handle is a look-alike of the brand name "
                    f"{site['brand']!r} ({check['how']}); who owns it is unknown.",
                    Confidence.LOW,
                ))
    return risks
