"""The rules and what they mean.

Each rule has a fixed title, a general description and general remediation advice. A risk takes
those from here, so the only text that varies per finding is its `explanation`, which states
what the cited evidence shows. SARIF export builds its rule list from this catalog too.
"""

from dataclasses import dataclass

from scrutator.model import Confidence
from scrutator.risk.model import Risk, Severity


@dataclass(frozen=True)
class RuleInfo:
    rule_id: str
    category: str  # "risk" or "analyst"
    severity: Severity  # the usual severity; a rule may raise or lower it with the evidence
    title: str
    description: str
    remediation: str


def _rule(rule_id, category, severity, title, description, remediation) -> RuleInfo:
    return RuleInfo(rule_id, category, Severity(severity), title, description, remediation)


_RULES = [
    _rule(
        "dangling-cname-claimable", "risk", "high",
        "CNAME to a claimable service that no longer exists",
        "A name is an alias (CNAME) of a host at a service whose names anyone can register, and that host does not exist. Whoever registers it controls what the name serves.",
        "Delete the CNAME record, or re-create the resource at the service so the name is yours again. Check what else (cookies, OAuth redirects, SPF) trusted the name.",
    ),
    _rule(
        "dangling-cname-known-service", "risk", "medium",
        "CNAME to a host that no longer exists, at a service known for takeovers",
        "A name is an alias of a host at a service that has been abused for subdomain takeover, and that host does not exist. The service may need an active check to confirm it can be claimed.",
        "Delete the CNAME record or re-create the resource at the service. In an authorised assessment, confirm with an active check.",
    ),
    _rule(
        "dangling-cname", "risk", "medium",
        "CNAME to a host that does not exist",
        "A name is an alias of a host that does not resolve. The target may be a domain that has lapsed and can be registered, or a service that released the name.",
        "Delete the CNAME record if the target is no longer used, or restore the target.",
    ),
    _rule(
        "spf-allows-all", "risk", "high",
        "SPF record authorises every sender",
        "The SPF record ends with +all (or a bare all), which tells receivers that any host may send mail for the domain.",
        "End the record with -all (or ~all while rolling out) and list only the senders you use.",
    ),
    _rule(
        "spf-neutral-all", "risk", "medium",
        "SPF record takes no position on unlisted senders",
        "The SPF record ends with ?all, so mail from hosts that are not listed is neither accepted nor rejected on SPF grounds.",
        "End the record with -all (or ~all while rolling out).",
    ),
    _rule(
        "spf-softfail-all", "risk", "low",
        "SPF record soft-fails unlisted senders",
        "The SPF record ends with ~all, so mail from unlisted hosts is marked suspicious but usually still delivered. This is common and acceptable when DMARC enforces a policy.",
        "Move to -all once the sender list is complete, and publish a DMARC policy.",
    ),
    _rule(
        "spf-no-all", "risk", "medium",
        "SPF record has no default result",
        "The SPF record has no all mechanism and no redirect, so hosts that match nothing get the default result (neutral).",
        "End the record with -all (or ~all while rolling out).",
    ),
    _rule(
        "spf-multiple-records", "risk", "medium",
        "More than one SPF record",
        "A name publishes several TXT records that start with v=spf1. Receivers treat that as a permanent error and ignore SPF.",
        "Merge the records into one.",
    ),
    _rule(
        "spf-too-many-lookups", "risk", "medium",
        "SPF record needs more than ten DNS lookups",
        "The SPF record itself already contains more than ten mechanisms that cause a DNS lookup (include, a, mx, ptr, exists, redirect). The limit is ten in total, so receivers return a permanent error. Only the record's own terms are counted; included records are not queried.",
        "Remove unused includes, replace includes with ip4/ip6 ranges, or flatten the record.",
    ),
    _rule(
        "dmarc-missing", "risk", "medium",
        "Mail domain without a DMARC record",
        "A name has MX records but neither it nor a parent domain publishes a DMARC record, so receivers have no instruction on how to treat spoofed mail.",
        "Publish a DMARC record at _dmarc.<domain>, starting with p=none and reporting addresses, then move to quarantine and reject.",
    ),
    _rule(
        "dmarc-monitoring-only", "risk", "low",
        "DMARC policy is monitoring only",
        "The DMARC record has p=none, so failing mail is reported but not treated differently.",
        "Move to p=quarantine and then p=reject once the reports show only legitimate senders.",
    ),
    _rule(
        "caa-missing", "risk", "low",
        "No CAA record at a zone apex",
        "A zone apex has no CAA record (and no parent zone has one), so any certificate authority may issue certificates for the domain.",
        "Publish CAA records naming the certificate authorities you use.",
    ),
    _rule(
        "domain-expired", "risk", "high",
        "Domain registration has expired",
        "The registry data lists an expiration date that is already past at the time the data was collected.",
        "Renew the domain at once, or confirm that it is meant to lapse and remove what depends on it.",
    ),
    _rule(
        "domain-expiring", "risk", "medium",
        "Domain registration expires within 30 days",
        "The registry data lists an expiration date within 30 days of the time the data was collected (within 14 days is rated high).",
        "Renew the domain and enable auto-renewal.",
    ),
    _rule(
        "forgotten-name", "risk", "low",
        "Name that looks like a forgotten test or staging system",
        "A name contains a label such as dev, staging, test, old or backup and still resolves. This is a heuristic: such systems are often left running unpatched.",
        "Confirm the system is still needed and maintained; otherwise remove the DNS record and the system.",
    ),
    _rule(
        "concentration-dns", "risk", "info",
        "All names depend on one DNS provider",
        "Every name server of every zone belongs to a single provider, so an outage or compromise there affects all of the names.",
        "Consider a secondary DNS provider on a different network, and protect the account with strong authentication.",
    ),
    _rule(
        "concentration-edge", "risk", "info",
        "Several names depend on one CDN or hosting provider",
        "Three or more names are served through a single CDN or hosting provider.",
        "Know the provider's outage and incident process; consider whether critical names need an alternative.",
    ),
    _rule(
        "ghost-hostname", "analyst", "info",
        "A certificate or archive names a host that DNS does not know",
        "A certificate-transparency log or web archive names a host in scope, but a DNS lookup for it returned NXDOMAIN. The host was retired, never existed or lives in an internal view; if it is not recorded anywhere else, its removal may have left references behind.",
        "Check whether the name is still referenced (certificates, links, configuration) and whether DNS or the certificate should be cleaned up.",
    ),
    _rule(
        "numbering-gap", "analyst", "info",
        "A gap in a numbered series of names",
        "Several names follow a numbered pattern (app1, app2, app4) and a number in the middle is missing. The missing host may have been retired, or may exist where this scan did not look.",
        "Check whether the missing number is a retired or unlisted system.",
    ),
    _rule(
        "source-disagreement", "analyst", "low",
        "Registry and DNS disagree about the name servers",
        "The name servers the registry (RDAP) lists for a domain differ from the NS records the zone itself publishes. A mismatch can mean a half-finished provider migration or a lame delegation.",
        "Make the registry delegation and the zone's NS records identical.",
    ),
]

RULES: dict[str, RuleInfo] = {rule.rule_id: rule for rule in _RULES}


def make(
    rule_id: str,
    entity_ids,
    evidence_ids,
    explanation: str,
    confidence: Confidence,
    *,
    severity: Severity | None = None,
) -> Risk:
    """Build a Risk for a catalogued rule. Evidence ids are de-duplicated, keeping their order."""
    info = RULES[rule_id]
    return Risk(
        rule_id=rule_id,
        severity=severity or info.severity,
        category=info.category,
        title=info.title,
        entity_ids=tuple(entity_ids),
        evidence_ids=tuple(dict.fromkeys(evidence_ids)),
        explanation=explanation,
        remediation=info.remediation,
        confidence=confidence,
    )
