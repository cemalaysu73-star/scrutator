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
        "exposed-risky-service", "risk", "medium",
        "A database, remote-administration or file-sharing port is open to the internet",
        "Shodan's InternetDB lists an open port on an address of the scan that is usually not meant to be reachable from the whole internet (a database, a remote desktop or shell, a file share, a cache). The data is Shodan's earlier scan, not a check made now, so it may be out of date. In an authorised active review a successful connection to the port confirms it is open now (rated high confidence).",
        "Confirm with the owner whether the port is open now; if it is, close it at the firewall or restrict it to known addresses, and require authentication.",
    ),
    _rule(
        "stale-exposure-data", "risk", "info",
        "A passive source reported a port open that a check made now found closed or unanswered",
        "A passive source (Shodan InternetDB) listed an open port on an address of the scan, and a connection check made during an authorised active review found it closed (the connection was refused) or unanswered (no reply within the timeout). Both facts are shown: the earlier report may simply be out of date, or something between the tester and the address (a firewall, the tester's own network) blocks the connection, in which case 'unanswered' proves little.",
        "Nothing to fix on the service if the port is meant to be closed. When an unanswered port matters, repeat the check from a second network, and let the third-party data age out or ask its operator to refresh it.",
    ),
    _rule(
        "tls-cert-expired", "risk", "high",
        "TLS certificate has expired",
        "During an authorised active review, a TLS handshake with an in-scope name returned a certificate whose validity ended before the check was made. Browsers refuse the connection or show a warning, and API clients fail.",
        "Issue and install a new certificate with the full chain, then reload the service. Automate renewal (for example ACME) and monitor expiry so it cannot lapse again.",
    ),
    _rule(
        "tls-cert-expiring", "risk", "medium",
        "TLS certificate expires within 30 days",
        "During an authorised active review, a TLS handshake with an in-scope name returned a certificate that expires within 30 days of the check (within 7 days is rated high).",
        "Renew the certificate before it expires and automate renewal (for example ACME); monitor the expiry date of every certificate, not only the website's.",
    ),
    _rule(
        "tls-hostname-mismatch", "risk", "medium",
        "TLS certificate does not cover the host name",
        "During an authorised active review, a TLS handshake that asked for an in-scope host name (SNI) returned a certificate whose names do not include it. Visitors get a certificate error, or the name is served by a default virtual host that was never configured for it.",
        "Issue a certificate that lists the host name (or a wildcard that covers it) and install it for that name, or remove the DNS record if the name is no longer served.",
    ),
    _rule(
        "tls-legacy-protocol", "risk", "medium",
        "Server still accepts TLS 1.0 or TLS 1.1",
        "During an authorised active review, a TLS handshake restricted to TLS 1.0 or TLS 1.1 completed. Both protocols are deprecated (RFC 8996) and weaker than TLS 1.2 and 1.3.",
        "Allow TLS 1.2 and TLS 1.3 only. Check for old clients (legacy devices, very old Java or Windows versions) before the change, and test the result with a second tool.",
    ),
    _rule(
        "http-no-https-redirect", "risk", "low",
        "Plain HTTP does not redirect to HTTPS",
        "During an authorised active review, one request for the home page over plain HTTP was answered with content, or with a redirect that does not lead to an HTTPS address of the same organisation, so a visitor who types the bare name stays unencrypted.",
        "Answer every plain-HTTP request with a permanent redirect (301 or 308) to the HTTPS URL of the same site, at the web server or the load balancer, then add HSTS once HTTPS works everywhere.",
    ),
    _rule(
        "http-missing-hsts", "risk", "low",
        "HTTPS site does not send HTTP Strict Transport Security",
        "During an authorised active review, the HTTPS answer for an in-scope name had no Strict-Transport-Security header (or max-age=0), so browsers do not remember to use HTTPS and a downgrade attack on a first visit stays possible.",
        "Send Strict-Transport-Security with a max-age of at least six months on every HTTPS response, starting with a short value while testing; add includeSubDomains only when every subdomain supports HTTPS.",
    ),
    _rule(
        "http-missing-security-headers", "risk", "low",
        "HTTP response lacks common browser security headers",
        "During an authorised active review, the home page answer for an in-scope name lacked one or more of: Content-Security-Policy, clickjacking protection (X-Frame-Options or a CSP frame-ancestors directive), X-Content-Type-Options: nosniff and Referrer-Policy. They are cheap defence in depth against script injection, framing and content sniffing; their absence is not a vulnerability by itself.",
        "Add the missing headers at the web server or CDN. Start with X-Content-Type-Options: nosniff, a Referrer-Policy such as strict-origin-when-cross-origin, and frame-ancestors; introduce Content-Security-Policy in report-only mode first.",
    ),
    _rule(
        "server-banner-discloses-version", "risk", "info",
        "A service banner or Server header names a software version",
        "During an authorised active review, a service greeting (SSH, FTP, SMTP and similar) or an HTTP Server or X-Powered-By header named a product with its version number. That tells an attacker which known weaknesses to try, and tells a defender how old the software is.",
        "Hide version numbers where the software allows it (for example ServerTokens Prod, server_tokens off, expose_php Off), but treat that as cosmetic: patching to a supported version is the real fix.",
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
    _rule(
        "brand-handle-unregistered", "risk", "low",
        "A brand handle is not registered on a platform the organisation uses",
        "The organisation's own site links to an account on a platform, and either that account or the bare brand name answers as an account that does not exist on the public profile page. Whoever registers the handle can pose as the organisation; a dead link on the site sends its own visitors there (medium). A suspended or renamed account can answer the same way, so this is low confidence.",
        "Register (or reclaim) the handle, and fix or remove the link on the site. Check the platform's own account page while signed in before acting.",
    ),
    _rule(
        "brand-lookalike-handle", "risk", "low",
        "A look-alike of the brand name exists on a platform the organisation uses",
        "A handle that looks like the brand name (a homoglyph, an added word, a separator or a typo) exists on a platform the organisation's site links to. Who owns it is unknown: it may be the organisation's own, a fan, a reseller or an impersonator.",
        "Look at the account by hand. If it is not yours and impersonates you, report it through the platform's impersonation process; consider registering the closest look-alikes yourself.",
    ),
    _rule(
        "breach-history", "risk", "info",
        "A public index lists a breach of a service under the organisation's domain",
        "A public breach index names a breach affecting a service under the organisation's domain, with its date, record count and the kinds of data involved. This is third-party history about the breached service (metadata only, never account lists), not a live finding about the systems scanned now.",
        "Confirm the breach and that credentials exposed in it have been rotated and are not reused. For sensitive breaches, check whether affected accounts were notified. Treat the date as the source's claim, not a verified fact.",
    ),
    _rule(
        "exposed-credential", "risk", "high",
        "A credential format was found in the organisation's own public repository",
        "A bounded scan of the organisation's own public repositories (--code-leaks) matched a well-known credential format in a committed file. The secret value is never stored: only its format, the repository, the path, the commit and a salted-hash fingerprint are recorded. A match can be a real secret, a test fixture or an example.",
        "Rotate the credential now (assume it is compromised), then remove it from the repository's history (not just the latest commit). Confirm by hand that the match is a live secret and not a sample before raising an incident.",
    ),
    _rule(
        "lookalike-package-exists", "risk", "low",
        "A look-alike of the brand name exists on a package registry",
        "A package or namespace whose name looks like the organisation's brand (a homoglyph, an added word, a separator or a typo) exists on a public registry and is not linked back to an in-scope domain. It may be the organisation's own, unrelated, or a typosquat.",
        "Look at the package by hand. If it impersonates the organisation or ships its name, report it to the registry; consider registering the closest look-alikes yourself.",
    ),
    _rule(
        "brand-namespace-unregistered", "risk", "info",
        "The brand name is unregistered on a public package registry",
        "The organisation's brand name is free as a package or namespace on a public registry. If an internal build ever resolves a dependency by that name from the public registry, an attacker who registers it first can run code in the build (dependency confusion).",
        "Register the brand name defensively on the registries the organisation uses, and pin internal packages to a private registry or a scope so a public package of the same name cannot be installed by mistake.",
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
