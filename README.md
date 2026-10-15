# Scrutator

Evidence-backed, AI-driven infrastructure OSINT. Point it at a domain; get a map of the
organisation's internet-facing infrastructure in which every claim links to the raw record
it came from.

**Status: v0.1.** Passive scanning with six keyless sources, a deny-by-default scope guard,
an evidence store, and JSON and HTML reports. The AI agent and verifier arrive in v0.2.

## Install

```bash
pipx install scrutator
```

From a checkout: `pip install -e ".[dev]"`.

## Use

```bash
scrutator scan example.com
```

This writes `scrutator-out/report.html` (open it in a browser), `report.json` and
`scrutator.db`. Sources: certificate transparency (crt.sh), DNS, RDAP, ASN (RIPEstat),
Internet Archive and Common Crawl. No API keys needed.

### Scope

By default the scope is the seed domain and its subdomains. For anything else, write a
scope file:

```yaml
domains:
  - example.com
cidrs:
  - 203.0.113.0/24
asns:
  - AS64500
```

```bash
scrutator scan example.com --scope scope.yaml
```

Scope is enforced in the engine, not by convention. Every discovered entity is marked
`in`, `linked` or `out`. Out-of-scope entities are recorded but never queried. An IP that
an in-scope host resolves to is `linked`: passive lookups about it are allowed.

### Evidence

Findings cannot exist without evidence ids. Each evidence record is the raw response of a
source, stored once and addressed by hash. A finding's confidence is the number of distinct
sources that agree: one is low, two medium, three or more high. Every module call is written to
a hash-chained audit log.

## Responsible use

Passive mode only queries third-party public sources, but those services see what you
search for. Only investigate organisations you are authorised to assess or that you are
entitled to research.

## Develop

```bash
pip install -e ".[dev]"
pytest
```

Licensed under Apache-2.0.
