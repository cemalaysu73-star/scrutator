# Benchmark protocol

This is the protocol the competitor comparison in [benchmarks.md](benchmarks.md) follows. It was written before the first run and is not changed to fit results. Amendments are recorded at the bottom, with the reason, and the original wording is kept.

## What is compared

Scrutator against other passive recon tools, on the same targets, with the same time budget, passive only.

- **Competitors that ran:** PyPI packages installed into an isolated virtual environment (sublist3r, dnsrecon in its passive crt.sh mode, knockpy in its passive mode). No executables downloaded, no `go install`.
- **Competitors not run:** subfinder, Amass, SpiderFoot and theHarvester. They need a binary or git download that was not approved. They are listed as "not run" in every table, and nothing is said about how Scrutator compares with them.
- **Metrics:** subdomain recall and precision against ground truth; share of reported names backed by a citable evidence record; wall time; whether the signed bundle verifies and whether tampering is caught; sources that failed.

## Frozen criterion

Scrutator is "best" in a round only if recall is at least the best competitor's on every truth target, every result is evidence-backed, and bundle verification passes. A tie on recall plus the evidence and verification columns counts as a win. Lower recall is a loss and is reported as such.

## Targets (frozen 2026-10-17, before any benchmark run)

Only these four names are ever queried, passively (no brute forcing, no port scans, no crawling).

| Id | Target | Truth |
|---|---|---|
| T1 | `zonetransfer.me` | A deliberate public DNS test zone. Truth is the zone's published listing (31 names below the apex). |
| T2 | `example.com` | Tiny control. Pseudo-truth. |
| T3 | `nmap.org` | Open-source project with many public subdomains. Pseudo-truth. |
| T4 | `owasp.org` | Open-source foundation with many public subdomains. Pseudo-truth. |

**Pseudo-truth (T2 to T4)** is the union of in-scope hostnames reported by any tool in the benchmark that also still resolve in DNS (A, AAAA or CNAME) at benchmark time. It is a lower bound of the real name set and is biased towards what the tools collectively see. Recall against it flatters every tool and says nothing about names no tool found. Only T1 is a real truth set, and it is one small zone.

## Honest reading

Scrutator is not the fastest or the widest tool. Its edge is that every name cites the raw record it came from and the whole result is a signed bundle that a third party can verify offline. The benchmark measures both sides.

## Amendments

1. The single zone-transfer attempt against the zone's published test name server timed out twice from the benchmark network, so T1 truth falls back to the zone listing its author publishes (a 2016 snapshot).
2. `nmap.org` turned out to use wildcard DNS. Names that resolve only to the wildcard address are classed "wildcard-covered" (existence unproven), not live, so the T3 pseudo-truth is very small. The target was kept rather than swapped after the results were seen.
