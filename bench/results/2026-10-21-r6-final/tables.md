# Benchmark tables (2026-10-21-r6-final)

Resolvers: 1.1.1.1, 8.8.8.8, 9.9.9.9. Timeout per tool run: 900 s. Scrutator 1.0.0rc2, commit 4c1e2e3.

## zonetransfer.me

Truth: zone owner names below the apex, source: published dig AXFR dump (https://digi.ninja/projects/zonetransferme.php) (31 names, 15 with A/AAAA/CNAME).

| Tool | Status | Names found | Live | Wildcard-covered | Stale/NX | Recall | Precision | Unique | Unique live | Time (s) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Scrutator | ok | 6 | 4 | 0 | 2 | 13% (27% of host names) | 67% | 2 | 2 | 23.33 |
| sublist3r | ok | 0 | 0 | 0 | 0 | 0% (0% of host names) | n/a | 0 | 0 | 12.88 |
| dnsrecon (crt) | error | 0 | 0 | 0 | 0 | 0% (0% of host names) | n/a | 0 | 0 | 2.34 |
| knockpy (recon) | ok | 4 | 2 | 0 | 2 | 6% (13% of host names) | 50% | 0 | 0 | 5.58 |

Scrutator extras:

| Hostnames reported | Evidence-backed | Backed by evidence naming the host | Findings | Risks | Evidence records | Bundle verify (pinned, no replay) | Tamper detected | Sources failed |
|---:|---:|---:|---:|---:|---:|---|---|---|
| 6 | 100% (6) | 100% (6) | 105 | 5 | 110 | PASS | True | certspotter, commoncrawl |

Scrutator's own name states (v0.6), checked against this harness's resolver:

| Marked live | Stale | Wildcard-covered | Unresolved | Marked live and live here | Marked live but not live here | Live here but not marked live | Precision of the live set | Recall of the live set |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 4 | 2 | 0 | 0 | 4 | 0 | 0 | 100% | 13% |

Scrutator's name tiers (v0.7), checked against this harness's resolver (apex excluded):

| Headline | Verified | Claimed | Stale | Wildcard | Verified and live here | Precision of the verified set | Recall of the verified set | Verified share of verified+claimed | Live here but not verified |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 5 verified, 2 claimed (0 stale, 0 wildcard-covered) | 4 | 2 | 0 | 0 | 4 | 100% | 13% | 67% | 0 |

Zone names no tool found (first 27): `164.180.147.217.in-addr.arpa.zonetransfer.me`, `_sip._tcp.zonetransfer.me`, `alltcpportsopen.firewall.test.zonetransfer.me`, `asfdbauthdns.zonetransfer.me`, `asfdbbox.zonetransfer.me`, `asfdbvolume.zonetransfer.me`, `canberra-office.zonetransfer.me`, `cmdexec.zonetransfer.me`, `contact.zonetransfer.me`, `dc-office.zonetransfer.me`, `deadbeef.zonetransfer.me`, `dr.zonetransfer.me`, `dzc.zonetransfer.me`, `email.zonetransfer.me`, `info.zonetransfer.me`, `internal.zonetransfer.me`, `intns1.zonetransfer.me`, `intns2.zonetransfer.me`, `ipv6actnow.org.zonetransfer.me`, `owa.zonetransfer.me`, `robinwood.zonetransfer.me`, `rp.zonetransfer.me`, `sip.zonetransfer.me`, `sqli.zonetransfer.me`, `sshock.zonetransfer.me`, `vpn.zonetransfer.me`, `xss.zonetransfer.me`

## example.com

Truth: pseudo-truth: union of live names found by any tool (1 names).

| Tool | Status | Names found | Live | Wildcard-covered | Stale/NX | Recall | Precision | Unique | Unique live | Time (s) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Scrutator | ok | 998 | 1 | 0 | 997 | 100% | 0% | 994 | 0 | 21.83 |
| sublist3r | ok | 1 | 1 | 0 | 0 | 100% | 100% | 0 | 0 | 11.94 |
| dnsrecon (crt) | error | 0 | 0 | 0 | 0 | 0% | n/a | 0 | 0 | 1.56 |
| knockpy (recon) | ok | 500 | 1 | 0 | 499 | 100% | 0% | 496 | 0 | 4.75 |

Scrutator extras:

| Hostnames reported | Evidence-backed | Backed by evidence naming the host | Findings | Risks | Evidence records | Bundle verify (pinned, no replay) | Tamper detected | Sources failed |
|---:|---:|---:|---:|---:|---:|---|---|---|
| 998 | 100% (998) | 100% (998) | 1048 | 3 | 2037 | PASS | True | certspotter, commoncrawl |

Scrutator's own name states (v0.6), checked against this harness's resolver:

| Marked live | Stale | Wildcard-covered | Unresolved | Marked live and live here | Marked live but not live here | Live here but not marked live | Precision of the live set | Recall of the live set |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 0 | 972 | 0 | 26 | 0 | 0 | 1 | n/a | 0% |

Scrutator's name tiers (v0.7), checked against this harness's resolver (apex excluded):

| Headline | Verified | Claimed | Stale | Wildcard | Verified and live here | Precision of the verified set | Recall of the verified set | Verified share of verified+claimed | Live here but not verified |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 2 verified, 993 claimed (4 stale, 0 wildcard-covered) | 1 | 993 | 4 | 0 | 1 | 100% | 100% | 0% | 0 |

## nmap.org

Truth: pseudo-truth: union of live names found by any tool (4 names).  Wildcard DNS at this apex (random labels resolve to 2600:3c01:e000:3e6::6d4e:7061, 50.116.1.184): names resolving only to those addresses are counted as wildcard-covered, not live, and excluded from the precision denominator.

| Tool | Status | Names found | Live | Wildcard-covered | Stale/NX | Recall | Precision | Unique | Unique live | Time (s) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Scrutator | ok | 349 | 4 | 341 | 4 | 100% | 50% | 2 | 0 | 20.06 |
| sublist3r | ok | 2 | 1 | 1 | 0 | 25% | 100% | 0 | 0 | 13.31 |
| dnsrecon (crt) | error | 0 | 0 | 0 | 0 | 0% | n/a | 0 | 0 | 1.41 |
| knockpy (recon) | ok | 355 | 4 | 347 | 4 | 100% | 50% | 8 | 0 | 2.73 |

Scrutator extras:

| Hostnames reported | Evidence-backed | Backed by evidence naming the host | Findings | Risks | Evidence records | Bundle verify (pinned, no replay) | Tamper detected | Sources failed |
|---:|---:|---:|---:|---:|---:|---|---|---|
| 349 | 100% (349) | 100% (349) | 1113 | 17 | 1160 | PASS | True | certspotter, commoncrawl |

Scrutator's own name states (v0.6), checked against this harness's resolver:

| Marked live | Stale | Wildcard-covered | Unresolved | Marked live and live here | Marked live but not live here | Live here but not marked live | Precision of the live set | Recall of the live set |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 4 | 4 | 341 | 0 | 4 | 0 | 0 | 100% | 100% |

Scrutator's name tiers (v0.7), checked against this harness's resolver (apex excluded):

| Headline | Verified | Claimed | Stale | Wildcard | Verified and live here | Precision of the verified set | Recall of the verified set | Verified share of verified+claimed | Live here but not verified |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 8 verified, 3 claimed (1 stale, 338 wildcard-covered) | 7 | 3 | 1 | 338 | 4 | 57% | 100% | 70% | 0 |

## owasp.org

Truth: pseudo-truth: union of live names found by any tool (61 names).

| Tool | Status | Names found | Live | Wildcard-covered | Stale/NX | Recall | Precision | Unique | Unique live | Time (s) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Scrutator | ok | 138 | 59 | 0 | 79 | 97% | 43% | 9 | 8 | 47.09 |
| sublist3r | ok | 24 | 24 | 0 | 0 | 39% | 100% | 2 | 2 | 10.39 |
| dnsrecon (crt) | error | 0 | 0 | 0 | 0 | 0% | n/a | 0 | 0 | 3.98 |
| knockpy (recon) | ok | 122 | 44 | 0 | 78 | 72% | 36% | 0 | 0 | 7.3 |

Scrutator extras:

| Hostnames reported | Evidence-backed | Backed by evidence naming the host | Findings | Risks | Evidence records | Bundle verify (pinned, no replay) | Tamper detected | Sources failed |
|---:|---:|---:|---:|---:|---:|---|---|---|
| 138 | 100% (138) | 100% (138) | 793 | 17 | 983 | PASS | True | certspotter, commoncrawl |

Scrutator's own name states (v0.6), checked against this harness's resolver:

| Marked live | Stale | Wildcard-covered | Unresolved | Marked live and live here | Marked live but not live here | Live here but not marked live | Precision of the live set | Recall of the live set |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 59 | 79 | 0 | 0 | 59 | 0 | 0 | 100% | 97% |

Scrutator's name tiers (v0.7), checked against this harness's resolver (apex excluded):

| Headline | Verified | Claimed | Stale | Wildcard | Verified and live here | Precision of the verified set | Recall of the verified set | Verified share of verified+claimed | Live here but not verified |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 60 verified, 66 claimed (13 stale, 0 wildcard-covered) | 59 | 66 | 13 | 0 | 59 | 100% | 97% | 47% | 0 |

## Not run

- subfinder: needs a Go binary (GitHub release or `go install`); `go` is not installed. Needs the user's approval.
- Amass: needs a Go binary (GitHub release or `go install`). Needs the user's approval.
- SpiderFoot: not on PyPI as the official tool; official install is a git clone or release download. Needs the user's approval.
- theHarvester: the PyPI name `theHarvester` is an unrelated 0.0.1 placeholder; the real tool installs from a git clone. Needs the user's approval.
