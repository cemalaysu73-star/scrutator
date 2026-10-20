# Benchmark tables (2026-10-20-r4-a)

Resolvers: 1.1.1.1, 8.8.8.8, 9.9.9.9. Timeout per tool run: 900 s. Scrutator 0.7.0, commit 17c37f1.

## zonetransfer.me

Truth: zone owner names below the apex, source: published dig AXFR dump (https://digi.ninja/projects/zonetransferme.php) (31 names, 15 with A/AAAA/CNAME).

| Tool | Status | Names found | Live | Wildcard-covered | Stale/NX | Recall | Precision | Unique | Unique live | Time (s) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Scrutator | ok | 6 | 4 | 0 | 2 | 13% (27% of host names) | 67% | 2 | 2 | 22.52 |
| sublist3r | ok | 0 | 0 | 0 | 0 | 0% (0% of host names) | n/a | 0 | 0 | 12.88 |
| dnsrecon (crt) | error | 0 | 0 | 0 | 0 | 0% (0% of host names) | n/a | 0 | 0 | 2.34 |
| knockpy (recon) | ok | 4 | 2 | 0 | 2 | 6% (13% of host names) | 50% | 0 | 0 | 5.58 |

Scrutator extras:

| Hostnames reported | Evidence-backed | Backed by evidence naming the host | Findings | Risks | Evidence records | Bundle verify (pinned, no replay) | Tamper detected | Sources failed |
|---:|---:|---:|---:|---:|---:|---|---|---|
| 6 | 100% (6) | 100% (6) | 130 | 5 | 111 | PASS | True | commoncrawl, crtsh, hackertarget |

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
| Scrutator | ok | 499 | 1 | 0 | 498 | 100% | 0% | 497 | 0 | 19.94 |
| sublist3r | ok | 1 | 1 | 0 | 0 | 100% | 100% | 0 | 0 | 11.94 |
| dnsrecon (crt) | error | 0 | 0 | 0 | 0 | 0% | n/a | 0 | 0 | 1.56 |
| knockpy (recon) | ok | 500 | 1 | 0 | 499 | 100% | 0% | 498 | 0 | 4.75 |

Scrutator extras:

| Hostnames reported | Evidence-backed | Backed by evidence naming the host | Findings | Risks | Evidence records | Bundle verify (pinned, no replay) | Tamper detected | Sources failed |
|---:|---:|---:|---:|---:|---:|---|---|---|
| 499 | 100% (499) | 100% (499) | 558 | 2 | 1064 | PASS | True | commoncrawl, crtsh, hackertarget |

Scrutator's own name states (v0.6), checked against this harness's resolver:

| Marked live | Stale | Wildcard-covered | Unresolved | Marked live and live here | Marked live but not live here | Live here but not marked live | Precision of the live set | Recall of the live set |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 498 | 0 | 0 | 1 | 0 | 0 | 100% | 100% |

Scrutator's name tiers (v0.7), checked against this harness's resolver (apex excluded):

| Headline | Verified | Claimed | Stale | Wildcard | Verified and live here | Precision of the verified set | Recall of the verified set | Verified share of verified+claimed | Live here but not verified |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 2 verified, 498 claimed (0 stale, 0 wildcard-covered) | 1 | 498 | 0 | 0 | 1 | 100% | 100% | 0% | 0 |

## nmap.org

Truth: pseudo-truth: union of live names found by any tool (4 names).  Wildcard DNS at this apex (random labels resolve to 2600:3c01:e000:3e6::6d4e:7061, 50.116.1.184): names resolving only to those addresses are counted as wildcard-covered, not live, and excluded from the precision denominator.

| Tool | Status | Names found | Live | Wildcard-covered | Stale/NX | Recall | Precision | Unique | Unique live | Time (s) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Scrutator | ok | 347 | 4 | 339 | 4 | 100% | 50% | 0 | 0 | 15.55 |
| sublist3r | ok | 2 | 1 | 1 | 0 | 25% | 100% | 0 | 0 | 13.31 |
| dnsrecon (crt) | error | 0 | 0 | 0 | 0 | 0% | n/a | 0 | 0 | 1.41 |
| knockpy (recon) | ok | 355 | 4 | 347 | 4 | 100% | 50% | 8 | 0 | 2.73 |

Scrutator extras:

| Hostnames reported | Evidence-backed | Backed by evidence naming the host | Findings | Risks | Evidence records | Bundle verify (pinned, no replay) | Tamper detected | Sources failed |
|---:|---:|---:|---:|---:|---:|---|---|---|
| 347 | 100% (347) | 100% (347) | 1125 | 15 | 1126 | PASS | True | commoncrawl, crtsh, hackertarget |

Scrutator's own name states (v0.6), checked against this harness's resolver:

| Marked live | Stale | Wildcard-covered | Unresolved | Marked live and live here | Marked live but not live here | Live here but not marked live | Precision of the live set | Recall of the live set |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 4 | 4 | 339 | 0 | 4 | 0 | 0 | 100% | 100% |

Scrutator's name tiers (v0.7), checked against this harness's resolver (apex excluded):

| Headline | Verified | Claimed | Stale | Wildcard | Verified and live here | Precision of the verified set | Recall of the verified set | Verified share of verified+claimed | Live here but not verified |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 8 verified, 4 claimed (0 stale, 336 wildcard-covered) | 7 | 4 | 0 | 336 | 4 | 57% | 100% | 64% | 0 |

## owasp.org

Truth: pseudo-truth: union of live names found by any tool (58 names).

| Tool | Status | Names found | Live | Wildcard-covered | Stale/NX | Recall | Precision | Unique | Unique live | Time (s) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Scrutator | ok | 132 | 53 | 0 | 79 | 91% | 40% | 6 | 5 | 31.67 |
| sublist3r | ok | 24 | 24 | 0 | 0 | 41% | 100% | 5 | 5 | 10.39 |
| dnsrecon (crt) | error | 0 | 0 | 0 | 0 | 0% | n/a | 0 | 0 | 3.98 |
| knockpy (recon) | ok | 122 | 44 | 0 | 78 | 76% | 36% | 0 | 0 | 7.3 |

Scrutator extras:

| Hostnames reported | Evidence-backed | Backed by evidence naming the host | Findings | Risks | Evidence records | Bundle verify (pinned, no replay) | Tamper detected | Sources failed |
|---:|---:|---:|---:|---:|---:|---|---|---|
| 132 | 100% (132) | 100% (132) | 946 | 5 | 869 | PASS | True | commoncrawl, crtsh, hackertarget |

Scrutator's own name states (v0.6), checked against this harness's resolver:

| Marked live | Stale | Wildcard-covered | Unresolved | Marked live and live here | Marked live but not live here | Live here but not marked live | Precision of the live set | Recall of the live set |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 53 | 79 | 0 | 0 | 53 | 0 | 0 | 100% | 91% |

Scrutator's name tiers (v0.7), checked against this harness's resolver (apex excluded):

| Headline | Verified | Claimed | Stale | Wildcard | Verified and live here | Precision of the verified set | Recall of the verified set | Verified share of verified+claimed | Live here but not verified |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 54 verified, 78 claimed (1 stale, 0 wildcard-covered) | 53 | 78 | 1 | 0 | 53 | 100% | 91% | 40% | 0 |

## Not run

- subfinder: needs a Go binary (GitHub release or `go install`); `go` is not installed. Needs the user's approval.
- Amass: needs a Go binary (GitHub release or `go install`). Needs the user's approval.
- SpiderFoot: not on PyPI as the official tool; official install is a git clone or release download. Needs the user's approval.
- theHarvester: the PyPI name `theHarvester` is an unrelated 0.0.1 placeholder; the real tool installs from a git clone. Needs the user's approval.
