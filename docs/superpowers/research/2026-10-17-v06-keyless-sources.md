# v0.6 keyless source research (probed 2026-10-16/17)

Scope: which additional keyless public sources Scrutator should add, judged by what answers from this machine today.
Method: 1-2 plain GETs per source, only for `example.com` and `1.1.1.1` (one exception, see "Probe hygiene"). User-Agent `Scrutator-research/0.6 (passive OSINT)`. No keys, logins, loops. Latency is wall time from this machine (EU, via Cloudflare/Amsterdam edge).
Existing coverage for comparison: crt.sh (CT names), DNS (A/AAAA/CNAME/MX/NS/TXT/CAA), rdap.org (domain registrar/NS, IP owner), RIPEstat prefix-overview (IP -> ASN), Wayback, Common Crawl.

## Ranked ADD list

1. Shodan InternetDB (IP -> open ports, CPEs, CVEs, hostnames)
2. mnemonic passive DNS (domain -> historic A/AAAA/NS/MX... with first/last seen)
3. RIPEstat extra data calls: whois, abuse-contact-finder, as-overview, rpki-validation, reverse-dns-ip (no allowlist change)
4. urlscan.io public search (domain -> past scans: IP, ASN, server, country)
5. CertSpotter issuances (second CT source: cert/pubkey fingerprints, issuer, revoked; crt.sh fallback)

MAYBE: Robtex free API, AlienVault OTX (general / url_list only), RIPE Database REST, PeeringDB, ipinfo.io, ipapi.is.
SKIP: Anubis, BufferOver, ThreatMiner, BGPView, GitHub code search, OTX passive_dns, HackerTarget, subdomain.center, GreyNoise community.

## Cross-cutting findings that affect design

- **Replay allowlist.** `ALLOWED_HTTP_HOSTS` is `crt.sh, rdap.org, stat.ripe.net, web.archive.org, index.commoncrawl.org`; https/443 only, no userinfo. Every ADD host below except RIPEstat needs adding: `internetdb.shodan.io`, `api.mnemonic.no`, `urlscan.io`, `api.certspotter.com` (and `rest.db.ripe.net`, `www.peeringdb.com`, `freeapi.robtex.com`, `otx.alienvault.com` if MAYBEs are promoted). Query strings are fine; replay re-issues the recorded GET.
- **Replay `supports()` semantics.** A recorded JSON *object* must equal the live object after dropping top-level `_VOLATILE` keys (`process_time, query_id, server_id, time, cached, version, build_version`). A recorded JSON *array* only needs each element still present in the live response (NDJSON is also parsed to a list). Consequences:
  - InternetDB, ipinfo, ipapi.is and OTX general return plain objects whose fields drift (ports, timestamps); whole-object equality will flag drift. That is arguably correct for a point-in-time scan, but modules should record the narrowest slice (a list of rows, or the single answer row) so replay reflects "does this fact still hold".
  - RIPEstat extras carry nested timestamps inside `data` (`query_time`, `query_starttime`, `latest_time`, `earliest_time`); `_VOLATILE` only strips top-level keys. Either extend the denoiser to strip these at depth or record only the relevant `data` slice as a list.
  - mnemonic and urlscan envelopes have `count`, `limit`, `lastUpdatedTimestamp`, `_score`, `sort`, screenshot URLs; record per-row slices (list form), not the envelope.
- **RIPEstat terms matter for what we already ship.** RIPEstat Service T&Cs (fetched): commercial use prohibited without written permission (Art. 3.3); re-packaging/redistributing RIPEstat Data prohibited without authorisation (3.3, 6.1); research must be reported to stat@ripe.net (3.2) and public results must credit the RIPE NCC and the original source. API docs: max 8 concurrent requests per IP; register if regularly over ~1000 req/day; add a `sourceapp=` identifier (letters/digits/-/_) and tell stat@ripe.net. The existing `asn` module embeds the full RIPEstat response in evidence bundles, so this issue already applies to v0.5. Recommend: add `sourceapp=scrutator` to RIPEstat requests, document attribution in the README, and flag bundles containing RIPEstat/InternetDB/CertSpotter payloads as non-commercial.
- **Several sources are free for personal/non-commercial use only** (InternetDB, CertSpotter, ipinfo; Robtex unclear). If Scrutator is released as OSS but used in commercial engagements, each module should carry a `licence_note` shown in module listings and in the bundle manifest.
- **Failure behaviour.** Four of the candidates (Anubis, BufferOver, ThreatMiner, BGPView) are dead, blocked or keyed today, and OTX gated passive_dns. Whatever is added must degrade to a recorded `ModuleError` without failing the scan (the engine already does this); expect sources to vanish between releases.

## Per-source results

### Shodan InternetDB - ADD (rank 1)
- URL: `GET https://internetdb.shodan.io/<ip>`
- Responded: HTTP 200, 0.30 s (Cloudflare). Unindexed IP (192.0.2.1): HTTP 404 `{"detail":"No information available"}`, a clean "no data" signal.
- Shape: `{"cpes":["cpe:/a:cloudflare:cloudflare"],"hostnames":["one.one.one.one","wireless-login.ucsd.edu","guest.mbcb.org"],"ip":"1.1.1.1","ports":[53,80,443,2052,...],"tags":[],"vulns":[]}`
- New evidence: internet-facing ports, product CPEs, known CVE ids, and Shodan-observed hostnames (rDNS and cert names) for an IP. None of the six existing modules say anything about exposed services; the hostnames can also feed back as DOMAIN entities. Strictly passive (Shodan's data, nothing sent to the target).
- Limits/ToS: page states no rate limit. "Free for non-commercial use"; an enterprise licence is needed for revenue-generating use (page FAQ). No key or account.
- Stability: low-med (static single-endpoint service, but Shodan could gate it).
- Verdict: ADD. Only source adding a new evidence class (service exposure) in one cheap call. Record `ports`/`vulns`/`hostnames` as separate slices.

### mnemonic passive DNS - ADD (rank 2)
- URL: `GET https://api.mnemonic.no/pdns/v3/<domain>?limit=N&offset=M` (only the domain form tested).
- Responded: HTTP 200, 0.72 s. No key.
- Shape: `{"responseCode":200,"limit":2,"offset":0,"count":997,"data":[{"query":"example.com","answer":"2606:4700:10::6814:179a","rrtype":"aaaa","firstSeenTimestamp":1775815867564,"lastSeenTimestamp":1792174125442,"times":928,"tlp":"white","minTtl":300,"maxTtl":300}, ...]}`
- New evidence: DNS *history* with first/last seen and observation counts, including answers that no longer resolve. The DNS module sees only today; Wayback/CC see URLs. Pivots: old IPs, retired NS, historical MX. `tlp: white` marks rows as freely shareable.
- Limits/ToS: no documented limit found; the docs/portal pages I tried were 404 or JS-only, so the licence is UNVERIFIED. Treat as best-effort: cap `limit` (say 200), one request per entity. Check mnemonic's terms before the release notes claim "free to redistribute".
- Stability: med (commercial MSSP running a free public endpoint; could add auth).
- Verdict: ADD. Highest history value; verify terms before release.

### RIPEstat additional data calls - ADD (rank 3)
All on `https://stat.ripe.net/data/<call>/data.json?resource=...`, same host as the existing `asn` module: no allowlist change. Latencies 0.13-0.9 s, HTTP 200 unless noted.

| call | sample (trimmed `data`) | adds |
|---|---|---|
| `whois?resource=1.1.1.1` | records: `inetnum 1.1.1.0/24`, `netname APNIC-LABS`, `descr APNIC and Cloudflare DNS Resolver project`, `country AU`, `org ORG-ARAD1-AP`, `admin-c`; `authorities:["apnic"]` | netname, descr, country, org handle (richer than RDAP `name`) |
| `abuse-contact-finder?resource=1.1.1.1` | `{"abuse_contacts":["helpdesk@apnic.net"],"authoritative_rir":"apnic"}` | abuse mailbox: possible EMAIL entity, ownership signal |
| `as-overview?resource=AS13335` | `{"holder":"CLOUDFLARENET - Cloudflare, Inc.","announced":true,"block":{...IANA...}}` | ASN holder name -> ORG entity (existing asn module stops at the number) |
| `rpki-validation?resource=AS13335&prefix=1.1.1.0/24` | `{"status":"valid","validating_roas":[{"origin":"13335","max_length":24}],"validator":"routinator"}` | routing-hygiene fact |
| `reverse-dns-ip?resource=1.1.1.1` | `{"result":["one.one.one.one"],"error":""}` | PTR for an IP via RIPE's resolver |
| `dns-chain?resource=example.com` | forward_nodes, reverse_nodes, `authoritative_nameservers`, `nameservers` | duplicates DNS module; low value |
| `related-prefixes?resource=1.1.1.0/24` | `{"prefixes":[]}` | little |
| `announced-prefixes?resource=AS13335` | 5,779 prefixes, **673 KB**, 0.9 s | ASN -> all prefixes; useful, but must be capped before storing as evidence |
| `as-neighbours` | HTTP 404, "data call does not exist" | removed upstream; do not use |

- Limits/ToS: see cross-cutting section (8 concurrent/IP, sourceapp, attribution, no commercial use or redistribution without permission).
- Stability: low (RIPE NCC, versioned calls; `as-neighbours` shows calls can still be removed).
- Verdict: ADD `whois`, `abuse-contact-finder`, `as-overview`, `reverse-dns-ip`, `rpki-validation`. SKIP `related-prefixes`, `dns-chain`; `announced-prefixes` MAYBE with a cap. Cheapest way to give IP/ASN entities an owner name and contact.

### urlscan.io public search - ADD (rank 4)
- URL: `GET https://urlscan.io/api/v1/search/?q=page.domain:<domain>&size=N`
- Responded: HTTP 200, 0.33 s, no key.
- Shape: `{"total":3158,"has_more":false,"results":[{"task":{"time":"2026-10-16T21:35:39Z","uuid":"..."},"page":{"domain":"example.com","ip":"172.66.147.243","asn":"AS13335","asnname":"CLOUDFLARENET - Cloudflare, Inc., US","server":"cloudflare","status":"200"},"stats":{...},"result":"https://urlscan.io/api/v1/result/<uuid>/","screenshot":"..."}]}`
- Caveat found: `q=domain:example.com` matches pages that *contacted* example.com (first hit was katu.com); `page.domain:` matches the scanned page itself. Modules must use `page.domain:` (or `page.apexDomain:`). Wildcard/subdomain queries were not tested.
- New evidence: dated observations of what actually served the domain (IP, ASN, server header, status) from real browser scans, with a result link per scan; querying `page.apexDomain:` surfaces subdomains as `page.domain`. A time-stamped hosting history that CT/DNS/RDAP do not give.
- Limits/ToS: anonymous search returned `X-Rate-Limit-Limit: 30` per minute per IP (scope ip-address, concurrency 10). Docs say unauthenticated users get "minor quotas" and not to mirror/scrape wholesale; commercial/redistribution terms are UNVERIFIED (ToS text not retrieved). Only public scans are visible and content is third-party submitted: store metadata only, no screenshots.
- Stability: med (anonymous quota can tighten; they push API keys).
- Verdict: ADD, with `size` capped (50-100) and one query per domain. Record per-row slices.

### CertSpotter issuances - ADD (rank 5, fallback/enrichment)
- URL: `GET https://api.certspotter.com/v1/issuances?domain=<d>&include_subdomains=true&expand=dns_names&expand=issuer`
- Responded: HTTP 200, 0.67 s. `X-Ratelimit-Limit: 10`, remaining decremented per call (window unstated; docs say a "limited number" of unauthenticated queries per hour).
- Shape (13 rows for example.com): `{"id":"12809115180","cert_sha256":"4973b4...","dns_names":["example.com","example.edu",...],"pubkey_sha256":"54d187...","issuer":{"friendly_name":"Sectigo","name":"C=GB, O=Sectigo Limited, CN=..."},"not_before":"2025-11-20T00:00:00Z","not_after":"2026-11-20T23:59:59Z","revoked":true}`
- New evidence vs crt.sh: same CT universe, but adds `pubkey_sha256` (pivot: key reuse across domains), `revoked`, normalised issuer name, and an independent fetch when crt.sh times out (crt.sh is the flakiest source we use; cross-source corroboration raises confidence). Pagination: `after=<last id>`, ordered by discovery time.
- Limits/ToS: unauthenticated use is "for personal or evaluation purposes"; production needs an SSLMate account; SSLMate "may discontinue, alter, or restrict functionality for free tier users at any time". Redistribution not addressed.
- Stability: med.
- Verdict: ADD as secondary CT source, run when crt.sh fails or on a deep scan; max 2 pages.

### Robtex free API - MAYBE
- URLs: `GET https://freeapi.robtex.com/pdns/forward/<domain>` (NDJSON), `/pdns/reverse/<ip>` (NDJSON), `/ipquery/<ip>` (JSON).
- Responded: HTTP 200 on all three, 0.22-0.55 s. forward: `{"rrname":"example.com","rrdata":"elliott.ns.cloudflare.com","rrtype":"NS","time_first":1642103570,"time_last":1792190178,"count":8}`. reverse/1.1.1.1 returned 23 KB of co-hosted names. ipquery: `{"status":"ok","as":13335,"bgproute":"1.1.1.0/24","asname":"Cloudflare","whoisdesc":"Cloudflare, Inc."}`.
- New evidence: passive DNS history and **reverse-IP (co-hosting)**, which nothing else here provides.
- Limits/ToS: docs state **10 requests/hour per IP** (429 `ratelimited`); Terms prohibit "excessive automated querying", abusers get blocked; as-is/best-effort; no commercial or redistribution clause, but the terms assert IP ownership of content, so redistribution is not granted.
- Stability: med.
- Verdict: MAYBE. Strong data, but 10/hour allows one domain plus a couple of IPs per hour. Ship only opt-in with a hard cap, or revisit if mnemonic also covers reverse lookups.

### AlienVault OTX - MAYBE (partial)
- `GET https://otx.alienvault.com/api/v1/indicators/domain/<d>/passive_dns` -> **HTTP 429 in 0.31 s: "Anonymous access to this endpoint is limited. Please authenticate."** Not usable keyless: SKIP for passive_dns.
- `.../general` -> HTTP 200 (`X-Remote-User-Name: Anonymous`): `validation` (Akamai rank, whitelist flags), `sections`, pulse info, whois link.
- `.../url_list?limit=2` -> HTTP 200: `{"url_list":[{"url":"https://hooks.example.com/webhooks/github","date":"2026-10-16T22:23:57","hostname":"hooks.example.com","domain":"example.com","httpcode":0}]}`. Dated hostnames seen in URLs (subdomain discovery).
- ToS: terms page is JS-rendered and could not be retrieved (UNVERIFIED). Rate limits undocumented; anonymous endpoints can be gated at any time (as passive_dns just was).
- Stability: high risk.
- Verdict: MAYBE for `url_list` only; not a v0.6 priority.

### RIPE Database REST - MAYBE
- `GET https://rest.db.ripe.net/search.json?query-string=<ip|org|mntner>&flags=no-filtering` -> HTTP 200, 0.41 s, 6.6 KB of `objects.object[]` (inetnum, organisation, role, mntner).
- Adds org/maintainer objects and inverse lookups (every network owned by an org handle): a real ownership pivot. Overlaps RIPEstat `whois`; returns personal data (person/role objects, emails), so needs privacy handling. RIPE DB terms page not retrievable (404 on URLs tried), UNVERIFIED.
- Stability: low. Verdict: MAYBE; revisit after RIPEstat `whois` ships, if org-to-network pivots are wanted.

### PeeringDB - MAYBE
- `GET https://www.peeringdb.com/api/net?asn=13335` -> HTTP 200, 0.65 s: `{"data":[{"id":4224,"name":"Cloudflare","website":"https://www.cloudflare.com","asn":13335,"irr_as_set":"AS13335:AS-CLOUDFLARE",...}]}`.
- Adds network display name, official website (domain pivot), IRR as-set; IX presence via `netixlan`. Only for operators that registered. Terms not checked. Stability: low. Verdict: MAYBE, narrow value for ASN -> website/ORG.

### ipinfo.io / ipapi.is - MAYBE (low)
- `GET https://ipinfo.io/1.1.1.1/json` -> 200, 0.47 s: hostname, city/region/country, `org: "AS13335 Cloudflare, Inc."`, anycast. `GET https://api.ipapi.is/?q=1.1.1.1` -> 200, 0.52 s: `company: APNIC Research and Development`, asn, geo.
- Adds geolocation (RDAP/RIPEstat lack it) and a company name. Geolocation is heuristic; keyless tiers are usage-limited with commercial restrictions (terms not retrieved). Verdict: MAYBE, only if geo is wanted.

### HackerTarget hostsearch - SKIP
- `GET https://api.hackertarget.com/hostsearch/?q=example.com` -> 200, 0.63-0.82 s, CSV: `www.example.com,172.66.147.243` (one row). Headers `X-API-Quota` / `X-API-Count`.
- Limits: FAQ says **50 calls/day per IP** free, 2 req/s; ToS not read. Origin opaque and largely overlaps CT/DNS; a shared NAT burns the quota at once.
- Verdict: SKIP (50/day, low unique value).

### subdomain.center - SKIP
- `GET https://api.subdomain.center/?domain=example.com` -> 200, 0.41 s, 499 names (e.g. `svs1.laboratory.example.com`, `sevendimensions.example.com`). Fast, but provenance undocumented and no ToS or limits stated; an evidence-first tool cannot cite an unknown origin. Verdict: SKIP.

### GreyNoise community - SKIP
- `GET https://api.greynoise.io/v3/community/1.1.1.1` -> 404 in 0.74 s with `{"noise":false,"riot":false,"message":"IP not observed scanning the internet."}`; `X-Ratelimit-Limit: 25`. Works keyless, but community tier is limited and scan-noise classification is tangential to infrastructure/ownership mapping. Verdict: SKIP.

### Dead, blocked or keyed today - SKIP
| source | observed | note |
|---|---|---|
| Anubis `jldc.me/anubis/subdomains/<d>` | 301 to `jonlu.ca/anubis/...`, then **403 Cloudflare "Attention Required"** challenge (0.29 s) | moved and bot-challenged; do not attempt to bypass |
| BufferOver `tls.bufferover.run/dns?q=.example.com` | **403 `{"message":"Forbidden"}`** (0.45 s) | now requires an API key |
| ThreatMiner `api.threatminer.org/v2/domain.php`, `host.php` | **HTTP 522 both times, ~20 s timeout** | origin down |
| BGPView `api.bgpview.io/ip/1.1.1.1` | **connection failure, HTTP 000 / 522 body** (0.03 s) | appears discontinued |
| GitHub code search `api.github.com/search/code` | **401 "Requires authentication"** | confirmed keyed |
| OTX passive_dns | 429 anonymous limited | see OTX section |

Side note: `rdap.org/autnum/13335` returns 200 in 1.19 s (11.9 KB) on the already-allowlisted host, so the existing `rdap` module could accept ASN entities (holder/org) at almost no cost.

## Suggested v0.6 sequencing
1. InternetDB module (accepts IP) plus allowlist entry; smallest change, biggest new evidence class.
2. RIPEstat extras for IP/ASN entities (`as-overview`, `whois`, `abuse-contact-finder`, `reverse-dns-ip`), with `sourceapp=scrutator`, attribution text, and nested-timestamp denoising.
3. mnemonic pdns (accepts DOMAIN; confirm terms first), then urlscan, then CertSpotter fallback.
4. Hold Robtex / OTX url_list / PeeringDB for v0.7 behind explicit source flags.

## Probe hygiene
- Roughly 55 GETs across about 30 endpoints; at most two per source, plus a few follow-ups on the same host to read headers or extract a field (OTX, urlscan, CertSpotter, HackerTarget, RIPEstat).
- Scope note: one HackerTarget request used `q=hackertarget.com` (their own domain) to see a multi-row response, outside the example.com-only rule; HackerTarget's quota headers show these requests count against the shared daily allowance. Nothing else strayed from example.com / 1.1.1.1 (plus 192.0.2.1, a documentation address, for the InternetDB 404 case).
- Doc and ToS pages were fetched read-only. Not verified (404 or JS-only): mnemonic terms, OTX terms, RIPE Database terms, full urlscan and SSLMate ToS text, Robtex RapidAPI terms.

## Addendum (v0.6 build, 2026-10-17): what changed after the first pass

Re-checked while building the v0.6 modules, example.com and 1.1.1.1 only (plus the services' own public pages).

- **HackerTarget: now ADD**, as one call per scan (the Round 2 brief asks for it). Its own page states the free tier: 50 calls per day from a single IP, 2 requests per second (429 above that), 500 lines per answer. Quota exhaustion arrives as the text `API count exceeded - Increase Quota with Membership` with HTTP 200; the module treats that as the source being unavailable. The quota is per IP and was used up by development runs, which is reported in `docs/benchmarks/2026-10-17-after-v0.6.md`.
- **subdomain.center: now ADD, as a claim source.** What the first pass called undocumented provenance is described on its homepage: web-scale crawling (Apache Nutch), real-time Certificate Transparency ingestion (Certstream), embedding-based correlation and in-house tooling; it says it does not resolve DNS, so its data includes hosts that never resolve. The free anonymous tier needs no key or account and returns up to 500 names in random order (`x-tier: anonymous`, `x-result-count`, `x-truncated` headers). Its terms of service and privacy policy (arpsyndicate.io/policy.html) grant a limited licence for personal, non-commercial use. Names from it are recorded as claims; the name states (live, stale, wildcard-covered, unresolved) separate them from hosts.
- **RapidDNS: SKIP.** Its pricing page gives anonymous users no API access and a 100-record, one-page view; free GitHub login gives 1,000 records and still no API. Scraping its HTML goes beyond what it offers, and it does not say where its data comes from. Its terms page was not read beyond that.
- **mnemonic passive DNS cannot list subdomains.** `pdns/v3/<name>` answers for one exact name; the wildcard forms `*.example.com`, `.example.com`, `*example.com` and `%2Aexample.com` all returned `object.not.found`, and `%25.example.com` returned a non-JSON error. It is used for the DNS history of the apex (addresses, name servers, mail servers, aliases with first and last seen), not for finding names. Its terms were still not retrievable.
- **urlscan.io: query on `page.apexDomain:` (with `page.domain:` for a seed that is not a registered domain).** `page.domain:*.example.com` returned an error; `page.apexDomain:example.com` returned scans whose `page.domain` was `example.com` and `www.example.com`. Only results whose scanned page is under the apex are kept.
- **CertSpotter pagination:** the `Link: rel="next"` header points at a URL without `/v1`; the module builds the next page itself with `after=<last id>` and reads at most 2 pages.
- **RIPEstat extras:** `abuse-contact-finder` and `whois` are called per in-scope address with `sourceapp=scrutator`; no new entity is created (there is no EMAIL entity type, and an abuse mailbox is a hint, not something to scan). `as-overview` was not added: an ASN reached from an address is out of scope, and the engine never runs a module on an out-of-scope entity.
