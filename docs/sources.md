# Sources and terms

Scrutator asks a dozen public services about a domain. Their terms are theirs, not ours: read them before relying on
a source in a commercial engagement. Which sources a scan uses is your decision (see [choosing sources](#choosing-sources)).

The table below has one row per module, exactly as `scrutator sources` lists them; a test fails if the two disagree
(module names, keyless or keyed and the variable, non-commercial flag, replayable flag).

| Module | Access | Non-commercial | Replayable | Gives | Terms in short |
|---|---|---|---|---|---|
| `asn` | keyless | yes | yes | IP to ASN and network name (RIPEstat) | RIPE NCC terms: non-commercial use, no redistribution of the data without permission, credit RIPE NCC and the original source. Requests identify the application (`sourceapp=scrutator`). Bundles that embed RIPEstat responses inherit this. |
| `brand` | keyless | no | yes | **Opt-in, `scan --brand` only.** The platform accounts the organisation's home page links to, and whether they, the bare brand name and up to 20 look-alikes of it exist on those platforms (HTTP status of the public profile page, nothing from the page) | Contacts the organisation's own site: robots.txt first (agent `scrutator`; an unreadable robots.txt counts as "disallow"), then the home page if allowed, one request a second, no login. Profile pages are asked only on github.com, gitlab.com, mastodon.social, huggingface.co, codeberg.org and hub.docker.com, and only when the site links to that platform. X, LinkedIn, Facebook, Instagram, TikTok, YouTube, Reddit, Bluesky, PyPI, npm, Medium, Telegram and Twitch are never requested (their terms restrict automated access, or the page does not tell): a link to them is reported as *unverifiable*. Only the profile checks replay; the organisation's site is never replayed. |
| `certspotter` | keyless | yes | yes | Second Certificate Transparency view: names, issuer, key hash, revocation (`api.certspotter.com`) | The unauthenticated API is for personal or evaluation use; production needs an SSLMate account; the free tier may change at any time. At most 2 pages per scan. |
| `commoncrawl` | keyless | no | yes | Hostnames seen in the latest crawl (`index.commoncrawl.org`) | Public index; fair use. |
| `crtsh` | keyless | no | yes | Certificate Transparency names (`crt.sh`) | Public service of Sectigo; no stated limit; often slow or answers 502. |
| `dns` | keyless | no | yes | A, AAAA, CNAME, MX, NS, TXT, CAA, with NXDOMAIN/NODATA as evidence | Your own resolver. |
| `exposure_dns` | keyless | no | no | **Only `scrutator exposure`, with an engagement file.** Report addresses in the DMARC record and the SOA contact mailbox of the engagement's domains, minimised | Your own resolver. Addresses outside the engagement are dropped and counted; DMARC report processors are kept as domains. |
| `exposure_rdap` | keyless | no | no | **Only `scrutator exposure`.** E-mail addresses in the domain's RDAP contacts (`rdap.org`), minimised | As `rdap`. Registrars' abuse addresses fall outside the engagement and are only counted. |
| `exposure_repos` | keyless | no | no | **Only `scrutator exposure`**, and only for the GitHub organisations the engagement file names: commit author and committer addresses of up to five recently pushed public repositories (`api.github.com`), minimised | GitHub's REST API without a key: 60 requests an hour per address; 6 per organisation. `noreply` addresses are counted, not kept. |
| `exposure_site` | keyless | no | no | **Only `scrutator exposure`.** robots.txt, `/.well-known/security.txt`, the home page and at most three contact, about, team, imprint or legal pages of the organisation's own site; e-mail addresses only, minimised | Contacts the organisation's site (robots.txt honoured, one request a second). Phone numbers, names and postal addresses on the pages are never extracted. |
| `hackertarget` | keyless | no | yes | Hostnames and addresses from its DNS data (`api.hackertarget.com`, `hostsearch`) | Free API: 50 calls per day per IP address (shared with everything else you run from it), 2 per second, 500 lines. One call per scan; a used-up quota is reported as the source being unavailable, never as "no names". |
| `internetdb` | keyless | yes | yes | For in-scope and linked addresses only: open ports, product names (CPE), CVE ids Shodan associates with them, host names it has seen (`internetdb.shodan.io`) | **Free for non-commercial use only**; revenue-generating use needs a Shodan enterprise licence. It is Shodan's earlier scan; nothing is sent to the address. Bundles that embed its data inherit this. |
| `mnemonic` | keyless | no | yes | DNS history of the apex with first and last seen: old addresses, name servers, mail servers, aliases (`api.mnemonic.no`) | TLP:white rows; terms of use could not be retrieved, so best effort. It answers for one exact name and cannot list subdomains. History is recorded under its own relations and is never scanned. |
| `rdap` | keyless | no | yes | Registrar, registrant organisation where published, name servers, expiry, network owner (`rdap.org`, which redirects to the registries' RDAP servers) | Public redirector. Free; `rdap.org` refuses more than about ten requests in ten seconds, so requests are paced. |
| `ripestat` | keyless | yes | yes | The abuse contact and the network name, description and country of an address (`stat.ripe.net`) | Same RIPE NCC terms as `asn`. |
| `securitytrails` | keyed (`SCRUTATOR_SECURITYTRAILS_KEY`) | no | no | Subdomains (`api.securitytrails.com`, `/v1/domain/{domain}/subdomains`) | Terms depend on the plan your key belongs to. |
| `shodan` | keyed (`SCRUTATOR_SHODAN_KEY`) | no | no | Shodan's DNS data for the domain (`api.shodan.io`, `/dns/domain/{domain}`, up to 2 pages, one query credit each); not the keyless InternetDB | Terms depend on the plan your key belongs to. |
| `subdomaincenter` | keyless | yes | yes | Names from web crawling, real-time CT ingestion and correlation, **including names that do not resolve** (`api.subdomain.center`) | Terms grant a limited licence for personal, non-commercial use. Free anonymous tier: up to 500 names per query, random order. Its names are one source's claim until DNS or a certificate agrees. |
| `urlscan` | keyless | no | yes | Hostnames it has scanned under the domain, with the IP, ASN, server and status that served them on a date (`urlscan.io`) | Anonymous search: 30 requests per minute; scans are submitted by third parties, so only metadata is kept (no screenshots, titles or page content). One call per scan. |
| `virustotal` | keyed (`SCRUTATOR_VIRUSTOTAL_KEY`) | no | no | Subdomains VirusTotal holds (`www.virustotal.com`, `/api/v3/domains/{domain}/subdomains`, up to 5 pages of 40) | Terms depend on the plan your key belongs to. |
| `wayback` | keyless | no | yes | Hostnames seen in the Internet Archive (`web.archive.org`, CDX API) | Public CDX API; fair use. |
| `wildcard` | keyless | no | yes | The wildcard-DNS probe: one random label under the apex, recorded as evidence | Part of DNS; it asks your resolver about a name that does not exist. |

Looked at and **not** used: RapidDNS (its own pricing page gives anonymous users no API access and 100 records, so
scraping its pages goes beyond what it offers), BufferOver, Anubis, ThreatMiner and BGPView (dead, blocked or keyed
when probed on 2026-10-17; notes in `docs/superpowers/research/2026-10-17-v06-keyless-sources.md`). Censys is not
offered: its search API is being replaced, so there is no stable documented shape to implement against yet.

Sources that list names (`crtsh`, `certspotter`, `subdomaincenter`, `hackertarget`, `urlscan`, `wayback`,
`commoncrawl`) are asked once per scan, about the apex. Failed sources are retried with backoff and reported under
**Source coverage**; a source that times out or answers 5xx/429 three times in a row (`--breaker 3`) is marked
**down** for the rest of the scan.

## Choosing sources

```bash
scrutator scan example.com --sources crtsh,dns,rdap          # only these
scrutator scan example.com --exclude-sources wayback,commoncrawl
scrutator scan example.com --no-noncommercial                # leave out the non-commercial free tiers
scrutator sources --no-noncommercial --json                  # preview a policy
```

A name is a module (`asn`) or the source family it belongs to (`ripestat` covers the `asn` and `ripestat` modules, `dns`
covers the resolver and the wildcard probe). An unknown name is an error that lists the valid ones, so a typo cannot
quietly leave a source on. `--exclude-sources` wins over `--sources`.

`--no-noncommercial` turns off every module marked "yes" in the Non-commercial column: `asn`, `ripestat`,
`certspotter`, `internetdb`, `subdomaincenter`. Nothing else changes, and the report says what was not asked, so a
smaller result is never mistaken for a cleaner one.

The policy is recorded three times: in the report (`source_policy`: the options, the sources enabled, and each
disabled source with its reason), in the signed manifest, and as the first record of the hash-chained audit log.
`scrutator verify` checks that the three agree and that no lookup in the audit log and no evidence record comes from
a source the policy forbids (check `source policy honoured`); it re-derives what `--no-noncommercial` forbids from
its own list, so a bundle cannot narrow the list it records.

## Keyed sources (optional, off by default)

The three keyed modules are **implemented against each service's documented API and not live-verified**: no key was
available to the author and no account was created to get one, so their tests use fake answers in the documented
shapes. Treat your first real run as the real test.

- A key comes **only from its environment variable**. There is no command-line option, config-file field or prompt
  for a key, so it cannot reach shell history or a process list. A source without its variable is off, and the report
  says so with the variable's name (never a value). Asking for one by name (`--sources shodan`) without its variable
  is an error.
- The key is read when a lookup runs and sent as the service requires (a header; Shodan insists on a query
  parameter). It is **never stored**: the evidence records the request without it. The report, HTML, signed bundle,
  audit log, database, request logs, MCP output and error messages contain no key (a canary-key test searches all of
  them). Error text goes through a redaction that replaces any configured key, also percent-encoded, with
  `[redacted]`.
- Keyed sources are scope-gated and passive like the others, and their names are claims until DNS or a certificate
  agrees. Their hosts are not on the replay allowlist (a replay would need your key), so `verify --replay` skips
  their evidence.

## What each service sees

Every module that runs sends the service the domain (or, for address sources, the addresses your in-scope names
resolve to). A service you did not choose never sees it: use `--sources` or `--exclude-sources`. The target itself is
never contacted by a passive scan, except that your resolver is asked DNS questions about it, which reach the
target's own name servers when your resolver has no cached answer. The opt-in `brand` module is the exception you
choose: with `scan --brand` it reads robots.txt and the home page of the organisation's site (see the table).
