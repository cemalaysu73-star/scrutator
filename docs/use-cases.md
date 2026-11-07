# Use cases

Seven workflows with the exact commands. Every command here exists (a test checks the command names and options
against the program), and every output shown is from a real run unless it says otherwise. Use `example.com`, a domain
you own, or a target you are authorised to assess. Passive scans only ask public sources; read
[Responsible use](#responsible-use) before the first real target.

All of them share three habits:

- keep one folder per case or client (`--out`), because the folder holds the evidence database and the report;
- sign what you will hand to anyone (`--bundle`, with a key from `scrutator keygen`), and give the reader your key
  fingerprint so they can `verify --pin`;
- read the **claimed** names as leads and the **verified** names as findings. The headline is `N verified, M claimed`.

## 1. Penetration tester or red teamer: recon before an engagement

Goal: an authorised, defensible map of the client's external footprint, kept inside the rules of engagement, that you
can attach to the report and that the client's security team can re-check.

```bash
scrutator keygen --passphrase                                      # once: your signing key, sealed by a passphrase
scrutator scan client.example --scope scope.yaml --attribution --bundle --out recon/client --ai off
scrutator risk --db recon/client/scrutator.db --category risk      # configuration risks, each with its evidence ids
scrutator candidates --db recon/client/scrutator.db --min-band possible
scrutator attribution --db recon/client/scrutator.db --entity partner.example.net   # why, and what could make it wrong
scrutator promote partner.example.net --db recon/client/scrutator.db --scope scope.yaml   # only after the client confirms it is theirs
```

`scope.yaml` is the rules of engagement in machine form. Anything not in it is recorded as `out` and never looked up:

```yaml
domains:
  - client.example
cidrs:
  - 203.0.113.0/24
asns:
  - AS64500
```

What you get: a report where each name is `verified` or only `claimed`, a list of risks (dangling CNAMEs at claimable
services, missing CAA, weak SPF or DMARC, forgotten staging hosts), the addresses the in-scope names resolve to with
their network owners, and, with `--attribution`, candidate assets outside the scope file ranked by evidence (a sister
domain delegated to the client's name servers, for example). A candidate is a lead: ask the client before it enters
the engagement, then `promote` it, which writes the scope file and a signed audit-log record.

Things to know:

- The passive scan sends nothing to the client's servers; your resolver may ask the client's authoritative name
  servers. Recall is limited by what passive sources have seen: on the one benchmark target with a real truth set,
  Scrutator reached 4 of 31 zone names (knockpy 2, the others none)
  ([benchmark](benchmarks/r6.md)). Run your usual enumeration tools as well.
- Active steps are separate, opt-in and need your authorisation. A zone-transfer request to the zone's own name servers
  needs both flags: `scrutator scan client.example --scope scope.yaml --axfr --active`; it is recorded in the signed
  audit log before any lookup, and most servers refuse. Authorised active confirmation of passive findings (a handful
  of ordinary connections to the addresses of the client's own names, only under an authorisation that covers active
  testing, bounded, with every connection recorded as evidence) is `scrutator audit --active`; see docs/active.md.
- Scope import for bug-bounty style programmes is in the next section; a statement of work is not machine readable, so
  write `scope.yaml` by hand from it.
- Verify what you hand over: `scrutator verify recon/client/proof.scrutator --pin ~/.config/scrutator/signing.pub`.

## 2. Bug-bounty hunter: scope in, alerts out

Goal: know first when a programme's scope grows a new asset or a takeover candidate, with the records that prove it,
without breaking the programme's rules.

```bash
scrutator bounty import scope.csv --program "Example" --out bounty-scope.yaml     # HackerOne CSV; or a Bugcrowd JSON, or a pasted list
scrutator bounty watch --scope bounty-scope.yaml --out bounty-watch --every 6h --key-dir keys
```

The import is deny by default and refuses what it cannot represent safely. A real run on a pasted list that included
a wildcard over a public suffix:

```
In scope: 1 host(s), 1 wildcard(s), 0 range(s). Out of scope: 0 host(s), 1 wildcard(s), 0 range(s).
  refused '*.com': *.com is a public suffix, far too broad
Wrote bounty-scope.yaml. Anything not listed in it is out of scope. Scan roots: api.example.org, example.com.
```

The first `watch` round is the baseline and announces nothing. After that, only what is new, in scope and not already
announced is reported, once each: `new_name`, `new_takeover`, `resolved_risk`, `new_cert`, `new_service`. Every
`new_takeover` alert also writes `findings/risk-<fingerprint>.md`, a ready-to-paste draft with the evidence records,
the `dig` commands that reproduce the observation by hand, and a reminder to confirm under the programme's rules.

Rules of the road: Scrutator never registers, claims or probes anything. A takeover *candidate* is a dangling CNAME
at a service whose fingerprint says the name can be claimed; whether you may confirm it, and how, is the programme's
policy, not the tool's. Re-rate the draft's severity under the programme's own policy.

More: [bug-bounty mode](bounty.md).

## 3. Consultant or company self-check: an external exposure review

Goal: a client-ready deliverable that rests on a signed scan and that the client's auditor can check offline. The same
flow works for a company reviewing its own domains.

```bash
scrutator audit-letter --lang en --client "Example Corp" --domains example.com --out authorisation
scrutator audit example.com --engagement authorisation/engagement.yaml --out audit-example       # client mode
scrutator audit example.com --self --yes --out audit-self                                        # your own domains: an attested self-assessment
scrutator audit-check audit-example/audit.html audit-example/proof.scrutator --pin audit-example/signing.pub
```

`audit-letter` writes an authorisation letter template (not legal advice; have counsel review it) and the
`engagement.yaml` that `audit` reads. `audit` **refuses to run** without that file (every `<fill in: ...>` replaced) or
`--self`. The output folder holds `audit.html` (print-ready), `audit.pdf` when a Chromium-based browser is installed,
`technical-annex.html` (the interactive report), `audit.json`, the signed bundle and the key. The client or their
auditor runs `audit-check`, which fails if a number, a finding or a sentence does not follow from the bundle, or the
page was edited. A real run on the bundled sample:

```
PASS  bundle verifies (pinned)
PASS  audit data readable
PASS  names this bundle
PASS  authorisation recorded at report time  (not in the signed log: the scan predates it)
PASS  content derivable
PASS  every claim cites evidence in the bundle
PASS  AI rewordings pass the deterministic floor
PASS  page is what the facts render to
Audit check passed: the report is what the signed evidence implies.
```

For retainers, run `watch` once per scheduler
tick; the folder holds the baseline, every change and a weekly digest:

```bash
scrutator watch client-a.com --client "Client A" --out clients/client-a --max-runs 1 --min-severity medium
```

Paid work: add `--no-noncommercial` to leave out sources whose free tier is for non-commercial use only; the audit
lists the sources it did not use. More: [client audits](audit.md), [monitoring](hosting.md). The Turkish report
language (`--lang tr`) is a product feature for Turkish-speaking clients.

## 4. Due diligence: a vendor or an acquisition target

Goal: an independent, dated outside-in view of an organisation's internet footprint before you sign: how many assets,
who hosts them, what is dangling, which domains belong to the company that the deal documents do not list.

```bash
scrutator scan target.example --attribution --no-noncommercial --bundle --out dd/target --ai off
scrutator risk --db dd/target/scrutator.db --compliance
scrutator candidates --db dd/target/scrutator.db --min-band probable
scrutator attribution --db dd/target/scrutator.db --entity brand-two.example
scrutator scan target.example --attribution --bundle --out dd/target-later --ai off       # a month later
scrutator diff 1 2 --db dd/target/scrutator.db                                            # or: diff old.scrutator new.scrutator
```

Reading it: `risk --compliance` adds an *informational* mapping of each rule to ISO/IEC 27001 Annex A, NIS2, CIS
Controls, OWASP and KVKK. It is not a certification and not a legal conclusion. Attribution tells you, with reasons,
which other domains look like the same organisation's; every candidate carries a pre-mortem of what could make it
wrong. **The attribution weights are hand-chosen and calibrated on nothing but a synthetic lab**, so treat a `probable`
as a question to put to the target, not an answer.

Be careful with what a passive outside-in view cannot see: internal systems, anything behind a login, hosts with no
public certificate, DNS record or archive entry. An empty risk list is not a clean bill of health.

Authorisation: for a deal you usually have the counterparty's consent; keep it. Public records about an organisation
are lawful to read in most places, but your jurisdiction and your engagement terms decide. See the
[FAQ](faq.md#is-it-legal).

## 5. Incident responder: what else is exposed, and what changed

Goal: during an incident, quickly list what the affected organisation exposes, freeze that view as evidence, and
compare it with an earlier one.

```bash
scrutator keygen --key-dir keys                                          # once per case, or reuse your key
scrutator quick victim.example --bundle --out ir/case-17 --key-dir keys    # names in seconds; prints live names as DNS confirms them
scrutator scan victim.example --attribution --bundle --out ir/case-17-full --key-dir keys
scrutator risk --db ir/case-17-full/scrutator.db --sarif ir/case-17.sarif
scrutator diff baseline.scrutator ir/case-17-full/proof.scrutator          # against a bundle made before the incident
scrutator verify ir/case-17-full/proof.scrutator --pin keys/signing.pub    # the integrity check you will want in the post-mortem
```

What helps: `quick` prints each verified name as soon as DNS confirms it; the full scan adds registration data, network
owners and ports a public index saw, and flags dangling CNAMEs and look-alike or forgotten hosts. Certificate
transparency tells you which certificates were issued for in-scope names and when (`new_cert` alerts in `watch`), which
is useful when you suspect a rogue issuance. Passive DNS history (the `mnemonic` source) shows old addresses and name
servers.

Chain of custody: the signed bundle freezes the evidence, the audit log and the report. It proves nothing changed since
signing; it does not prove when it was made (no trusted timestamp) or that a source told the truth. Add an external
timestamp or store the bundle's sha256 in your ticketing system with a time you control.

## 6. Journalist or OSINT researcher: organisations, with provenance

Goal: investigate an organisation's infrastructure (who runs which domains, what they share with whom) and publish or
hand to an editor a result that every claim in can be traced to a record a third party can check.

```bash
scrutator keygen --passphrase --key-dir case-keys
scrutator scan company.example --attribution --bundle --key-dir case-keys --out case/company --ai off
scrutator candidates --db case/company/scrutator.db --min-band possible
scrutator attribution --db case/company/scrutator.db --entity sister-site.example
scrutator verify case/company/proof.scrutator --pin case-keys/signing.pub
```

With `--ai off` no model is involved. If you want a verified summary, `--ai local` uses a model on your machine and
refuses any endpoint that is not loopback; a cloud model is never used unless you ask for it by name. **The seed is a domain, never a person.** The tool will not search for a named individual, and
organisation records can still contain personal data (an RDAP contact, a name in a certificate): handle that like any
personal data you hold.

### How to cite Scrutator evidence

A claim in an article or a report should point to something a reader or an editor can verify without you. Give:

1. the claim in your words, and the **evidence id(s)** it rests on (64 hex characters, from the report's evidence
   drawer or `evidence.jsonl`);
2. the **bundle**: the file, its own sha256, and where it can be downloaded;
3. the **signing key fingerprint**, published somewhere the reader trusts (your site over HTTPS, the publication's
   page), so that `scrutator verify --pin` is meaningful;
4. a note that the bundle proves the report follows from the records and that nothing was altered after signing, not
   that the sources were right, and not when it was made. If timing matters, timestamp the bundle with an external
   service when you create it.

A reader can then run `scrutator verify proof.scrutator --pin <fingerprint>`, recompute any evidence id by hand (the id
is the sha256 of the source, request and payload, see [how it works](how-it-works.md#what-evidence-backed-and-verifiable-mean-a-worked-example)),
and with `--replay` ask the sources again to see whether they still say the same.

### Operational security: what the tool does on the network

Plan with this list; it is the whole of it.

- **Who is asked, and what they learn.** Every enabled source learns **the domain you are investigating and the IP
  address you ask from**. The hosts are: `crt.sh` (also its PostgreSQL database on port 5432 when the web search
  fails), `api.certspotter.com`, `rdap.org` and the registries' own RDAP servers (`rdap.arin.net`,
  `rdap.db.ripe.net`, `rdap.apnic.net`, `rdap.lacnic.net`, `rdap.afrinic.net`), `stat.ripe.net`, `web.archive.org`,
  `index.commoncrawl.org`, `api.hackertarget.com`, `api.subdomain.center`, `urlscan.io`, `ip.thc.org`,
  `api.mnemonic.no` and `internetdb.shodan.io`. The keyed sources (VirusTotal, SecurityTrails, Shodan) are off unless
  you set a key. `api.github.com` is used only by `scrutator exposure`. The list is in the code
  (`egress.SOURCE_HOSTS`) and in [sources](sources.md); `scrutator sources` shows what is on. Leave a source out with
  `--exclude-sources` or choose `--sources`.
- **DNS** goes to your system's configured resolver, in clear, over UDP/TCP 53. Your resolver may ask the target's
  authoritative name servers. If the target operates its own DNS, it can see the resolver's address.
- **The target's own servers** are not contacted in a passive scan. The exceptions are opt-in: `--axfr --active`
  (name servers), `--brand` (the organisation's home page and the public profile pages of a few platforms) and
  `scrutator exposure` (the organisation's site and public repositories).
- **The user agent** is `scrutator/<version>`. It says what the traffic is.
- **One proxy setting, and what it does not cover.** `SCRUTATOR_PROXY=URL` (or `scrutator --proxy URL <command>`; prefer
  the variable, which keeps credentials out of your shell history) sends every HTTP request of the sources, the
  opt-in web modules and the crt.sh database connection through an `http://`, `socks5://` or `socks5h://` proxy. SOCKS
  for the HTTP sources needs `pip install "scrutator[socks]"`. **DNS is not proxied**: names go to your system
  resolver in clear, and the resolver (and, behind it, the target's name servers) sees every name asked about. The proxy
  operator sees every destination. For Tor, `socks5h://127.0.0.1:9050` carries the HTTP and database traffic and leaves
  DNS as it is, so for an investigation where the lookups themselves must not be attributable, run the whole process
  where all egress, DNS included, already goes through the path you trust (a VPN, a VM or container with routed
  traffic and a DNS forwarder). Many public services block or throttle Tor exits and VPN ranges, so expect more
  failed sources; the report says which failed.
- **Where evidence is stored.** In the case folder (`--out`): `scrutator.db` (SQLite, every evidence record and
  the audit log), `report.html`, `report.json`, `proof.scrutator`. The signing key is in `~/.config/scrutator/` unless
  you pass `--key-dir`. Reports contain the raw answers of the sources about the target, so treat the folder as
  sensitive. Nothing is uploaded anywhere.
- **Wipe a case.** Close anything holding the files, then delete the whole case folder and the key directory you
  made for it (`rm -r case/ case-keys/`, or `Remove-Item -Recurse -Force case, case-keys` in PowerShell). Deleting is
  not secure erasure on SSDs or journaling filesystems: for work that needs that, keep the case on an encrypted volume
  and destroy the volume key. Also clear your shell history, which holds the domain names you typed, and remember the
  bundles and reports you shared.
- **The MCP server** (`scrutator mcp`) reads the same database; it offers no scan or promote tool unless you start it
  with `--allow-scan` or `--allow-promote`. If you connect it to a cloud-hosted assistant, what its tools return
  (names and text from public records about your target) goes to that provider.

## 7. Everyone: check a report someone sent you

```bash
scrutator verify their.scrutator --pin their-signing.pub          # or --pin <fingerprint> from a channel you trust
scrutator verify their.scrutator --pin their-signing.pub --replay # also re-ask the sources
```

`verify` is built to be run on files from people you do not trust: it never extracts members to disk, bounds sizes
before inflating and fails with a named check. Details: [proof bundles](proof-bundles.md#verifying-an-untrusted-bundle).
Without `--pin` it warns: anyone can sign a forged bundle with their own key.

## Responsible use

- **Authorisation.** Scan what you own, what you are engaged to assess, or what you are entitled to research. A
  scope file is a record of what you decided to look at; it is not permission.
- **No person lookup.** The seed is a domain. Do not use the output to harass, profile or locate individuals.
- **Passive by default.** The default scan asks public sources and your resolver. Anything else is opt-in, recorded in
  the signed audit log, and for authorised targets only.
- **Sources have terms.** Several free tiers are for non-commercial use; use `--no-noncommercial` for paid work.
- **A finding is a lead.** Risks describe configuration visible in public records. Confirm with the owner before
  you call something a vulnerability, and follow the programme's or client's disclosure rules.

The full policy: [RESPONSIBLE_USE.md](../RESPONSIBLE_USE.md). Security problems in Scrutator itself:
[SECURITY.md](../SECURITY.md).
