# Changelog

Built from the git history (`git log`), newest first. Dates are commit dates. Versions before 0.7 were never
tagged or published; the numbers are the ones in `pyproject.toml` at the time. Nothing here has been released on
PyPI.

## 1.0.0rc4 (2026-11-07, a release candidate; not published)

Round R8: authorised active confirmation, strictly guardrailed, and an outbound proxy. The edge stays the same: every
claim is signed evidence a stranger can check; what is new is a way to say "checked now" instead of "a third party
said so once".

- **Active confirmation** (`scrutator audit --active`, `scrutator active-plan`; docs/active.md)
  - After the passive scan, a few ordinary connections to the addresses an in-scope name resolves to: a TCP connect
    check with a read-only banner capture on the ports a passive source lists plus a fixed list of risky ports and 80/443,
    a TLS handshake per name (certificate, hostname match, protocol, whether TLS 1.0/1.1 still complete), and one
    `GET /` per name with a fixed generic User-Agent, no redirect followed.
  - Guardrails: an engagement with `active_testing: true` or a `--self` attestation naming the systems, recorded in the
    signed audit log before the first lookup; never reachable from MCP; shared platforms (new `shared.yaml` pack) and
    private, loopback, link-local, reserved and IPv6 addresses skipped with the reason recorded (also when a public name
    resolves to one); a hard connection cap (60), concurrency 4, a rate limit, per-step timeouts and a deadline;
    Ctrl-C safe; no login, payload, fuzzing, brute force or UDP.
  - Evidence sources `tcp`, `tls`, `http` and `active` (the plan, written before the first connection). Active
    evidence is never replayed. `verify` re-derives the plan from the passive evidence and fails a bundle whose probes
    left it, exceeded the cap, hit a refused or shared address, or lack an authorisation recorded before the lookups.
  - Rules: `exposed-risky-service` is confirmed (high confidence) when a connection succeeds; new `stale-exposure-data`
    when a third party listed a port that is closed or unanswered now (both are shown); `tls-cert-expired`,
    `tls-cert-expiring`, `tls-hostname-mismatch`, `tls-legacy-protocol`, `http-no-https-redirect`, `http-missing-hsts`,
    `http-missing-security-headers`, `server-banner-discloses-version`. Mapped in the compliance pack, in SARIF, in the
    HTML report (a new section and the evidence drawer), in the audit ("checked now" versus "reported earlier by a
    third party") and in `scrutator risk`.
- **`--proxy`** (also `SCRUTATOR_PROXY`): one HTTP or SOCKS5 proxy for every outbound request: the HTTP sources, the web
  modules, the crt.sh fallback and the active probes. DNS is not proxied; docs/active.md says what that means.
- **Bench**: `scrutator-bench/5` with the section `active` (local listeners).
- Rule set 4 (bundles made with rule set 3 verify unchanged unless they hold active evidence); the audit's sample
  documents were regenerated for this version.

## 1.0.0rc3 (2026-10-21, a release candidate; not published)

Round R7: make it sellable by someone who sells it. The one edge kept in front: every claim carries signed, independently
verifiable evidence. Speed and source count are not claimed.

- **Client audits** (`scrutator audit`, `audit-check`, `audit-letter`; docs/audit.md)
  - A passive scan, or an existing signed bundle, becomes a client deliverable: one self-contained HTML file with an A4
    print style sheet and no running script, a PDF through an installed Chromium-based browser (nothing downloaded),
    the interactive report as the technical annex, the signed bundle. Cover, authorisation, executive summary in English
    or Turkish, findings in priority order with remediation and an effort estimate, asset inventory, what was not
    tested, methodology, glossary, evidence appendix with the three offline verification commands.
  - Refuses to run without `--engagement` (client) or `--self`; a new scan writes the authorisation to the signed audit
    log before its first lookup. `audit-letter` writes a fill-in letter (template, not legal advice) and the engagement
    file; unfilled placeholders are refused.
  - `audit-check` re-derives the whole document from the bundle and catches an edited page, a dropped finding re-rendered
    with consistent data, another bundle and a tampered one. Branding (`audit.yaml`) is treated as hostile input.
  - Optional AI rewording of the English executive sentences, kept only when the deterministic floor and the verifier
    pass it (`scrutator.verify.polish`).
- **Compliance mapping pack**: every risk rule mapped to ISO/IEC 27001:2022 Annex A, NIS2 Art. 21(2), CIS Controls v8.1,
  OWASP and KVKK references, informational only; references read at an authoritative public page are verified, every
  ISO one is not (`scrutator risk --compliance`).
- **Bug-bounty mode** (`scrutator bounty import`, `bounty watch`; docs/bounty.md): HackerOne CSV, Bugcrowd / bounty-targets
  JSON and plain lists into a deny-by-default scope (hostile entries refused); scheduled passive scans that announce
  new in-scope names, takeover candidates, certificates and open services once, with a report draft per candidate.
- **Monitoring** (`watch`): severity-ranked alerts announced once per client folder, a "why this matters" line, a weekly
  digest, `--min-severity`, e-mail with SMTP credentials from the environment only; docs/hosting.md (scheduled task,
  systemd timer, Docker Compose).
- **Fixed (R6 debt)**: crt.sh's database is the one TCP endpoint and is checked by the egress policy before connecting;
  sources that only list names can no longer use up the entity cap or the step budget before DNS resolves the names a
  certificate or DNS vouches for (a test with 20,000 junk names); the cap is reported per source; the report's summary
  strip never leaves an empty cell or a lone stat (checked at 360, 768 and 1280 px).
- **Bench**: `scrutator-bench/4` with sections `audit`, `bounty`, `monitor`.
- **Business pack** (docs/business/): offers, competitor prices read from their own pages with URL and date, measured
  machine time per audit, three labelled revenue scenarios, a 30-day go-to-market in Turkish and English, a legal and
  risk checklist, open-core licensing options.

## 1.0.0rc2 (2026-10-21, a release candidate; not published)

Round R6: speed you feel, recall that does not depend on a lucky quota day, and a report worth showing.

- **Speed**
  - `scrutator scan` prints each name the moment DNS confirms it is live (`--live`, on by default on a terminal);
    the report is unchanged. On owasp.org the first verified name appears at a 7.0 s median instead of 29.2 s.
  - New `scrutator quick <domain>`: the name sources and DNS only (no RDAP/ASN/InternetDB enrichment), a verified-name
    list in about 7 s on owasp.org (12.7 s on nmap.org), with the same evidence and an optional signed bundle.
  - A public address is asked of the regional registry that holds it (IANA's RDAP bootstrap, bundled) instead of the
    rate-limited `rdap.org` redirector; registration, the announcing prefix and the abuse contact are asked once per
    network; a recent network record from the same database is reused. Measured (three interleaved runs): the first
    verified name on owasp.org at 7.0 s instead of 29.2 s; the full scan 29.2 to 25.5 s on owasp.org but 11.6 to 18.0 s
    on nmap.org (slower); `quick` 7.0 s on owasp.org, 12.7 s on nmap.org. Details: docs/benchmarks/r6.md.
- **Recall**
  - The crt.sh module falls back to crt.sh's public database when its web search is down (502 in every benchmark run
    since R4), with the same data and a fixed query, replayable.
  - New keyless source IP.THC.ORG (subdomain finder); the scan also mines the records it already holds for in-scope
    names written inside them (a host in an archived URL, a mail server in a TXT record), without any new request.
  - Opt-in `scan --axfr --active`: one zone transfer per in-scope name server, every outcome kept as evidence;
    `--active` is recorded in the signed audit log first. A name only a transfer lists is verified.
- **Report**
  - The HTML report was rewritten: a verdict strip, a searchable/sortable/filterable name table with evidence-tier
    chips, risks grouped by severity, an evidence drawer (click any name, risk or finding to see the exact records
    behind it, each with its sha256 and the verify command), a dependency/infrastructure graph collapsed to the
    investigated entities, a coverage panel and a proof panel. Light and dark, keyboard-navigable, WCAG AA contrast,
    print stylesheet. Still one JSON data block and one script, so the integrity guarantees are unchanged.

## 1.0.0rc1 (2026-10-21, a release candidate; not published)

Rounds R4 (security and robustness audit, the v1.0 pieces) and R5 (two opt-in modules). The v1.0 gate, the benchmark
and what still needs the maintainer: [docs/benchmarks/v1.0-candidate.md](docs/benchmarks/v1.0-candidate.md).

- **Fixed (audit findings, each with a failing test first)**
  - The Shodan key of the keyed source travels in a URL, and `httpx` logs request URLs: the key reached the MCP
    server's stderr. Request logs are redacted and the MCP server keeps target URLs out of its log.
  - Text from RDAP and other sources (organisation names) kept terminal escape and bidirectional control characters;
    every CLI line now goes through a terminal-safe filter, and canonical entity values drop control characters.
  - `scrutator verify` crashed with a traceback on a forged bundle (JSON nested too deeply, report sections of the
    wrong type). It now fails closed with a named check.
  - The fence around untrusted text in AI prompts only neutralised the exact string `</data>`.
  - A verifier model that obeys planted text could publish a statement naming an invented host or address. A
    deterministic grounding check now runs before the verifier; a second one drops statements that repeat a
    record's free text as a fact or assert an alarm word the cited facts do not (see docs/security.md for the limit).
  - Common Crawl's index list names the URL to query and the module fetched it verbatim (any scheme, host, port);
    module and replay requests followed redirects anywhere. An egress guard now allows only `https` to the source
    hosts (RDAP referrals to public addresses excepted).
  - MCP `verify_bundle` accepted a UNC path, which on Windows opens an SMB connection with the user's credentials.
  - The bundle reader inflated up to 128 MiB per member before checking, parsed the whole zip central directory
    before any limit, and did not bound the manifest. Limits are checked against declared sizes first.
  - `--max-entities` was soft (one answer could add thousands past the cap). It is a hard cap, and the dropped
    count is reported.
  - A damaged or locked database ended in a traceback; it is now a one-line error with what to do.
  - A scan too large for a bundle that `verify` accepts now writes no bundle and says so, instead of writing one
    that cannot be verified.
  - `verify --replay` of a hostile bundle was unbounded: the bundle's evidence decides the requests, so a million
    records meant a million lookups. A replay is limited to 20,000 records and 2,000 distinct HTTP requests
    (`--replay-limit`); the rest are reported as skipped.
- **Added**
  - Passphrase-protected signing keys (scrypt + ChaCha20-Poly1305), `scrutator protect-key`, warnings when a plain
    key signs, owner-only permissions on POSIX.
  - `scrutator --version`.
  - `scrutator bench`: OSINT-Bench v0, offline, one command: planted risk lab, attribution lab, name tiers, bundle
    tamper and replay, scope-safety audit and the Hallucination Test. JSON with a versioned schema, non-zero exit
    below the thresholds.
  - Documentation in `docs/` (checked by tests: links, the sources table against `scrutator sources`, every command
    line in a code block against the CLI), SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, this file.
  - A two-minute demo (`demo/run_demo.py`, offline or `--live`) with recorded transcripts.
  - A wheel smoke test (`tools/wheel_smoke.py`), a CI job that builds the wheel, installs it into a fresh environment
    and runs it on Linux, macOS and Windows, a `bench` job, Python 3.13 in the matrix, and a Dockerfile (written, not
    yet built: CI builds it).
  - Launch drafts (`docs/launch/`, not published), example reports (`docs/examples/`), good first issues.
  - `tools/sbom.py` (CycloneDX 1.5 SBOM of an installed environment; CI uploads one with each wheel), RESPONSIBLE_USE.md.
- **Added in round R5 (opt-in modules)**
  - Brand presence, `scan --brand` (off by default): the platform accounts an organisation's home page links to
    (robots.txt honoured), whether they, the bare brand name and up to 20 look-alikes exist on those platforms (HTTP
    status of the public profile page only), as a report section and two low-confidence risks. Platforms are data
    (knowledge-pack kind `platforms`); those whose terms restrict automated access are never asked.
  - Organisation exposure, `scrutator exposure` (a preview: needs `SCRUTATOR_PREVIEW_EXPOSURE=1` and an engagement
    file): aggregate social-engineering exposure from what the organisation itself publishes, minimised at collection,
    per-person detail only with a logged `--detail`. Not legally reviewed yet.
  - `scrutator bench` sections `brand` and `org_exposure` (bench schema 2).
- **Changed**
  - Risk rule set 3 (brand rules); bundles of rule set 2 are still re-derived when they hold no brand evidence, and
    bundles made before the `platforms` pack kind still verify.
  - `api.github.com` is a source host (used only by organisation exposure, for organisations its engagement file names).

## 0.7.0 (2026-10-20)

- Name tiers: every name is `verified`, `claimed`, `stale` or `wildcard`, derived from evidence and re-derived by
  `verify`; the report, CLI and HTML lead with `N verified, M claimed`.
- Speed: a pipelined scheduler, one SQLite transaction per lookup, a bounded DNS pool, one RDAP lookup per network,
  A and CNAME first so a missing name costs two queries instead of six. owasp.org median 86 s to 36 s.
- Source policy: `--sources`, `--exclude-sources`, `--no-noncommercial`, recorded in the report, the manifest and
  the audit log, and checked by `verify`.
- Keyed sources (VirusTotal, SecurityTrails, Shodan DNS) from environment variables only, and `scrutator sources`.
  Implemented against the documented APIs and not live-verified.

## 0.6.0 (2026-10-17)

- New keyless sources: CertSpotter, mnemonic passive DNS, HackerTarget, urlscan.io, Subdomain Center, Shodan
  InternetDB, RIPEstat contact data. All scope-gated and replayable.
- Resolution state for every in-scope name (`live`, `stale`, `wildcard`, `unresolved`) with a recorded random-label
  wildcard probe.
- A scan always ends inside a deadline (`--deadline`), a failing source is marked down (`--breaker`), and name-listing
  sources run once per apex.
- Exposure table (open ports, products, CVE ids as claimed by Shodan's earlier scan).
- A reproducible benchmark harness (`bench/`) against sublist3r, dnsrecon and knockpy, with written results in
  `docs/benchmarks/`.

## 0.5.0 (2026-10-17)

- Attribution engine: names outside the scope that probably belong to the organisation, with ten signals, a score, a
  band (`confirmed`, `probable`, `possible`, `unlikely`), a pre-mortem and the evidence behind each; the `candidate`
  scope state (passive lookups only); `promote` writes the scope file and the audit log.
- AI leads that must cite listed evidence and pass the verifier; pivot playbooks as a knowledge pack kind, offered to
  the planner by the situation of the investigation.
- `scrutator mcp`: a read-only MCP server over stdio; `scan` and `promote_candidate` only when enabled.

## 0.4.0 (2026-10-16)

- Knowledge packs (providers, takeover fingerprints, signal frequencies) with schema validation and a manifest.
- Dependency and risk analysis: hygiene rules, provider concentration and analyst detectors; every risk cites
  evidence. The proof bundle records the analysis and `verify` re-derives it.
- `scrutator risk`, SARIF 2.1.0 export, `scrutator packs`.
- DNS answers carry their status (NXDOMAIN, NODATA) as evidence; compact denial of existence (NSEC NXNAME) is
  treated as NXDOMAIN.
- A planted lab covering every rule, with a clean-zone control.

## 0.3.0 and 0.3.1 (2026-10-15)

- Signed proof bundles (`export`, `verify`, `verify --replay`), Ed25519 keys (`keygen`), pinning.
- `diff` between two scans and `watch` with https-only webhooks.
- 0.3.1: replay fixes found by a live run (RDAP records the requested URL, replay checks that the source still
  supports the evidence instead of demanding equality, RDAP boilerplate ignored).

## 0.2.0 (2026-10-15)

- The AI layer: local-first providers (Ollama, OpenAI-compatible, Anthropic), schema-validated generation with
  repair and an untrusted-data fence, a budgeted planner, a writer and an independent verifier, egress log and
  `--redact`, hypothesis log, `scrutator ai doctor`, source coverage in the report.

## 0.1.0 (2026-10-15)

- Entity, evidence and finding model; SQLite store with a hash-chained audit log; deny-by-default scope policy with
  fuzz tests; engine; a deterministic expander; modules for crt.sh, DNS, RDAP, ASN, Wayback and Common Crawl;
  JSON and single-file HTML reports; `scrutator scan`.
