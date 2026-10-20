# Changelog

Built from the git history (`git log`), newest first. Dates are commit dates. Versions before 0.7 were never
tagged or published; the numbers are the ones in `pyproject.toml` at the time. Nothing here has been released on
PyPI.

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
