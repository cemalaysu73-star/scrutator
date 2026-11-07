# Scrutator v1.0.0

**Infrastructure OSINT where every claim has a receipt.** Scrutator asks public sources (certificate transparency,
DNS, RDAP, archives, aggregators) what they know about a domain you are allowed to assess, and gives back a map of the
organisation's internet-facing infrastructure in which every finding cites the raw record it came from. The whole
report ships as a signed proof bundle that a stranger can verify offline.

For penetration testers and red teamers, bug-bounty hunters, investigative journalists and OSINT researchers, incident
responders and due-diligence analysts. Passive by default; no person lookup; no exploitation.

Start with [how it works](../docs/how-it-works.md) and the [use cases](../docs/use-cases.md).

## What is in it

- **Passive scan** (`scrutator scan`, `scrutator quick`): 15 keyless sources on by default, three optional keyed ones and six narrow opt-in modules, scope decided
  by the engine and deny by default, every raw answer stored as hashed evidence, absence (NXDOMAIN) recorded as
  evidence, failures recorded as failures.
- **Verified or only claimed.** Every name gets a tier from the evidence: `2 verified, 498 claimed`, not `500 subdomains`.
- **Risks and attribution.** Deterministic rules and knowledge packs (dangling CNAMEs at claimable services, weak SPF
  and DMARC, missing CAA, forgotten hosts, provider concentration); names outside the scope that evidence ties to the
  organisation, scored with reasons and a pre-mortem; only a human promotes one into scope.
- **Signed proof bundles** (`scrutator export`, `scrutator verify --pin`): nineteen named checks that re-derive the
  findings, risks, name tiers and attribution from the bundle's own evidence. Built to be run on files from strangers.
- **Workflows:** client audits with an authorisation gate (`scrutator audit`, `audit-check`, `audit-letter`; English and
  Turkish), bug-bounty scope import and watch (`scrutator bounty`), retainer monitoring (`scrutator watch`), an MCP
  server (`scrutator mcp`), local-first AI with a deterministic grounding floor in front of the verifier.
- **Offline benchmark** (`scrutator bench`): planted labs for risks, attribution, tiers, bundle tamper cases, scope
  safety and the Hallucination Test. No network; exits non-zero when a threshold fails.

## Honest limits

Read these before you rely on it. The full list is in [docs/security.md](../docs/security.md) and the
[README](../README.md#honest-limits).

- **Passive recall is limited by what passive sources have seen.** On `zonetransfer.me`, the one target with a real
  truth set (31 names in its published zone), Scrutator found 4 and the best competitor run (knockpy) 2. 87% of the zone
  is reached by no tool we ran. The opt-in zone transfer would reach the rest, but it times out from the network the
  benchmark ran on.
- **Not the fastest, not the widest.** A full scan takes tens of seconds; knockpy takes seconds. subfinder, Amass,
  SpiderFoot and theHarvester were **not run** in the benchmark (they need an executable or a repository download), so
  nothing is claimed about them. Three of the four truth sets are pseudo-truth built from what the tools found.
- **A signed bundle proves integrity and consistency, not truth and not time.** There is no trusted timestamp (RFC 3161),
  and without `--pin` anyone can sign a forged bundle with their own key.
- **Attribution is a lead, not a finding.** Its weights are chosen by hand and calibrated on nothing but a synthetic
  lab written by the author of the scoring.
- **The AI layer is a filter, not an oracle.** A deterministic floor stops invented hosts, addresses, numbers, alarm
  words, negations and copied record text; an invention in plain words about a name the facts know still needs the
  verifier model to catch it.
- **Not tested against the real services:** the three keyed sources (VirusTotal, SecurityTrails, Shodan DNS), and the MCP
  server with Claude Desktop itself.
- **DNS is not proxied.** A proxy (`SCRUTATOR_PROXY`) carries the HTTP sources and the crt.sh connection; DNS goes to your
  system resolver.
- **Organisation exposure** is a preview that has not had the legal and ethics review its design requires; it runs only
  when you set `SCRUTATOR_PREVIEW_EXPOSURE=1` and supply an engagement file.

## Benchmark numbers

Exactly as measured, from [docs/benchmarks/r6.md](../docs/benchmarks/r6.md) (run `2026-10-21-r6-final`, one machine and
network) and [docs/benchmarks/v1.0-candidate.md](../docs/benchmarks/v1.0-candidate.md). The criterion: recall at least the
best competitor's on every truth target, every result evidence-backed, bundle verifies.

| Target | Truth | Scrutator | Best competitor run | Evidence-backed | Bundle verifies (pinned) | Tamper detected |
|---|---|---|---|---|---|---|
| zonetransfer.me | 31 zone names | 13% (4 live) | knockpy 6% | 100% (6) | PASS | yes |
| example.com | 1 live name | 100% | sublist3r, knockpy 100% | 100% (998) | PASS | yes |
| nmap.org | 4 live names | 100% | knockpy 100% | 100% (349) | PASS | yes |
| owasp.org | 61 live names (union of tools) | 97% (59 live) | knockpy 72% (44) | 100% (138) | PASS | yes |

The criterion is met on all four targets, against sublist3r 1.0, knockpy 9.0.0 and a dnsrecon 0.10.1 that errored on
every target because crt.sh answered HTTP 502. Part of the owasp.org gain is a quota day (HackerTarget answered); most is
not. Scrutator's own seconds in that run: 23.3 (zonetransfer.me), 21.8 (example.com), 20.1 (nmap.org), 47.1 (owasp.org).
Speed, measured with three interleaved runs per version: on owasp.org the first verified name appears after 7.0 s
instead of 29.2 s, but the full scan is not reliably faster (nmap.org: 11.6 s before, 18.0 s after, median).

`scrutator bench` (offline) passes; run it yourself, it needs no network. Its fixtures are written by the author of the
code they test, which the output says.

## Verify a release

Releases are **not signed yet**, and the repository has no trusted timestamp. What you can check today:

1. **The files.** Compare the sha256 of the downloaded wheel or sdist with the checksums in this release's
   `SHA256SUMS` (a placeholder until the release is cut: `<attached to the release by the maintainer>`):

   ```bash
   sha256sum scrutator-1.0.0-py3-none-any.whl        # Windows: Get-FileHash -Algorithm SHA256 .\scrutator-1.0.0-py3-none-any.whl
   ```

2. **The example bundles in the repository,** signed with throwaway demo keys that are not anyone's identity. Install,
   then verify them with the signer pinned by fingerprint:

   ```bash
   scrutator verify docs/examples/lab-zone/proof.scrutator --pin b8dc88a33a0016aea35a4b45d4bf6c944bf2a7293905daaeaf001239d8eea6ca
   scrutator verify docs/examples/example.com/proof.scrutator --pin 3d0f002d59884ecdeb75198fe7c36afbb6c35136ab02b1ddc4e36a829e35699f
   ```

   Both end with `Verification passed.` The lab-zone bundle prints a warning that it includes user packs (the lab ships
   its own small knowledge pack).

3. **The software supply chain.** The CI `wheel` job builds the wheel, installs it into a fresh environment outside the
   checkout, smoke-tests it and uploads a CycloneDX SBOM per operating system.
4. **Your own check of the tool:** `scrutator bench --out scrutator-bench` runs the offline benchmark, including ten
   bundle tamper cases that must all be caught.

## Known issues

- Not on PyPI yet: install from a clone (`pip install -e .`).
- crt.sh's web search often answers HTTP 502; Scrutator then asks its public database, which adds 20 to 30 seconds.
- HackerTarget's free tier allows 50 calls a day per address and CertSpotter limits unauthenticated use: a busy day
  lowers recall because sources were unavailable, and the report says which.
- `quick` misses 10 s on a wildcard zone (nmap.org 12.7 s).
- A noisy source can still fill the entity cap before DNS runs (IP.THC.ORG is capped at 500 names per answer).
- The Docker image is built and smoke-run by CI only; it was not built on the author's machine.

## Responsible use

Passive means public sources and your resolver, but those services see what you search for. Only investigate
organisations you are authorised to assess or entitled to research. Scrutator never looks up a named person. A finding is
a lead for the owner to confirm, not proof of compromise. See [RESPONSIBLE_USE.md](../RESPONSIBLE_USE.md).

## Thanks

To the public services whose data makes passive recon possible and who ask for little: crt.sh (Sectigo), SSLMate
CertSpotter, the RIPE NCC, ARIN, APNIC, LACNIC and AFRINIC RDAP services, the Internet Archive, Common Crawl, Shodan
InternetDB, urlscan.io, mnemonic, HackerTarget, Subdomain Center and IP.THC.ORG; to the can-i-take-over-xyz project for
the takeover fingerprints; and to the authors of sublist3r, knockpy and dnsrecon, whose tools the benchmark ran against.
Please read each source's terms in [docs/sources.md](../docs/sources.md); several free tiers are non-commercial only.
