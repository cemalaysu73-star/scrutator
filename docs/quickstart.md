# Quickstart

Ten minutes, no accounts, no API keys. Everything here is passive: Scrutator only asks public sources what they
know. Use `example.com` (reserved for documentation) or a domain you are allowed to assess.

## Install

```bash
pipx install scrutator            # or: pip install scrutator
pipx install "scrutator[mcp]"     # with the MCP server
scrutator --version
```

Python 3.11 or newer. The package is not published on PyPI yet; until it is, install from a checkout:
`pip install -e .` (or `pip install ".[mcp]"`). Windows, macOS and Linux are supported; the test suite and the
installed-wheel smoke test run on all three in CI.

## 1. Scan

```bash
scrutator keygen                                    # once: a signing key for proof bundles
scrutator scan example.com --ai off --bundle        # passive scan, no AI, with a signed proof bundle
```

A real run of that command (example.com, 2026-10-20, 18 seconds) printed:

```
Scan #1 of example.com: 2 verified, 499 claimed (0 stale, 0 wildcard-covered).
542 entities, 559 relations, 559 findings (527 module runs, 2 rounds).
Findings: 51 about verified names and 9 about addresses and registrations; 499 more about claimed (499), stale (0) or wildcard-covered (0) names, kept in the report and collapsed in the HTML.
Names: 2 live, 499 stale, 0 wildcard-covered, 0 unresolved.
Risks: 2 (0 high, 0 medium, 2 low, 0 info). Run `scrutator risk` for the list.
3 source run(s) failed after retries; see Source coverage in the report.
AI: off (no local model found, or --ai off). Deterministic mode.
Wrote report.json, report.html to scrutator-out
Proof bundle: scrutator-out\proof.scrutator (signing key bc5efe57...)
```

The first line is the result: **2 names verified, 499 only claimed.** Aggregators happily list five hundred
names for a domain that has one website; Scrutator separates the names the evidence supports from the ones a list
merely says. See [concepts](concepts.md#name-tiers). The third line reports that three source runs failed: a
missing result is never presented as a negative, and the report says which sources failed.

Files in `scrutator-out/`: `report.html` (open it in a browser; one self-contained file), `report.json` (the same
data), `scrutator.db` (the SQLite store), `proof.scrutator` (the bundle).

## 2. Read the report

Open `scrutator-out/report.html`. Click a finding: the raw record it rests on appears (the DNS answer, the
certificate JSON, the RDAP record). Every finding, risk and name carries evidence ids; a claim without evidence
cannot exist. [Reading a report](reading-a-report.md) explains each section.

```bash
scrutator risk                  # configuration risks, each citing its evidence
scrutator sources               # which sources are on, and how each fared in the last scan
```

## 3. Verify the bundle

```bash
scrutator verify scrutator-out/proof.scrutator --pin ~/.config/scrutator/signing.pub
```

```
PASS  readable bundle
PASS  manifest parses
PASS  file hashes
PASS  signature valid
PASS  signing key pinned
PASS  audit chain
PASS  evidence hashes
PASS  report references
PASS  findings derivable
...
Verification passed.
```

Nineteen named checks. `--pin` is what makes it mean something: a signature alone only proves that the bundle
matches the key inside it. Give the reader your key's fingerprint through a channel they trust. See
[proof bundles](proof-bundles.md).

## 4. Tamper with it

A bundle is a zip. Change one byte of `report.json` inside it and verification fails with the check that caught it
(`file hashes`, and the checks that re-derive the findings). The demo does this for you and records the output:

```bash
python demo/run_demo.py            # offline, about a minute: fixture scan, bundle, tamper, verify fails
python demo/run_demo.py --live     # the same on example.com
```

See [demo/README.md](../demo/README.md).

## 5. Check the whole tool offline

```bash
scrutator bench --out scrutator-bench
```

OSINT-Bench v0: planted risk lab, attribution lab, name tiers, bundle tamper and replay, a scope-safety audit and the
Hallucination Test. It needs no network and exits non-zero if a threshold fails. See [benchmarks](benchmarks.md).

## Next

- Different scope than "the domain and its subdomains": a scope file ([concepts](concepts.md#scope)).
- Add a local model for a verified summary and leads: [AI modes and privacy](ai-and-privacy.md).
- Use it from Claude Desktop: [MCP](mcp.md).
- Pick or exclude sources (commercial work, privacy): [sources and terms](sources.md).
