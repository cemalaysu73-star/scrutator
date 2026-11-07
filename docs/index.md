# Scrutator documentation

Start here. Pages are plain Markdown and read the same on GitHub, in an editor or in a terminal. Every command shown is
checked against the program by a test, and every number comes from a run that is named next to it.

## I want to understand it

| Page | Read it to |
|---|---|
| [How it works](how-it-works.md) | the pipeline from seed to signed bundle, with diagrams; what "evidence-backed" and "verifiable" mean, with a worked example; how it differs from other recon tools; scope states; local-first AI; what it will never do |
| [Concepts](concepts.md) | the evidence model, scope states, name tiers, knowledge packs and attribution in detail |
| [Reading a report](reading-a-report.md) | what each section of the HTML and JSON report means and how far to trust it |
| [Security model and known limits](security.md) | the guarantees, how they are tested, what is not guaranteed |

## I want to use it

| Page | Read it to |
|---|---|
| [Quickstart](quickstart.md) | install, scan `example.com`, open the report, verify and tamper with a bundle |
| [Use cases](use-cases.md) | seven workflows with exact commands: pentest recon, bug bounty, consultant audit and self-check, due diligence, incident response, journalism and research (with an operational-security note), verifying someone else's report |
| [FAQ](faq.md) | legality, safety, what leaves your machine, why sources fail, adding a source or pack, verifying a report |
| [Sources and terms](sources.md) | every data source, what it gives, its terms, keyed sources, the source policy |
| [Proof bundles](proof-bundles.md) | what a bundle holds, what `verify` checks, what a signature does and does not prove |
| [AI modes and privacy](ai-and-privacy.md) | local-first AI, what leaves your machine, the verifier and its deterministic floor |
| [Client audits](audit.md) | `scrutator audit`: a branded, print-ready deliverable from a signed scan, the authorisation letter, how the client checks it offline |
| [Bug-bounty mode](bounty.md) | import a programme scope (deny by default), watch it for new assets and takeover candidates, get report drafts |
| [Running monitoring for clients](hosting.md) | `watch` as a retainer: alerts, weekly digest, e-mail; a Windows scheduled task, a systemd timer, Docker Compose |
| [MCP](mcp.md) | drive Scrutator from Claude Desktop or any MCP client |
| [Demo](../demo/README.md) | a two-minute tour: scan, follow a claim to its evidence, tamper with a bundle, watch verification fail |
| [Example reports](examples/README.md) | reports and signed bundles you can open and verify without running anything |

## I want to extend or check it

| Page | Read it to |
|---|---|
| [Writing a knowledge pack](knowledge-packs.md) | add a provider, a takeover fingerprint or a playbook |
| [Writing a module](writing-a-module.md) | add a data source |
| [Benchmark](benchmarks.md) | OSINT-Bench v0 (`scrutator bench`), the competitor comparison, how to reproduce either |
| [Contributing](../CONTRIBUTING.md) | set up, the rules that make the project what it is, good first contributions |
| [Good first issues](good-first-issues.md) | small, well-defined starting points |

## Policies

[Responsible use](../RESPONSIBLE_USE.md) · [Security policy](../SECURITY.md) · [Code of conduct](../CODE_OF_CONDUCT.md) ·
[Changelog](../CHANGELOG.md) · [Licence](../LICENSE) (Apache-2.0)
