# Scrutator documentation

| Page | Read it to |
|---|---|
| [Quickstart](quickstart.md) | install, scan `example.com`, open the report, verify and tamper with a bundle |
| [Concepts](concepts.md) | the evidence model, scope states, name tiers, packs, attribution |
| [Reading a report](reading-a-report.md) | what each section of the HTML and JSON report means and how far to trust it |
| [Proof bundles](proof-bundles.md) | what a bundle holds, what `verify` checks, what a signature does and does not prove |
| [Sources and terms](sources.md) | every data source, what it gives, its terms, keyed sources, the source policy |
| [AI modes and privacy](ai-and-privacy.md) | local-first AI, what leaves your machine, the verifier and its deterministic floor |
| [MCP](mcp.md) | drive Scrutator from Claude Desktop or any MCP client |
| [Client audits](audit.md) | `scrutator audit`: a branded, print-ready deliverable from a signed scan, the authorisation letter, and how the client checks it offline |
| [Bug-bounty mode](bounty.md) | import a programme scope (deny by default), watch it for new assets and takeover candidates, get report drafts |
| [Running monitoring for clients](hosting.md) | `watch` as a retainer: alerts, weekly digest, e-mail; a Windows scheduled task, a systemd timer, Docker Compose |
| [Writing a knowledge pack](knowledge-packs.md) | add a provider, a takeover fingerprint or a playbook |
| [Writing a module](writing-a-module.md) | add a data source |
| [Security model and known limits](security.md) | the guarantees, how they are tested, what is not guaranteed |
| [Benchmark](benchmarks.md) | OSINT-Bench v0 (`scrutator bench`), the competitor comparison, how to reproduce either |
| [Brand presence](../README.md#brand-presence) and [organisation exposure](../README.md#organisation-exposure-authorised-aggregate) | the two opt-in modules (`scan --brand`, `scrutator exposure`), what they contact and what they never do |
| [Responsible use](../RESPONSIBLE_USE.md) | what the tool may be used for, what it will not do, the two opt-in modules |

Also: [README](../README.md), [CHANGELOG](../CHANGELOG.md), [SECURITY](../SECURITY.md),
[CONTRIBUTING](../CONTRIBUTING.md), [demo](../demo/README.md).

These are plain Markdown files that read the same on GitHub, in an editor or in a terminal. Every command shown
here is a command that exists (a test checks the names against the CLI), and every number comes from a run that is
named next to it.

More: [good first issues](good-first-issues.md) · [launch drafts](launch/) (blog posts, not published) · [example reports](examples/README.md).
