# Scrutator — Evidence-backed, AI-driven infrastructure OSINT

Status: draft for review. Name, license and repo layout are defaults and can change.

## 1. Goal

An open-source tool that investigates a domain or organisation's internet-facing infrastructure and returns a report in which **every claim is backed by re-checkable evidence**. An LLM agent plans the investigation; deterministic modules gather the data; an independent verifier decides what reaches the report. The AI also acts as an **analyst that notices what humans miss** (D17), always with evidence. **AI is local-first**: the whole pipeline runs on a model on the user's machine, and cloud models are an explicit opt-in.

Four capabilities set it apart beyond evidence-backed AI: AI that runs fully **local by default, with cloud as a metered, logged opt-in** (D12), reports that ship as **signed proof bundles anyone can re-verify** (D9), an **attribution engine** that finds assets that belong to the organisation without any name match, with explainable scores (D10), and a **dependency and risk analysis** that turns the graph into prioritised, evidence-cited actions (D11). Around the core sit community-extensible **knowledge packs** that ground the AI (D13), **lookalike and live certificate-transparency monitoring** (D14), **integrations that fit existing workflows** (D16) and an open benchmark anyone can add tools to (D15).

"Strongest on the market" is a claim we earn with a published benchmark (section 17), not one we assert.

## 2. Non-goals

- No general people search: never a lookup of a named private individual, never home addresses, personal phone numbers, family, personal social accounts, photos or location. The only people-related capability is the authorised, organisation-scoped exposure analysis in section 12, which cannot take a person as its seed.
- No port scanning, no exploitation, no vulnerability validation (XSS/SQLi etc.). Nmap, Nuclei and Shodan already cover these.
- No wrapping of third-party binaries. All modules are native async Python.

## 3. Differentiators and acceptance criteria

| # | Differentiator | Beats | Measurable criterion |
|---|---|---|---|
| D1 | Enforced evidence: a claim without evidence IDs cannot enter the report | OpenOSINT ("AI summaries are leads, not proof"), roxm337 | 0 unsupported claims in benchmark reports; adversarial hallucination fixtures all rejected |
| D2 | Engine-level scope guard (deny by default), not prompt-level | roxm337 (none), BBOT (no AI adversary) | Fuzz suite: no outbound request to an out-of-scope host via redirects, CNAME chains, IDN/punycode, IPv6, case tricks |
| D3 | Native Python, no external binaries; Windows/macOS/Linux | BBOT (Linux only), OpenOSINT (unsandboxed binaries) | `pipx install scrutator` works on all three in CI |
| D4 | Graph-first store with temporal diff and watch mode | All open-source AI tools | `scrutator diff` reports added/removed/changed assets between two scans |
| D5 | Hypothesis-driven agent with cost budget (not a call-count cap) | OpenOSINT (15-call cap, tool chaining) | Agent beats deterministic baseline on asset recall at equal budget in benchmark |
| D6 | Prompt-injection hardened: target-controlled text is untrusted data | All | Injection corpus (hostile TXT/HTTP/HTML content) never changes agent actions or scope |
| D7 | Works without an LLM key (deterministic mode) | roxm337 partial, OpenOSINT needs a model | Same CLI, `--no-llm`; also serves as benchmark baseline |
| D8 | Reproducible public benchmark vs BBOT, Amass, SpiderFoot, OpenOSINT | — | Methodology + raw results published, including where we lose |
| D9 | Signed proof bundles with `scrutator verify` (offline integrity check and live replay) | All: no competitor lets a third party re-verify a report | Changing any byte of a bundle fails verification; replay of an unchanged lab zone reports 100% of evidence unchanged |
| D10 | Attribution engine: finds assets that belong to the organisation without a name match, scored and explained | All: they enumerate subdomains, none attribute unnamed assets | On the lab zone with planted unnamed assets, precision >= 0.9 in the `probable` band; recall and precision published for all bands |
| D11 | Dependency and risk analysis: dangling CNAMEs, third-party concentration, mail and DNS hygiene, prioritised with cited evidence | All: they output data, not actions | Every planted lab issue is detected; 0 risk statements without evidence; remediation text passes the verifier |
| D12 | Local-first AI: agent and verifier run on a local model; cloud is opt-in, metered and logged | Cloud-only AI tools (Neo); OpenOSINT defaults to Claude | The full pipeline runs end to end on a local model of 9B parameters or less with 0 unsupported claims; in local mode the AI layer opens no non-loopback connection (tested); every byte sent in cloud mode is logged |
| D13 | Knowledge packs: versioned, schema-validated data (provider fingerprints, takeover fingerprints, signal frequencies, pivot playbooks) that anyone can extend with a pull request | All: knowledge is hardcoded or closed | Adding a provider is one data entry plus a fixture; packs validate in CI; an ablation (agent with and without playbooks) is published |
| D14 | Lookalike-domain detection and live certificate-transparency watch, passive only | Single-purpose paid brand-protection services | Planted lab lookalikes all flagged; false-positive rate on a published brand list reported; alert within one poll interval of a new certificate |
| D15 | OSINT-Bench: an open benchmark repository with ground-truth lab zones, scoring scripts and tool adapters, open to any tool | — | A third party adds a tool adapter in under a day; CI reproduces published numbers; our tool gets no special treatment |
| D16 | Integrations: webhook, Slack and Teams alerts, deduplicated GitHub and Jira tickets, executive summary of verified findings only, GitHub Action | Tools that stop at a report file | Re-running an unchanged scan opens 0 new tickets; the Action fails a build on a new high-severity exposure against a baseline |
| D17 | Analyst: deterministic detectors plus AI-generated leads that are tested with passive evidence and verified, so subtle oddities surface that a human reviewer skips | All: they list assets, they do not reason across them | On a lab zone with K planted subtle oddities, planted-oddity recall beats the deterministic-only and a checklist baseline; lead precision published; 0 unsupported claims; no claim of beating human analysts without a human baseline study |
| D18 | Authorised people-exposure analysis: organisation-scoped, work-context only, aggregate by default, engagement file required | Tools that search individuals with no guardrails | A named individual is refused as a seed; personal-data categories never appear in output (tested); the module refuses to run without a valid engagement file |

## 4. Architecture

Python 3.11+, asyncio, httpx, pydantic v2, typer, SQLite. Units communicate through typed interfaces.

```
src/scrutator/
  model/      Entity, Edge, Evidence, Finding (pydantic)
  store/      SQLite graph + evidence store, scan snapshots, diff
  scope/      ScopePolicy: parse scope file, decide(target) -> allow|deny + reason
  engine/     scheduler, rate limiter, cache, module runner (enforces scope, mode, budget)
  modules/    one file per source; declares inputs, outputs, passive|active, needs_key
  agent/      planner loop, hypothesis tracker, LLM provider adapters
  verify/     verifier: evidence existence, entailment check, corroboration scoring
  report/     json, markdown, html (single file, graph view), sarif, stix
  mcp/        MCP server exposing modules and graph queries
  cli.py
benchmark/    harness, ground-truth lab zone, competitor runners
tests/
```

### 4.1 Data model

- **Entity**: type (domain — apex and subdomains alike —, ip, asn, org in v0.1; cert, email, tech, url later), canonical value, first_seen, last_seen.
- **Edge**: typed relation between entities (resolves_to, issued_for, announced_by, ...), with evidence IDs.
- **Evidence**: immutable, content-addressed (sha256 of raw payload), source module, request metadata, timestamp. Stored raw so a claim can be re-checked offline. An append-only audit log chains hashes of every module call.
- **Finding**: claim text, entity/edge refs, evidence IDs (required, at least one), confidence (low/medium/high), status (verified/rejected).

### 4.2 Modules

Contract: `async run(entity, ctx) -> list[Observation]`. Each module declares accepted entity types, produced types, mode (`passive` or `active`), and key requirement. Adding a source is one file plus a recorded fixture test.

- Passive, no key: crt.sh, DNS (A/AAAA/MX/NS/TXT/CAA, SPF, DMARC), RDAP, ASN/BGP (RIPEstat), Wayback, CommonCrawl index.
- Active (`--active`, authorisation prompt): HTTP probe, TLS inspection, tech fingerprint, security headers, takeover check.
- Optional keyed: Shodan, Censys, VirusTotal, SecurityTrails, GitHub leak search.

### 4.3 Scope guard (D2)

`scope.yaml` lists domains (with wildcard rules), CIDRs and ASNs. Deny by default. The engine calls `ScopePolicy.decide()` before every outbound request and again on every redirect and CNAME hop. Each entity gets a scope state: `in` (may be investigated), `linked` (reached from an in-scope entity, e.g. an IP an in-scope host resolves to: passive third-party lookups only, never contacted by active modules) or `out` (recorded, never investigated). Out-of-scope hops are recorded as entities but never contacted. The LLM cannot widen scope; only the user's file defines it.

## 5. Agent

Inputs: seed(s), scope, budget (USD, tokens, steps, wall time), mode.

Loop:
1. Summarise graph state (counts, unexplored entities, open hypotheses) as structured data.
2. LLM proposes hypotheses ("this IP range belongs to the target's CDN") and chooses actions from the module registry (JSON-schema-constrained tool calls).
3. Engine validates action against scope, mode and budget, executes, normalises results into entities/edges/evidence.
4. LLM marks hypotheses confirmed/refuted/open from evidence IDs.
5. Stop when the budget is spent or no high-value open hypotheses remain; then draft findings.

Rules:
- The LLM never writes evidence. It can only reference existing evidence IDs.
- Tool output is passed inside delimited data blocks, labelled untrusted (D6). Actions come only from schema-validated tool calls.
- `--no-llm`: a rule-based breadth-first expander runs every applicable module until fixpoint (D7).
- Providers sit behind one `LLMProvider` interface (section 5.1).

### 5.1 AI backends, modes and small-model-safe design (D12)

**Modes.** `--ai off|local|cloud|hybrid`, also settable in `~/.config/scrutator/config.toml`. Default `auto`: use `local` if a local runtime answers on loopback, otherwise `off` (deterministic mode). **It never falls back to cloud silently.**

**Backends.**
- `OllamaProvider`: native API, passes the Pydantic JSON schema as `format` so generation is constrained token by token.
- `OpenAICompatProvider`: any OpenAI-compatible endpoint. Covers llama.cpp server, LM Studio and vLLM locally, and OpenAI, OpenRouter and similar in the cloud.
- `AnthropicProvider`: Claude via the Messages API.
- All three are plain `httpx` adapters. No AI SDK is required; official SDKs are optional extras.

**One call shape for every model.** `generate(messages, schema) -> validated Pydantic object`. Scrutator does not depend on a model's native tool-calling quality: the agent asks for a schema-constrained "choose the next action" object and validates it itself. Any model that can follow a JSON schema works.

**Roles are routed independently**: `planner` (chooses actions), `verifier` (judges entailment), `writer` (turns verified findings into prose). Example hybrid setup: local verifier and writer, cloud planner. The verifier should differ from the planner; the CLI warns when it does not.

**Small-model-safe design.** A local 8-9B model cannot be trusted with open-ended work, so it never gets any:
- Every call is narrow: (a) pick one action from at most N listed options given a compact graph summary; (b) judge one claim against one evidence excerpt; (c) write one paragraph from already verified findings.
- Enumeration, parsing, scoring and scope checks are deterministic code. The model supplies judgement, not mechanics.
- Prompts stay within roughly 8-16K tokens by summarising the graph (counts, top unexplored entities, open hypotheses), not dumping it.
- Output is validated; on a violation the call is retried with the validation error up to 2 times, then the agent falls back to the deterministic expander for that step. The verifier is conservative: an unparseable or uncertain judgement means rejection.
- A weak model therefore degrades coverage, never correctness.

**`scrutator ai doctor`.** Detects local runtimes and installed models, runs a built-in self-test of about 30 cases (valid-schema rate, correct action choice on fixtures, entailment accuracy on supported and unsupported claims), and prints pass or fail per role with a recommendation. Model suggestions are starting points to be confirmed by the self-test, not hardcoded: reviews in 2026 recommend Qwen3-class 8-9B models for 8 GB GPUs and 24-35B dense or mixture-of-experts models for 16-24 GB, and report Phi-4 as weak at tool use. These figures are mostly vendor-reported, which is why the doctor measures instead of trusting them.

### 5.2 Privacy and egress control

- **Local mode**: the AI layer connects only to loopback. A test asserts this.
- **No telemetry**, in any mode. The database, evidence and reports never leave the machine in any mode.
- **Cloud mode** requires an explicit flag or config entry, an API key from the environment or OS keyring (never written to reports or bundles), and a first-use consent prompt listing what is sent: graph summaries and evidence excerpts about the target. Hybrid mode asks per role.
- **Egress log**: every cloud request is recorded (provider, model, role, byte size, sha256 of the payload; the payload itself only with `--log-prompts`). The log is part of the proof bundle manifest.
- **`--redact`** (optional, cloud): apex domains, IPs and organisation names are replaced by stable pseudonyms (`d1.example`, `ip-3`, `org-2`) in outgoing prompts and mapped back on return. Subdomain label words such as `dev` or `staging` are kept because the model reasons over them.
- **Cost control**: cloud runs have a USD budget with a hard stop; local runs have token and wall-time budgets.

## 6. Verifier (D1)

Each draft finding passes three checks:
1. **Existence**: every cited evidence ID exists and belongs to this scan.
2. **Entailment**: a separate LLM call (different prompt, optionally different model) judges whether the cited raw evidence supports the claim. Skipped in `--no-llm`, where findings are generated by templates and are entailed by construction.
3. **Corroboration**: confidence = low for one source, medium for two independent sources, high when also confirmed by active evidence or three sources.

Failures go to an "unverified leads" appendix, never the main report.

## 7. Temporal diff and watch (D4)

Every scan is a snapshot. `scrutator diff <scanA> <scanB>` lists new, removed and changed assets with evidence. `scrutator watch` reruns on a schedule and emits the diff as JSON or webhook.

## 8. Proof bundles (D9)

`scrutator export <scan> --bundle out.scrutator` writes a zip:

- `report.json` and `evidence.jsonl` (all raw evidence, content-addressed),
- `audit.jsonl` (hash-chained module-call log),
- `manifest.json` with the sha256 of every file, the tool version and the scope file,
- `manifest.sig`: an Ed25519 signature made with a local key (`scrutator keygen`). The public key is embedded; users pin it out of band.

`scrutator verify <bundle>`:

1. **Offline**: manifest hashes match, audit chain intact, signature valid, every evidence id referenced by a finding exists and matches its hash.
2. **`--replay`**: re-issues each replayable evidence request (HTTP GET and DNS lookups only, nothing that touches the target beyond what the original passive run did) and reports per record `unchanged`, `changed` or `unavailable`. Drift is information, not failure.

Evidence therefore stores its request in structured form (method, URL, params, or record type and name), not only as text. v0.1 stores `GET <url>` and `DNS <type> <name>`, which already parse unambiguously; the structured form is introduced with the bundle format.

## 9. Attribution engine (D10)

Goal: connect assets to the organisation when no name matches, without ever widening scope on its own.

- **Signals** (passive, keyless first): shared certificate SAN sets, identical non-provider NS sets, SPF include chains, shared MX, CNAME targets, same ASN plus netblock owner. Later, with active mode: favicon hash, analytics ids, `security.txt`.
- **Scoring**: each signal has a weight discounted by how common it is across unrelated organisations (an IDF-style discount, so Cloudflare name servers or Let's Encrypt carry almost no weight). Combining signals yields a score in [0, 1] and a band: `suggested`, `probable`, `strong`.
- **Explainable**: every attribution lists its signals, weights and evidence ids. "Why is this ours?" always has a cited answer.
- **Scope safety**: attributed entities enter the store in a fourth scope state, `candidate`. They are never investigated until the user accepts them (`scrutator scope accept <entity>`), which writes them to the scope file. The agent may propose hypotheses and explain them; the deterministic scorer decides the score; the verifier gates the narrative.

## 10. Dependency and risk analysis (D11)

Deterministic rules produce the facts; the agent only prioritises and explains.

- **Dependency map**: third-party providers behind each asset (DNS provider from NS, mail provider from MX/SPF, CDN or hosting from CNAME and ASN, certificate issuer). Concentration findings such as "12 hostnames depend on one DNS provider".
- **Hygiene findings** (passive, evidence-backed): dangling CNAME to an unregistered or claimable target (confirmation in active mode), SPF with `+all` or more than 10 lookups, missing DMARC, missing CAA, domain registration near expiry (RDAP), long-lived wildcard certificates, forgotten-looking names (dev, staging, test) that still resolve.
- **Prioritisation**: severity x exposure x confidence. Each risk cites evidence ids; remediation text is generated by the agent and must pass the verifier.
- **Output**: a Risk section in the HTML report and SARIF export.

## 11. Analyst: noticing what humans miss (D17)

Goal: surface things a human reviewer skips because they are subtle, spread across sources, or about something that is absent. Every result is a finding with evidence, or a clearly marked lead.

**Three layers**
1. **Deterministic detectors** for known classes, cheap and exact: ghost hostnames (a certificate exists, DNS does not), orphaned SPF includes pointing at defunct domains, disagreement between sources (RDAP says one provider, SPF another), expected-but-missing records (a domain that sends mail with no DMARC), temporal oddities (a new asset right after a registrar or name-server change), gaps in naming sequences (`app1`, `app2`, `app4`), clusters that share an unusual combination of name servers, issuer and netblock.
2. **AI hypothesis generator**: reads a compact graph summary plus the detectors' output and proposes **leads** as schema objects: claim, rationale, the entities involved, and a *test* (which registry module and query could confirm or refute it, and what evidence would show it). It also runs a pre-mortem per asset: "what would an attacker see here that the owner has forgotten?"
3. **Test and verify**: the engine runs each lead's test passively. The verifier judges the result. A confirmed lead becomes a finding tagged *AI-noticed*; a refuted lead is logged; an untestable lead sits in the leads appendix and never in the main report.

**Guards**: the AI cannot create evidence; a lead may only reference existing entity ids; its tests are limited to registered passive modules; calls are narrow and schema-constrained so a small local model can do them; a budget applies.

**Measurement**: the benchmark lab zone contains K planted subtle oddities of the classes above. Metrics: planted-oddity recall against the deterministic-only run and against a plain checklist run, lead precision (confirmed over proposed), and unsupported claims (must be 0). "Better than human analysts" is not claimed anywhere unless a human baseline study exists.

## 12. Authorised people-exposure analysis (D18)

**Purpose.** An organisation's human attack surface (phishing and social-engineering exposure) is part of what red teams and defenders assess. This module measures that exposure for an organisation the user is authorised to assess. It is not a way to look people up.

**Preconditions**
- An `engagement.yaml` naming the organisation, its domains, who authorised the work (name and role), the date range and the purpose. The CLI shows the attestation and requires the user to confirm it; it is written to the audit log and the proof bundle. Without a valid engagement file the module does not run.
- The seed is always an organisation or domain. A personal name, personal email or phone number is refused.

**Data in scope (work context only, public sources only)**: the organisation's own public pages, `security.txt` and DMARC report addresses, RDAP organisation contacts where public, public repositories owned by the organisation (work-domain addresses and role names). Professional-network scraping is excluded because it breaks those services' terms.

**Data never collected**: home addresses, personal phone numbers, family members, personal social accounts, photos, location, anything about minors, anything outside the work context.

**Output**: aggregate by default: how many work addresses are publicly discoverable, the naming pattern (for example `first.last@`), which roles cluster in public view (finance, IT administration), and what an attacker could infer. Per-person detail needs an explicit `--detail` flag and is logged. Optional breach-exposure counts come from a keyed provider (v1.1) and are counts only by default.

**Minimisation and privacy**: local storage only; cloud AI is refused for any personal data; names are always pseudonymised before any model call; `scrutator purge` deletes personal data from the database and bundles; bundles exclude personal data unless explicitly included.

**AI role**: pattern-level reasoning only (naming conventions, role clusters, likely high-value targets). No narrative profile of any individual.

**Release gate**: a legal and ethics review, a responsible-use policy update, and the tests listed under D18 before this ships; it ships off by default.

## 13. Knowledge packs (D13)

Everything the tool knows about the world that is not code lives in versioned data packs, so the community can extend it without touching Python.

- **Provider fingerprints**: patterns (NS suffixes, MX suffixes, CNAME suffixes, ASN numbers) mapped to provider name and category (DNS, mail, CDN, hosting, certificate authority). Feeds the dependency map (D11).
- **Takeover fingerprints**: provider hostnames that can be claimed when a CNAME dangles, with the evidence that confirms a dangling state. Feeds D11.
- **Signal frequencies**: how common each attribution signal is across unrelated organisations. Feeds the IDF-style discount in D10.
- **Pivot playbooks**: short YAML recipes ("dangling CNAME to provider X: check A, B, C") retrieved as context for the agent. This grounds small local models with curated knowledge instead of relying on what they happen to remember.
- **Format and trust**: JSON Schema-validated files, a manifest with sha256 per file, signed releases. `scrutator packs update` fetches a newer signed set; offline use of the bundled set always works.
- **Contribution path**: one file per entry, a fixture test per entry, validation in CI.

## 14. Lookalike domains and live CT watch (D14)

- `scrutator lookalikes <domain>` generates permutations (homoglyphs, typos, transpositions, TLD swaps, keyword additions) and checks them **passively**: DNS existence, MX configured, certificates seen in CT, registration age from RDAP. Each candidate gets an explainable risk score (new registration, mail configured, certificate issued, resembles the brand closely).
- `scrutator watch --ct` follows certificate transparency for new certificates matching the scope or the lookalike set and raises an alert through the integrations in section 15. v1.2 polls crt.sh; direct CT log reading (RFC 6962) can replace polling later.
- Lookalike sites are never contacted. Fetching them to classify content is an active-mode feature and needs explicit authorisation.

## 15. Integrations (D16)

- **Alerts**: generic webhook, Slack and Teams payloads for diff and watch events.
- **Tickets**: GitHub issues and Jira tickets for risk findings. Each finding has a stable fingerprint (rule id plus entity), so a re-run updates an existing ticket instead of creating a duplicate, and closes it when the finding disappears.
- **Executive summary**: a one-page narrative built only from verified findings, so it carries the same evidence guarantees as the full report.
- **GitHub Action**: runs a scan on a schedule or on pull requests, compares with a stored baseline and fails the build when a new high-severity exposure appears. Uploads SARIF to GitHub code scanning.

## 16. Outputs

JSON (canonical), Markdown, single-file interactive HTML with graph view, SARIF and STIX export. MCP server exposes the same modules and graph queries (passive tools by default; active tools listed only when enabled locally).

## 17. Benchmark (D8)

- **Ground truth**: a lab DNS zone and hosts we control (known assets, including planted subdomains, a dangling CNAME, shared certs), plus historical snapshots for public targets with community-verified asset lists where available.
- **Competitors**: BBOT, Amass, SpiderFoot, OpenOSINT, each in its passive configuration, same time limit, same keys (or none).
- **Our own configurations**: Scrutator is run in `off`, `local` (a 9B-class model) and `cloud` modes, so the local-versus-cloud gap is published rather than claimed.
- **Metrics**: asset recall, asset precision (each asset DNS-resolved or probe-verified), claim false-positive rate, wall time, LLM cost.
- **Publication**: methodology, scripts and raw outputs in the repo; results published even when a competitor wins a category.
- **OSINT-Bench (D15)**: the harness lives in its own repository so it is credible as a neutral standard. It contains the ground-truth lab zones, task definitions, scoring scripts and one adapter per tool (a small interface: run the tool on a target, return found assets). Anyone can add a tool by pull request; CI re-runs everything. Scrutator is one adapter among others.

## 18. Testing

- Module contract tests on recorded HTTP/DNS fixtures (no live network in CI).
- Scope guard: property-based and fuzz tests (redirect chains, CNAME loops, IDN/punycode, IPv6 forms, mixed case, trailing dots).
- Verifier: fixtures of fabricated claims, claims citing wrong evidence, and claims stronger than their evidence. All must be rejected.
- Agent: scripted fake LLM for deterministic loop tests; injection corpus asserts actions and scope are unchanged.
- Providers: contract tests against recorded Ollama, OpenAI-compatible and Anthropic responses; a scripted misbehaving model (garbage, preamble, extra fields, wrong enum) must trigger repair, then deterministic fallback, never a crash or an unsupported claim.
- Egress: local mode asserts no non-loopback connection from the AI layer; cloud mode asserts every request is in the egress log and that `--redact` leaves no original apex domain or IP in an outgoing payload.
- `ai doctor`: self-test cases run against a fake provider with known-good and known-bad behaviour.
- Store: snapshot/diff round-trip tests.
- Proof bundles: tamper tests (flip a byte in each file type, swap a key, drop an evidence record), replay tests against recorded drift.
- Attribution: lab-zone fixtures with planted unnamed assets and decoy shared-provider assets; precision and recall asserted.
- Risk rules: one fixture per rule (positive and negative); every emitted risk must cite existing evidence.
- Knowledge packs: schema validation of every bundled file, a fixture per entry, signature and tamper tests for `packs update`.
- Lookalikes: permutation generator property tests (every output is a valid hostname, none equals the input); lab fixtures with planted lookalikes and benign near-names.
- Analyst: one fixture per detector class (positive and negative); leads are rejected when they cite unknown entities or untestable queries; recall measured on the planted-oddity lab zone.
- People exposure: seed refusal tests (names, emails, phone numbers), a scan of every output for forbidden personal-data categories, engagement-file validation tests, purge tests.
- Integrations: ticket deduplication tests (unchanged re-run creates nothing, resolved finding closes its ticket), webhook payload snapshot tests, Action tested on a sample repository.
- CI matrix: Linux, macOS, Windows; Python 3.11 and 3.12.

## 19. Roadmap

| Version | Content | Exit criterion |
|---|---|---|
| v0.1 | model, store, scope guard, engine, 6 passive modules, `--no-llm` expander, CLI, JSON + HTML report | Full passive scan of a lab domain; scope fuzz suite green |
| v0.2 | Agent, local-first providers (Ollama, OpenAI-compatible, Anthropic), `ai doctor`, egress log and `--redact`, hypothesis tracker, verifier, injection tests, source-error visibility in reports, result cache | Full pipeline on a local model of 9B or less: 0 unsupported claims, recall at least the deterministic baseline; local mode opens no non-loopback connection |
| v0.3 | Proof bundles (`export`, offline `verify`, `--replay`), diff, watch | Tampered bundles always fail; diff verified on lab changes |
| v0.4 | Knowledge packs (schema, provider and takeover fingerprints, signal frequencies), dependency and risk analysis, analyst detectors (D17 layer 1), SARIF export | All planted lab issues detected; 0 unsupported risk statements; adding a provider needs only a data entry |
| v0.5 | Attribution engine with `candidate` scope state, AI leads and pre-mortem (D17 layers 2 and 3), playbook retrieval for the agent, MCP server | Attribution precision >= 0.9 in the `probable` band on the lab zone; playbook ablation published; Claude Desktop drives a scan via MCP |
| v1.0 | Benchmark harness, OSINT-Bench repository and published results (including the Hallucination Test), README, demo, docs site, private beta completed | Benchmark reproducible by a third party in one command; launch assets in section 18.4 complete |
| v1.1 | `--active` modules, keyed modules, STIX export | Active modules gated by scope and authorisation prompt |
| v1.2 | Lookalike detection, live CT watch | Planted lab lookalikes all flagged; alert within one poll interval |
| v1.3 | Integrations: webhooks, tickets, executive summary, GitHub Action | Unchanged re-run opens 0 new tickets; Action fails a build on a new high-severity exposure |
| v1.4 | Authorised people-exposure analysis (D18), off by default, after the legal and ethics review | A named individual is refused as a seed; no personal-data category in any output; module refuses without a valid engagement file |

**Admission rule.** A feature enters the roadmap only with a measurable exit criterion, fixture-based tests, and a place in the benchmark or the demo. Nothing after v1.0 may delay v1.0: the passive core plus the benchmark is the story that gets the project noticed.

## 20. Positioning and launch plan

### 18.1 Positioning

- **Tagline**: *AI OSINT that can't lie.* Sub-line: every claim links to the raw record it came from, and the AI runs on your machine.
- **README first screen** (must be understood in three seconds): tagline, a captioned demo of 60 seconds or less, the install line `pipx install scrutator`, the run line `scrutator scan example.com`, and a screenshot of the report with an evidence panel open.
- **Honest scope statement**: passive infrastructure OSINT. Scrutator never searches for a named private individual. The only people-related feature is an opt-in, engagement-authorised, organisation-scoped exposure analysis. This is a selling point for security teams and keeps the project clear of the stalking-tool reputation.

### 18.2 The signature story: the Hallucination Test

OSINT-Bench (D15) gets one headline metric alongside recall and precision: the **unsupported-claim rate**, the share of claims in a tool's report that its own collected data does not support, checked against the ground-truth lab zones. The launch story is "we measured how often AI OSINT tools make things up". Fairness rules, because a benchmark that picks on others without care backfires:

- every tool runs in its documented recommended configuration, with the same targets, time limit and keys;
- raw outputs and scoring scripts are public;
- maintainers of every tool measured get the results and raw outputs before publication and a chance to point out a misconfiguration;
- our own failures are reported the same way.

### 18.3 The 60-second demo

1. `scrutator scan` on the lab domain, with network access to the AI turned off ("airplane-mode AI": the local model still runs).
2. The report opens; click a finding; the raw evidence appears.
3. A scripted model deliberately invents a claim; the verifier rejects it ("1 claim rejected: no evidence").
4. Export a proof bundle, change one byte, `scrutator verify` fails.

### 18.4 Launch assets (all ready before v1.0 is announced)

- Documentation site with a quickstart and "add a module in 30 minutes" tutorial.
- Example reports generated only from targets we own or that are reserved for documentation (the lab zone, `example.com`). **Never a real third-party organisation without permission.**
- Blog post 1: why AI OSINT needs receipts. Blog post 2: the Hallucination Test results.
- Packaging: PyPI, Docker image, Homebrew formula; signed releases and an SBOM.
- Credibility files: `SECURITY.md`, a responsible-use policy, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, labelled good-first issues (mostly knowledge-pack entries).

### 18.5 Sequence

1. **Private beta, about six weeks before v1.0**: 10 to 20 practitioners from OSINT, recon and bug-bounty communities; fix the rough edges; collect permission-based quotes.
2. **Launch day**: GitHub release, then a Show HN whose title states the claim, a post to r/netsec and r/OSINT following each community's self-promotion rules, a social thread, and posts in Turkish security communities. Pull requests to awesome-osint, awesome-recon and MCP server directories.
3. **About two weeks later**: the Hallucination Test post as a second wave. Never the same day as the launch.
4. **Conferences**: Black Hat Arsenal takes open-source tools; the Black Hat Asia 2027 call closes on 2026-11-02, too early for a v1.0. Watch for the Black Hat USA 2027 call. DEF CON 35 is on 2027-08-05 to 08-08; Recon Village's CFP ran April to mid-June in 2025 and 2026, so a 2027 call will probably follow that pattern (an inference, not a published date). Target: v1.0 and the benchmark public before April 2027 so the submission is a working tool.
5. **Never**: buying or farming stars, posting the same pitch everywhere at once, badge overload, naming real companies as showcase targets.

### 18.6 Measuring success without telemetry

There is no telemetry (section 5.2). Track PyPI and Docker downloads, GitHub traffic, issues and pull requests, external contributors, packs entries contributed, and OSINT-Bench adapters submitted by third parties. Stars are a vanity metric. As a reference only: a 2025 study of 138 AI-tool launches found an average of 121 stars within 24 hours of Hacker News exposure; security audiences are more sceptical, so set real targets after the beta, not before.

## 21. Defaults pending confirmation

- Working name: **Scrutator** (PyPI, npm and GitHub name checks done 2026-10-15; domain and trademark not checked).
- License: **Apache-2.0** (patent grant; permissive like OpenOSINT's MIT).
- Package: `scrutator` on PyPI.

## 22. Risks

- Strong overlap with OpenOSINT: mitigated by D1, D2, D4, D8, D9, D10 and D11 being hard to copy quickly.
- Attribution false positives would damage trust: `candidate` state, explainable scores, IDF-style discounting of common signals, and a published precision target.
- LLM cost and variance: deterministic mode, budgets, and recorded-LLM tests.
- Weak local models: narrow schema-constrained calls, repair then deterministic fallback, conservative verifier, and a measured `ai doctor` instead of assumed model quality.
- Data exposure through cloud AI: opt-in only, consent prompt, egress log, optional pseudonymisation, no silent fallback.
- Third-party source rate limits and ToS changes: per-module rate limiting, caching, graceful degradation, fixture tests to catch format drift.
- Launching without beta feedback: a private beta of 10 to 20 practitioners precedes v1.0.
- A benchmark dispute with other maintainers: pre-publication sharing of results and raw outputs, documented recommended configurations, our own failures published equally.
- Scope creep: the admission rule above, and v1.0 is defined as v0.5 plus the benchmark.
- Maintenance burden of knowledge packs: one file per entry, schema and fixture checks in CI, signed releases, bundled set always usable offline.
- People-exposure misuse: engagement file required, organisation seed only, aggregate output by default, work-context data only, logged detail access, off by default, ethics review before release.
- Misuse: no general people search, passive default, enforced scope, active mode requires explicit authorisation text.
