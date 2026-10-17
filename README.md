# Scrutator

Evidence-backed, AI-driven infrastructure OSINT. Point it at a domain; get a map of the
organisation's internet-facing infrastructure in which every claim links to the raw record
it came from. The AI is local-first: it runs on a model on your machine, and cloud models are
an explicit, logged opt-in.

**Status: v0.5.** Passive scanning with six keyless sources, a deny-by-default scope guard,
an evidence store, JSON and HTML reports, a budgeted agent, an AI summary in which every
statement is checked against evidence by a separate verifier, signed proof bundles that anyone
can verify and replay, diff between scans, scheduled watching, knowledge packs, a dependency
and risk analysis in which every risk cites its evidence and can be re-derived from a proof
bundle, deterministic analyst detectors, SARIF export, and now an attribution engine (names
outside the scope that probably belong to the organisation, with a score, a band and the evidence
behind it), AI leads that must cite evidence, playbooks for the agent, and an MCP server. The
benchmark is planned.

## Install

```bash
pipx install scrutator
pipx install "scrutator[mcp]"     # with the MCP server
```

From a checkout: `pip install -e ".[dev]"` (this includes the MCP SDK; without it the MCP tests skip).

## Use

```bash
scrutator scan example.com
```

This writes `scrutator-out/report.html` (open it in a browser), `report.json` and
`scrutator.db`. Sources: certificate transparency (crt.sh), DNS, RDAP, ASN (RIPEstat),
Internet Archive and Common Crawl. No API keys needed. Transient source failures are
retried with backoff; any that still fail are listed under **Source coverage** in the report,
so a missing result is never mistaken for a negative one.

### Scope

By default the scope is the seed domain and its subdomains. For anything else, write a
scope file:

```yaml
domains:
  - example.com
cidrs:
  - 203.0.113.0/24
asns:
  - AS64500
```

```bash
scrutator scan example.com --scope scope.yaml
```

Every discovered entity is marked `in`, `candidate`, `linked` or `out`. Out-of-scope entities are
recorded but never queried. An IP that an in-scope host resolves to is `linked`: passive lookups
about it are allowed. A `candidate` is a name outside the scope that the attribution engine found
evidence for (see below): it gets passive lookups only, until you promote it. Only your scope file
defines what may be investigated.

### Evidence

Findings cannot exist without evidence ids. Each evidence record is the raw response of a
source, stored once and addressed by hash. A finding's confidence is the number of distinct
sources that agree: one is low, two medium, three or more high. Every module call is written
to a hash-chained audit log.

Absence is evidence too. When a lookup answers "this name does not exist" (NXDOMAIN) or "this
name has no such record" (NODATA), that answer is stored like any other, and it is what a
risk about a missing record rests on. A timeout or a failed lookup is not stored as a negative:
silence is never turned into a finding.

## Risks

```bash
scrutator risk                          # the latest scan in scrutator-out/scrutator.db
scrutator risk 3 --db other.db          # a scan by id
scrutator risk proof.scrutator          # a bundle (verified first; a forged one is refused)
scrutator risk --category analyst       # only the analyst detectors
scrutator risk --sarif risks.sarif      # also write SARIF 2.1.0
scrutator risk --fail-on high           # for CI: exit status 1 if a high risk exists
```

Deterministic rules read the stored graph and its evidence. Each risk has a rule id, a severity
(`info`, `low`, `medium`, `high`), the entities it is about, **at least one evidence id** (a risk
cannot exist without one), an explanation that says only what the cited evidence shows, a general
remediation hint, and a confidence. The HTML report has a **Risks** section where every risk expands
to its raw evidence.

| Rule | Severity | What the evidence must show |
|---|---|---|
| `dangling-cname-claimable` | high | A name is a CNAME of a host at a service whose names anyone can register (takeover fingerprint), and the address lookup returned NXDOMAIN. |
| `dangling-cname-known-service` | medium | The same, at a service known for takeovers where NXDOMAIN does not prove it can be claimed. |
| `dangling-cname` | medium | A CNAME whose address lookup returned NXDOMAIN, target unknown to the packs. |
| `spf-allows-all` / `spf-neutral-all` / `spf-softfail-all` | high / medium / low | The SPF record ends with `+all` (or `all`), `?all`, `~all`. |
| `spf-no-all`, `spf-multiple-records`, `spf-too-many-lookups` | medium | No default result; more than one `v=spf1` record; more than ten lookup terms in the record's own text (included records are not queried). |
| `dmarc-missing` | medium | A name with real MX records (a null MX does not count) and no DMARC record at `_dmarc.<name>` or a parent domain. |
| `dmarc-monitoring-only` | low | A DMARC record with `p=none`. |
| `caa-missing` | low | A zone apex whose CAA lookup returned nothing, and no parent zone has CAA. |
| `domain-expired`, `domain-expiring` | high; medium or high | The RDAP expiration is past, or within 30 days (14 days is high), measured against the time the data was **collected**, not today. |
| `forgotten-name` | low | A name with a label such as `dev`, `staging`, `test`, `old`, `backup` that still resolves. A heuristic, low confidence. |
| `concentration-dns`, `concentration-edge` | info (low from ten names) | Every name server of every zone belongs to one provider; three or more names sit behind one CDN or host. Silent unless every host is recognised. |
| `ghost-hostname` (analyst) | info | A certificate or archive names an in-scope host and DNS says NXDOMAIN. |
| `numbering-gap` (analyst) | info | `app1`, `app2`, `app4`: a number in a series is missing. |
| `source-disagreement` (analyst) | low | RDAP and the zone list different name servers. |

The **analyst** category is layer 1 of the analyst in the design: deterministic detectors for the
subtle things a reviewer skips. There is no AI in any detector. With an AI summary, risks are given to
the writer as findings, so a sentence about a risk is checked against the same evidence as everything
else, and an unsupported one lands in *Unverified leads*.

The report also holds a **dependency map**: which providers stand behind the names (DNS provider from
the name servers, mail provider from MX and SPF, CDN or host from CNAME targets and the AS behind each
address, certificate authority from currently valid certificates).

**Exit status.** `0` on success, also when risks exist. `1` when `--fail-on` is given and a risk at or
above that severity exists (and from `verify` when a check fails). `2` for usage errors: a missing
database, an unknown option value, a pack directory that fails validation.

**SARIF.** Entities are *logical* locations (a DNS name is not a file), so results have no physical
location. Uploaders that need one (GitHub code scanning does) must supply it; that belongs to a later CI
integration. Each result has a stable `partialFingerprints` entry made of the rule and the entities, so
a later run can recognise the same finding and update its ticket instead of opening a new one.

## Attribution

Some assets belong to an organisation without any name match: a sister domain, an acquired brand, a
service run under another name. Attribution looks for names **outside your scope** that the evidence
ties to the organisation, scores them, and explains every score.

```bash
scrutator scan example.com --scope scope.yaml --attribution   # mark and look at candidates, passively
scrutator candidates                                          # who may be ours, strongest first
scrutator attribution --entity partner.example.net            # why, and what could make it wrong
scrutator promote partner.example.net --scope scope.yaml      # accept it into scope (asks first)
```

**What it looks at.** Ten signals, each computed from stored evidence only. A signal that points at a
shared provider (a CDN, a mail service, a public CA, a DNS operator the packs know) is kept in the
output with weight 0 and the reason, so you can see what was ignored.

| Signal | Weight | The evidence |
|---|---|---|
| `ns_in_scope` | 0.90 | the name is delegated to a name server under an in-scope domain |
| `mx_in_scope` | 0.70 | its mail is received by a host under an in-scope domain |
| `spf_in_scope` | 0.60 | its SPF record includes a name under an in-scope domain |
| `cert_san` | 0.60 | one certificate lists both an in-scope name and this name |
| `rdap_registrant` | 0.60 | its registrant organisation is the same as an in-scope domain's |
| `shared_ns` | 0.50 | it uses the same name servers as an in-scope zone, and they are not a shared provider |
| `shared_mx` | 0.40 | it receives mail on a host an in-scope name also uses, and that host is not a shared provider |
| `network_owner` | 0.35 | its address is in a network with the same owner or AS as an in-scope address, and that is not a shared provider |
| `scope_uses` | 0.20 | an in-scope name points its name servers, mail or SPF at it, and it is not a shared provider |
| `cert_issuer` | 0.10 | it and an in-scope name use certificates from the same issuer, and that issuer is not a common CA |

A certificate with more than ten names counts for less (ten divided by the number of names: it looks
like a shared service's), and one that had been expired for over a year when it was collected counts
half. A registrant that is a redaction placeholder or a privacy service is not a registrant.

**The score and the band.** Independent signals combine as `1 - product(1 - weight)`, so no score
passes 1 and weak signals stay weak. Bands: `confirmed` (score 0.90 or more from at least two kinds of
signal), `probable` (0.70), `possible` (0.35), `unlikely`. **`probable` and `confirmed` need an
ownership signal**: `ns_in_scope`, `mx_in_scope`, `spf_in_scope` or `rdap_registrant`, evidence that
only the owner, or someone it runs services for, can produce. A shared certificate, name servers,
network or mail host can just as well be a partner's or a host's, so on their own they never get past
`possible`. The planted lab showed this rule was needed: without it a partner with a co-branded
certificate and the same small DNS operator scored 0.80.

**These weights are chosen by hand.** They are not measured and not calibrated to the real world.
The knowledge packs' `signals` file can lower a signal's weight with a measured frequency (how often
unrelated organisations show it, with the sample size); it ships empty because no such corpus has been
collected, and numbers are not invented.

**What a candidate may and may not receive.** A name enters the `candidate` state when at least one
counted signal of 0.20 or more points at it (at most `--max-candidates`, 20 by default). It then gets
passive DNS, registration and certificate lookups, once, and the network lookups for the addresses it
resolves to. Names found through a candidate are only recorded. No active module ever runs on it.
Names that nothing in the scan links to the scope cannot be found this way: finding them needs a
reverse lookup (names on this name server, names on this address), which is a keyed source and not part
of passive mode.

**Promotion is the only way in.** `scrutator promote NAME --scope scope.yaml` shows the band, score and
evidence count, asks for confirmation (`--yes` skips it), adds the name to your scope file (the old file
is kept as `scope.yaml.bak`; YAML comments are not preserved), writes a `promoted` record to the
hash-chained audit log (who asked: `cli` or `mcp`; when; the score and evidence it rested on), and only
then raises the entity to `in`. Adding a name adds everything under it, so promote the apex you mean.
Scan again to investigate it fully. Anything that is not a candidate is refused.

**What the bundle checks.** `verify` recomputes the attribution from the report's own evidence
(`attribution derivable`), so a raised band or a hidden caveat fails even when the bundle is re-signed.
It also checks that the report's promotions are exactly those in the signed audit log
(`promotions recorded`) and that every lead cites evidence that is in the bundle.

### How well does it work?

Measured on the planted lab (`tests/attrlab.py`): an organisation with 16 names of its own and a set of
decoys, answered by a fake resolver and mocked sources, no network. It is a synthetic zone written by the
author of the scoring: it shows the scoring behaves as designed on the cases its author thought of, not
how accurate it is on real organisations. The decoys are the cases the design discounts (Cloudflare name
servers, a shared hosting AS, a certificate that lists 28 names, a vendor the SPF record includes), two
cases it only partly handles (a partner with a co-branded certificate on the same small DNS operator, an
old certificate on that operator), and **one it cannot solve**: a customer whose DNS the organisation
runs, which looks exactly like the organisation's own, and is a planted false positive in the
`confirmed` band. Of the 16 true names, one is found but not believed (an old certificate and nothing
else) and one cannot be found at all.

| Band | Names | True | Precision | Precision, this band or better | Recall, this band or better |
|---|---|---|---|---|---|
| confirmed | 7 | 6 | 0.86 | 0.86 | 0.38 |
| probable | 5 | 5 | 1.00 | 0.92 | 0.69 |
| possible | 5 | 3 | 0.60 | 0.82 | 0.88 |
| unlikely | 31 | 1 | 0.03 | 0.31 | 0.94 |

The exit criterion is precision of at least 0.9 in the `probable` band on the lab: 5 of 5 in the band,
11 of 12 for `probable` or better. Five names is a small sample; read it as a regression test, not as a
rate.

## Analyst leads and the pre-mortem (AI)

Every candidate comes with a **pre-mortem** made by rules: what in the evidence could make the
attribution wrong (one kind of signal only, a certificate that may be a partner's, signals ignored as
shared providers, a name nobody has looked at yet), each citing the evidence it rests on. It needs no
model.

With a model, `scrutator scan --attribution` also asks the planner role for up to eight **leads**
(something odd the evidence shows) and **pre-mortems** (what could make an attribution wrong). The model
sees entities and evidence as short references (`N1`, `E3`), never real ids, inside fenced data blocks,
and can only cite what was listed to it: an item with an unknown reference, a pre-mortem about something
that is not a candidate, or a suggested check that is not a registered passive module on a listed
entity is discarded before anyone reads it. What is left goes to the verifier role, like the summary
statements: unsupported items are kept as *Unverified leads*, never in the report proper, and with no
verifier nothing is published. A suggested check is shown, never run. Without a model, or when it fails,
the rules' pre-mortem stands alone.

## Knowledge packs

Everything the tool knows about the world that is not code is in versioned YAML packs shipped inside
the package: provider fingerprints (name server, mail, CDN, hosting and certificate-authority patterns,
and AS numbers), takeover fingerprints, a schema for attribution-signal frequencies (empty until there is
a measured corpus), and **playbooks**.

```bash
scrutator packs list                    # the files in use, versions, entry counts
scrutator packs validate                # schema and manifest check of the bundled packs
scrutator packs validate my-packs/      # the same for your directory
scrutator scan example.com --packs my-packs/   # extend or override the bundled data
scrutator risk 3 --packs my-packs/      # re-evaluate an old scan with newer knowledge
```

**Adding a provider is one data entry, no code.** Drop a file like this into a directory and pass it
with `--packs`:

```yaml
schema: 1
kind: providers
version: 2026.10.1
updated: 2026-10-16
entries:
  - id: acme-dns
    provider: Acme DNS
    category: dns            # dns | mail | cdn | hosting | ca
    ns: [dns.acme.example]   # host suffixes; a label may contain *; mx, spf, cname, asn, issuer for other categories
    examples: [ns1.dns.acme.example]   # values this entry must match: a fixture the validator can run
    source: "https://docs.acme.example/nameservers"
    verified: false          # true once you checked the patterns against the source
```

An entry with the same `id` as a bundled one replaces it. The packs a scan used are recorded with it
and travel inside its proof bundle, so a report is always read with the knowledge it was made with.
The same entry also decides attribution: a name server operator listed here is a shared provider, and
signals that point at it stop counting.

**Playbooks** are short recipes for the agent: a title, the situations in which it applies (an alias
points outside the scope, a certificate names an outside host, a name receives mail, a zone is
delegated, an address has no network yet, candidates are waiting, an SPF record names other senders),
the steps, and the modules the steps are about. Which situations hold is decided from the graph alone.
When the planner has more lookups than steps and a model is running, the (at most three) playbooks that
fit are put in its prompt as curated guidance outside the data fence; they can change the order it
chooses in, never the options, and the scope stays whatever your file says. `--no-playbooks` turns them
off, and the audit log records which playbooks each round was offered. Playbooks are loaded and
validated like the other packs but are not part of the hash a proof depends on, because no derived
result depends on them. The bundled ones are procedures written for Scrutator, all marked `verified:
false`: their `source` is background reading.

### Do playbooks help?

A deterministic harness (`tests/ablation.py`) runs the agent on the planted lab with a stand-in planner
that obeys guidance the way a model asked to would, once with the playbooks in its prompt and once
without, at four lookup budgets:

| Lookup budget | Names resolved, without | Names resolved, with | Risks found, without | Risks found, with |
|---|---|---|---|---|
| 8 | 1 | 6 | 1 | 2 |
| 10 | 1 | 8 | 1 | 3 |
| 14 | 4 | 8 | 2 | 3 |
| 24 | 8 | 8 | 3 | 3 |

This shows that retrieval reaches the prompt and changes what the agent does with a tight budget, and
that with room to spare both finish the same investigation. It does **not** show that a real model
benefits: the stand-in obeys by construction. The real-model ablation is part of the v1.0 benchmark.

To change the bundled packs: edit the YAML in `src/scrutator/packs/data`, run `scrutator packs manifest
src/scrutator/packs/data` to refresh the sha256 manifest, run `pytest`, and open a pull request.

**Where the bundled data comes from.** Takeover entries come only from the community project
[can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) (a service is listed only if its
`fingerprints.json` gives a CNAME pattern and rates it Vulnerable or Edge case). Provider entries marked
`verified: true` were checked against the vendor documentation named in their `source`; those marked
`verified: false` are widely known patterns that have not been re-checked yet, and the dependency map
says so. Each entry carries `examples` that the test suite runs against the entry itself.

## Proof bundles

A scan can be exported as a signed bundle that anyone can check without trusting you or this tool's output.

```bash
scrutator keygen                      # once: creates ~/.config/scrutator/signing.key and signing.pub
scrutator scan example.com --bundle   # also writes <out>/proof.scrutator
scrutator export 3 --bundle proof.scrutator   # or export any scan in the database
scrutator verify proof.scrutator --pin <fingerprint-or-signing.pub>
scrutator verify proof.scrutator --pin signing.pub --replay
```

A bundle holds `report.json`, every raw evidence record (`evidence.jsonl`), the hash-chained audit
log (`audit.jsonl`) and a signed manifest. `verify` checks each layer on its own: file hashes, the
Ed25519 signature, the audit chain, that every evidence record hashes to its id, that everything the
report cites is in the bundle, that the report's findings are exactly what the evidence implies, and
that its **risks and its attribution are exactly what the evidence and the embedded packs imply**
(`risks derivable`, `attribution derivable`): both engines are pure functions of the report, so `verify`
recomputes them. The manifest records the packs used; `packs intact` checks them against this tool's own
copy of the bundled packs, so removing a takeover fingerprint and recomputing every result is still
caught. Pack entries you added yourself cannot be checked against a trusted copy; `verify` says so, and
the signer is vouching for them. Change one byte anywhere and a named check fails. Bundles made by
older versions still verify; the checks that did not exist then are reported as not applicable.

**A valid signature only proves the bundle matches the key inside it.** Anyone can sign a forged
bundle with their own key, so give readers your key fingerprint through a channel they trust and
have them verify with `--pin`. Without `--pin`, `verify` warns.

`--replay` re-issues the recorded requests (HTTPS GETs to the public sources the modules use, and DNS
lookups of types A, AAAA, CNAME, MX, NS, TXT and CAA) and reports each as unchanged, changed or
unavailable. A recorded NXDOMAIN or NODATA replays as unchanged while it still holds. Drift is not
forgery: sources change and go down. Replay only ever contacts that fixed set of source hosts, so a
hostile bundle cannot make `verify` fetch arbitrary URLs.

### Compare and monitor

```bash
scrutator diff 1 2                         # two scans in the database
scrutator diff old.scrutator new.scrutator # two verified bundles
scrutator watch example.com --every 6h --webhook https://hooks.example.test/x
```

`watch` re-scans on a schedule, prints what changed, writes `diff-<n>.json`, and posts a summary
(counts and changes, no raw evidence) to the webhook. Webhooks must be HTTPS (plain HTTP only for
localhost). Watch scans are deterministic; they do not use AI.

## AI

```bash
scrutator scan example.com             # --ai auto: uses a local model if one is running
scrutator scan example.com --ai off    # deterministic, no model
scrutator ai doctor                    # measure the configured models
```

`--ai auto` looks for Ollama, LM Studio or a llama.cpp server on this machine. If none is found
it runs without AI. **It never falls back to a cloud model on its own.**

What the models do:

- **Planner**: when there are more lookups than the step budget (`--max-steps`), it ranks the
  numbered options, guided by the playbooks that fit. It can only choose from the list it is given; if
  it fails, the first options run. It also keeps a log of hypotheses, settled only with real evidence,
  and proposes the leads described above.
- **Writer**: drafts a short summary, each statement citing findings (risks included).
- **Verifier**: checks each statement and each lead against the evidence it cites. Unsupported or
  unverifiable ones go to *Unverified leads* and never into the report. With no verifier, nothing is
  published.

Collected text is passed to models inside fenced data blocks marked untrusted, and model output
is validated against a schema, with repair attempts and a deterministic fallback.

### Configuration

`~/.config/scrutator/config.toml` (or `--config`):

```toml
[ai]
mode = "auto"        # auto | off | local | cloud | hybrid
redact = false
max_steps = 60

[ai.planner]
provider = "ollama"  # ollama | openai (any OpenAI-compatible server) | anthropic
model = "qwen3:8b"

[ai.verifier]        # use a different model from the writer for independence
provider = "ollama"
model = "llama3.2"
```

### Cloud models

Cloud use needs an explicit mode or config, an API key in an environment variable named by
`api_key_env` (never written to reports), and your consent at a prompt (`--yes-cloud` skips it).
Every request that leaves the machine is recorded in the report's `egress` list (provider, model,
role, size, sha256 of the payload). `--redact` replaces apex domains, IPs and organisation names
with stable pseudonyms in outgoing prompts and restores them in the answers. In `local` mode any
non-loopback endpoint is refused.

```toml
[ai.planner]
provider = "anthropic"
model = "claude-sonnet-5-5"
api_key_env = "ANTHROPIC_API_KEY"
```

## MCP server

`scrutator mcp` serves Scrutator to an MCP client such as Claude Desktop over stdio, using the official
[MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) (`pip install "scrutator[mcp]"`).

```bash
scrutator mcp --db scrutator-out/scrutator.db                      # read-only tools only
scrutator mcp --db scrutator-out/scrutator.db --scope scope.yaml --allow-scan
scrutator mcp --db scrutator-out/scrutator.db --scope scope.yaml --allow-promote
```

| Tool | Offered | What it does |
|---|---|---|
| `list_candidates` | always | names outside the scope that may be ours, with band and score |
| `attribution` | always | every signal and its evidence, and what could make it wrong |
| `risk` | always | configuration risks of a scan, each citing evidence |
| `verify_bundle` | always | the checks of `scrutator verify` for a `.scrutator` file |
| `scan` | `--allow-scan` | a passive scan of a seed inside your scope file; a seed outside it is refused before anything is looked up; no AI, no active modules |
| `promote_candidate` | `--allow-promote` | accept a candidate into scope; changes nothing unless called with `confirm=true` |

A Claude Desktop entry (adapt the paths; use the full path to `scrutator` if it is not on `PATH`):

```json
{
  "mcpServers": {
    "scrutator": {
      "command": "scrutator",
      "args": ["mcp", "--db", "C:\\scans\\scrutator.db", "--scope", "C:\\scans\\scope.yaml", "--allow-scan"]
    }
  }
}
```

What is checked, and what is not. The test suite starts the server as a real subprocess and speaks to it
in raw JSON-RPC frames over stdio: the handshake, the tool list, every tool, refusals, and that stdout
carries nothing but protocol frames. It has **not** been run against Claude Desktop itself; the roadmap
criterion "Claude Desktop drives a scan via MCP" needs a manual run. Results contain names and text from
the investigated organisation's public records, so each result says they are untrusted data; a client
that shows you every tool call before it runs is also the human in the loop for `promote_candidate`,
which Scrutator cannot check. The server never offers `scan` or `promote_candidate` unless you started it
with the flag, and the scope file is the only thing that decides what a scan may touch.

## Checking it against a real domain

`example.com` is reserved for documentation, so it is a safe target, and everything below is passive.
Run this yourself; the commands need network access and, for the bundle, a signing key. A scan with
attribution can take several minutes when crt.sh or the archives are slow.

```bash
scrutator keygen
scrutator scan example.com --out live05 --ai off --attribution --bundle
scrutator risk --db live05/scrutator.db
scrutator candidates --db live05/scrutator.db --min-band unlikely
scrutator attribution --db live05/scrutator.db --min-band unlikely
scrutator verify live05/proof.scrutator --pin ~/.config/scrutator/signing.pub --replay
scrutator packs validate
```

What to look for, and what the design predicts for example.com at the time of writing (your run is the
test, not this paragraph):

- `risk` lists only risks whose evidence it can show; open the HTML report and expand a few. The name
  servers are Cloudflare's, so expect `concentration-dns` (info). The null MX record (`0 .`) means
  "no mail", so there must be **no** `dmarc-missing`. The SPF record is `-all`, so there must be no SPF risk.
- Old certificates in the CT logs name hosts such as `dev`, `m`, `products` and `support` that DNS no
  longer knows, so expect four `ghost-hostname` findings (info, analyst), each citing a stored `DNS A
  <host>` record whose payload is `NXDOMAIN`. Cloudflare-hosted zones such as example.com do not send a
  real NXDOMAIN for a missing name: they answer NOERROR with an NSEC record whose type bitmap lists
  `NXNAME` ("compact denial of existence"), and only to a query that asks for DNSSEC records. Scrutator
  sets the DO bit and treats that answer as `nxdomain`; an NSEC without `NXNAME` stays `nodata`, which is
  why the apex CAA lookup is still `NODATA` and `caa-missing` appears if the apex has no CAA record.
- `candidates` should list **nothing** at `possible` or better. The only name outside the scope that
  shares a certificate with example.com is `m.testexample.com`, on a certificate that expired in 2017:
  expect it as `unlikely`, score 0.30 (`cert_san` halved for age), marked `candidate`, and a pre-mortem
  that says one kind of evidence supports it. After its one passive look nothing else ties it to
  example.com: its name servers are not example.com's. The Cloudflare name servers example.com
  uses are a shared provider, so they are not candidates at all. A name that appears here as `probable`
  or better is a bug: open the evidence it cites.
- `verify` should pass every check, including `risks derivable`, `attribution derivable`, `promotions
  recorded` and `packs intact`. With `--replay` the NXDOMAIN, NODATA and CAA records should replay as
  `unchanged`, and `skipped` should be 0.
- Any risk or candidate that looks wrong is a bug: open the evidence it cites, and file an issue with the
  evidence id.

## Responsible use

Passive mode only queries third-party public sources, but those services see what you search
for, and cloud AI sees summaries of what was found. Only investigate organisations you are
authorised to assess or that you are entitled to research. Scrutator never searches for a
named private individual. Risk findings describe configuration visible in public DNS and
certificate records; they are leads for the owner to confirm, not proof of compromise. Attribution is
a set of leads with scores: a `candidate` is not yours until you say so, and nothing is investigated
beyond passive lookups before then. Takeover confirmation by an active check is not part of passive mode.

## Develop

```bash
pip install -e ".[dev]"
pytest
```

Licence: to be confirmed (Apache-2.0 is the intended default).
