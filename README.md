# Scrutator

Evidence-backed, AI-driven infrastructure OSINT. Point it at a domain; get a map of the
organisation's internet-facing infrastructure in which every claim links to the raw record
it came from. The AI is local-first: it runs on a model on your machine, and cloud models are
an explicit, logged opt-in.

**Status: v0.4.** Passive scanning with six keyless sources, a deny-by-default scope guard,
an evidence store, JSON and HTML reports, a budgeted agent, an AI summary in which every
statement is checked against evidence by a separate verifier, signed proof bundles that anyone
can verify and replay, diff between scans, scheduled watching, knowledge packs, a dependency
and risk analysis in which every risk cites its evidence and can be re-derived from a proof
bundle, deterministic analyst detectors, and SARIF export. Attribution and the benchmark are
planned.

## Install

```bash
pipx install scrutator
```

From a checkout: `pip install -e ".[dev]"`.

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

Every discovered entity is marked `in`, `linked` or `out`. Out-of-scope entities are recorded
but never queried. An IP that an in-scope host resolves to is `linked`: passive lookups about
it are allowed.

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

## Knowledge packs

Everything the tool knows about the world that is not code is in versioned YAML packs shipped inside
the package: provider fingerprints (name server, mail, CDN, hosting and certificate-authority patterns,
and AS numbers), takeover fingerprints, and a schema for attribution-signal frequencies (empty until
v0.5 has a measured corpus; inventing numbers would break the evidence rule).

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

**Where the bundled data comes from.** Takeover entries come only from the community project
[can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) (a service is listed only if its
`fingerprints.json` gives a CNAME pattern and rates it Vulnerable or Edge case). Provider entries marked
`verified: true` were checked against the vendor documentation named in their `source`; those marked
`verified: false` are widely known patterns that have not been re-checked yet, and the dependency map
says so. Each entry carries `examples` that the test suite runs against the entry itself.

To change the bundled packs: edit the YAML in `src/scrutator/packs/data`, run `scrutator packs manifest
src/scrutator/packs/data` to refresh the sha256 manifest, run `pytest`, and open a pull request.

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
that its **risks are exactly what the evidence and the embedded packs imply** (`risks derivable`): the
risk engine is a pure function of the report, so `verify` recomputes it. The manifest records the packs
used; `packs intact` checks them against this tool's own copy of the bundled packs, so removing a
takeover fingerprint and recomputing every risk is still caught. Pack entries you added yourself cannot be
checked against a trusted copy; `verify` says so, and the signer is vouching for them. Change one byte
anywhere and a named check fails.

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
  numbered options. It can only choose from the list it is given; if it fails, the first
  options run. It also keeps a log of hypotheses, settled only with real evidence.
- **Writer**: drafts a short summary, each statement citing findings (risks included).
- **Verifier**: checks each statement against the cited findings' evidence. Unsupported or
  unverifiable statements go to *Unverified leads* and never into the summary. With no verifier,
  nothing is published.

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

## Checking it against a real domain

`example.com` is reserved for documentation, so it is a safe target. Run this yourself; the commands
need network access and, for the bundle, a signing key.

```bash
scrutator keygen
scrutator scan example.com --out live04 --ai off --bundle
scrutator risk --db live04/scrutator.db
scrutator risk --db live04/scrutator.db --sarif live04/risks.sarif
scrutator verify live04/proof.scrutator --pin ~/.config/scrutator/signing.pub --replay
scrutator packs validate
```

What to look for, and what the design predicts for example.com at the time of writing (your run is the
test, not this paragraph):

- `risk` lists only risks whose evidence it can show; open the HTML report and expand a few. The name
  servers are Cloudflare's, so expect `concentration-dns` (info). The null MX record (`0 .`) means
  "no mail", so there must be **no** `dmarc-missing`. The SPF record is `-all`, so there must be no SPF risk.
- Old certificates in the CT logs name hosts such as `dev`, `m`, `products` and `support` that DNS no
  longer knows; expect `ghost-hostname` findings (info, analyst) citing both the certificate and the
  NXDOMAIN. `caa-missing` appears if the apex has no CAA record.
- `verify` should pass every check, including `risks derivable` and `packs intact`. With `--replay`
  the NXDOMAIN, NODATA and CAA records should replay as `unchanged`, and `skipped` should be 0.
- Any risk that looks wrong is a bug: open the evidence it cites, and file an issue with the evidence id.

## Responsible use

Passive mode only queries third-party public sources, but those services see what you search
for, and cloud AI sees summaries of what was found. Only investigate organisations you are
authorised to assess or that you are entitled to research. Scrutator never searches for a
named private individual. Risk findings describe configuration visible in public DNS and
certificate records; they are leads for the owner to confirm, not proof of compromise. Takeover
confirmation by an active check is not part of passive mode.

## Develop

```bash
pip install -e ".[dev]"
pytest
```

Licence: to be confirmed (Apache-2.0 is the intended default).
