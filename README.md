# Scrutator

Evidence-backed, AI-driven infrastructure OSINT. Point it at a domain; get a map of the
organisation's internet-facing infrastructure in which every claim links to the raw record
it came from. The AI is local-first: it runs on a model on your machine, and cloud models are
an explicit, logged opt-in.

**Status: v0.2.** Passive scanning with six keyless sources, a deny-by-default scope guard,
an evidence store, JSON and HTML reports, a budgeted agent, and an AI summary in which every
statement is checked against evidence by a separate verifier. Proof bundles, risk analysis,
attribution and the benchmark are planned.

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
- **Writer**: drafts a short summary, each statement citing findings.
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

## Responsible use

Passive mode only queries third-party public sources, but those services see what you search
for, and cloud AI sees summaries of what was found. Only investigate organisations you are
authorised to assess or that you are entitled to research. Scrutator never searches for a
named private individual.

## Develop

```bash
pip install -e ".[dev]"
pytest
```

Licence: to be confirmed (Apache-2.0 is the intended default).
