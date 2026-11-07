# Contributing to Scrutator

Thank you. The easiest useful contribution is a knowledge-pack entry (one data entry plus one fixture); the next is a
data source; the next is a bug report with an evidence id or a proof bundle.

## Set up

```bash
git clone https://github.com/cemalaysu73-star/scrutator.git
cd scrutator
python -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python -m pytest -q -p no:cacheprovider              # about 4 minutes; no network is used
scrutator bench --out /tmp/bench                     # the offline benchmark; must exit 0
```

Python 3.11 or newer. The test suite never touches the network: every HTTP source is answered by `respx` fixtures and
every DNS lookup by a fake resolver. A test that needs the network does not belong in the suite.

## The rules that make the project what it is

A change that breaks one of these will not be merged, however useful it is:

1. **Every claim cites evidence.** A finding, risk, lead or statement without evidence ids cannot exist. Absence
   (NXDOMAIN, NODATA) is evidence; a timeout is not.
2. **Scope is decided by the engine, deny by default.** Nothing outside the scope file is looked up; a name found
   through a CNAME, a certificate or an aggregator is recorded as `out` and never queried.
3. **Passive only.** No port scanning, no probing of the target, no brute force, no exploitation. Active modules are
   a later, separately gated feature.
4. **Collected text is data, never instructions.** Anything a source returns is attacker-influenced. It is escaped in
   the HTML (data block plus `textContent`), made terminal-safe in the CLI, and fenced as untrusted when it goes to a
   model. A model may be wrong or obedient to planted text, so a deterministic check stands in front of it.
5. **Secrets stay out.** API keys come from environment variables only and never appear in evidence, reports,
   bundles, logs, errors or MCP output (`tests/test_secrets_canary.py` checks this with a canary).
6. **Bundles must be verifiable by someone who does not trust us.** Anything `verify` relies on is re-derived from
   the bundle's own evidence.
7. **Honest numbers.** A claim in the docs comes from a run you did. A limit you know about goes in
   `docs/security.md` or the README, not in a drawer.

## Workflow

- Write the failing test first, then the fix. Never weaken a test to make a change pass; if a test is wrong, say why
  in the commit message.
- One logical change per commit, conventional prefix (`feat:`, `fix:`, `docs:`, `test:`, `perf:`, `chore:`), a message
  that says what and why.
- Run the whole suite and `scrutator bench` before you open a pull request. CI runs both on Linux, macOS and Windows
  (Python 3.11 to 3.13) and installs the built wheel into a clean environment.
- Line endings are LF. Files are UTF-8. Everything in the repository is written in English.
- A pull request template asks for the test you added and for the rules above; please fill it in.

## Good first contributions

### A knowledge-pack entry

Providers, takeover fingerprints, signal frequencies and pivot playbooks are YAML in `src/scrutator/packs/data/`.
Adding a provider is one entry with a source URL for the fingerprint and one fixture. See
[docs/knowledge-packs.md](docs/knowledge-packs.md). `scrutator packs validate` must pass.

### A data source

A source is one file in `src/scrutator/modules/`: a `Module` subclass with `name`, `accepts` and an async `run` that
returns `Observation`s (an entity, a relation and the raw `Evidence`). Add its host to `egress.SOURCE_HOSTS` and to
the replay allowlist, record its terms in [docs/sources.md](docs/sources.md) (the table is checked against
`scrutator sources` by a test), and write contract tests on a recorded response, including a hostile one. See
[docs/writing-a-module.md](docs/writing-a-module.md). A source whose terms forbid automated use, or that needs
scraping, will not be added.

### A benchmark case

The labs behind `scrutator bench` are in `src/scrutator/benchlab/`. A new planted issue needs a positive and a
negative case. See [docs/benchmarks.md](docs/benchmarks.md). Adapters for other tools live in `bench/`.

## Reporting bugs and security problems

Bugs and ideas: open an issue (there are forms for a bug, a feature, a new source and a false positive) with the version, the command, and the evidence id or a minimal bundle. Security problems:
see [SECURITY.md](SECURITY.md); do not open a public issue.
