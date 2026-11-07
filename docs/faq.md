# FAQ

## Is it legal?

Short answer: reading public records about an organisation is lawful in most places, and Scrutator's default scan does
only that. That is not legal advice, and "most places" is not your place.

- The default scan asks public services (certificate transparency, RDAP, archives, aggregators) and your DNS resolver.
  It sends nothing to the target's servers and never probes, brute-forces or exploits anything.
- Whether you may assess a particular organisation depends on your jurisdiction, your contract and the data sources'
  terms. Get written authorisation for engagements. `scrutator audit-letter` writes a template (not legal advice);
  `scrutator audit` refuses to run without a filled-in authorisation or `--self`.
- Data sources have terms. Several free tiers are for non-commercial use only; `--no-noncommercial` leaves them out.
  The table is in [sources](sources.md).
- Records can contain personal data (an RDAP contact, a name in a certificate). Under GDPR, KVKK and similar laws you
  handle it as personal data. The tool never searches for a named person, and the opt-in exposure module reduces
  personal-looking addresses to a shape and a pseudonym before storage.
- Active features (a zone-transfer request, `--brand`, `scrutator exposure`) are opt-in, recorded in the signed audit
  log, and for targets you are authorised to test.

Policy text: [RESPONSIBLE_USE.md](../RESPONSIBLE_USE.md).

## Is it safe to run?

On the machine: it makes outbound HTTPS requests to a fixed list of source hosts (anything else is refused by the
egress guard), DNS queries through your resolver, and one PostgreSQL connection to `crt.sh:5432` when crt.sh's web
search fails. It writes to the folder you give it and reads your signing key if you ask for a bundle. It does not
install anything, run a server (unless you start `scrutator mcp`), or execute downloaded code.

On untrusted input: everything a source returns is treated as attacker-influenced. HTML output uses `textContent` and
an escaped data block, terminal output filters control and bidirectional characters, and text sent to a model is
fenced as untrusted data. `scrutator verify` is built to be run on bundles from strangers and is tested against zip
bombs, traversal names, hostile JSON and signature confusion. What is guaranteed, where it is tested and what is not:
[security model](security.md). Found a hole? [SECURITY.md](../SECURITY.md).

Check the tool on your own machine with no network at all: `scrutator bench` runs the offline benchmark and exits
non-zero if a threshold fails.

## What leaves my machine?

1. **The queries to the sources.** Each enabled source learns the domain (or address) you ask about and your IP
   address. The hosts are listed under
   [operational security](use-cases.md#operational-security-what-the-tool-does-on-the-network) and in [sources](sources.md).
2. **DNS questions** to your configured resolver, which may ask the target's own name servers.
3. **AI prompts, only in cloud or hybrid mode.** With `--ai off`, `--ai local`, or `--ai auto` with a local model,
   nothing from the AI layer leaves the machine. `--ai cloud` needs an explicit choice and a consent prompt, and every
   outgoing request is recorded in the report; `--redact` pseudonymises apex domains, addresses and organisation names.
4. Nothing else: no telemetry, no analytics, no upload of reports. The tool has no phone-home.

What it does not hide: the sources see your IP address unless you send the traffic through a proxy
(`SCRUTATOR_PROXY` or `--proxy`, `http://`, `socks5://` or `socks5h://`), and **DNS is never proxied**: it goes to your
system resolver. For a stronger guarantee run the whole process behind a network path you trust. See
[operational security](use-cases.md#operational-security-what-the-tool-does-on-the-network).

## Why do some sources fail?

Public services go down, rate-limit and change. crt.sh's web search often answers HTTP 502 (Scrutator then asks its
public database, which is slower); HackerTarget allows 50 calls a day per IP address, shared with everything else you
run; CertSpotter limits unauthenticated use. A source that times out or answers 5xx/429 three times in a row is marked
**down** for the rest of the scan.

A failure is never turned into a negative. The report lists every failed source under *Source coverage*, `scrutator
sources` shows how each fared last time, and the summary line says how many runs failed. On a busy day recall drops
because sources were unavailable, not because the names do not exist: the benchmark documents show recall differing by
a source's availability alone ([r6](benchmarks/r6.md)).

## Why does it list so few names (or so many "claimed" ones)?

Passive recall is limited by what the passive sources have seen. On `zonetransfer.me`, whose full zone is published
(31 names), Scrutator found 4 and the best competitor 2; names that no certificate, archive or aggregator holds are not
found passively. And aggregators list names that never resolved, so `example.com` shows `2 verified, 498 claimed`. The
claimed names are not deleted: they stay in the evidence, with the reason they are only claims.

## How do I add a source or a knowledge pack?

- **A knowledge-pack entry** (a provider fingerprint, a takeover fingerprint, a playbook) is one YAML entry in
  `src/scrutator/packs/data/` plus one fixture. No code. [Writing a knowledge pack](knowledge-packs.md);
  `scrutator packs validate` must pass.
- **A source** is one file in `src/scrutator/modules/`: a `Module` subclass with a name, the entity kinds it accepts and
  an async `run` that returns observations with their raw evidence. Add its host to `egress.SOURCE_HOSTS`, document its
  terms in [sources](sources.md), and write contract tests on a recorded response, including a hostile one. A source
  whose terms forbid automated use, or that needs scraping, will not be merged. [Writing a module](writing-a-module.md);
  the issue form "New source proposal" has the terms checklist.
- Your own pack directory works too: `scrutator scan --packs DIR`. The bundle then records that user packs were used,
  and `verify` warns that it cannot compare them with a trusted copy.

## How do I verify a report someone sent me?

You need the `.scrutator` file and the sender's public key (`signing.pub`) or its fingerprint **from a channel you
trust**, not from the same message as the bundle.

```bash
scrutator verify their.scrutator --pin their-signing.pub
```

Exit status 0 means all nineteen checks passed; 1 means a named check failed, and the output says which. Without
`--pin`, `verify` warns: a signature alone proves only that the bundle matches the key inside it, and anyone can sign a
forged bundle with their own key. For a deeper check, `--replay` re-asks the sources and reports each record as
unchanged, changed or unavailable (drift is information, not failure).

For a client audit (`audit.html`), also run `scrutator audit-check audit.html proof.scrutator --pin signing.pub`: it
fails if a number, finding or sentence does not follow from the bundle, or the page was edited.

What a pass means and does not mean: [proof bundles](proof-bundles.md#what-a-valid-signature-proves-and-what-it-does-not).
In short, integrity and consistency yes; truth of the sources no; the time it was made no.

## Can I use it from an AI assistant?

Yes: `scrutator mcp` serves it over MCP (stdio) with read-only tools by default (`list_candidates`, `attribution`,
`risk`, `verify_bundle`). `scan` and `promote_candidate` exist only if you start the server with `--allow-scan` or
`--allow-promote`, and a scan can only touch what your scope file allows. It has been tested with raw JSON-RPC over
stdio, not with Claude Desktop itself. [MCP](mcp.md).

## Does it need an account, a key or a cloud service?

No. The default sources are keyless, signing keys are made locally, and AI is optional and local-first. Three optional
sources (VirusTotal, SecurityTrails, Shodan DNS) use API keys you hold, read only from environment variables; they are
implemented against the documented APIs but have not been tested against the real services.

## Is it a vulnerability scanner?

No. It does not scan ports, test credentials or exploit anything. It reports configuration visible in public records
(a dangling CNAME, a weak SPF record, a missing CAA record) as leads for the owner to confirm. Use it for recon and for
evidence, and use a scanner or a person for testing, under authorisation.

## Who can I ask?

Questions and ideas: open a GitHub issue. Bugs: the issue forms ask for the version, the command and an
evidence id or a minimal bundle. Security problems: [SECURITY.md](../SECURITY.md), through GitHub's private vulnerability
reporting, never a public issue. Contributing: [CONTRIBUTING.md](../CONTRIBUTING.md).
