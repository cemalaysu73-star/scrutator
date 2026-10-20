# Writing a knowledge pack

Everything the tool knows about the world that is not code is YAML in `src/scrutator/packs/data/`, shipped inside the
package and validated by a schema in which **unknown keys are errors**, so a typo fails loudly instead of silently
matching nothing. Adding a provider is one data entry and one fixture, no code.

| File (`kind`) | What it holds | Used by |
|---|---|---|
| `providers.yaml` (`providers`) | name server, mail, CDN, hosting and certificate-authority patterns, AS numbers | the dependency map; risk rules (concentration); attribution (a shared provider's signals count 0) |
| `takeover.yaml` (`takeover`) | services whose names can be claimed when a CNAME to them dangles | `dangling-cname-*` risks |
| `signals.yaml` (`signals`) | how often an attribution signal shows up in unrelated organisations (empty: no measured corpus exists) | attribution weights |
| `playbooks.yaml` (`playbooks`) | short recipes offered to the agent's planner by the situation of the investigation | the planner only; no result depends on them |

```bash
scrutator packs list                      # the files in use, versions, entry counts
scrutator packs validate                  # schema, manifest and examples of the bundled packs
scrutator packs validate my-packs/        # the same for your directory
scrutator scan example.com --packs my-packs/    # extend or override the bundled data
scrutator risk 3 --packs my-packs/        # re-evaluate an old scan with newer knowledge
```

## A provider

Put a file like this in a directory and pass it with `--packs`:

```yaml
schema: 1
kind: providers
version: 2026.10.1          # calendar version: YYYY.M.N
updated: 2026-10-16
entries:
  - id: acme-dns            # lower case, digits, hyphens; the same id as a bundled entry replaces it
    provider: Acme DNS
    category: dns           # dns | mail | cdn | hosting | ca
    ns: [dns.acme.example]  # host suffixes; one label may contain * (matches inside that label only)
    examples: [ns1.dns.acme.example]   # values this entry must match: the fixture
    source: "https://docs.acme.example/nameservers"   # an https URL
    verified: false         # true only once you checked the patterns against the source
```

Which patterns an entry may use depends on its category: `dns` uses `ns`; `mail` uses `mx` and `spf`; `cdn` and
`hosting` use `cname` and `asn`; `ca` uses `issuer` (at least four characters, matched case-insensitively). An entry
needs at least one pattern. The validator runs every entry against its own `examples`, and the test suite does the
same for the bundled packs, so a pattern that matches nothing it claims to match fails in review.

## A takeover fingerprint

```yaml
  - {id: acme-pages, provider: Acme Pages, cname: [pages.acme.example], status: vulnerable,
     dangling: nxdomain, examples: [demo.pages.acme.example],
     source: "https://github.com/EdOverflow/can-i-take-over-xyz", verified: true}
```

`status` is `vulnerable` or `edge-case`; `dangling` is how the dangling state shows: `nxdomain` (the target name does
not exist: a passive lookup can see it) or `http-fingerprint` (the name resolves but the service shows an "unclaimed"
page, which needs an active probe that passive mode never makes; such a service is reported only when its target also
fails to resolve). Bundled entries come only from the community project can-i-take-over-xyz.

## A playbook

```yaml
  - id: dangling-alias
    title: An alias points outside the scope
    when: [cname_out]          # situations that must all hold; the graph decides each (agent/playbooks.py)
    steps:                     # up to 6 sentences of at most 200 characters
      - "Look up the address records of the alias target itself."
    prefer: [dns]              # modules the recipe is about
    source: "https://..."
    verified: false
```

Situations: `cname_out`, `san_cohabitants`, `mail`, `delegated`, `ip_without_network`, `candidates`, `spf_includes`.
A playbook can change the order in which the planner ranks lookups, never the options it can choose from, and never the
scope. Playbooks are procedures written for Scrutator; the bundled ones are all `verified: false` and their `source`
is background reading.

## Rules

- `verified: true` means a maintainer checked the patterns against the cited `source`. Entries marked `false` stay
  visible so they can be checked; the dependency map says so.
- A pack the scan used is recorded with the scan and travels inside the proof bundle. `verify` checks the bundled
  packs against its own copy (`packs intact`), so a bundle cannot quietly drop a fingerprint. Entries you added
  yourself cannot be checked against a trusted copy; `verify` says so and the signer vouches for them.
- Never invent a number. `signals.yaml` ships empty because nobody has measured how common each signal is; a made-up
  frequency would make attribution look calibrated when it is not.

## Changing the bundled packs

Edit the YAML in `src/scrutator/packs/data`, run `scrutator packs manifest src/scrutator/packs/data` to refresh the
sha256 manifest, run `python -m pytest`, and open a pull request. A good first issue is a provider entry with a
source URL.
