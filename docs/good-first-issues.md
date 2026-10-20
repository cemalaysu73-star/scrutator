# Good first issues

These are real, small, checkable pieces of work. The repository has no issue tracker yet; when it does, each of these
becomes a labelled `good first issue`. Every one has a clear definition of done, and the first three are data, not code.

| # | Task | Done when |
|---|---|---|
| 1 | **Verify a provider entry.** 54 of the 68 entries in `src/scrutator/packs/data/providers.yaml` are `verified: false`: widely known patterns that nobody has re-checked against the vendor's own documentation. Pick one, open its `source`, confirm the name-server / MX / CNAME / AS patterns, fix what is wrong, set `verified: true`, and put the exact documentation URL in `source`. | `scrutator packs validate` passes; `python -m pytest tests/test_packs_bundled.py` passes; the manifest is refreshed (`scrutator packs manifest src/scrutator/packs/data`) |
| 2 | **Check the one unverified takeover entry** (`github-pages-takeover`). Decide from the community fingerprint list whether `edge-case` and `http-fingerprint` are right, and say so in `note`. | the entry is `verified: true` with a note, or removed with a reason |
| 3 | **Review a playbook.** The 7 playbooks in `playbooks.yaml` were written for Scrutator and are all `verified: false`. Read one against its `source` and the situation it names (`src/scrutator/agent/playbooks.py`); tighten the steps or mark it verified. | the playbook's steps are accurate and each is one sentence of at most 200 characters |
| 4 | **Add a provider that is missing.** Cloud DNS, mail and CDN providers outside the list. One entry with `examples` (the validator runs them) and a source URL. | `scrutator packs validate` passes |
| 5 | **A hostile case for a module.** Pick a module and add a test with a realistic hostile answer it does not yet get (a list where an object is expected, a 2 MB name, a name with a right-to-left override). `tests/test_hostile_data.py` already covers every module with 30 bodies; this is for answers specific to one source's format. | the test fails on a deliberately broken parser and passes on the real one |
| 6 | **Windows key permissions.** On POSIX `keygen` writes the key `0600` and reports a readable one; on Windows the tool sets and checks nothing. Use `icacls` (or the `pywin32`-free route you prefer) to restrict the key file to the current user and report when it is broader. | the limit in `docs/security.md` and `docs/proof-bundles.md` is lifted, with a test that skips off Windows |
| 7 | **Wildcard probes below a delegated sub-zone.** The probe covers the apex only (`docs/security.md`). A zone `a.example.com` with its own wildcard makes every name under it look live. Probe each in-scope delegated zone that DNS evidence shows. | a lab fixture with a sub-zone wildcard puts those names in the `wildcard` tier |
| 8 | **A second opinion on a source's terms.** `mnemonic`'s terms of use could not be retrieved when the module was written (`docs/sources.md`). Find them, quote what they say about automated use, and update the table or propose removing the source. | the row says what the terms say, with a link |

Start with [CONTRIBUTING.md](../CONTRIBUTING.md). Questions about scope, passive-only rules or what will not be merged
(active scanning, people search, anything that scrapes against a service's terms) are answered there.
