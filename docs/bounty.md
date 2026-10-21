# Bug-bounty mode: `scrutator bounty import` and `bounty watch`

For hunters who want to know, before others do, when a programme's scope grows a new asset or a takeover candidate,
and who want every alert to come with the records that prove it. Passive only: Scrutator asks public sources and
ordinary DNS; it never probes, scans or claims anything.

Speed and source count are not where Scrutator leads: established recon tools ask more sources, faster. What it adds
is that each alert carries the evidence records it rests on (and, with `--key-dir`, a signed bundle), and a
ready-to-paste report draft for takeover candidates.

## 1. Import the scope

```bash
scrutator bounty import scope.csv --program "Example" --out bounty-scope.yaml      # HackerOne scope CSV export
scrutator bounty import targets.json --out bounty-scope.yaml                       # Bugcrowd target groups or bounty-targets JSON
scrutator bounty import - --out bounty-scope.yaml < scope.txt                      # a plain list, pasted
```

Plain lists: one entry per line, `#` comments, `In scope:` / `Out of scope:` section headers (also `Kapsam` /
`Kapsam dışı`), `!host` or `-host` to exclude a single entry, `- ` / `* ` bullets.

**Deny by default.** A host is in scope only when an include rule matches it and no exclude rule does; exclusions win.
`*.example.com` does not include `example.com` itself (list it if the programme does); an excluded `*.dev.example.com`
also excludes `dev.example.com`. Refused, and listed in the output and the scope file:

- `*` alone, `*.*`, wildcards over a public suffix (`*.com`, `*.com.tr`, `*.co.uk`), a wildcard that is not the leftmost
  whole label (`api.*.example.com`, `example.*`, `*example.com`);
- schemes other than http(s)/ws(s) (`javascript:`, `data:`, `file:`, `ftp:`), URLs with user info
  (`https://example.com@evil.test` is evil.test), control and bidirectional-override characters, invalid names;
- private or reserved address ranges, ranges wider than /8 (IPv4) or /32 (IPv6);
- files over 5 MiB or 50,000 lines, more than 5,000 rules.

Non-ASCII names are normalised with IDNA (`example。com` becomes `example.com`) and noted so you can check it is the
name the programme means. Path-level rules (`https://example.com/blog` out of scope) cannot be expressed by a
DNS-level tool: they are kept as notes and the host stays in scope. The public-suffix check is a short built-in list,
not the full Public Suffix List: read the refused list.

## 2. Watch it

```bash
scrutator bounty watch --scope bounty-scope.yaml --out bounty-watch --every 6h
scrutator bounty watch --scope bounty-scope.yaml --every 6h --webhook https://hooks.example.com/x --key-dir keys
scrutator bounty watch --scope bounty-scope.yaml --max-runs 1 --json
```

Each round runs a passive scan per root (every wildcard base, and each listed host not under one): the name sources,
DNS with the wildcard probe, and Shodan's InternetDB for the addresses (`--no-noncommercial` leaves it and the other
non-commercial free tiers out). The **first round is the baseline** and announces nothing. After it, only what is new
and in scope is announced, **once**:

| Alert | When |
|---|---|
| `new_name` | an in-scope name is newly verified (DNS resolves it, or a recent certificate names it) |
| `new_takeover` | a new dangling-CNAME finding (the takeover rules of the knowledge pack) |
| `resolved_risk` | a takeover candidate went away |
| `new_cert` | a certificate (crt.sh or CertSpotter id) names an in-scope host for the first time |
| `new_service` | InternetDB lists a port not seen before on an address an in-scope name resolves to |

An alert is remembered in `monitor-state.json` and not repeated; it is announced again only if the thing went away and
came back. Out-of-scope and excluded names are never announced, whatever the sources return. Output: the terminal,
`alerts-<time>.json`, `--json`, and `--webhook` (https, or http only to localhost; redirects are not followed).

## 3. Finding drafts

Every `new_takeover` alert writes `findings/risk-<fingerprint>.md`: the asset, the evidence records with their ids,
source, request and collection time and an excerpt, the DNS commands to reproduce by hand (`dig +short CNAME ...`),
`scrutator verify <bundle> --pin <key>` when the round was signed, the impact, and a reminder: **confirm under the
programme's rules before reporting, and never register or claim the resource unless the programme explicitly allows a
proof of concept.** Re-rate the severity under the programme's own policy; the draft's severity is the rule's.
