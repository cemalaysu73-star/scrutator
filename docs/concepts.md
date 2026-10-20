# Concepts

## Evidence

An **evidence record** is the raw answer of one source to one question, stored once and addressed by hash:

| Field | Meaning |
|---|---|
| `id` | sha256 of `source`, `request` and `payload`. Identical observations are stored once, and changing a byte changes the id. |
| `source` | the module that asked (`crtsh`, `dns`, `rdap`, ...) |
| `request` | what was asked, in a form that can be replayed: `GET https://crt.sh/?q=%25.example.com&output=json`, `DNS A www.example.com` |
| `payload` | the raw answer |
| `collected_at` | the clock of the machine that collected it |

Everything else is built on evidence:

- A **finding** is a claim ("www.example.com resolves to 192.0.2.10") with the ids of the evidence it rests on.
  A finding without evidence ids cannot be created. Its **confidence** is the number of distinct sources that agree:
  one is `low`, two `medium`, three or more `high`.
- A **risk** is a finding made by a deterministic rule (a dangling CNAME, a weak SPF record). Each cites evidence.
- **Absence is evidence.** "This name does not exist" (NXDOMAIN) and "this name has no such record" (NODATA) are
  stored like any answer, and a rule about a missing record rests on them. A timeout or a failed lookup is never
  stored as a negative: silence does not become a finding.
- The **audit log** is a hash chain of every module call (what was asked, what came back, how long it took). Removing
  or reordering a record breaks the chain.

An AI summary is built from findings, never from raw text: each statement cites finding numbers, a separate verifier
checks it against the evidence, and a deterministic check stands in front of the verifier
([AI modes](ai-and-privacy.md)).

## Scope

Scope is decided by the engine, deny by default, never by a prompt. By default it is the seed domain and its
subdomains. Anything else comes from a scope file:

```yaml
domains: [example.com]
cidrs: [203.0.113.0/24]
asns: [AS64500]
```

Every discovered entity is in one of four states:

| State | Meaning | May be queried? |
|---|---|---|
| `in` | inside the scope | yes, all passive lookups |
| `linked` | an address an in-scope name resolves to | passive lookups about it (network owner, ports as Shodan saw them) |
| `candidate` | outside the scope, but evidence ties it to the organisation ([attribution](#attribution)) | one round of passive DNS, registration and certificate lookups; nothing else until promoted |
| `out` | outside the scope | never. Recorded so that you can see it, but no module runs on it. |

A CNAME that points outside the scope, a name an aggregator lists, a host a certificate names: all are recorded as
`out` unless attribution selects them as candidates. Only the scope file defines what may be investigated; a
`candidate` becomes `in` only when a human runs `scrutator promote` (which writes the scope file and the audit log).

## Names are not hosts: resolution states

A certificate or an archive can name a host retired years ago, and an aggregator lists names that never resolved. So
every in-scope name carries a **resolution state** derived from the DNS evidence:

| State | Meaning |
|---|---|
| `live` | an A or AAAA answer was recorded |
| `stale` | the address lookup returned NXDOMAIN |
| `wildcard` | it resolves, but only to addresses that a random label under the same zone also resolves to (a probe recorded as evidence), so DNS does not prove the name exists |
| `unresolved` | no address and no NXDOMAIN was recorded (the name has no address record, or the lookup did not run or failed). Never read as a negative. |

## Name tiers

The state says what DNS said. The **tier** says how well the evidence supports "this name exists", and the number to
quote for a scan is *N verified, M claimed*:

| Tier | Meaning |
|---|---|
| `verified` | DNS resolves it, **or** a certificate (`crtsh`, `certspotter`) or a scan of the host (`urlscan`) timestamped within 90 days of collection names it, and DNS does not contradict it |
| `claimed` | only a list names it (an aggregator, an archive, `known_as` from InternetDB) and DNS shows no sign of it |
| `stale` | it was evidenced once (a certificate or scan, however old) and DNS no longer agrees |
| `wildcard` | only the zone's wildcard record answers for it and nothing dated vouches for it |

Nothing is deleted: every claim stays in the evidence store, the report and the bundle with the reason it is a
claim (`tier_reason`). What changes is what you see first. Only certificate validity and scan time vouch for a name;
a listing from an aggregator never does, whatever dates its payload carries. `verify` re-derives tiers, the tier of
every finding and the headline from the bundle's own evidence.

Why it matters: on `example.com`, one live name, an aggregator lists 499 more. v0.6 reported "499 names"; the same
evidence now reads "2 verified, 499 claimed" ([benchmark](benchmarks.md)).

## Knowledge packs

Everything the tool knows about the world that is not code is versioned, schema-validated YAML shipped in the
package: provider fingerprints (name server, mail, CDN, hosting and certificate-authority patterns, AS numbers),
takeover fingerprints (from the community project can-i-take-over-xyz), signal frequencies (empty: no measured
corpus exists yet) and pivot playbooks for the agent. A scan records the packs it used, and the proof bundle carries
them, so a report is always read with the knowledge it was made with. `verify` checks the bundled packs against its
own copy, so removing a takeover fingerprint and recomputing everything is still caught. Adding a provider is one
data entry and one fixture, no code: [writing a knowledge pack](knowledge-packs.md).

## Attribution

Some assets belong to an organisation without any name match: a sister domain, an acquired brand, a service run
under another name. Attribution (`scrutator scan --attribution`, `scrutator candidates`) looks for names **outside
your scope** that the evidence ties to the organisation, scores them and explains every score.

Ten signals, each computed from stored evidence only, each with a hand-chosen weight: the name is delegated to an
in-scope name server (0.90), its mail goes to an in-scope host (0.70), its SPF includes an in-scope name (0.60), one
certificate lists it with an in-scope name (0.60), the registrant organisation matches (0.60), and weaker ones
(shared name servers or mail host, network owner, being pointed at by the scope, certificate issuer). A signal that
points at a shared provider (a CDN, a public CA, a DNS operator the packs know) is kept in the output with weight 0
and the reason, so you can see what was ignored.

Independent signals combine as `1 - product(1 - weight)`. Bands: `confirmed` (0.90 or more from at least two kinds
of signal), `probable` (0.70), `possible` (0.35), `unlikely`. `probable` and `confirmed` need an **ownership
signal** (name-server delegation, mail, SPF or registrant): a shared certificate or network can just as well be a
partner's or a host's.

Every candidate comes with a **pre-mortem**: what in the evidence could make the attribution wrong. **The weights are
not calibrated to the real world.** The only measurement is a synthetic lab written by the author of the scoring
(see [benchmarks](benchmarks.md)); it shows the scoring behaves as designed on the cases its author thought of, not
how accurate it is on real organisations. A `candidate` is a lead, not a finding.
