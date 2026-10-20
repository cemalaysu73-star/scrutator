# Security model and known limits

Scrutator reads data that anyone can write (a DNS TXT record, a certificate name, an RDAP remark, a proof bundle from
a stranger) and makes claims that others will rely on. The threat model is therefore: **every payload from a source is
attacker-influenced, every bundle is untrusted input, and a language model may be wrong or may obey planted text.**
This page lists what is guaranteed, where it is tested, and what is not guaranteed. It is written for people who will
try to break it; the way to report a break is [SECURITY.md](../SECURITY.md).

Two things are *not* in the threat model: a compromised machine (whoever can run code as you can read your signing key
and your database), and the sources' own integrity (a service that lies produces a lie that is faithfully recorded).

## Guarantees and where they are tested

| Guarantee | How | Tested in |
|---|---|---|
| **Out-of-scope names are never queried.** A name found through a CNAME, a certificate or an aggregator is recorded as `out`; the wildcard probe is a child of an in-scope apex; MCP `scan` seeds that are look-alikes, have userinfo, fragments, NUL bytes, or an IP outside the scope are refused before any lookup. | the engine classifies every entity before any module runs on it | scope fuzz tests, `tests/test_planted_lab.py`, `tests/test_mcp_tools.py`, the scope-safety section of `scrutator bench` (523 DNS questions and 273 requests of the lab scans, 0 outside the scope) |
| **The HTTP client reaches only source hosts.** `https`, port 443, a host name (no IP literal, no userinfo), on the source list; redirects are refused except RDAP referrals, which must resolve to public addresses. A URL a source hands back (Common Crawl's index list) is not trusted. Webhooks never follow redirects. `verify --replay` uses the same guard and looks up only DNS names inside the bundle's own scope. | `egress.EgressGuard` on the module and replay client | `tests/test_egress.py` |
| **No secret reaches an output.** Source API keys come only from `SCRUTATOR_*_KEY` variables, are never stored, and are redacted from request logs and error text. | `scrutator.keys` | `tests/test_secrets_canary.py`: a canary in all three variables, a scan through the MCP tool layer, and a search of logs, results, report JSON, HTML, every bundle member, the database, the audit log, `sources` output and `verify` output |
| **Source text cannot execute.** HTML: all text is placed with `textContent`; the data block escapes `<`; the only scripts are the template's two. Terminal: every line goes through a filter that shows control and bidirectional characters escaped. JSON and SARIF are `json.dumps`. Entities drop control and bidirectional characters at the model layer. There is no CSV output. | | `tests/test_hostile_data.py`: 30 hostile bodies through every HTTP module, then the report, JSON, SARIF and HTML |
| **A claim without evidence cannot exist.** Findings, risks, leads and statements carry evidence ids; the report builder refuses otherwise. | the model layer | the risk, lab and verifier tests; the bench's `risks_without_evidence = 0` |
| **A bundle that was altered fails verification**, in a named check; `verify` fails closed (a failed check, not a traceback) on hostile JSON, wrong types, depth bombs, zip bombs, traversal names, duplicate members, symlinks, encrypted members, signature/key confusion. | [proof bundles](proof-bundles.md) | `tests/test_bundle*.py`, `tests/test_bundle_reader_limits.py`, the 10 tamper cases of `scrutator bench` |
| **Bounded reading of untrusted bundles**: sizes are checked from the declared header before inflating (a 200 KiB zip bomb: refused in under 2 s, under 16 MB of memory). | `bundle/reader.py` | `tests/test_bundle_reader_limits.py` |
| **Prompt injection cannot add facts.** Text from sources is fenced as untrusted data for models; a deterministic floor drops statements that name anything the cited facts do not, assert an alarm word or a negation they do not, or repeat a raw record's prose; a verifier checks the rest; nothing is published without one. | [AI and privacy](ai-and-privacy.md) | `tests/test_injection_guard.py` (a writer, planner and verifier that all obey the planted text), the Hallucination Test |
| **Interrupted and parallel scans leave a consistent database.** Ctrl-C in the middle of a lookup's write batch rolls that batch back; the audit chain verifies; the partial bundle verifies; two scans in parallel on one database file both finish (busy timeout 30 s). A damaged or locked database is a one-line error with what to do. | one transaction per lookup | `tests/test_robustness_r4.py` |
| **The opt-in modules reach only the scope and the platforms they may ask.** `scan --brand` and `scrutator exposure` use a separate client: in-scope hosts that resolve to public addresses, the hosts of the platforms whose profile page tells existence by status (brand), `rdap.org` and `api.github.com` for the engagement's own GitHub organisations (exposure). No automatic redirects; robots.txt honoured (unreadable = disallow); one request a second per host. | `scrutator.web.WebGuard` | `tests/test_brand.py`, `tests/test_org_exposure.py` (every request and DNS question of the lab runs checked against the allowed set) |
| **Organisation exposure stores no personal address and needs an engagement.** Without a valid engagement file, with a person as the seed, or with a domain outside the engagement, nothing is looked up. Person-like addresses are reduced to a shape and a one-run pseudonym before storage; the database, report, HTML and bundle are scanned for every planted name, address, phone number and place in the lab: none appears. `--detail` writes a separate file and an audit record. | `scrutator/orgexposure.py`, `scrutator/engagement.py` | `tests/test_org_exposure.py` |
| **Private signing keys can be encrypted at rest** (scrypt + ChaCha20-Poly1305; passphrase never an argument). | [proof bundles](proof-bundles.md#keys) | `tests/test_key_at_rest.py` |

## Known limits

Stated plainly, because a security claim is only as good as the list of what it does not cover.

**Evidence and trust**

- **A bundle proves integrity and consistency, not truth and not time.** There is no trusted timestamp (RFC 3161):
  `created_at` and `collected_at` come from the signer's clock, and a signer can back-date. A signature proves only that
  the bundle matches the key in it; without `--pin`, anyone can sign a forged bundle with their own key.
- Evidence is what a source *said*. If crt.sh, an aggregator or a DNS server lied, the bundle contains the lie.
  DNSSEC is requested (the DO bit, to see compact denial of existence) but **not validated**; answers from a resolver on
  a hostile network can be forged.
- Confidence counts agreeing sources; two sources that copy each other count as two.
- Pack entries you add yourself cannot be checked by `verify` against a trusted copy; the signer vouches for them.

**Egress**

- A source host on the list could itself be compromised or change hands. The list is short and in the code
  (`egress.SOURCE_HOSTS`).
- The address of an RDAP server a redirect led to is checked once per scan, before its first request: a name that changes
  its answer between the check and the connection, or later in the scan (DNS rebinding), is not caught.
- DNS questions go to your configured resolver, which asks the target's own name servers when it has no cached answer.
  A passive scan therefore reaches the target's authoritative DNS, as any lookup of its names does.
- Webhook URLs and scope files come from you and are trusted (a webhook to an internal address is your choice).

**AI**

- The deterministic floor is a list: a judgement expressed with words it does not know, and an invention that uses
  only known names and plain words ("www.example.com serves a legacy application"), pass it. The verifier model is the
  only line for those, and models can be talked into things. The Hallucination Test reports the class that survives an
  obedient verifier, and the measured result for one real local model, one run; `scrutator ai doctor` measures yours.
- The bench's gated row uses a mechanical stand-in verifier, not a language model, so it shows the pipeline does its
  job when the verifier does its job.
- In cloud mode a summary of what was found leaves your machine; `--redact` pseudonymises names, addresses and
  organisations but not what can be inferred from structure.

**Opt-in modules**

- Brand presence reads the HTTP status of a public profile page and nothing else. A suspended or renamed account can
  answer like a missing one; a platform can change its behaviour at any time (each entry records what was observed on
  2026-10-20 from one network). Both brand risks are therefore low confidence.
- Organisation exposure has **not had the legal and ethics review** the design requires before release; it is a
  preview. Work addresses are personal data in many jurisdictions (the GDPR among them), even minimised. The
  `exposure-detail.json` file written by `--detail` holds work addresses in clear text and is not encrypted (owner-only
  permissions on POSIX; none set on Windows). The report and the audit log name the person who authorised the
  engagement, by design. Role mailboxes are shown as they are. There is no `purge` command yet: nothing personal is
  stored outside the detail file, which you delete like any file.
- The classification of a mailbox as a role or a person is a word list: a person whose address is a role word
  (`office@`) is counted as a role, and an unusual role mailbox as a person.

**Keys and files**

- On Windows the tool does not set or check file ACLs: the signing key inherits the folder's access rules. An unencrypted
  key can be read by anyone who can read the file; use `--passphrase`.
- The SQLite database, report and bundle are not encrypted. They contain what the sources returned, including
  organisation names and abuse contacts from RDAP. Handle them like the personal data they may contain.
- The HTML report embeds all evidence payloads in one file; sharing the report shares them.

**Scale and robustness**

- A scan records at most `--max-entities` (default 5000) entities; past the cap, names are counted, not recorded, and
  the report says how many were dropped. Larger caps cost memory and time linearly (see below). The bundle writer
  refuses a scan larger than the verifier would read.
- The wildcard probe covers the apex only, not wildcards below a delegated sub-zone.
- Name tiers depend on DNS at one moment: a name that resolves tomorrow stays claimed in today's report.

**Supply chain and release**

- The package is not published; there are no signed releases and no SBOM yet. Dependencies are lower-bounded, not pinned
  (`httpx`, `pydantic`, `typer`, `dnspython`, `pyyaml`, `cryptography`, optionally `mcp`).
- The keyed sources (VirusTotal, SecurityTrails, Shodan DNS) were implemented against documentation and have never run
  against the real services. The MCP server has been exercised with raw JSON-RPC, not with Claude Desktop.

## Resource limits

What a very wide scan costs, measured offline with `python bench/profile_wide.py N --max-entities M`: one fake crt.sh
answer that names N hosts under example.com, a fake resolver (everything NXDOMAIN but two names), the real engine,
store, report builder, HTML renderer, bundle writer and verifier. `tracemalloc` is on during the run, so the times are
roughly twice those of a plain run; memory is the peak of Python allocations, not the process size. One machine
(Windows 11, Python 3.11), one run each, 2026-10-20.

| Names (cap) | Collect | Build report | JSON + HTML | Bundle | Verify | Peak traced memory | report.json | Bundle |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 5,000 (5,000, the default) | 5.0 s | 7.9 s | 3.2 s | 11.1 s | 10.1 s | 79 MB | 7.8 MB | |
| 20,000 (60,000) | 16.5 s | 30.5 s | 12.2 s | 42.3 s | 36.3 s | 311 MB | 31 MB | 5.2 MB |
| 50,000 (60,000), 2026-10-21 | 969 s | 99 s | 40 s | 134 s | 103 s (passes) | 1,210 MB | 128 MB (HTML 107 MB) | 29.6 MB |

At 50,000 names the collection phase dominates (16 minutes with tracing on); the bundle
verifies, inside the reader's limits. The memory column is the largest phase peak. A scan of that width is far
outside the default cap; the HTML report at that size is too large for a browser to be pleasant.

Time and memory grow linearly with the number of names (a cProfile of the report builder at 5,000 names shows no
quadratic step). The limits that bound a hostile or huge input:

| Limit | Value | Where |
|---|---|---|
| Entities a scan records | `--max-entities`, default 5,000; past it names are counted, not recorded | `engine.py` |
| Bundle members | 5 expected, 16 read at most; manifest 1 MiB; signature 4 KiB; each data file 256 MiB; all members 512 MiB; the file on disk 512 MiB | `bundle/reader.py` |
| Bundle writer | refuses a scan whose bundle the reader would refuse | `bundle/writer.py` |
| Replay | 20,000 records and 2,000 distinct HTTP requests (`--replay-limit`) | `bundle/replay.py` |
| One scan | `--deadline`, default 600 s; `--breaker`, default 3 failures in a row | `scan.py`, `engine.py` |
