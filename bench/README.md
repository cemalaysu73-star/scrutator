# Scrutator benchmark

There are two benchmarks, and they answer different questions:

| | `scrutator bench` (OSINT-Bench v0) | `bench/run_bench.py` (this folder) |
|---|---|---|
| Question | does Scrutator do what it claims on planted ground truth: risks, attribution, name tiers, bundle tamper and replay, scope safety, unsupported statements | how does Scrutator's passive recall, precision and speed compare with other tools on real public targets |
| Network | none | yes: public sources and the competitors' own sources, from your network |
| Needs | `pip install scrutator` | Scrutator plus a venv with the competitors (below) |
| Deterministic | yes (the Hallucination Test with `--verifier-model` is not) | no: public sources change, fail and rate-limit |
| Third party can reproduce | all of it, in one command | the method, not the numbers: three of the four truth sets are pseudo-truth built from the tools' own output |
| Covered in | [docs/benchmarks.md](../docs/benchmarks.md) | below, and `docs/benchmarks/` |

A head-to-head, passive, keyless comparison of Scrutator with the subdomain/recon tools that can be
installed from PyPI without downloading executables. One command reproduces it.

The frozen targets and the bar are in `.cemal/PLAN.md`. The latest written reading is in
`docs/benchmarks/`.

## Targets

| Target | Truth |
|---|---|
| `zonetransfer.me` | Its zone, from one AXFR against the published test name server `nsztm1.digi.ninja` (the zone exists for that purpose), cached in `results/<date>/zone.truth.txt` and not repeated unless `--refresh-axfr`. If the transfer does not complete from your network (it timed out from the network used for the 2026-10-17 baseline, which left `axfr.failed.txt`), the harness falls back to the dig AXFR dump the zone's author publishes on `digi.ninja/projects/zonetransferme.php` and records that source. |
| `example.com` | Pseudo-truth. |
| `nmap.org` | Pseudo-truth. |
| `owasp.org` | Pseudo-truth. |

Pseudo-truth = the union of in-scope hostnames reported by any tool in the run that still resolve
(A/AAAA, CNAMEs followed) at run time. It is a lower bound of the real name set. Recall against it
only says how much of what the tools collectively saw each tool saw; it cannot reward a name nobody
found. Precision against it equals the live share of a tool's output.

`run_bench.py` refuses any target that is not in its `TARGETS` table. Nothing brute forces, scans
ports, crawls or needs an account or key.

## Tools

| Tool | How it is run | Why this way |
|---|---|---|
| Scrutator | `scrutator scan <t> --out ... --format json --ai off --no-summary --bundle --key-dir bench/work/keys` then `scrutator verify proof.scrutator --pin signing.pub` (no `--replay`) | AI off: the benchmark measures deterministic collection. Everything else is default. |
| sublist3r 1.0 | `sublist3r -d <t> -n -o out.txt` | No `-b` (brute force), no `-p` (port scan). Default search-engine and web sources. |
| dnsrecon 0.10.1 | `dnsrecon -d <t> -t crt --disable_check_recursion --disable_check_bindversion -j out.json` | Only the crt.sh type. `std` (SRV guessing), `axfr`, `brt` are active; the recursion and BIND-version probes hit the target's own name servers. |
| knockpy 9.0.0 | `python bench/adapters/knock_recon.py <t>` (its `Recon` class, default settings) | `knockpy --recon` also attempts AXFR and HTTP-probes every found host. The adapter calls only the passive collector. |

Not run, because they need a binary or a git download that needs the user's approval: subfinder,
Amass, SpiderFoot, theHarvester (the PyPI name `theHarvester` is an unrelated placeholder).

## Setup

```
python -m venv %USERPROFILE%\bench-venv
%USERPROFILE%\bench-venv\Scripts\python -m pip install dnsrecon sublist3r knock-subdomains
```

The harness itself needs Python with `dnspython` and the `scrutator` executable, for example the
Scrutator development venv (`pip install -e .`). The competitor venv is separate on purpose.

## Run

```
python bench/run_bench.py                         # today's date, all targets, all tools
python bench/run_bench.py --date 2026-10-17       # fixed results folder
python bench/run_bench.py --targets example.com --tools scrutator knockpy
python bench/run_bench.py --timeout 900 --bench-venv D:\venvs\bench --scrutator D:\venvs\s\Scripts\scrutator.exe
```

Re-score or re-run a subset without repeating everything:

```
python bench/run_bench.py --date X --reuse-from bench/results/Y --rerun scrutator --targets owasp.org --timeout 3600
python bench/summarize_runs.py RUN1 RUN2 RUN3          # run-to-run variance table
python bench/attribute_sources.py --date 2026-10-17    # which sublist3r engine / knockpy service gave which names (owasp.org)
```

Defaults: 900 s per tool run, bench venv at `~/bench-venv` (or `$BENCH_VENV`), Scrutator found next
to the Python that runs the harness.

## What it measures

Per target and tool: names found (in scope, apex excluded), then each name classed as live
(resolves, A/AAAA with CNAMEs followed, to something other than the apex wildcard), wildcard-covered
(resolves only to the address a random label also resolves to, so its existence is unproven), or
stale (NXDOMAIN/no address). Recall against the truth; precision (zone target: share inside the
zone; pseudo-truth targets: live share of the names that can be judged, i.e. excluding
wildcard-covered); names unique to the tool (and unique live); wall time.

Scrutator only (v0.6): its own resolution state for each name (live, stale, wildcard-covered,
unresolved), cross-checked against the harness's resolver: names it marks live that are live here,
names it marks live that are not, and live names it did not mark live. This is the check that
Scrutator knows which of the names it reports are hosts.

Scrutator only: share of reported hostnames backed by at least one evidence record cited by an edge,
finding or risk; the stricter share where the cited evidence actually contains the hostname;
findings; risks; evidence records; sources that failed; `scrutator verify --pin` on the bundle; a
tamper test (one byte of `evidence.jsonl` flipped in a copy must fail verification).

## Output

`results/<date>/`: `results.json`, `tables.md`, `resolution.json` (live/stale per name),
`zone.truth.txt`, and per target the exact command, truncated stdout/stderr and normalised name list
of each tool, plus `scrutator.summary.json`. Full Scrutator reports and databases stay in
`bench/work/` (ignored by git), as do bundles and signing keys. Folders starting with `_` under
`results/` are scratch and ignored.

## Caveats

- Free public sources have per-IP quotas that this harness spends. HackerTarget allows 50 calls a day
  per IP address, shared by Scrutator's `hackertarget` module and knockpy's `hackertarget` service,
  and CertSpotter allows about ten unauthenticated calls: run the benchmark once a day from a given
  address, and read the per-source failures Scrutator reports before comparing two runs.

- The resolver view is a snapshot; names come and go between runs, so numbers move a little.
- The public sources are rate-limited and sometimes down (Common Crawl and the Wayback Machine
  time out often from some networks). Failed sources are reported, not hidden, and they affect
  both recall and Scrutator's wall time.
- Competitors are older or narrower than their GitHub namesakes in some cases (sublist3r 1.0 is
  from 2016). The best-known passive tools (subfinder, Amass) are not in this run.
