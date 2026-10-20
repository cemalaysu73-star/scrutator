# Demo: scan, check the evidence, catch a made-up claim, tamper with a bundle

A two-minute tour of what is different about Scrutator. It follows the 60-second demo in the design: scan, follow a
finding to its raw evidence, watch a model's invented claims get rejected, export a signed proof bundle, change it, and
watch `scrutator verify` fail.

```bash
pip install -e .                       # from the repository root (or install the wheel)
python demo/run_demo.py                # offline: a planted fixture zone, no network, about 30 seconds
python demo/run_demo.py --live         # the same on example.com: passive, public sources only, about 40 seconds
python demo/run_demo.py --model qwen3:8b       # also let a local Ollama model play the verifier in step 3
python demo/run_demo.py --transcript my-run.txt    # keep everything printed
```

The demo writes to `demo-out/` (ignored by git): `report.html`, `report.json`, `scrutator.db`, `proof.scrutator`, a
throwaway signing key. Open `demo-out/offline/report.html` in a browser and click a risk to see the raw record.

## What is real and what is a fixture

| Step | Offline | `--live` |
|---|---|---|
| 1. Scan | The real engine, report builder and modules, run in this process against a **planted lab zone**: a fake resolver and recorded answers of the public sources (`src/scrutator/benchlab/risklab.py`: 22 planted issues, such as a dangling CNAME at a claimable service, a weak SPF record, a forgotten staging host). The command line scans the real network, so it cannot be pointed at a fixture. | The real command line against `example.com`: `scrutator scan example.com --ai off --bundle`. It asks certificate transparency, DNS, RDAP, the archives and the aggregators in [docs/sources.md](../docs/sources.md); it never contacts example.com's own servers beyond DNS. |
| 2. Follow a claim | Prints the most severe risk and the raw record it cites. | Same, from the real report. |
| 3. Made-up claims | A **scripted writer** proposes 18 statements about a tiny scan, 12 of them invented (an invented host, address, port, CVE id or date; a planted instruction in a TXT record obeyed; a negation; an overclaim). The deterministic grounding check and a verifier decide what is published. Without `--model` the verifier is a **mechanical stand-in, not a language model**; with `--model` it is a model on your machine (loopback only). | Same. |
| 4. Export | The real `scrutator keygen` and `scrutator export`. | The scan already wrote the bundle. |
| 5-6. Verify, tamper | The real `scrutator verify` on the real bundle and on three altered copies. | Same. |

## What the tamper step shows

- **A.** One bit flipped in `report.json`: `file hashes` and `findings derivable` fail.
- **B.** A forger deletes a risk, rebuilds every file hash and re-signs with their own key: caught even without a pin,
  because `verify` recomputes the risks from the evidence (`risks derivable`, `analysis recorded`).
- **C.** A different but internally consistent bundle signed by another key: **every check passes** unless you pin the
  signer's key. Without `--pin`, `verify` passes with a warning; with `--pin`, it fails. This is the case where the
  signature alone proves nothing, and why [proof bundles](../docs/proof-bundles.md) tell readers to pin.

The "bundle includes user packs" warning in the offline run is because the lab zone ships its own small knowledge
pack; the real scan has no such warning.

## Transcripts

Recorded from real runs of the script on 2026-10-20 (nothing edited by hand; the working folder is shown as
`demo-out`):

| File | Run |
|---|---|
| [transcripts/offline.txt](transcripts/offline.txt) | `python demo/run_demo.py` (31 s) |
| [transcripts/offline-local-model.txt](transcripts/offline-local-model.txt) | `python demo/run_demo.py --model srchmnmichael/qwen3.5-9B-uncensored:latest` (88 s): step 3 with a 9B model on this machine as the verifier |
| [transcripts/live.txt](transcripts/live.txt) | `python demo/run_demo.py --live` (39 s): example.com |

A live run depends on public services that are sometimes down or rate-limited; the report says which failed. Numbers
differ from run to run (the live transcript shows 498 claimed names where an earlier run showed 499).
