# Example reports

Two reports you can open without running anything, each with its signed proof bundle and the signer's public key.
They are generated only from targets we may use: `example.com`, which is reserved for documentation, and a planted
fixture zone. No real third-party organisation appears in them.

| Folder | What it is | How it was made |
|---|---|---|
| [example.com/](example.com/) | A real passive scan of `example.com` on 2026-10-20: 2 verified names, 498 claimed, 2 low risks (no CAA record at the apex; all name servers belong to one provider), three sources failed and say so in *Source coverage* | `python demo/run_demo.py --live` ([transcript](../../demo/transcripts/live.txt)) |
| [audit/](audit/) | A client audit (`scrutator audit`) made from the lab-zone bundle: a fictional client ("Example Corp (fictional sample)"), a placeholder auditor, a sample engagement file; `audit.html`, `audit.pdf`, `technical-annex.html`, the bundle and the key, and the Turkish version in `audit/tr/`. Check it with `scrutator audit-check docs/examples/audit/audit.html docs/examples/audit/proof.scrutator --pin docs/examples/audit/signing.pub` | `scrutator audit --from-bundle docs/examples/lab-zone/proof.scrutator --engagement engagement.yaml --branding audit.yaml` |
| [lab-zone/](lab-zone/) | The planted lab zone: 22 planted issues (a dangling CNAME at a claimable service, weak SPF, a forgotten staging host, ...), run through the real engine against fake DNS and recorded answers | `python demo/run_demo.py` ([transcript](../../demo/transcripts/offline.txt)) |

Each folder holds `report.html` (open it in a browser; one self-contained file, click a finding or risk to see the raw
record), `proof.scrutator` and `signing.pub`. Verify a bundle yourself, pinning the signer:

```bash
scrutator verify docs/examples/example.com/proof.scrutator --pin docs/examples/example.com/signing.pub
```

The keys are throwaway demo keys, not anyone's identity: pinning proves that the file is the one the demo run signed,
which is all a pin can prove. The lab-zone bundle prints a warning that it includes user packs (the lab ships its own
small knowledge pack); the example.com bundle does not.

The example.com report reflects what the public sources answered at that moment (crt.sh, Common Crawl and HackerTarget
failed; CertSpotter answered). A scan today will differ.
