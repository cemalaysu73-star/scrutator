# Reading a report

`scrutator scan` writes `report.html` (one self-contained file; nothing is loaded from the network) and `report.json`
(the same data). Both are generated from the stored evidence; the JSON is what `verify` re-derives from.

## The first line

```
Scan #1 of example.com: 2 verified, 499 claimed (0 stale, 0 wildcard-covered).
```

This is the number to quote. *Verified* names are supported by DNS or by a dated certificate or scan; *claimed* names
are only listed by an aggregator or an archive and DNS shows no sign of them. A scan of a one-website domain can list
hundreds of claims. See [name tiers](concepts.md#name-tiers). Stale and wildcard-covered names are counted
separately because they mean something different (a name that used to exist; a name only a wildcard record answers).

## Sections of the HTML report

| Section | What it shows | How far to trust it |
|---|---|---|
| Summary cards | counts by tier, entities, findings, risks | derived from the lists below |
| AI summary | statements a writer model drafted and a verifier model accepted, each with its evidence ids | only present when a model ran. Each statement passed a deterministic check and a verifier; neither is perfect ([security](security.md)). Rejected statements are not shown here; they are listed as unverified leads. |
| Source coverage | each source: answered, failed, marked down, not run; the deadline; the source policy | read this first when a result is smaller than expected: a failed source is a gap, never a negative |
| Risks | configuration risks from deterministic rules, severity, the entities, remediation, and the evidence they cite (click to expand) | a lead for the owner to confirm, not proof of compromise |
| Provider dependencies | which providers stand behind the names (DNS, mail, CDN/host, CA) | recognised from the knowledge packs; an unrecognised provider is not listed |
| Name states | for each in-scope name: tier, DNS state, why | verified tables open; claimed, stale and wildcard names are folded in counted groups |
| Exposure | ports and products Shodan InternetDB saw on in-scope addresses, abuse contact, network | an earlier scan by Shodan, not a check made now; CVE ids are Shodan's guesses from product versions; non-commercial data |
| Attribution | candidate names outside the scope, band, score, every signal, the pre-mortem | weights are not calibrated; a candidate is a lead |
| Analyst leads / Unverified leads | AI-written observations, and what the verifier did not accept | leads are not findings |
| Findings | every claim, ordered verified first, with its tier, confidence and evidence | click a finding to see the raw records |
| Graph | entities and relations | |
| Entities | everything seen, with its scope state | `out` entities were recorded, never queried |

## Following a claim to its evidence

In the HTML, click a finding or a risk: the evidence ids expand into the raw records (source, request, collected
time, payload). In `report.json`:

```python
import json
report = json.load(open("report.json", encoding="utf-8"))
finding = report["findings"][0]          # {"claim": ..., "confidence": ..., "tier": ..., "evidence_ids": [...]}
for evidence_id in finding["evidence_ids"]:
    record = report["evidence"][evidence_id]   # {"source", "request", "payload", "collected_at"}
```

Anyone can recompute an evidence id: `sha256(source + "\n" + request + "\n" + payload)`.

## Confidence

The number of distinct sources that agree: one is `low`, two `medium`, three or more `high`. It measures agreement
between sources, not truth: two sources that copy each other count as two.

## What the report cannot tell you

- Whether a name is *the organisation's*: attribution is a score with reasons, calibrated on nothing but a synthetic
  lab.
- Whether a risk is exploitable. Takeover and exposure findings are inferences from public records; nothing was
  probed.
- That nothing else exists. Passive sources see what they have seen. The one public truth set in the benchmark
  (`zonetransfer.me`) shows that 87% of that zone's names are reached by no passive tool tried
  ([benchmarks](benchmarks.md)).
- Anything about the time between the scan and now. Evidence carries the time it was collected; drift is normal
  (`verify --replay` measures it).
