# Client audits: `scrutator audit`, `audit-check`, `audit-letter`

`scrutator audit` turns a passive scan into a document you can hand to a client: a single self-contained HTML file with
a print style sheet (A4), a PDF when a Chromium-based browser is installed, the interactive report as the technical
annex, and the signed proof bundle everything rests on. The client, or their auditor, checks the document offline
against the bundle with three commands.

It is built for consultants, MSPs and freelancers who sell a one-off **external exposure review** to small and
mid-size companies, for example as evidence for ISO/IEC 27001, NIS2 or KVKK/GDPR work. It is passive by default (an opt-in, authorised [active confirmation](active.md) is described on its own page): no port scan, no
vulnerability scan, no login attempt, no exploitation. Say so when you sell it (the document says so too).

## 1. Get a written authorisation

```bash
scrutator audit-letter --lang tr --client "Ornek A.S." --domains ornek.com.tr --start 2026-11-01 --end 2026-11-30 --out authorisation
```

This writes a letter (`authorisation-letter.txt`, or `yetki-belgesi.txt` in Turkish) and `engagement.yaml`. The letter
is a **template, not legal advice**: have it reviewed by counsel in your jurisdiction before you use it. Every field you
did not give stays as `<fill in: ...>`; `scrutator audit` refuses an engagement file that still holds one, so an
unsigned template can never authorise an audit. Get the letter signed by someone entitled to authorise testing of the
systems in scope, then copy the signed values into `engagement.yaml`.

## 2. Run the audit

```bash
scrutator keygen --passphrase                       # once: the key that signs your bundles
scrutator audit ornek.com.tr --engagement authorisation/engagement.yaml --branding audit.yaml --out audit-ornek
scrutator audit example.com --self --out audit-self # your own domains: a self-assessment, attested and recorded
scrutator audit --from-bundle proof.scrutator --engagement engagement.yaml   # from a bundle you already have
```

- **No authorisation, no audit.** Exactly one of `--engagement FILE` (client mode) or `--self` (domains you own or
  control) is required, and it must be confirmed on the terminal or with `--yes` (recorded as such). The scan's seed
  and scope must be inside the engagement's domains, and the engagement must have been in force on the day of the scan.
- **For a new scan the authorisation is written to the scan's hash-chained audit log before the first lookup** (the
  engagement file's sha256 and its fields, or the self-attestation). That log is inside the signed bundle, and
  `scrutator verify` checks it was recorded before any lookup.
- **From an existing bundle** the signed log cannot be changed: if it already holds the same authorisation it is used;
  otherwise the document says plainly that the authorisation was recorded at report time, and `audit-log.jsonl` in the
  output folder records the engagement hash, the bundle hash and the time.
- Paid work: consider `--no-noncommercial`, which leaves out sources whose free tier is for non-commercial use only
  (InternetDB, RIPEstat, CertSpotter, Subdomain Center). The audit lists the sources it did not use.

Output folder: `audit.html`, `audit.pdf` (when a browser was found), `audit.json` (the facts, machine-readable),
`technical-annex.html`, `proof.scrutator`, `signing.pub` (new scans), `audit-log.jsonl`.

### What the document contains

Cover (client, auditor, date, engagement reference, scope, bundle hash) · authorisation statement tied to the engagement
record · executive summary in plain language, each sentence citing the evidence it rests on · findings in priority
order (severity, then confidence, then effort) with remediation, an effort estimate and an **informational** mapping to
ISO/IEC 27001:2022 Annex A, NIS2 Art. 21(2), CIS Controls v8.1, OWASP and KVKK · asset inventory (verified names,
addresses, providers, networks) · what was not tested (fixed exclusions, and every source that failed or was not used)
· methodology · glossary · evidence appendix with the bundle fingerprint, the signing key and the three verification
commands.

The executive summary is deterministic text in English or Turkish (`--lang`, or `language:` in `audit.yaml`). With
`--ai local` (or cloud/hybrid) the English sentences are offered to a writer model for plainer wording; a rewording is
kept only when it passes the deterministic floor (no host, address, number or date the facts do not hold, no alarm word
or negation they do not make, no prose copied out of a raw record) and the verifier model supports it. Otherwise the
deterministic sentence stays. Rewording is not offered for Turkish (the floor's word lists are English).

The mapping to frameworks is **not a certification, an audit opinion or a legal conclusion**; every ISO/IEC 27001
reference is unverified (the standard is not public). See [knowledge packs](knowledge-packs.md#a-compliance-mapping).

## 3. The client checks it, offline

```bash
sha256sum proof.scrutator                     # Windows: certutil -hashfile proof.scrutator SHA256
scrutator verify proof.scrutator --pin <signing key fingerprint printed in the appendix>
scrutator audit-check audit.html proof.scrutator
```

`audit-check` re-derives the whole document from the bundle: the bundle verifies and is the one the document names;
the authorisation is the one the signed log records (or is marked as recorded at report time); every number, finding
and sentence is what the bundle implies; every cited record is in the bundle; AI rewordings pass the deterministic
floor; and the page is byte for byte what those facts render to. Edit one number in the HTML, or drop a finding and
re-render, and it fails, naming the check. It needs the same Scrutator version that made the audit (the compliance
mapping and the wording come from the tool).

## Branding: `audit.yaml`

```yaml
auditor: Example Security Consulting
contact: audits@example.com
logo: logo.png                   # PNG or JPEG, at most 512 KiB (SVG is refused: it can carry script)
colours: {primary: "#1f3a5f", accent: "#2f7d5b"}
language: tr                     # or en
client: Örnek A.Ş.               # optional; default: the engagement's organisation
```

Every field is treated as hostile input: text is escaped where it is placed, colours must be `#rrggbb`, the logo is
checked by its first bytes and embedded as a data URI, and nothing else from the file reaches the style sheet. The
page has no script that runs: its only `<script>` element is the JSON data block `audit-check` reads.

## PDF

The PDF is printed by a Chromium-based browser that is already installed (`SCRUTATOR_BROWSER`, then Edge, Chrome,
Chromium, Brave in their standard places, then PATH), headless, with a throwaway profile. Nothing is downloaded. With no
browser found the audit says so: open `audit.html` in any browser and print it to PDF; the print style sheet gives the
same A4 document (cover page, page numbers, findings kept on one page where they fit).

## Limits you must tell the client

- Passive recall is limited by what public sources have seen; a name no certificate log, archive or aggregator holds
  is not in the report. Established tools ask more sources and scan actively; Scrutator's difference is that every
  claim is verifiable, not that it finds more.
- A signed bundle proves integrity, not truth and not time (no trusted timestamp). Pin the signing key through a
  channel the client trusts.
- Effort estimates and the framework mapping are the tool author's judgement, labelled as such.
