# Proof bundles

A report is only as good as the reader's trust in whoever produced it. A **proof bundle** lets a reader check a
report without trusting the author or this tool's printed output: it carries the report together with every raw
record it rests on, and `scrutator verify` re-derives what it can and checks the rest.

## Make one

```bash
scrutator keygen                              # once: ~/.config/scrutator/signing.key and signing.pub
scrutator keygen --passphrase                 # the same, with the private key sealed by a passphrase
scrutator scan example.com --bundle           # also writes <out>/proof.scrutator
scrutator export 3 --bundle proof.scrutator   # or export any scan already in the database
```

A bundle is a zip with exactly five members:

| Member | Holds |
|---|---|
| `report.json` | the report |
| `evidence.jsonl` | every raw evidence record the scan collected (id, source, request, payload, time) |
| `audit.jsonl` | the hash-chained log of every module call, starting with the source policy |
| `manifest.json` | sha256 and size of the three files above, the tool version, the scan identity, the source policy, a record of the risk/attribution analysis and the knowledge packs used, the public key and its fingerprint |
| `manifest.sig` | an Ed25519 signature over the manifest bytes |

## Verify one

```bash
scrutator verify proof.scrutator --pin signing.pub          # or --pin <fingerprint>
scrutator verify proof.scrutator --pin signing.pub --replay # also re-ask the sources
```

Exit status 0 when every check passes, 1 when any fails. Each layer is a named check on its own, so a failure says
what failed:

| Check | What it establishes |
|---|---|
| `readable bundle` | the file is a zip with only the five allowed member names, within size limits (see below) |
| `manifest parses`, `file hashes` | the manifest is well-formed; the three data files hash to what it says |
| `signature valid` | the manifest was signed by the key inside it |
| `signing key pinned` | that key's fingerprint is the one you pinned |
| `audit chain` | the audit log's hash chain is intact |
| `evidence hashes` | every evidence record hashes to its id |
| `report references` | everything the report cites exists in the bundle |
| `findings derivable` | the report's findings are exactly what the evidence implies |
| `scan identity`, `analysis recorded`, `packs intact` | the manifest matches the report; the bundled knowledge packs match this tool's own copy |
| `risks derivable`, `exposure derivable`, `attribution derivable` | the risk, exposure and attribution engines are pure functions of the report; `verify` recomputes them, so a hidden risk or a raised band fails even if the bundle is re-signed |
| `name states derivable`, `headline derivable` | states, tiers and the headline are re-derived |
| `source policy honoured` | the policy agrees in the report, manifest and audit log, and no lookup or evidence record comes from a source it forbids |
| `promotions recorded` | the report's promotions are exactly those in the signed audit log |

Change one byte anywhere and a named check fails. The bundle test suite flips bytes in each file type, swaps keys,
drops evidence records, hides a risk, raises a confidence and truncates the audit log, all of which fail
(`scrutator bench` runs ten such cases). Bundles made by older versions still verify; checks that did not exist then
report "not applicable".

## What a valid signature proves, and what it does not

- **A signature alone proves only that the bundle matches the key inside it.** Anyone can sign a forged bundle with
  their own key. Without `--pin`, `verify` passes the signature check but warns. Give readers your key fingerprint
  through a channel they already trust (your website over HTTPS, a signed email, a release page) and have them pin
  it.
- **The signer's clock is not proof of time.** `created_at` and each record's `collected_at` come from the machine
  that made the bundle. There is **no trusted timestamp** (RFC 3161): the bundle cannot prove *when* it was made, and
  a signer can back-date. It proves integrity (nothing changed since signing) and internal consistency, not date.
- **It proves the report follows from the evidence, not that the evidence is true.** The evidence is what the
  sources returned. If crt.sh or a DNS server lied at the time, the bundle faithfully contains the lie. `--replay`
  lets a reader ask the sources again.
- Pack entries you added yourself (`--packs`) cannot be checked against a trusted copy. `verify` says so; the signer
  vouches for them.

## `--replay`

Re-issues the recorded requests (HTTPS GETs to the fixed set of source hosts, and DNS lookups of type A, AAAA, CNAME,
MX, NS, TXT, CAA) and reports each as `unchanged`, `changed` or `unavailable`. A recorded NXDOMAIN or NODATA replays as
unchanged while it still holds. **Drift is information, not failure**: sources change and go down. Replay contacts
only the source hosts (and the RIR RDAP servers `rdap.org` refers to, and only if they resolve to public addresses),
and looks up only DNS names inside the bundle's own scope, so a hostile bundle cannot make a verifier fetch arbitrary
URLs or resolve tracking names. Keyed sources are not replayable (a replay would need your key). Replay warns when
the signer is not pinned, and is bounded in volume because the bundle decides the requests: at most 20,000 records and
2,000 distinct HTTP requests per replay (`--replay-limit` changes the first); the rest are reported as skipped.

## Verifying an untrusted bundle

`verify` is designed to be run on files from people you do not trust:

- Members are never extracted to disk; a member is bytes in memory, so names like `../x` cannot write anywhere.
  Any member name other than the five is refused, as are duplicates, symbolic links and encrypted members.
- Declared sizes are checked before anything is inflated: each data file may be at most 256 MiB, the manifest 1 MiB,
  the signature 4 KiB, all members together 512 MiB, the file on disk 512 MiB, and the entry count is read from the
  end-of-central-directory record before the zip is listed. A 200 KiB zip bomb is refused in under two seconds and a
  few MB of memory (tested).
- Hostile JSON (nesting deeper than the parser allows, wrong types) fails a named check instead of raising.
- Everything printed from a bundle goes through a terminal-safe filter (control and bidirectional characters are
  shown escaped, not obeyed).
- The writer refuses a scan too large for the reader's limits (use a lower `--max-entities`; 50,000 names makes a
  report of about 128 MiB), so a bundle this tool writes can be verified by it.

## Keys

- `keygen --passphrase` seals the private key (scrypt, N=2^16, r=8, p=1, then ChaCha20-Poly1305; the KDF parameters
  and salt are authenticated). The passphrase comes from `SCRUTATOR_KEY_PASSPHRASE` or a hidden prompt, never from
  an argument. `scrutator protect-key` encrypts an existing key in place; the key and its fingerprint stay the same.
- Unencrypted keys still work, with a warning every time they sign.
- On POSIX the key is written `0600` in a `0700` directory, and a group- or world-readable key is reported. On
  Windows the tool does not set or check ACLs (mode bits mean nothing there); the key inherits the folder's access
  rules, so keep it in your profile directory or protect it with a passphrase.
