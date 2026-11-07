# Active confirmation: `scrutator audit --active`

A passive review reports what third parties say. Shodan's InternetDB saw port 23 open on an address last month: is it
open today? Active confirmation answers that with a handful of ordinary connections to the addresses of the client's own
names, inside a set of guardrails that are the point of the feature. It is opt-in, authorised, bounded, recorded in the
signed log before the first connection, and checked again by `scrutator verify`.

Use it for: an external exposure review you are engaged for, a self-assessment of infrastructure you control, an
incident-response check that a port really is closed now. Do not use it to look at anyone else's servers: the
authorisation you give is the only thing that makes it lawful, and Scrutator cannot check that you are telling the truth.

```bash
scrutator keygen --passphrase
scrutator active-plan scrutator-out/proof.scrutator                  # offline: what would be probed, what would be skipped, why
scrutator audit example.com --self --active --out audit-active       # your own systems (attested)
scrutator audit example.com --engagement engagement.yaml --active --out audit-active
scrutator audit example.com --self --active --max-connections 40 --out audit-active
scrutator --proxy=socks5h://127.0.0.1:9050 audit example.com --self --active --out audit-active
```

## What it does, and nothing else

After the passive collection, and only for addresses an in-scope name resolves to:

1. **TCP connect check** on each planned port: `open`, `closed` (refused) or `filtered` (no answer in time). On an open
   port it only *listens*: up to 256 bytes within 2 seconds, sanitised (control characters, escape sequences and Telnet
   option negotiation removed), stored as evidence. Nothing is sent: not a greeting, not a command. Binary data behind a
   text line (the key-exchange packet after an SSH identification string) is dropped, and a MySQL or MariaDB handshake is
   reduced to its version string, so a per-connection random challenge is never stored.
2. **TLS posture** on open TLS ports (443, 8443, 465, 993, 995, 636): a handshake per in-scope name (SNI), then close.
   Recorded: protocol and cipher negotiated, certificate subject, alternative names, issuer, validity, whether it covers the
   name asked for, and whether a handshake restricted to TLS 1.0 or TLS 1.1 completes. The certificate chain is not
   validated.
3. **HTTP posture** on open ports 80 and 443: one `GET /` per in-scope name, `Host:` set to the name, the fixed
   User-Agent `Scrutator/<version> (authorised review)` (no personal address anywhere), no cookies, no redirects followed.
   Recorded: status, `Location`, and a fixed list of headers (Server, X-Powered-By, Strict-Transport-Security,
   Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Content-Type). At most 16 KiB are
   read; the body is not.

## What it never does

No login attempt, no credential guessing, no anonymous-FTP test, no exploit or vulnerability payload, no fuzzing, no
directory or file brute force, no UDP, no port outside the lists below, no address outside the plan, no second request, no
request to a shared platform, no connection to a private, loopback, link-local or reserved address, no IPv6 in this
version. These are not options that are off by default: there is no code path for them, and `verify` fails a bundle whose
evidence shows one of the address, port or count limits broken.

## The guardrails

| Guardrail | How it is enforced | Tested in |
|---|---|---|
| **No authorisation, no connection.** An engagement file with `active_testing: true`, or `--self` with `--active` (which attests that you own or control the *systems* the names point at, not only the domains). The record is in the signed audit log before the first lookup. Not reachable from MCP at all. | `scrutator.active.gate`; `run_scan` refuses before the scan exists | `tests/test_active_core.py` |
| **Only addresses an in-scope name resolves to**, backed by a DNS evidence record. Never neighbours, ranges or candidates. | `scrutator.active.plan`, a pure function of the scan's evidence | `tests/test_active_core.py` |
| **Only these ports:** those a passive source says are open on that address, plus 21, 22, 23, 25, 110, 143, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017 and 80, 443. Each fixed port has a stated reason in `scrutator.active.PORT_REASONS`. | fixed in code, never read from a response or a bundle | `tests/test_active_core.py` |
| **Shared platforms are never probed** (Cloudflare, Fastly, Akamai, CloudFront, Vercel, Netlify, GitHub Pages, Google and Azure front ends, Heroku, Shopify, ...). Recognised by AS number, address range, CNAME target, reverse name or network name; kept as data in `packs/data/shared.yaml`, with `verified: false` where the pattern was not re-read. The skip and its reason are recorded. | `scrutator.active.guard.shared_platform` | `tests/test_active_core.py` |
| **Private, loopback, link-local, reserved and documentation addresses are refused**, also when a public name resolves to one (SSRF through DNS; the cloud metadata address is link-local). Checked again at the lowest layer, so a bug in a caller cannot open the connection. | `scrutator.active.guard.refusal`, `scrutator.active.net.connect` | `tests/test_active_core.py`, `tests/test_active_tcp.py` |
| **Bounded.** At most 60 connections per run by default (`--max-connections`, up to 500), 4 at a time, 8 new connections a second, 4 s to connect, 2 s for a banner, 5 s for a handshake, 6 s for a request, 120 s for the whole phase. The cap counts every connection: connect checks, handshakes and requests. | `scrutator.active.guard.Budget` | `tests/test_active_tcp.py` |
| **Ctrl-C safe.** Probes stop at once, what was recorded stays, the log says `active_interrupted`, and `audit` still builds a (partial) deliverable. | `scrutator.active.run` | `tests/test_active_tcp.py` |
| **The plan is written before the first connection**, as an evidence record (`ACTIVE PLAN`) and an audit record, including every skipped address and why. | `scrutator.active.run` | `tests/test_active_core.py` |

## The authorisation

Client mode needs the signed letter to allow it and the engagement file to say so:

```yaml
active_testing: true
```

A clause you can add to the letter (a template, not legal advice; have counsel review it): *"In addition to clause 3, the
Reviewer may make connection checks to the IP addresses that the domains in scope resolve to, limited to: TCP connection
attempts to a fixed list of ports, TLS handshakes, and one HTTP request for the home page per host name, at most 60
connections in all, from the Reviewer's network. No login attempts, exploitation, fuzzing or brute force. Addresses
belonging to third-party platforms (CDNs, hosting platforms) are not tested. The Client confirms it controls, or is entitled
to authorise testing of, the systems at those addresses."* An engagement without `active_testing: true` is refused with a
message that says so; nothing is sent. A domain on shared infrastructure that the client does not control is not covered by
the client's signature, which is why shared platforms are skipped.

Self mode: `--self --active` asks you to confirm that you own or control the domains **and the systems their names resolve
to**; the confirmation (`--yes`, or typed at the terminal) is recorded as such.

## What the evidence looks like

Every probe is a content-addressed, timestamped evidence record in the bundle:

| Source | Request | Payload |
|---|---|---|
| `tcp` | `TCP CONNECT 192.0.2.10:23` | `{"state": "open", "banner": "...", "banner_bytes": 21}` or `closed` / `filtered` with a detail |
| `tls` | `TLS HANDSHAKE 192.0.2.10:443 sni=www.example.com` | protocol, cipher, subject, SAN, issuer, validity, `hostname_match` |
| `tls` | `TLS LEGACY 192.0.2.10:443 TLSv1` | `accepted`, `refused`, `unsupported` (this machine cannot offer it: nothing is concluded), `error` |
| `http` | `HTTP GET https://www.example.com/ via 192.0.2.10:443` | status, `Location`, the kept headers |
| `active` | `ACTIVE PLAN example.com` | the whole plan: targets, ports and why, skipped addresses and why, limits |

**Active evidence is not replayed.** `verify --replay` reports `skipped: active evidence is not replayed` for these records
and never contacts a target. What `verify` does check, from the signed log and the evidence alone: the active authorisation
was recorded before the first lookup; the plan was recorded before the first probe; every probe record is accounted for in
the log; no probe went to an address that is not public, to a shared platform, outside the plan, or to a port outside the
passive and fixed lists; TLS and HTTP records have an open port behind them; the count does not exceed the recorded cap; the
report's `active` section and every risk follow from the evidence. Flip an open port to closed in a bundle and re-sign it:
the record's hash, or the risks derived from it, no longer match, and `verify` fails (`tests/test_active_report.py`).

A bundle made by the tests or the bench (local listeners, loopback allowed) says so in its signed log and `verify` prints
a warning; no command-line option can switch that on.

## Reading the results

- **open now** is a completed TCP handshake from this machine, at the time on the record.
- **closed** is a refusal (a RST) from the address. **filtered / unanswered** is silence within the timeout. Silence can be
  the target's firewall, but it can equally be the tester's own network: many home and corporate networks block outbound
  25, 23 or 445. Before you tell a client a port is closed, repeat the check from a second network; before you tell them it
  is open, remember that only the first holds up on its own.
- **A port number is not a protocol.** A finding names the service by the greeting when the greeting is unmistakable: a
  port 23 that answers `SSH-2.0-...` is reported as "SSH service on the usual Telnet port" and rated medium, not as a
  clear-text Telnet shell. Check what is really there before you tell a client "Telnet is open".
- When the connection cap bites, the page and its headers are requested before certificates, and the legacy TLS attempts
  go last; a run that stopped for the cap says so in `active_done`.
- On Windows a refused connection takes about two seconds to report (the OS retries the connect), which is why the connect
  timeout is 4 s.
- **Confirmed and stale are both shown.** When the connection succeeds, `exposed-risky-service` becomes a high-confidence
  finding ("a connection ... succeeded at ...: the port is open now") and cites both the check and Shodan's earlier record.
  When Shodan listed a port that the check found closed or unanswered, `stale-exposure-data` (info) cites both. Neither
  hides the other. Every finding now carries "how established": *checked now*, *reported earlier by a third party*, or both.

New rules (fixed remediation text, mapped to ISO/IEC 27001, NIS2, CIS, OWASP and KVKK references in the compliance pack, each
reference marked verified or not): `exposed-risky-service` (confirmed), `stale-exposure-data`, `tls-cert-expired` (high),
`tls-cert-expiring` (under 30 days; under 7 high), `tls-hostname-mismatch`, `tls-legacy-protocol`, `http-no-https-redirect`,
`http-missing-hsts`, `http-missing-security-headers` (low, one finding listing what is missing),
`server-banner-discloses-version` (info). A confirmed Telnet, SMB, RDP, VNC, database or cache port is rated high; FTP,
rsync and NFS stay medium.

`quick` is never active, and `scan` has no active confirmation: `audit` is the only entry point.

## Through a proxy

`scrutator --proxy URL ...` (or the `SCRUTATOR_PROXY` variable, preferable when the URL holds credentials) sends every
outbound request through one proxy: the HTTP data sources, the opt-in web modules, the crt.sh fallback connection and every
active probe. `http://host:port` (HTTP CONNECT), `socks5://host:port` and `socks5h://host:port` are accepted; for the HTTP
data sources a SOCKS proxy needs `pip install "scrutator[socks]"`, while the active probes use a built-in tunnel.

What a proxy does **not** do, honestly:

- **DNS is not proxied.** Name lookups go from this machine to its configured resolver (and from there to the target's own
  name servers). The resolver and anyone watching your network see every name asked about. If that matters, run Scrutator in a
  network namespace, behind a VPN or with a DNS forwarder that exits where your traffic does.
- The proxy operator sees every destination and, for plain HTTP, the request. Through a proxy a "closed" port means the
  proxy reported a refusal and a "filtered" port means it timed out or reported the host unreachable; a proxy that
  blocks a port looks like a filtered port. A proxy that refuses the tunnel shows as an `error` state, never as closed.
- The audit log records the proxy's host and port (never credentials).

## Limits a critic will raise

- It checks reachability and posture, not vulnerability. Open is not exploitable; version banners are what the server says.
- Shared-platform recognition is data: an unlisted platform is probed with a few connections. Add it to a pack
  (`--packs`) and send the entry.
- An address can serve several customers without being on a listed platform (a shared web host). Your authorisation must
  cover it.
- Hostnames on one address share the connection budget; only the first three names per address get a handshake and a request.
- IPv6, UDP, STARTTLS ports (25, 110, 143, 587 are read for their banner only) and the TLS chain trust are not covered.
- The tool cannot tell a firewall on the target from one on your network, and it checks from one network at one moment.
- Active evidence is the tool's own observation, signed by your key: a signature proves the file was not altered, not that
  the probe happened. Pin the signing key and say how you ran it.
