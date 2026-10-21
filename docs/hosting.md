# Running monitoring for clients

`scrutator watch` is the retainer product: one output folder per client holds that client's baseline
(`monitor-state.json`), the scans (`scrutator.db`), every change (`diff-<n>.json`) and the weekly digest
(`digest-<year>-W<week>.md`). The first run is the baseline; after it, each run announces only what is new, once, ranked
by severity, each alert with its evidence ids and a "why this matters" line.

```bash
scrutator watch client-a.com --client "Client A" --out clients/client-a --every 24h
scrutator watch client-a.com --client "Client A" --out clients/client-a --max-runs 1 --min-severity medium
scrutator watch client-a.com --out clients/client-a --max-runs 1 --webhook https://hooks.example.com/client-a
scrutator watch client-a.com --out clients/client-a --max-runs 1 --email-to it@client-a.com --lang tr
```

- **One run per scheduler tick.** With a scheduler, run `--max-runs 1` each time: the baseline and the dedupe state are
  on disk, so nothing depends on a long-lived process. `--every` is for running it in a terminal instead.
- **Alerts** at or above `--min-severity` (default `low`) are printed, posted to the webhook (`https://`, or `http://`
  to localhost only; redirects are never followed; the payload carries titles, details and evidence ids, never raw
  evidence) and, with `--email-to`, e-mailed. Every alert, whatever its severity, stays in `monitor-state.json`.
- **E-mail** server and credentials come only from the environment (`SCRUTATOR_SMTP_HOST`, `SCRUTATOR_SMTP_PORT` (587
  STARTTLS by default, 465 implicit TLS), `SCRUTATOR_SMTP_USER`, `SCRUTATOR_SMTP_PASSWORD`, `SCRUTATOR_SMTP_FROM`),
  never from the command line, and the password is never written to any output, log or state file (tested with a
  canary). A server that does not offer STARTTLS on 587 is refused.
- **AI** (`--ai local`): the English "why this matters" line may be reworded by a local model; the rewording is kept
  only when the deterministic floor and the verifier pass it, and is marked "(AI, verified)". Default: off.
- **Data:** the folder holds public records about the client's infrastructure. Keep it on an encrypted disk, back it
  up, and delete it when the retainer ends.

Nothing below has been deployed by the author of this page: these are configurations to start from, tested only as far
as their syntax goes. Adjust paths and users.

## Windows: a scheduled task

```powershell
# once: a folder per client, and the e-mail variables for the account that runs the task
setx SCRUTATOR_SMTP_HOST smtp.example.com
setx SCRUTATOR_SMTP_FROM watch@example.com
setx SCRUTATOR_SMTP_USER watch@example.com
# the password: set it in the account's environment by hand (System Properties > Environment Variables), not in a script

schtasks /Create /TN "Scrutator Client A" /SC DAILY /ST 06:30 /RU "%USERNAME%" ^
  /TR "\"C:\Tools\scrutator-venv\Scripts\scrutator.exe\" watch client-a.com --client \"Client A\" --out C:\Clients\client-a --max-runs 1 --email-to it@client-a.com"
schtasks /Run /TN "Scrutator Client A"      # try it once
```

## Linux: a systemd timer

`/etc/systemd/system/scrutator-client-a.service`:

```ini
[Unit]
Description=Scrutator monitoring for Client A
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=scrutator
EnvironmentFile=/etc/scrutator/smtp.env
ExecStart=/opt/scrutator/venv/bin/scrutator watch client-a.com --client "Client A" --out /var/lib/scrutator/client-a --max-runs 1 --email-to it@client-a.com
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/scrutator
PrivateTmp=true
```

`/etc/systemd/system/scrutator-client-a.timer`:

```ini
[Unit]
Description=Daily Scrutator run for Client A

[Timer]
OnCalendar=*-*-* 06:30:00
RandomizedDelaySec=30m
Persistent=true

[Install]
WantedBy=timers.target
```

`/etc/scrutator/smtp.env` (mode 0600, owner root): `SCRUTATOR_SMTP_HOST=...`, `SCRUTATOR_SMTP_FROM=...`,
`SCRUTATOR_SMTP_USER=...`, `SCRUTATOR_SMTP_PASSWORD=...`. Then `systemctl daemon-reload && systemctl enable --now
scrutator-client-a.timer`, and `journalctl -u scrutator-client-a` shows the runs.

## Docker Compose

The repository's `Dockerfile` builds an image that runs `scrutator` as an unprivileged user (CI builds it; it was not
run on the machine these docs were written on). One service per client, run once by the host's scheduler (cron or a
systemd timer calling `docker compose run --rm client-a`):

```yaml
# compose.yaml
services:
  client-a:
    build: .
    image: scrutator:local
    command: ["watch", "client-a.com", "--client", "Client A", "--out", "/work/client-a", "--max-runs", "1",
              "--email-to", "it@client-a.com"]
    env_file: ./smtp.env          # SCRUTATOR_SMTP_*; keep out of version control
    volumes:
      - ./clients:/work
    read_only: true
    tmpfs: [/tmp]
    security_opt: ["no-new-privileges:true"]
    restart: "no"
```

```bash
docker compose build
docker compose run --rm client-a
```

## What to watch for

- A run takes as long as a scan (tens of seconds for a small domain; see the benchmark docs). Stagger clients.
- Source quotas: HackerTarget allows 50 free calls a day per IP; several clients a day from one address use it up.
  The run says which sources failed; the digest reflects only what was collected.
- The non-commercial free tiers (InternetDB, RIPEstat, CertSpotter, Subdomain Center): for paid monitoring run with
  `--no-noncommercial` or obtain the providers' commercial terms ([sources](sources.md)).
