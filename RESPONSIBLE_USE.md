# Responsible use

Scrutator maps an organisation's internet-facing infrastructure from public records and proves where every claim
came from. Used well, it helps defenders see what an attacker sees. This page says what it is for, what it will not
do, and what you owe the people and services on the other side.

## Use it only where you may

- Investigate organisations **you are authorised to assess** (your own, a client under a written engagement, a bug
  bounty programme whose rules cover passive reconnaissance) or that you are otherwise entitled to research.
- Public data is not free of rules. The sources Scrutator asks have terms of their own; some free tiers are for
  non-commercial use only. Read [docs/sources.md](docs/sources.md) before using a source in paid work, and use
  `--exclude-sources` or `--no-noncommercial` when you must.
- A finding is a lead for the owner to confirm, not proof of compromise. Do not publish a third party's findings
  without their permission, and never use the tool's output to attack, extort or embarrass anyone.

## What it does not do, by design

- **It does not look people up.** No command takes a person's name, username, e-mail address or phone number and
  searches for them, and none will be added under another name. It never collects home addresses, personal phone
  numbers, family members, personal social accounts, photos or locations.
- **It does not attack.** A passive scan asks public sources and DNS about the target. It never port-scans,
  brute-forces names, tries passwords or sends exploit traffic.
- **It does not widen its own scope.** Only your scope file decides what may be investigated; names found outside it
  are recorded and never queried, and a candidate only gets passive lookups until you promote it yourself.

## The two modules that are off by default

- **Brand presence** (`scan --brand`) fetches a few pages of the organisation's own website (robots.txt honoured, rate
  limited, no login) to read the social links the organisation publishes, then asks the public profile pages of those
  platforms whether the published handles and close look-alikes of the brand exist (HTTP status only, nothing from the
  page). Use it on an organisation's domain, not on a personal site: it is meant to find handles that could be used
  to impersonate a brand.
- **Organisation exposure** (`scrutator exposure`) estimates an organisation's social-engineering exposure from what the
  organisation itself publishes. It refuses to run without an engagement file (organisation, domains, who authorised
  the work, dates, purpose), refuses a person as the seed, reports aggregates (how many work addresses are public,
  their naming pattern, which functions are visible) and shows per-person detail only with `--detail`, which is written
  to the audit log. It is meant for authorised red-team and defensive assessments. **It has not had the legal and
  ethics review the design requires before release**; treat it as a preview and check the law where you work (for
  example the GDPR in the EU) before using it on real data.

## If you find misuse or a way around these limits

A way to make Scrutator look up a person, contact something outside the scope, or hide a finding is a security
problem: report it as described in [SECURITY.md](SECURITY.md).
