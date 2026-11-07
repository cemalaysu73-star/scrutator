# Repository metadata (for the GitHub "About" box)

Repository: `cemalaysu73-star/scrutator`

## Description (under 350 characters)

Evidence-backed infrastructure OSINT. Passive recon of a domain you may assess: every finding cites a hashed raw record, names are verified or only claimed, and the report ships as a signed proof bundle that anyone can verify offline. Local-first AI, no person lookup, no exploitation.

## Topics

```
osint
reconnaissance
attack-surface
subdomain-enumeration
certificate-transparency
bug-bounty
dns
digital-forensics
supply-chain-security
mcp
```

## Settings to switch on after the push

- Security tab: enable **Private vulnerability reporting** (SECURITY.md and the issue-form config point to it).
- Settings, General: disable Wikis and Projects if unused; enable Discussions only if you want them (the docs say "open an issue").
- Labels: create the ones in `.github/labels.yml` (`gh label create` or a label-sync action).
- Settings, Actions: allow GitHub Actions; the CI workflow needs no secrets.
- Branch protection on `main`: require the `ci` jobs and a pull-request review.
- Social preview image: `docs/screenshots/report-hero.jpg`.
