# Organisation intelligence (opt-in, `scan --org`)

A passive Scrutator scan maps a **domain**. With `--org` it also looks at the **organisation** behind the domain: the
legal entity and its group, the breach history of its own services, the code it hosts in the open, and the package
namespaces and public handles that carry its brand. Every source is public, keyless (except the two keyed company
registers and the opt-in code scan), scope-gated and audited like every other lookup, and every statement it makes
cites the evidence it rests on, so `scrutator verify` re-derives the whole Organisation section from the bundle.

This page says what each source tells you, what it cannot, and the terms. The hard rule first.

## What this never does

Organisations only — legal entities, domains, repositories and package namespaces. Scrutator does **not**, with
`--org` or any flag:

- look up a natural person by name, username, e-mail or phone;
- collect officers, directors, shareholders, employees or commit authors; the GitHub member endpoint is reduced to a
  *count*, package author and maintainer fields are dropped, and free text (a repository or organisation description)
  has e-mail addresses removed before it is stored;
- request X, LinkedIn, Facebook, Instagram, TikTok, Reddit, Medium, Substack or Telegram (their terms restrict
  automated access, or the page does not tell existence from a status);
- log in, create an account or a key, or exploit anything.

The seed is always a domain. A legal name is taken only from evidence that it names an organisation (a Wikidata
organisation item, a GLEIF record, an RDAP `org` registrant of the seed) or from an explicit `--legal-name`, and each
derived name is recorded with the evidence that produced it.

## The input model

```
scrutator scan example.com --org                       # the organisation sources, keyless
scrutator scan example.com --org --legal-name "Example Foundation"
scrutator scan example.com --org --github-org example-org
scrutator scan example.com --org --code-leaks --self   # also scan the org's own repos for secrets (needs a token)
```

The organisation is resolved like this: Wikidata is asked for the organisation item whose official website is the seed;
its label is a legal-name candidate and its `P1278` LEI and `P2037` GitHub account are handed to the later sources. If
Wikidata finds nothing, the RDAP registrant collected in the passive phase and `--legal-name` stand in. The GitHub
account comes from Wikidata or `--github-org`.

## The sources

### Company records — `gleif`, `wikidata`

- **GLEIF** (keyless, CC0): the legal entity by its LEI (from Wikidata) or by an **exact** legal name, its status,
  jurisdiction and legal address, and its direct parent, ultimate parent and direct children — all as legal entities.
  An entity reached by the organisation's own LEI is **confirmed**; an exact legal-name match is kept apart as an
  **unconfirmed name match**, because the same name can belong to an unrelated entity (searching "ICANN" returns a
  Mexican real-estate company). No fuzzy matching is done, and no natural person is ever in a GLEIF record.
- **Wikidata** (keyless, CC0): the organisation item whose official website (`P856`) is the seed, filtered in the SPARQL
  query to an instance of a subclass of *organization* (`Q43229`) so a **software or product item is never taken as the
  organisation** (e.g. nmap.org's official-website item is the Nmap software, so nothing is derived). Its label, LEI,
  headquarters country, stock ticker and GitHub account, and the official websites of it, its parent (`P749`) and its
  subsidiaries (`P355`). The parent's and subsidiaries' domains become candidate scope entries.

What they cannot tell you: a small foundation often has no LEI (OWASP has none), an acronym label can collide with an
unrelated company, and Wikidata is community data that can be stale or wrong. Treat the legal entity as a lead to
confirm, not a conclusion.

### Breach history — `hibp`

Have I Been Pwned's **public breaches-by-domain metadata** endpoint (keyless): for the organisation's domain, the
breaches a public index names, each with the breached service's name, date, record count and the kinds of data
involved. This is **metadata about the breached service**, CC BY 4.0 (credit haveibeenpwned.com) — never account lists
or e-mail addresses. The endpoint that returns those (`breacheddomain`) needs a key and proof of control of the domain
and is **never called**. A breach is reported as `breach-history` (info; low when the data is sensitive) with the fixed
advice to confirm the breach and rotate any still-valid credentials. It is history as a third party reported it, not a
live finding; the date is the source's claim.

### GitHub — `github`, `github_leaks`

- **`github`** (keyless, 60 requests/hour; the optional `SCRUTATOR_GITHUB_TOKEN` raises the limit and is never logged):
  the organisation's public account (resolved from Wikidata or `--github-org`), its public repositories (name,
  description, homepage, archived, fork, language, topics, last push, licence, default branch), and the **count** of
  public members — never their names. In-scope host names written in a repo's homepage, description or README (first
  8 KB) become candidate names; a host named by an **archived** repository is flagged as named by an abandoned
  repository. A name first seen this way is asked of DNS once at the end of the organisation phase (at most 50), so its
  tier says whether it exists instead of staying an unchecked claim. The organisation's e-mail field and member names
  are dropped.
- **`github_leaks` (`--code-leaks`)**: opt-in, and it needs `--org`, **`--self`** (you confirm you own or control the
  organisation's public repositories; recorded in the signed audit log before any lookup) and the token. It looks only
  at the organisation's **own** public repositories (capped repositories, files and API calls), for well-known
  credential **formats** (`.env`, `*.pem`, `*.key`, `credentials`, config files, …). The secret value is **never
  stored**: an exposure records only the format, the repository, the path, the commit sha, a per-run salted-hash
  fingerprint and a 2+2 character mask. The finding is `exposed-credential` (high): rotate the credential, then remove
  it from history — and confirm by hand that the match is a live secret and not a test fixture before raising an
  incident (responsible disclosure). A canary test proves the value is in no evidence record, report, bundle, log or
  MCP output.

### Brand protection — `packages`, `handles`

- **`packages`** (keyless): whether the organisation's brand name (the first label of the seed) exists as a package or
  namespace on **npm, PyPI, Docker Hub, crates.io, RubyGems and NuGet**, and whether the registry's homepage or
  repository URL points back to an in-scope domain (a **confirmed namespace**). Look-alikes of the brand name (from the
  existing variant generator, capped, on npm, PyPI and Docker Hub) that exist and are **not** linked to the
  organisation are reported as `lookalike-package-exists` (low); a brand name that is **free** on a registry is reported
  as `brand-namespace-unregistered` (info) with the dependency-confusion explanation. Author and maintainer fields are
  never stored.
- **`handles`** (keyless): whether the organisation holds the brand handle on **GitLab** (public group), **Docker Hub**
  (namespace) and **Bluesky** (the seed domain as a handle, and `<brand>.bsky.social`), each reported *exists*,
  *absent* or *unverifiable* strictly by HTTP status or JSON — never guessed. GitLab's 404 means "no public group of
  that path" (a private group or a user namespace answers the same), so absence there is "no public group", not "free".

### Keyed, documented-only (off without a key)

OpenCorporates and UK Companies House expose company-level endpoints (never officers or persons with significant
control) behind a key. They are **not implemented yet**: R9 built the keyless sources first. When they are added, they
will be off unless their key variable is set and labelled "implemented against the documented API, not live-verified".

## Terms and non-commercial use

All the keyless organisation sources are free for use; GLEIF and Wikidata are CC0, HIBP is CC BY 4.0 (credit
haveibeenpwned.com). None is marked non-commercial. The registries and code hosts allow access through their documented
public APIs within published limits; Scrutator uses a descriptive User-Agent (no personal address), paces its requests
and caps them. Read each service's terms before relying on it in a paid engagement; the per-source terms are in
`scrutator sources` and in [sources.md](sources.md). The probes that established each source's shape, status behaviour
and terms are recorded in [dev/r9-source-probes.md](dev/r9-source-probes.md).

## What `verify` checks

The Organisation section is a pure function of the report's own organisation evidence and scope, so
`scrutator verify` recomputes it and compares (`organisation derivable`); hiding or changing a company record, a breach
or a package result and re-signing the bundle fails that check. The three replayable sources (GLEIF, Wikidata, HIBP) can
be re-asked with `verify --replay`; the rest store a minimised projection and are skipped by a replay, like keyed
sources.
