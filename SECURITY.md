# Security policy and responsible use

## Reporting a vulnerability

Do not open a public issue for a security problem.

- **How:** use GitHub's private vulnerability reporting: open the repository's **Security** tab, choose **Report a
  vulnerability**, and describe the problem there. Only the maintainers can see it. If that option is missing, open a
  public issue that says only "I have a security report, please enable private reporting" and put no details in it.
- **What to include:** the version (`scrutator --version`), the platform, what you did, what happened, and, if you
  have one, a proof bundle or a minimal fixture that shows it. Never send a real signing key or a real API key.
- **What to expect:** this is a volunteer project without a service level. The maintainer aims to acknowledge a
  report within 7 days and to say within 30 days whether it is accepted, but those are intentions, not promises.
  Fixes go into the next release with a CHANGELOG entry; reporters are credited unless they ask not to be.

### What counts

Anything that breaks one of the guarantees in [docs/security.md](docs/security.md), in particular:

- a request to a host that is not in scope or not a source host (a scope or egress bypass);
- a bundle that `scrutator verify` accepts although a byte was changed, or a bundle that makes `verify` or the MCP
  server crash, hang, read outside the bundle, or use unbounded memory;
- a secret (an API key, a signing key, a passphrase) reaching a report, bundle, log, database, MCP result or error;
- text from a data source that executes in the HTML report or on the terminal;
- an AI summary or lead that reaches the report without evidence, or a planted instruction in collected data that
  changes what the tool does.

Known limits are listed in docs/security.md. A report of a listed limit is welcome as a suggestion but is not a
vulnerability.

## Supported versions

Only the latest release and the latest commit on the main branch are supported. Fixes go into the next release.

## Responsible use

Scrutator is a passive tool: it asks public sources (certificate transparency, DNS, RDAP, archives, aggregators)
what they know about a domain. It never port-scans, never probes the target, never brute-forces names and never
searches for a named private individual.

Even so:

- Third-party services see what you search for. Only investigate organisations you are authorised to assess, or that
  you are entitled to research, and respect each source's terms (see [docs/sources.md](docs/sources.md); several free
  tiers are for non-commercial use only, and `--no-noncommercial` leaves them out).
- A finding is a lead for the owner to confirm, not proof of compromise or wrongdoing. Risks describe configuration
  visible in public records. Attribution is a score with reasons; a `candidate` is not the organisation's until a
  human promotes it.
- Do not use the tool or its output to harass, profile or locate individuals. Names of people that appear in public
  records (for example in RDAP) are data you should handle like any personal data under the law that applies to you.
- Examples, tests and the demo use only `example.com`, reserved documentation ranges and fixtures. Do not publish
  reports about third-party organisations without their permission.
- Cloud AI is an explicit opt-in. In cloud mode a summary of what was found leaves your machine (logged in the
  report); use `--redact` if the organisation's name must not.

## Handling keys

- The signing key proves who made a bundle. Protect it with a passphrase (`scrutator keygen --passphrase`,
  `scrutator protect-key`); anyone who holds the key can sign bundles as you. On Windows file permissions are not
  tightened by the tool.
- Source API keys are read from environment variables only and are never stored.
