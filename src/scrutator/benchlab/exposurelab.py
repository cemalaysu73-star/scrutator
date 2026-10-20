"""The organisation-exposure lab: a planted organisation (example.com) that publishes work addresses in the places the
exposure modules read, and planted personal data that must never come out. No network.

Planted and expected (aggregate):
- role mailboxes: security@ (security.txt), info@ and billing@ (home page), jobs@ (contact page), hostmaster@ (RDAP),
  dmarc-reports@ (DMARC rua): six, functions security, general, finance, hr, it, automation;
- person-like work addresses: jane.doe@, john.smith@ and a.berg@ (contact page), m.ross@ (SOA contact), p.kim@ and
  jane.doe@ again (commits): five distinct, three `initial.word` and two `word.word`;
- outside the engagement, dropped and only counted: a personal gmail address on the contact page, a registrar's abuse
  address in RDAP, a DMARC report processor, a commit from another company.

Personal data that must not appear in any aggregate output (PERSONAL): the names, the person-like addresses, phone
numbers, a street address, a private address and a social handle on the contact page.
"""

import httpx

from scrutator.benchlab.fakes import Router

SITE = "example.com"

ENGAGEMENT_YAML = """organisation: Example Corp (lab)
domains: [example.com]
authorised_by: {name: Lab Authoriser, role: CISO}
start: 2026-01-01
end: 2030-12-31
purpose: Planted lab for the organisation-exposure benchmark
github_orgs: [example-lab]
"""

SECURITY_TXT = "Contact: mailto:security@example.com\nExpires: 2030-01-01T00:00:00.000Z\nPreferred-Languages: en\n"
HOME = """<html><body><h1>Example Corp</h1>
<a href="mailto:info@example.com">Write to us</a> · invoices: billing@example.com
<a href="/contact">Contact</a> <a href="/about-us">About</a> <a href="https://example.net/contact">partner</a>
<a href="/blog/2026/post">blog</a>
</body></html>"""
CONTACT = """<html><body>
<h2>Our team</h2>
<p>Jane Doe, Chief Financial Officer: <a href="mailto:jane.doe@example.com">jane.doe@example.com</a>, +31 20 555 0123</p>
<p>John Smith, IT manager: john.smith@example.com, mobile 06-12345678, home: Main Street 1, Springfield</p>
<p>Anna Berg: a.berg@example.com (private: anna.berg.private@gmail.com, @annaberg on X)</p>
<p>Applications: jobs@example.com</p>
</body></html>"""
ABOUT = "<html><body><p>Founded in 1999. Call +1 555 0100.</p></body></html>"
RDAP = {
    "objectClassName": "domain",
    "ldhName": "example.com",
    "entities": [
        {"roles": ["technical"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["email", {}, "text", "hostmaster@example.com"]]]},
        {"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@registrar.example.net"], ["tel", {}, "uri", "tel:+1.5555550100"]]]},
    ],
}
DNS = {
    ("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com,mailto:x@dmarc.vendor.example.org"'],
    ("example.com", "SOA"): ["ns1.example.com. m\\.ross.example.com. 2026102001 7200 3600 1209600 3600"],
}
REPOS = [{"name": "website"}, {"name": "tools"}]
COMMITS = {
    "website": [
        {"commit": {"author": {"name": "P Kim", "email": "p.kim@example.com"}, "committer": {"name": "GitHub", "email": "noreply@github.com"}}},
        {"commit": {"author": {"name": "Jane Doe", "email": "jane.doe@example.com"}, "committer": {"name": "Jane Doe", "email": "jane.doe@example.com"}}},
    ],
    "tools": [
        {"commit": {"author": {"name": "Contractor", "email": "dev@othercompany.example.org"}, "committer": {"name": "x", "email": "123+x@users.noreply.github.com"}}},
    ],
}

PERSONAL = (
    "Jane Doe", "jane.doe", "John Smith", "john.smith", "Anna Berg", "a.berg", "anna.berg.private", "m.ross", "p.kim",
    "555 0123", "12345678", "Main Street", "Springfield", "@annaberg", "+1.5555550100", "dev@othercompany", "Lab Authoriser",
)
# Lab Authoriser is the engagement's own record (who authorised the work): it is in the audit log and the report's
# engagement block by design, so the personal-data scan of outputs skips that block (see PERSONAL_EXCEPT_ENGAGEMENT).
PERSONAL_EXCEPT_ENGAGEMENT = tuple(p for p in PERSONAL if p != "Lab Authoriser")

TRUTH = {
    "role": 6,
    "person_like": 5,
    "functions": {"automation": 1, "finance": 1, "general": 1, "hr": 1, "it": 1, "security": 1},
    "top_shape": "initial.word",
    "outside": 4,
}
ALLOWED_HOSTS = {SITE, "rdap.org", "api.github.com"}


def router() -> Router:
    lab = Router()
    lab.add(SITE, "/robots.txt", httpx.Response(200, text="User-agent: *\nDisallow: /blog/\n"))
    lab.add(SITE, "/.well-known/security.txt", httpx.Response(200, text=SECURITY_TXT))
    lab.add(SITE, "/", httpx.Response(200, text=HOME, headers={"content-type": "text/html"}))
    lab.add(SITE, "/contact", httpx.Response(200, text=CONTACT, headers={"content-type": "text/html"}))
    lab.add(SITE, "/about-us", httpx.Response(200, text=ABOUT, headers={"content-type": "text/html"}))
    lab.add("rdap.org", "/domain/example.com", httpx.Response(200, json=RDAP))
    lab.add("api.github.com", "/orgs/example-lab/repos", httpx.Response(200, json=REPOS))
    for name, rows in COMMITS.items():
        lab.add("api.github.com", f"/repos/example-lab/{name}/commits", httpx.Response(200, json=rows))
    return lab


class Resolver:
    """The lab's DNS: only the records above; everything else is empty."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def lookup(self, name, rtype):
        self.calls.append((name, rtype))
        return list(DNS.get((name, rtype), []))


async def public_resolve(host: str) -> list[str]:
    return ["93.184.215.14"]
