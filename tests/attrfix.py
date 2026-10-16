"""Reports for the attribution tests, built from the same shapes a real scan produces.

`AttrZone` extends the risk tests' `Zone` with the records attribution reads: certificates that
list several names, registrants and netblock owners. Only reserved names are used."""

import json

from riskfix import COLLECTED, Zone

CRT = "GET https://crt.sh/?q=%25.{root}&output=json"
LETS_ENCRYPT = "C=US, O=Let's Encrypt, CN=R3"


class AttrZone(Zone):
    def state_of(self, value):
        return "in" if any(value == d or value.endswith("." + d) for d in self.scope["domains"]) else "out"

    def candidate(self, value):
        """A name outside the scope that the scan decided to look at passively."""
        return self.name(value, "candidate")

    def outside(self, value):
        return self.name(value, "out")

    def cert(
        self,
        *names,
        root="example.com",
        issuer=LETS_ENCRYPT,
        cert_id=1,
        not_before="2026-09-01T00:00:00",
        not_after="2026-12-01T00:00:00",
        collected=None,
    ):
        """One certificate listing `names`, as crt.sh returns it for a query on `root`: one record
        per name other than the root, each holding the certificates that name appears on, and a
        relation from the root to that name."""
        row = {"id": cert_id, "issuer_name": issuer, "name_value": "\n".join(names), "not_before": not_before, "not_after": not_after}
        evidence = []
        for name in names:
            if name == root:
                continue
            eid = self.ev("crtsh", CRT.format(root=root), json.dumps([row], sort_keys=True), collected)
            rel = "has_subdomain" if name.endswith("." + root) else "related_host"
            self.edge(self.name(root, self.state_of(root)), rel, self.name(name, self.state_of(name)), eid)
            evidence.append(eid)
        return evidence

    def registrant(self, name, org):
        payload = json.dumps(
            {"ldhName": name.upper(), "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", org]]]}]},
            sort_keys=True,
        )
        eid = self.ev("rdap", f"GET https://rdap.org/domain/{name}", payload)
        self.edge(self.name(name, self.state_of(name)), "registrant", self.entity("org", org, "in"), eid)
        return eid

    def owner(self, ip, org):
        eid = self.ev("rdap", f"GET https://rdap.org/ip/{ip}", json.dumps({"name": org}, sort_keys=True))
        self.edge(self.entity("ip", ip, "linked"), "netblock_owner", self.entity("org", org, "in"), eid)
        return eid

    def spf_of(self, name, *includes):
        return self.txt(name, "v=spf1 " + " ".join(f"include:{i}" for i in includes) + " -all")

    def link(self, src, rel, dst, eid):
        """A relation backed by evidence that already exists (an NS, MX or TXT record)."""
        self.edge(self.name(src, self.state_of(src)), rel, self.name(dst, self.state_of(dst)), eid)


__all__ = ["AttrZone", "COLLECTED", "LETS_ENCRYPT"]
