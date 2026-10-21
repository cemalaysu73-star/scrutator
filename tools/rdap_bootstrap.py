#!/usr/bin/env python
"""Refresh the bundled snapshot of IANA's RDAP bootstrap registry for IP addresses (RFC 9224).

    python tools/rdap_bootstrap.py            # writes src/scrutator/modules/rdap_bootstrap.json

Scrutator asks the regional registry (RIR) that holds an address directly instead of going through the rdap.org
redirector, whose rate limit (about ten requests in ten seconds) was the longest wait of a scan. Which RIR holds which
block comes from IANA's bootstrap files. The RIRs refer a query about space they do not hold to the RIR that does
(HTTP 301/303, checked 2026-10-21), so an out-of-date snapshot costs one redirect, never a wrong answer.

Only the https base URLs of the five RIRs are kept; anything else in the files is dropped.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.request import Request, urlopen

FILES = {"ipv4": "https://data.iana.org/rdap/ipv4.json", "ipv6": "https://data.iana.org/rdap/ipv6.json"}
RIR_HOSTS = ("rdap.arin.net", "rdap.db.ripe.net", "rdap.apnic.net", "rdap.lacnic.net", "rdap.afrinic.net")
OUT = Path(__file__).resolve().parent.parent / "src" / "scrutator" / "modules" / "rdap_bootstrap.json"


def main() -> int:
    snapshot: dict = {"source": FILES, "publication": {}, "services": {}}
    for family, url in FILES.items():
        with urlopen(Request(url, headers={"User-Agent": "scrutator-tools"}), timeout=30) as resp:  # noqa: S310
            data = json.load(resp)
        snapshot["publication"][family] = data.get("publication")
        table: dict[str, list[str]] = {}
        for prefixes, bases in data["services"]:
            base = next((b for b in bases if b.startswith("https://") and b.split("/")[2] in RIR_HOSTS), None)
            if base is None:
                continue
            base = base if base.endswith("/") else base + "/"
            table.setdefault(base, []).extend(sorted(prefixes))
        snapshot["services"][family] = table
    OUT.write_text(json.dumps(snapshot, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {OUT} ({sum(len(v) for t in snapshot['services'].values() for v in t.values())} prefixes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
