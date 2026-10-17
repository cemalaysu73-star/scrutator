"""What the scan knows about the IP addresses it reached: open ports, products and vulnerabilities
(Shodan InternetDB), who to tell about a problem and what the network is called (RIPEstat).

A pure function of a report's own entities and evidence, like the findings and the risks, so
`scrutator verify` can recompute it from a bundle and compare. Only addresses the scan was allowed
to look at (`in` or `linked`) are described; evidence about any other address is ignored.
"""

import ipaddress
import json
import re
from urllib.parse import parse_qs, urlsplit

_INTERNETDB = re.compile(r"GET https://internetdb\.shodan\.io/(\S+)")
_RIPESTAT = re.compile(r"GET (https://stat\.ripe\.net/data/(abuse-contact-finder|whois)/data\.json\?\S+)")
_LOOKED_AT = ("in", "linked")
_WHOIS_FIELDS = {"netname": "netname", "country": "country", "descr": "description"}


def _slices(payload: str) -> list[dict]:
    try:
        rows = json.loads(payload)
    except ValueError:
        return []
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def _blank(ip: str, state: str) -> dict:
    return {
        "ip": ip, "state": state, "ports": [], "cpes": [], "vulns": [], "hostnames": [],
        "abuse_contacts": [], "netname": "", "country": "", "description": "", "evidence_ids": [],
    }


def exposure(report: dict) -> list[dict]:
    """One row per address that has InternetDB or RIPEstat evidence, sorted by address."""
    allowed = {e["value"]: e["state"] for e in report["entities"] if e["type"] == "ip" and e["state"] in _LOOKED_AT}
    rows: dict[str, dict] = {}
    seen: dict[tuple[str, str], set] = {}

    def add(ip: str, key: str, values, evidence_id: str) -> None:
        target = rows.setdefault(ip, _blank(ip, allowed[ip]))
        bucket = seen.setdefault((ip, key), set())
        wanted = int if key == "ports" else str
        for value in values:
            if isinstance(value, wanted) and not isinstance(value, bool):
                bucket.add(value)
        target["evidence_ids"].append(evidence_id)

    def put(ip: str, key: str, value, evidence_id: str) -> None:
        target = rows.setdefault(ip, _blank(ip, allowed[ip]))
        target[key] = target[key] or str(value)
        target["evidence_ids"].append(evidence_id)

    for evidence_id in sorted(report["evidence"]):
        record = report["evidence"][evidence_id]
        request = record["request"]
        if record["source"] == "internetdb":
            match = _INTERNETDB.fullmatch(request)
            if not match or match.group(1) not in allowed:
                continue
            ip = match.group(1)
            for item in _slices(record["payload"]):
                if item.get("ip") != ip:
                    continue
                for key in ("ports", "cpes", "vulns", "hostnames"):
                    if isinstance(item.get(key), list):
                        add(ip, key, item[key], evidence_id)
        elif record["source"] == "ripestat":
            match = _RIPESTAT.fullmatch(request)
            if not match:
                continue
            ip = (parse_qs(urlsplit(match.group(1)).query).get("resource") or [""])[0]
            if ip not in allowed:
                continue
            for item in _slices(record["payload"]):
                if match.group(2) == "abuse-contact-finder" and isinstance(item.get("abuse_contacts"), list):
                    add(ip, "abuse_contacts", item["abuse_contacts"], evidence_id)
                elif match.group(2) == "whois" and item.get("key") in _WHOIS_FIELDS:
                    put(ip, _WHOIS_FIELDS[item["key"]], item.get("value", ""), evidence_id)

    for (ip, key), values in seen.items():
        rows[ip][key] = sorted(values)
    for row in rows.values():
        row["evidence_ids"] = sorted(set(row["evidence_ids"]))
    return [rows[ip] for ip in sorted(rows, key=lambda v: (ipaddress.ip_address(v).version, ipaddress.ip_address(v)))]
