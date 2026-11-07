"""Exposed services: the rule that reads Shodan InternetDB evidence, and, when an authorised active review ran, the
connection checks that confirm or contradict it.

InternetDB is Shodan's earlier scan, not a check made now, so a port it lists is a low-confidence finding that says so.
When the scan also holds `tcp` evidence (scrutator audit --active), each port is in one of three states and each is shown:

- open now: a connection succeeded. `exposed-risky-service` at high confidence, whether or not InternetDB listed the port;
- closed or unanswered now although InternetDB listed it: `stale-exposure-data` (info), citing both records;
- not checked (the plan did not reach it): still the low-confidence passive finding, for those ports only.

It fires only for ports that are rarely meant to face the whole internet; web and SSH are not on the list.
"""

from scrutator.active.records import active_records
from scrutator.exposure import exposure
from scrutator.model import Confidence
from scrutator.risk.catalog import make
from scrutator.risk.model import Risk, Severity

RISKY_PORTS = {
    21: "FTP", 23: "Telnet", 135: "Microsoft RPC", 139: "NetBIOS", 445: "SMB file sharing",
    873: "rsync", 1433: "Microsoft SQL Server", 1521: "Oracle database", 2049: "NFS",
    2375: "Docker API (unencrypted)", 3306: "MySQL", 3389: "Remote Desktop (RDP)", 5432: "PostgreSQL",
    5900: "VNC", 5984: "CouchDB", 6379: "Redis", 9200: "Elasticsearch", 11211: "memcached",
    27017: "MongoDB",
}
# Open now, these are rated high: a clear-text remote shell or file share, a remote desktop, a database or cache that is
# usually unauthenticated or one password away. The others (FTP, rsync, NFS, RPC, NetBIOS) stay at the rule's usual medium.
HIGH_WHEN_CONFIRMED = frozenset({23, 445, 1433, 1521, 2375, 3306, 3389, 5432, 5900, 5984, 6379, 9200, 11211, 27017})


def _label(port: int) -> str:
    return f"{port} ({RISKY_PORTS.get(port, 'service')})"


def spoken(banner: str) -> str:
    """The protocol a greeting says the server speaks, where it is unmistakable ("" otherwise)."""
    if banner.startswith("SSH-"):
        return "SSH"
    if banner.startswith("MySQL/MariaDB handshake"):
        return "MySQL/MariaDB"
    return ""


def _service(port: int, banner: str) -> str:
    """What the finding calls the service on `port`: the usual one, or, when the greeting names another protocol, both (a Telnet
    port that answers with an SSH identification line is an SSH service, not Telnet)."""
    usual, said = RISKY_PORTS[port], spoken(banner)
    if said and said.split("/")[0].lower() not in usual.lower():
        return f"{said} service on the usual {usual} port"
    return usual


def _state(rec) -> tuple[str, str]:
    return str(rec.payload.get("state", "")), str(rec.payload.get("detail", ""))


def exposed_services(report: dict) -> list[Risk]:
    active = active_records(report)
    risks = []
    rows = {row["ip"]: row for row in exposure(report)}
    for ip in {ip for ip, _ in active.tcp} - set(rows):  # checked now, never listed by a passive source (not indexed at all)
        rows[ip] = {"ip": ip, "ports": [], "evidence_ids": []}
    for row in (rows[ip] for ip in sorted(rows, key=lambda v: tuple(int(p) for p in v.split(".")) if v.count(".") == 3 else (999,))):
        ip = row["ip"]
        passive = sorted(p for p in row["ports"] if p in RISKY_PORTS)
        internetdb = [
            evidence_id for evidence_id in row["evidence_ids"]
            if report["evidence"][evidence_id]["source"] == "internetdb" and '"ports"' in report["evidence"][evidence_id]["payload"]
        ]
        checked = {port: active.tcp[(ip, port)] for port in passive if (ip, port) in active.tcp}
        open_now = sorted(port for (a, port), rec in active.tcp.items() if a == ip and port in RISKY_PORTS and _state(rec)[0] == "open")
        unchecked = [port for port in passive if port not in checked]

        if open_now:
            evidence = [active.tcp[(ip, port)].evidence_id for port in open_now]
            listed_too = [port for port in open_now if port in passive]
            if listed_too:
                evidence += internetdb
            sentences = []
            elsewhere = []  # open on a risky port, but the greeting shows a different service (e.g. SSH on port 23)
            for port in open_now:
                rec = active.tcp[(ip, port)]
                banner = str(rec.payload.get("banner") or "")
                sentences.append(
                    f"A connection to {ip}:{port} ({_service(port, banner)}) succeeded at {rec.collected_at}: the port is open now"
                    + (f"; it answered with the greeting {banner!r}" if banner else "") + "."
                )
                said = spoken(banner)
                if said and said.split("/")[0].lower() not in RISKY_PORTS[port].lower():
                    elsewhere.append(port)
            tail = []
            if listed_too:
                tail.append(f"Shodan InternetDB had also listed {', '.join(_label(p) for p in listed_too)} earlier.")
            not_listed = [p for p in open_now if p not in passive]
            if not_listed:
                tail.append(f"InternetDB had not listed {', '.join(_label(p) for p in not_listed)}: the check found what the earlier scan missed.")
            closed_now = [p for p in passive if p in checked and _state(checked[p])[0] in ("closed", "filtered") and p not in open_now]
            if closed_now:
                tail.append(f"InternetDB also listed {', '.join(_label(p) for p in closed_now)}, which the check found closed or unanswered now (see the stale-exposure-data finding).")
            if unchecked:
                tail.append(f"Not re-checked, so still only reported earlier by InternetDB: {', '.join(_label(p) for p in unchecked)}.")
            # a port whose greeting names another protocol is not rated as the service its number suggests: SSH on port 23 is
            # remote administration with a login, not a clear-text Telnet shell
            high = any(p in HIGH_WHEN_CONFIRMED and p not in elsewhere for p in open_now)
            risks.append(make(
                "exposed-risky-service", [f"ip:{ip}"], evidence, " ".join([*sentences, *tail]), Confidence.HIGH,
                severity=Severity.HIGH if high else None,
            ))
        elif unchecked:
            listed = ", ".join(_label(p) for p in unchecked)
            note = ""
            if checked:
                note = f" The other listed ports were checked now and are closed or unanswered ({', '.join(str(p) for p in sorted(checked))})."
            risks.append(make(
                "exposed-risky-service", [f"ip:{ip}"], internetdb,
                f"Shodan InternetDB lists these open ports on {ip}: {listed}. InternetDB reports an earlier scan by Shodan, not a check made now.{note}",
                Confidence.LOW,
            ))

        # every port a passive source listed open that a check made now found closed or unanswered, risky or not
        stale = sorted(
            port for port in {p for p in row["ports"] if isinstance(p, int)}
            if (ip, port) in active.tcp and _state(active.tcp[(ip, port)])[0] in ("closed", "filtered")
        )
        if stale and internetdb:
            parts = []
            for port in stale:
                state, detail = _state(active.tcp[(ip, port)])
                parts.append(f"{port}: {state}" + (f" ({detail})" if detail else ""))
            filtered = any(_state(active.tcp[(ip, p)])[0] == "filtered" for p in stale)
            checked_at = max(active.tcp[(ip, p)].collected_at for p in stale)
            risks.append(make(
                "stale-exposure-data", [f"ip:{ip}"], [*internetdb, *(active.tcp[(ip, p)].evidence_id for p in stale)],
                f"Shodan InternetDB listed {', '.join(str(p) for p in stale)} as open on {ip}. A connection check made at {checked_at} found: {'; '.join(parts)}. "
                "The earlier report may be out of date"
                + (", or something between the tester and the address blocks the connection ('filtered' says only that nothing answered)." if filtered else "."),
                Confidence.MEDIUM if filtered else Confidence.HIGH,
            ))
    return risks
