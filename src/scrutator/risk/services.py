"""Exposed services: the one rule that reads Shodan InternetDB evidence.

InternetDB is Shodan's earlier scan, not a check made now, so the rule is rated low confidence and
says so. It fires only for ports that are rarely meant to face the whole internet; web and SSH are
not on the list.
"""

from scrutator.exposure import exposure
from scrutator.model import Confidence
from scrutator.risk.catalog import make
from scrutator.risk.model import Risk

RISKY_PORTS = {
    21: "FTP", 23: "Telnet", 135: "Microsoft RPC", 139: "NetBIOS", 445: "SMB file sharing",
    873: "rsync", 1433: "Microsoft SQL Server", 1521: "Oracle database", 2049: "NFS",
    2375: "Docker API (unencrypted)", 3306: "MySQL", 3389: "Remote Desktop (RDP)", 5432: "PostgreSQL",
    5900: "VNC", 5984: "CouchDB", 6379: "Redis", 9200: "Elasticsearch", 11211: "memcached",
    27017: "MongoDB",
}


def exposed_services(report: dict) -> list[Risk]:
    risks = []
    for row in exposure(report):
        hits = [(port, RISKY_PORTS[port]) for port in row["ports"] if port in RISKY_PORTS]
        if not hits:
            continue
        evidence = [
            evidence_id for evidence_id in row["evidence_ids"]
            if report["evidence"][evidence_id]["source"] == "internetdb"
            and '"ports"' in report["evidence"][evidence_id]["payload"]
        ]
        listed = ", ".join(f"{port} ({name})" for port, name in hits)
        risks.append(
            make(
                "exposed-risky-service", [f"ip:{row['ip']}"], evidence,
                f"Shodan InternetDB lists these open ports on {row['ip']}: {listed}. "
                "InternetDB reports an earlier scan by Shodan, not a check made now.",
                Confidence.LOW,
            )
        )
    return risks
