"""Authorised active confirmation: `scrutator audit --active`.

A passive review reports what third parties say (Shodan saw port 23 open last month). Active confirmation answers
whether it is true now, with a handful of ordinary connections to the addresses of the client's own names. It is
opt-in, authorised, bounded and recorded; what it does and never does is in docs/active.md.

    plan.py    which addresses and ports may be probed: a pure function of the scan's own evidence (so `verify` re-derives it)
    gate.py    the authorisation gate: no engagement or attestation that covers active testing, no connection
    guard.py   address refusals (private, loopback, link-local, reserved), shared platforms, the connection budget
    probes.py  TCP connect + banner, TLS handshake, one HTTP GET: the only things ever sent
    run.py     the orchestrator: audit-log records before the first connection, evidence per probe, Ctrl-C safe
    section.py the report's `active` section, derived from the evidence alone
"""

from scrutator import __version__

# The evidence sources of active probes. A replay never contacts a target for any of them; verify checks them.
SOURCES = ("tcp", "tls", "http", "active")
PROBE_SOURCES = ("tcp", "tls", "http")

# Fixed in code, never read from a response, a bundle or a pack: the ports probed besides those a passive source says
# are open on the address. Each is there for a stated reason (docs/active.md).
RISKY_PORTS = (21, 22, 23, 25, 110, 143, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017)
WEB_PORTS = (80, 443)
PORT_REASONS = {
    21: "FTP: clear-text credentials, often left open by old hosting panels",
    22: "SSH: confirms remote administration is reachable (banner shows the software version)",
    23: "Telnet: clear-text remote shell, should not exist on the internet",
    25: "SMTP: mail relay (many networks block outbound 25, so 'filtered' can be the tester's own network)",
    110: "POP3: clear-text mail retrieval",
    143: "IMAP: clear-text mail retrieval",
    445: "SMB: Windows file sharing, a common ransomware entry point",
    1433: "Microsoft SQL Server",
    3306: "MySQL / MariaDB",
    3389: "Remote Desktop (RDP)",
    5432: "PostgreSQL",
    5900: "VNC remote screen",
    6379: "Redis cache, frequently unauthenticated",
    8080: "alternative HTTP, often an admin panel or a forgotten test service",
    8443: "alternative HTTPS, often an admin console",
    9200: "Elasticsearch HTTP API",
    11211: "memcached",
    27017: "MongoDB",
    80: "HTTP: redirect and header posture",
    443: "HTTPS: certificate, protocol and header posture",
}
# Ports on which a TLS handshake is tried when the TCP connect finds them open (handshake only: nothing else is sent).
TLS_PORTS = (443, 8443, 465, 993, 995, 636)
# Ports on which one HTTP GET / is sent: plain HTTP on 80, HTTP over TLS on 443. Nowhere else.
HTTP_PORT, HTTPS_PORT = 80, 443
# What the three constants above are in a release. A test may rebind them so that local listeners on other ports stand in for
# a web server; a run that did so says so in the signed audit log (`test_ports`), and only a run in test mode may.
DEFAULT_PORTS = {"http": 80, "https": 443, "tls": (443, 8443, 465, 993, 995, 636)}

USER_AGENT = f"Scrutator/{__version__} (authorised review)"
MAX_BANNER = 256
