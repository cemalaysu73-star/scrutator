import ipaddress
from urllib.parse import urlsplit


def is_loopback(url: str) -> bool:
    """True only for localhost names and loopback addresses. Anything else, including
    look-alikes such as 127.0.0.1.evil.com and 0.0.0.0, is treated as remote."""
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return False
    if not host:
        return False
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
