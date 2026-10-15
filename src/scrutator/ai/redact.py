import ipaddress
import re
from collections.abc import Iterable

from scrutator.model.canonical import canonical_host

_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.]*\w)")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")


class Redactor:
    """Reversible pseudonymisation for prompts sent to non-local endpoints.
    Apex domains become d1.example, IPs ip-1, organisations org-1. Subdomain label words
    (dev, staging) are kept because the model reasons over them."""

    def __init__(self, apex_domains: Iterable[str] = (), orgs: Iterable[str] = ()) -> None:
        self._apex: dict[str, str] = {}
        self._orgs: dict[str, str] = {}
        self._ips: dict[str, str] = {}
        for domain in apex_domains:
            self.add_apex(domain)
        for org in orgs:
            self.add_org(org)

    def add_apex(self, domain: str) -> None:
        canonical = canonical_host(domain)
        self._apex.setdefault(canonical, f"d{len(self._apex) + 1}.example")

    def add_org(self, org: str) -> None:
        name = " ".join(org.split())
        if name:
            self._orgs.setdefault(name, f"org-{len(self._orgs) + 1}")

    def _ip_alias(self, ip: str) -> str:
        return self._ips.setdefault(ip, f"ip-{len(self._ips) + 1}")

    def redact(self, text: str) -> str:
        for org in sorted(self._orgs, key=len, reverse=True):
            text = re.sub(re.escape(org), self._orgs[org], text, flags=re.IGNORECASE)
        for apex in sorted(self._apex, key=len, reverse=True):
            pattern = rf"(?<![A-Za-z0-9-]){re.escape(apex)}(?![A-Za-z0-9-])"
            text = re.sub(pattern, self._apex[apex], text, flags=re.IGNORECASE)

        def swap_ip(match: re.Match[str]) -> str:
            value = match.group(0)
            if value == "::":
                return value
            try:
                ipaddress.ip_address(value)
            except ValueError:
                return value
            return self._ip_alias(value)

        return _IPV6.sub(swap_ip, _IPV4.sub(swap_ip, text))

    def restore(self, text: str) -> str:
        reverse = {
            **{alias: org for org, alias in self._orgs.items()},
            **{alias: apex for apex, alias in self._apex.items()},
            **{alias: ip for ip, alias in self._ips.items()},
        }
        for alias in sorted(reverse, key=len, reverse=True):
            text = text.replace(alias, reverse[alias])
        return text
