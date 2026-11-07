"""Risks derived from authorised active checks: TLS posture, HTTP posture, version banners.

Pure functions of a report's `tcp`, `tls` and `http` evidence (scrutator.active.records), like every other rule: no clock
(expiry is measured from the time the check was made), no network. Every finding says "checked" and cites the records of the
check; the confidence is high because the check was made by this tool at the time recorded, never inferred.
"""

from __future__ import annotations

import re
from datetime import timedelta
from urllib.parse import urlsplit

from scrutator.active.records import active_records
from scrutator.model import Confidence
from scrutator.risk.catalog import make
from scrutator.risk.model import Risk, Severity
from scrutator.risk.view import parse_time
from scrutator.scope import ScopePolicy

_VERSIONED = re.compile(r"([A-Za-z][A-Za-z0-9_.+-]{2,})[/_ -]v?(\d+(?:\.\d+){1,3}[A-Za-z0-9._+-]*)")
_SSH_PREFIX = re.compile(r"^SSH-\d\.\d+-")
_SHOWN = 160


def _in(ip: str) -> str:
    return f"ip:{ip}"


def _dom(name: str) -> str:
    return f"domain:{name}"


def _ports(ports) -> str:
    ports = sorted(set(ports))
    return ("port " if len(ports) == 1 else "ports ") + ", ".join(str(p) for p in ports)


def _clip(text: str) -> str:
    return text if len(text) <= _SHOWN else text[: _SHOWN - 3] + "..."


# TLS -------------------------------------------------------------------------------------------


def _tls_certificates(report: dict, found) -> list[Risk]:
    risks: list[Risk] = []
    grouped: dict[tuple[str, str], list] = {}
    for (ip, port, sni), rec in sorted(found.tls.items()):
        if rec.payload.get("handshake") == "ok" and sni:
            grouped.setdefault((ip, sni), []).append((port, rec))
    for (ip, sni), items in sorted(grouped.items()):
        entities = [_in(ip), _dom(sni)]
        ports = [p for p, _ in items]
        # the certificates of one name on one address: judged by the one that ends first
        dated = []
        for port, rec in items:
            checked, ends = parse_time(rec.collected_at), parse_time(str(rec.payload.get("not_after", "")))
            if checked is not None and ends is not None:
                dated.append((ends, port, rec, checked))
        if dated:
            ends, port, rec, checked = min(dated, key=lambda d: (d[0], d[1]))
            subject, issuer = _clip(str(rec.payload.get("subject", ""))), _clip(str(rec.payload.get("issuer", "")))
            left = ends - checked
            if left <= timedelta(0):
                risks.append(make(
                    "tls-cert-expired", entities, [rec.evidence_id],
                    f"The certificate that {ip}:{port} presented for {sni} at {rec.collected_at} expired on {ends.isoformat(timespec='seconds')} UTC "
                    f"(subject {subject}, issuer {issuer}).",
                    Confidence.HIGH,
                ))
            elif left < timedelta(days=30):
                days = left.days
                risks.append(make(
                    "tls-cert-expiring", entities, [rec.evidence_id],
                    f"The certificate that {ip}:{port} presented for {sni} at {rec.collected_at} expires on {ends.isoformat(timespec='seconds')} UTC, "
                    f"{days} day{'s' if days != 1 else ''} after the check (subject {subject}, issuer {issuer}).",
                    Confidence.HIGH, severity=Severity.HIGH if left < timedelta(days=7) else None,
                ))
        mismatched = [(port, rec) for port, rec in items if rec.payload.get("hostname_match") is False]
        if mismatched:
            port, rec = mismatched[0]
            names = ", ".join(str(n) for n in (rec.payload.get("san") or [])[:6]) or str(rec.payload.get("subject", ""))
            risks.append(make(
                "tls-hostname-mismatch", entities, [r.evidence_id for _, r in mismatched],
                f"{ip}:{port} answered a TLS handshake that asked for {sni} with a certificate that does not list it (it lists: {_clip(names)}); "
                f"checked at {rec.collected_at}.",
                Confidence.HIGH,
            ))
    return risks


def _tls_legacy(found) -> list[Risk]:
    by_ip: dict[str, list] = {}
    for (ip, port, version), rec in sorted(found.legacy.items()):
        if rec.payload.get("result") == "accepted":
            by_ip.setdefault(ip, []).append((port, version, rec))
    risks = []
    for ip, items in sorted(by_ip.items()):
        said = "; ".join(f"{_ports([p])} accepted {v}" for p, v, _ in items)
        risks.append(make(
            "tls-legacy-protocol", [_in(ip)], [r.evidence_id for _, _, r in items],
            f"{ip}: a TLS handshake restricted to an old protocol completed ({said}); checked at {items[0][2].collected_at}.",
            Confidence.HIGH,
        ))
    return risks


# HTTP ------------------------------------------------------------------------------------------


def _headers(rec) -> dict:
    headers = rec.payload.get("headers")
    return headers if isinstance(headers, dict) else {}


def _status(rec) -> int:
    status = rec.payload.get("status")
    return status if isinstance(status, int) and not isinstance(status, bool) else 0


def _redirects_to_https(rec, policy: ScopePolicy | None) -> bool:
    location = str(_headers(rec).get("location", ""))
    try:
        parts = urlsplit(location)
    except ValueError:
        return False
    if parts.scheme != "https" or not parts.hostname:
        return False
    return policy is None or policy.decide(parts.hostname).allowed


def _http(report: dict, found) -> list[Risk]:
    policy = ScopePolicy(**report["scope"]) if report.get("scope") else None
    risks: list[Risk] = []
    by_name: dict[tuple[str, str], dict[str, tuple[int, object]]] = {}
    for (ip, port, name, scheme), rec in sorted(found.http.items()):
        by_name.setdefault((ip, name), {})[scheme] = (port, rec)
    for (ip, name), schemes in sorted(by_name.items()):
        entities = [_in(ip), _dom(name)]
        plain, secure = schemes.get("http"), schemes.get("https")
        if plain is not None:
            port, rec = plain
            status = _status(rec)
            serves = 200 <= status < 300 or (300 <= status < 400 and _headers(rec).get("location") and not _redirects_to_https(rec, policy))
            if serves:
                what = f"answered with HTTP {status}" + (f" and a redirect to {_clip(str(_headers(rec).get('location')))}" if 300 <= status < 400 else " and content")
                risks.append(make(
                    "http-no-https-redirect", entities, [rec.evidence_id],
                    f"One plain-HTTP request for http://{name}/ to {ip}:{port} at {rec.collected_at} {what}, not a redirect to an HTTPS address of the organisation.",
                    Confidence.HIGH,
                ))
        if secure is not None:
            port, rec = secure
            status, headers = _status(rec), _headers(rec)
            if 200 <= status < 400:
                hsts = str(headers.get("strict-transport-security", "")).lower()
                match = re.search(r"max-age\s*=\s*\"?(\d+)", hsts)
                if not match or int(match.group(1)) == 0:
                    risks.append(make(
                        "http-missing-hsts", entities, [rec.evidence_id],
                        f"The HTTPS answer for https://{name}/ from {ip}:{port} at {rec.collected_at} (HTTP {status}) "
                        + ("had no Strict-Transport-Security header." if not hsts else f"sent Strict-Transport-Security with no usable max-age ({_clip(hsts)})."),
                        Confidence.HIGH,
                    ))
        for scheme in ("https", "http"):  # the secure answer is judged when there is one that serves a page, else the plain one
            chosen = schemes.get(scheme)
            if chosen is not None and 200 <= _status(chosen[1]) < 300:
                port, rec = chosen
                headers = _headers(rec)
                csp = str(headers.get("content-security-policy", ""))
                missing = []
                if not csp:
                    missing.append("Content-Security-Policy")
                if not headers.get("x-frame-options") and "frame-ancestors" not in csp.lower():
                    missing.append("X-Frame-Options (or CSP frame-ancestors)")
                if "nosniff" not in str(headers.get("x-content-type-options", "")).lower():
                    missing.append("X-Content-Type-Options: nosniff")
                if not headers.get("referrer-policy"):
                    missing.append("Referrer-Policy")
                if missing:
                    risks.append(make(
                        "http-missing-security-headers", entities, [rec.evidence_id],
                        f"The {scheme.upper()} answer for {scheme}://{name}/ from {ip}:{port} at {rec.collected_at} (HTTP {_status(rec)}) lacked: {', '.join(missing)}.",
                        Confidence.HIGH,
                    ))
                break
    return risks


# banners ---------------------------------------------------------------------------------------


def _version_in(text: str) -> str | None:
    if text.startswith("MySQL/MariaDB handshake: server "):
        # "5.5.5-10.6.20-MariaDB-x": MariaDB announces itself behind a fake 5.5.5 compatibility prefix
        version = text.split("server ", 1)[1]
        numbers = re.findall(r"\d+(?:\.\d+)+", version)
        if not numbers:
            return None
        maria = "mariadb" in version.lower()
        return f"{'MariaDB' if maria else 'MySQL'} {numbers[-1] if maria else numbers[0]}"
    match = _VERSIONED.search(_SSH_PREFIX.sub("", text))
    return f"{match.group(1)} {match.group(2)}" if match else None


def _banners(found) -> list[Risk]:
    by_ip: dict[str, list[tuple[str, str, str]]] = {}  # ip -> (where, what, evidence id)
    for (ip, port), rec in sorted(found.tcp.items()):
        if rec.payload.get("state") == "open" and rec.payload.get("banner"):
            seen = _version_in(str(rec.payload["banner"]))
            if seen:
                by_ip.setdefault(ip, []).append((f"port {port} greeting", seen, rec.evidence_id))
    for (ip, port, name, scheme), rec in sorted(found.http.items()):
        for header in ("server", "x-powered-by"):
            seen = _version_in(str(_headers(rec).get(header, "")))
            if seen:
                by_ip.setdefault(ip, []).append((f"{header} header of {scheme}://{name}/", seen, rec.evidence_id))
    risks = []
    for ip, items in sorted(by_ip.items()):
        unique = list(dict.fromkeys(items))
        risks.append(make(
            "server-banner-discloses-version", [_in(ip)], [e for _, _, e in unique],
            f"{ip} names software versions without being asked: " + "; ".join(f"{where}: {what}" for where, what, _ in unique[:6]) + ".",
            Confidence.HIGH,
        ))
    return risks


def active_risks(report: dict) -> list[Risk]:
    found = active_records(report)
    if not (found.tls or found.legacy or found.http or found.tcp):
        return []
    return [*_tls_certificates(report, found), *_tls_legacy(found), *_http(report, found), *_banners(found)]
