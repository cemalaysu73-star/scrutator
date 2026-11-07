"""The authorisation gate: no authorisation that covers active testing, no connection.

Active confirmation needs the same two things as an audit (an engagement file, or a self-attestation) and one more:
the authorisation must say it covers active testing. For a client engagement that is `active_testing: true` in the
signed engagement file; for a self-assessment it is the attestation made with `--active`, which names the systems the
domains resolve to, not only the domains. The record is in the signed audit log before the first lookup.
"""

from __future__ import annotations

from scrutator.active.guard import Limits


class ActiveRefused(ValueError):
    """Active confirmation was asked for without an authorisation that covers it. Nothing was sent."""


def active_authorisation(events: list[dict] | None) -> dict:
    """The authorisation event (engagement or self-attestation) among the events about to be written to the audit log, if
    it covers active testing; otherwise ActiveRefused."""
    for event in events or ():
        kind = event.get("event")
        if kind == "engagement":
            if event.get("active_testing") is True:
                return event
            raise ActiveRefused(
                "the engagement does not authorise active testing: the signed letter must allow it, and the engagement file "
                "must then say `active_testing: true`. No connection was made."
            )
        if kind == "self_attestation":
            if event.get("active") is True:
                return event
            raise ActiveRefused("a self-assessment must attest that you own or control the systems the domains point at (--active). No connection was made.")
    raise ActiveRefused("active confirmation needs an authorisation: an engagement file (--engagement) or --self. No connection was made.")


def authorised_event(limits: Limits, *, fixed_ports, proxy: str | None, relax: frozenset[str]) -> dict:
    """The audit-log record written, before any lookup, when active confirmation is in force: what it may do and the
    limits it runs under."""
    event = {
        "event": "active_confirmation_authorised", "by": "--active",
        "may": ["tcp connect and banner read", "tls handshake", "one http GET / (fixed User-Agent)"],
        "never": ["login or credential attempts", "exploit or vulnerability payloads", "fuzzing", "directory brute force", "udp", "other addresses than the plan"],
        "limits": limits.record(), "fixed_ports": list(fixed_ports), "proxy": proxy,
    }
    if relax:
        from scrutator import active

        event["test_mode"] = sorted(relax)
        ports = {"http": active.HTTP_PORT, "https": active.HTTPS_PORT, "tls": list(active.TLS_PORTS)}
        if ports != {**active.DEFAULT_PORTS, "tls": list(active.DEFAULT_PORTS["tls"])}:
            event["test_ports"] = ports
    return event
