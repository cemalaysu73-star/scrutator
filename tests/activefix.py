"""Scans built by hand for the active-confirmation tests: in-scope names that resolve to addresses, with the passive
evidence (InternetDB ports, an announcing AS, a CNAME) the plan reads. Addresses are RFC 5737 documentation addresses
(allowed only through the tests' `relax`) or 127.0.0.1 (a local listener standing in for a server)."""

from scrutator.active.guard import Limits
from scrutator.active.run import ActiveConfig
from scrutator.benchlab.activelab import make_active_store  # noqa: F401 (re-exported for the tests)

RELAX = frozenset({"loopback", "documentation"})
FAST = Limits(connect_timeout=0.5, banner_timeout=0.3, handshake_timeout=1.5, http_timeout=1.5, rate_per_second=50.0, deadline_s=30.0)


def config(**changes) -> ActiveConfig:
    limits = Limits(**{**FAST.__dict__, **changes}) if changes else FAST
    return ActiveConfig(limits=limits, relax=RELAX)


def self_authorisation(domain="example.com", *, active=True):
    from scrutator.audit.content import self_event

    return [self_event([domain], "", "--yes", active=active)]
