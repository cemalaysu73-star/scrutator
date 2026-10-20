"""The planted risk lab and the clean control zone, as the tests use them through respx. The lab itself (zones,
planted issues, source answers) lives in scrutator.benchlab.risklab, where `scrutator bench` runs the same one."""

from datetime import datetime, timezone

from scrutator.benchlab.risklab import (  # noqa: F401 - re-exported for the tests
    PLANTED,
    PLANTED_RULES,
    SCOPE_DOMAINS,
    TXT,
    clean_router,
    clean_zone,
    lab_packs_dir,
    lab_router,
    lab_zone,
    rdap_body,
    stamp,
)


def lab_sources(router):
    """The lab: example.com expires in 20 days, example.net expired 5 days ago, the registry
    lists a name server the zone does not, and certificates and the archive name hosts."""
    router.route().mock(side_effect=lab_router())
    return datetime.now(timezone.utc)


def clean_sources(router):
    router.route().mock(side_effect=clean_router())
    return datetime.now(timezone.utc)
