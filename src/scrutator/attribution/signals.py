"""The evidence that ties a name outside the scope to the organisation.

Each extractor looks at one kind of evidence for one candidate name and returns at most one
Signal: the strongest of that kind. A signal whose evidence points at a shared provider (a CDN, a
mail service, a public CA) is kept with weight 0 and a note, so a reader can see what was seen and
why it was not counted. Nothing here reads a clock or the network; the inputs are the Index, whose
tables over the in-scope names are built once, so a scan with thousands of candidates stays fast.
"""

from collections.abc import Callable

from scrutator.attribution.index import Index
from scrutator.attribution.model import SIGNALS, Signal

_CLIP = 80
SMALL_CERT = 10  # a certificate with more names than this is probably a shared service's
STALE_AFTER_DAYS = 365  # a certificate that had been expired this long when it was collected says little


def _clip(text: str) -> str:
    return text if len(text) <= _CLIP else text[: _CLIP - 3] + "..."


def _signal(kind: str, detail: str, evidence: tuple[str, ...] | list[str], *, factor: float = 1.0, note: str = "") -> Signal:
    raw = SIGNALS[kind][0]
    return Signal(kind, round(raw * factor, 4), raw, detail, tuple(sorted(set(evidence))), note)


def _best(found: list[Signal]) -> list[Signal]:
    if not found:
        return []
    return [min(found, key=lambda s: (-s.weight, s.evidence_ids, s.detail))]


def _shared_provider(view: Index, kind: str, values: list[str]) -> str:
    """Names of the providers the pack data recognises behind these values; empty if any of them
    is unknown (one unknown host keeps the evidence alive)."""
    providers = []
    for value in values:
        entry = view.packs.match_provider(kind, value)
        if entry is None:
            return ""
        providers.append(entry.provider)
    return ", ".join(sorted(set(providers)))


# delegation and mail: the candidate's own records point into the scope


def ns_in_scope(view: Index, name: str) -> list[Signal]:
    found = view.targets("NS", name)
    if found is None:
        return []
    inside = [t for t in found[0] if view.in_scope(t)]
    if not inside:
        return []
    return [_signal("ns_in_scope", f"{name} is delegated to {', '.join(inside)}", [found[1]])]


def mx_in_scope(view: Index, name: str) -> list[Signal]:
    found = view.targets("MX", name)
    if found is None:
        return []
    inside = [t for t in found[0] if view.in_scope(t)]
    if not inside:
        return []
    return [_signal("mx_in_scope", f"mail for {name} is received by {', '.join(inside)}", [found[1]])]


def spf_in_scope(view: Index, name: str) -> list[Signal]:
    found = view.spf_targets(name)
    if found is None:
        return []
    inside = [t for t in found[0] if view.in_scope(t)]
    if not inside:
        return []
    return [_signal("spf_in_scope", f"the SPF record of {name} includes {', '.join(inside)}", [found[1]])]


# certificates


def cert_san(view: Index, name: str) -> list[Signal]:
    found = []
    for cert in view.certs_naming(name):
        inside = [n for n in cert.names if view.in_scope(n)]
        if not inside:
            continue
        size = len(cert.names)
        factor, notes = 1.0, []
        if size > SMALL_CERT:
            factor *= SMALL_CERT / size
            notes.append(f"the certificate lists {size} names, which looks like a shared service")
        expired = view.expired_days(cert)
        if expired is not None and expired > STALE_AFTER_DAYS:
            factor *= 0.5
            notes.append(f"the certificate had been expired for {int(expired)} days when it was collected")
        found.append(
            _signal(
                "cert_san",
                f"certificate {cert.cert_id or '?'} lists {inside[0]} and {name} ({size} names)",
                [cert.evidence_id],
                factor=factor,
                note="; ".join(notes),
            )
        )
    return _best(found)


def cert_issuer(view: Index, name: str) -> list[Signal]:
    found = []
    for cert in view.certs_naming(name):
        if any(view.in_scope(n) for n in cert.names) or not cert.issuer.strip():
            continue  # a certificate that also lists the scope is already a cert_san signal
        others = [c for c in view.scope_issuers.get(cert.issuer.strip().lower(), []) if name not in c.names]
        if not others:
            continue
        other = min(others, key=lambda c: c.evidence_id)
        entry = view.packs.match_provider("issuer", cert.issuer)
        if entry is not None:
            found.append(
                _signal(
                    "cert_issuer", f"both use certificates from {entry.provider}",
                    [cert.evidence_id, other.evidence_id], factor=0.0,
                    note=f"{entry.provider} issues certificates for many unrelated organisations",
                )
            )
        else:
            found.append(
                _signal(
                    "cert_issuer", f"both use certificates from the issuer {_clip(cert.issuer)}",
                    [cert.evidence_id, other.evidence_id],
                )
            )
    return _best(found)


# registration


def rdap_registrant(view: Index, name: str) -> list[Signal]:
    found = []
    for org, own_evidence in view.registrants(name):
        for other, _, evidence in view.registrant_holders.get(org.casefold(), []):
            found.append(_signal("rdap_registrant", f"{name} and {other} have the registrant {_clip(org)}", [*evidence, *own_evidence]))
    return _best(found)


# shared infrastructure that is not a shared provider


def shared_ns(view: Index, name: str) -> list[Signal]:
    mine = view.targets("NS", name)
    if mine is None or all(view.in_scope(t) for t in mine[0]):
        return []
    found = []
    for zone, theirs in view.scope_zones.items():
        outside = {t for t in set(mine[0]) & set(theirs[0]) if not view.in_scope(t)}
        if not outside:
            continue
        evidence = [mine[1], theirs[1]]
        provider = _shared_provider(view, "ns", sorted(set(mine[0])))
        if provider:
            found.append(
                _signal(
                    "shared_ns", f"{name} and {zone} use the same name servers ({provider})", evidence, factor=0.0,
                    note=f"the name servers belong to {provider}, which serves many unrelated organisations",
                )
            )
        elif set(mine[0]) == set(theirs[0]):
            found.append(_signal("shared_ns", f"{name} and {zone} use the same name servers {', '.join(mine[0])}", evidence))
        else:
            found.append(
                _signal(
                    "shared_ns", f"{name} and {zone} share the name server(s) {', '.join(sorted(outside))}", evidence, factor=0.5,
                    note="the two name server sets overlap but are not the same",
                )
            )
    return _best(found)


def shared_mx(view: Index, name: str) -> list[Signal]:
    mine = view.targets("MX", name)
    if mine is None:
        return []
    found = []
    others: dict[str, list[tuple[str, str]]] = {}
    for host_name in mine[0]:
        if not view.in_scope(host_name):
            for other, evidence in view.mx_users.get(host_name, []):
                others.setdefault(other, []).append((host_name, evidence))
    for other, shared in sorted(others.items()):
        common = sorted({h for h, _ in shared})
        evidence = [mine[1], shared[0][1]]
        provider = _shared_provider(view, "mx", common)
        if provider:
            found.append(
                _signal(
                    "shared_mx", f"{name} and {other} receive mail on {provider}", evidence, factor=0.0,
                    note=f"{provider} receives mail for many unrelated organisations",
                )
            )
        else:
            found.append(_signal("shared_mx", f"{name} and {other} receive mail on {', '.join(common)}", evidence))
    return _best(found)


def network_owner(view: Index, name: str) -> list[Signal]:
    found = []
    for ip, evidence in view.addresses(name):
        own = view.networks(ip)
        for kind, value, own_ev in own:
            for other_ip, other_evidence, theirs in view.scope_networks.get((kind, value), []):
                their_ev = next((ev for k, v, ev in theirs if (k, v) == (kind, value)), ())
                ids = [*evidence, *other_evidence, *own_ev, *their_ev]
                asns = [v for k, v, _ in [*own, *theirs] if k == "asn"]
                shared = _shared_provider(view, "asn", asns) if asns else ""
                label = f"AS number {value}" if kind == "asn" else f"netblock owner {value}"
                if shared:
                    found.append(
                        _signal(
                            "network_owner", f"{name} and an in-scope name are both in {label}", ids, factor=0.0,
                            note=f"the network belongs to {shared}, which hosts many unrelated organisations",
                        )
                    )
                else:
                    found.append(_signal("network_owner", f"{name} ({ip}) and an in-scope address are both in {label}", ids))
    return _best(found)


def scope_uses(view: Index, name: str) -> list[Signal]:
    found = []
    for other, label, kind, evidence in view.uses.get(name, []):
        entry = view.packs.match_provider(kind, name)
        if entry is not None:
            found.append(
                _signal(
                    "scope_uses", f"{other} uses {name} for {label}", [evidence], factor=0.0,
                    note=f"{name} belongs to {entry.provider}, a provider many organisations use",
                )
            )
        else:
            found.append(_signal("scope_uses", f"{other} uses {name} for {label}", [evidence]))
    return _best(found)


def org_record(view: Index, name: str) -> list[Signal]:
    records = view.org_records(name)
    if not records:
        return []
    evidence = tuple(sorted({e for _, ids in records for e in ids}))
    how = "Wikidata" if any(rel == "org_official_site" for rel, _ in records) else "the organisation's GitHub repositories"
    return [_signal("org_record", f"{name} is listed as an official domain of the organisation by {how}", evidence)]


EXTRACTORS: tuple[Callable[[Index, str], list[Signal]], ...] = (
    org_record,
    ns_in_scope,
    mx_in_scope,
    spf_in_scope,
    cert_san,
    rdap_registrant,
    shared_ns,
    shared_mx,
    network_owner,
    scope_uses,
    cert_issuer,
)


def signals_for(view: Index, name: str) -> list[Signal]:
    """Every signal found for a candidate name, strongest first."""
    found = [signal for extractor in EXTRACTORS for signal in extractor(view, name)]
    return sorted(found, key=lambda s: (-s.weight, s.kind))
