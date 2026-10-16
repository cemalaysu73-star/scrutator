"""The attribution engine: a pure function of a report's own content and the pack data.

`attribute` reads only `scope`, `entities`, `edges` and `evidence` from the report, plus the packs
(passed in, or the ones embedded in the report). It reads no clock, no network and no database,
which is what lets `scrutator verify` recompute the attribution from a proof bundle alone.

Every name outside the scope that has at least one counted signal becomes a candidate with a
score, a band, the signals behind it (each citing evidence) and a pre-mortem: the plain reasons
this attribution could be wrong, each citing the evidence it rests on. The pre-mortem is built by
rules, so it is derivable like the rest; the model-written one is separate (analyst/leads.py).
"""

from dataclasses import replace

from scrutator.attribution.index import Index
from scrutator.attribution.model import BANDS, RULESET_VERSION, Signal, band_for, combine
from scrutator.attribution.signals import signals_for
from scrutator.packs import PackSet

_NETWORK = {"ns_in_scope", "mx_in_scope", "spf_in_scope", "shared_ns", "shared_mx", "network_owner"}
MAX_UNLIKELY = 50  # a shared service's certificate can name hundreds of strangers; the strongest 50 are listed


def _measured(packs: PackSet) -> dict[str, tuple[float, int]]:
    """The highest measured frequency per signal kind: how often unrelated organisations show it."""
    best: dict[str, tuple[float, int]] = {}
    for entry in packs.signals:
        if entry.signal not in best or entry.frequency > best[entry.signal][0]:
            best[entry.signal] = (entry.frequency, entry.sample_size)
    return best


def _discounted(signal: Signal, measured: dict[str, tuple[float, int]]) -> Signal:
    if signal.kind not in measured or signal.weight == 0:
        return signal
    frequency, sample = measured[signal.kind]
    note = f"seen in {frequency:.0%} of {sample} unrelated organisations"
    return replace(signal, weight=round(signal.weight * (1 - frequency), 4), note="; ".join(x for x in (signal.note, note) if x))


def _premortem(index: Index, name: str, signals: list[Signal]) -> list[dict]:
    counted = [s for s in signals if s.weight > 0]
    strongest = counted[0]
    kinds = sorted({s.kind for s in counted})
    out: list[dict] = []

    def add(text: str, evidence: tuple[str, ...]) -> None:
        out.append({"text": text, "evidence_ids": list(evidence)})

    if len(kinds) == 1:
        add(f"Only one kind of evidence supports this ({kinds[0]}); a second, independent kind would make it much stronger.", strongest.evidence_ids)
    cert = next((s for s in counted if s.kind == "cert_san"), None)
    if cert is not None and not set(kinds) & _NETWORK:
        add(
            "A shared certificate can also list a partner, a reseller or a shared service. Nothing in this name's DNS or network ties it to the scope.",
            cert.evidence_ids,
        )
    if index.dns("NS", name) is None and index.dns("A", name) is None and not index.addresses(name):
        add("This name has not been looked at: the evidence holds no DNS records for it, so its name servers, mail and network could not be compared.", strongest.evidence_ids)
    ignored = [s for s in signals if s.weight == 0]
    if ignored:
        evidence = tuple(sorted({e for s in ignored for e in s.evidence_ids}))
        add(f"{len(ignored)} signal(s) were not counted because they point at shared providers or common issuers ({', '.join(sorted({s.kind for s in ignored}))}).", evidence)
    for signal in counted:
        if signal.note and len(out) < 6:
            add(f"The {signal.kind} signal was reduced: {signal.note}.", signal.evidence_ids)
    return out


def _explanation(value: str, score: float, band: str, signals: list[Signal]) -> str:
    counted = [f"{s.kind} {s.weight:.2f}" for s in signals if s.weight > 0]
    text = f"{value} scores {score:.2f} ({band}) from {', '.join(counted)}."
    ignored = [s.kind for s in signals if s.weight == 0]
    if ignored:
        text += f" Not counted: {', '.join(sorted(set(ignored)))}."
    return text


def attribute(report: dict, packs: PackSet | None = None) -> dict:
    """The attribution of every name outside the scope that has evidence, as plain dictionaries."""
    packs = packs if packs is not None else PackSet.from_dict(report["packs"])
    index = Index(report, packs)
    measured = _measured(packs)
    candidates = []
    for name in index.universe():
        signals = [_discounted(s, measured) for s in signals_for(index, name)]
        signals.sort(key=lambda s: (-s.weight, s.kind))
        counted = [s for s in signals if s.weight > 0]
        if not counted:
            continue
        score = combine([s.weight for s in counted])
        band = band_for(score, {s.kind for s in counted})
        entity_id = f"domain:{name}"
        candidates.append(
            {
                "entity_id": entity_id,
                "value": name,
                "state": index.entities[entity_id]["state"],
                "score": score,
                "band": band,
                "explanation": _explanation(name, score, band, signals),
                "signals": [s.to_dict() for s in signals],
                "evidence_ids": sorted({e for s in signals for e in s.evidence_ids}),
                "premortem": _premortem(index, name, signals),
            }
        )
    candidates.sort(key=lambda c: (-c["score"], c["entity_id"]))
    listed, omitted, unlikely = [], 0, 0
    for item in candidates:
        if item["band"] == "unlikely":
            if unlikely >= MAX_UNLIKELY:
                omitted += 1
                continue
            unlikely += 1
        listed.append(item)
    return {
        "ruleset": RULESET_VERSION,
        "bands": {band: sum(1 for c in listed if c["band"] == band) for band in BANDS},
        "omitted_unlikely": omitted,
        "candidates": listed,
    }
