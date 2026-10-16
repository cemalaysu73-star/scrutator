"""Precision and recall of an attribution against known ground truth (a lab zone).

For each band: how many candidates the band holds, how many of them are really the organisation's,
and the precision. Then the same for "this band or better", with recall over all the true names the
lab planted (a true name the scan never discovered counts against recall). The numbers describe
the lab, not the world; they are published for every band so a weak band is visible.
"""

from scrutator.attribution.model import BANDS


def evaluate(attribution: dict, truth: set[str]) -> dict[str, dict]:
    by_band = {band: [c["entity_id"] for c in attribution["candidates"] if c["band"] == band] for band in BANDS}
    result = {}
    for position, band in enumerate(BANDS):
        ids = by_band[band]
        upto = [i for b in BANDS[: position + 1] for i in by_band[b]]
        hits, upto_hits = sum(1 for i in ids if i in truth), sum(1 for i in upto if i in truth)
        result[band] = {
            "count": len(ids),
            "true": hits,
            "precision": round(hits / len(ids), 4) if ids else None,
            "or_better_count": len(upto),
            "or_better_precision": round(upto_hits / len(upto), 4) if upto else None,
            "or_better_recall": round(upto_hits / len(truth), 4) if truth else None,
        }
    return result
