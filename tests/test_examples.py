"""The example bundles shipped in docs/examples verify with their signer pinned, with this version of the tool.

They were made by earlier versions, so this is also the backward-compatibility test: a new check, rule or pack kind
must never make an honest old bundle fail."""

from pathlib import Path

import pytest

from scrutator.bundle.keys import fingerprint, load_public_raw
from scrutator.bundle.verify import verify_bundle

EXAMPLES = Path(__file__).resolve().parent.parent / "docs" / "examples"
FOLDERS = sorted(p for p in EXAMPLES.iterdir() if (p / "proof.scrutator").exists()) if EXAMPLES.exists() else []


def test_there_are_example_bundles():
    assert {p.name for p in FOLDERS} >= {"example.com", "lab-zone"}


@pytest.mark.parametrize("folder", FOLDERS, ids=lambda p: p.name)
def test_an_example_bundle_verifies_pinned(folder):
    pin = fingerprint(load_public_raw(folder / "signing.pub"))
    result = verify_bundle(folder / "proof.scrutator", pinned_fingerprint=pin)
    failed = [f"{c.name}: {c.detail}" for c in result.checks if not c.ok]
    assert result.ok, failed
