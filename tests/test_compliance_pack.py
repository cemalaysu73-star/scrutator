"""R7 T3: the informational compliance mapping (packs/data/compliance.yaml).

Every risk rule has a mapping, no mapping names a rule that does not exist, every ISO/IEC 27001 mapping is unverified
(the standard is not public and iso.org could not be read), a mapping marked verified cites one of the authoritative
public pages that were read, and the mapping never changes a scan's results (it stays out of the hashed pack content)."""

import yaml

from scrutator.packs import PackError, load_packs
from scrutator.packs.loader import parse_file
from scrutator.risk.catalog import RULES

PACKS = load_packs()
AUTHORITATIVE = (
    "https://publications.europa.eu/resource/cellar/",  # NIS2, Official Journal text
    "https://www.cisecurity.org/controls/",
    "https://wstg.owasp.org/",
    "https://top10.owasp.org/2021/",
    "https://www.mevzuat.gov.tr/",
)


def test_every_rule_has_a_mapping_and_every_mapping_a_rule():
    mapped = {e.rule for e in PACKS.compliance}
    assert mapped == set(RULES)
    assert all(e.id == e.rule for e in PACKS.compliance)


def test_iso_mappings_are_never_marked_verified():
    iso = [m for e in PACKS.compliance for m in e.mappings if m.framework == "iso27001"]
    assert iso and not any(m.verified for m in iso)


def test_a_verified_mapping_cites_an_authoritative_page_that_was_read():
    for entry in PACKS.compliance:
        for mapping in entry.mappings:
            if mapping.verified:
                assert mapping.source.startswith(AUTHORITATIVE), (entry.id, mapping.ref, mapping.source)
        assert entry.verified == all(m.verified for m in entry.mappings)


def test_an_entry_cannot_claim_verified_when_a_mapping_is_not():
    document = {
        "schema": 1, "kind": "compliance", "version": "2026.10.1", "updated": "2026-10-21",
        "entries": [{
            "id": "caa-missing", "rule": "caa-missing", "source": "https://www.iso.org/standard/27001", "verified": True,
            "mappings": [{"framework": "iso27001", "ref": "A.8.24", "title": "x", "verified": False, "source": "https://www.iso.org/standard/27001"}],
        }],
    }
    try:
        parse_file("c.yaml", yaml.safe_dump(document).encode(), "user")
    except PackError as exc:
        assert "verified only when every one" in str(exc)
    else:
        raise AssertionError("an entry claiming verified with an unverified mapping was accepted")


def test_the_mapping_is_not_part_of_the_hashed_pack_content():
    assert "compliance" not in PACKS.effective() and "compliance" not in PACKS.to_dict()["effective"]
    assert PACKS.compliance_for("dmarc-missing").mappings[0].ref == "CIS 9.5"


def test_risk_compliance_shows_the_mapping_and_says_it_is_informational(tmp_path):
    from typer.testing import CliRunner

    from riskbundlefix import make_risky_store
    from scrutator import cli

    path = tmp_path / "scans.db"
    store, _ = make_risky_store(path=path)
    store.close()
    result = CliRunner().invoke(cli.app, ["risk", "--db", str(path), "--compliance"])
    assert result.exit_code == 0, result.output
    assert "informational mapping: OWASP WSTG-CONF-10" in result.output
    assert "not a certification or a legal conclusion" in result.output and "(unverified)" in result.output
    import json

    data = json.loads(CliRunner().invoke(cli.app, ["risk", "--db", str(path), "--json", "--compliance"]).output)
    assert data["compliance"]["spf-allows-all"][0]["ref"] == "CIS 9.5"
