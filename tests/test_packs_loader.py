import pytest
from packfix import provider, signal, takeover, write_manifest, write_pack

from scrutator.packs import PackError, PackSet, build_manifest, file_digest, load_packs, validate_dir


def packs_from(tmp_path, *dirs):
    return load_packs([tmp_path / d for d in dirs], bundled=False)


def test_user_directories_are_merged_by_id_and_the_later_one_wins(tmp_path):
    write_pack(tmp_path / "a", "p.yaml", "providers", [provider("one", provider="First"), provider("two")])
    write_pack(tmp_path / "b", "p.yaml", "providers", [provider("one", provider="Override"), provider("three")])
    packs = packs_from(tmp_path, "a", "b")
    assert {e.id: e.provider for e in packs.providers} == {"one": "Override", "two": "Example DNS", "three": "Example DNS"}
    assert [f["origin"] for f in packs.files] == ["user", "user"]


def test_the_bundled_packs_load_and_validate():
    assert isinstance(load_packs(), PackSet)
    assert validate_dir() == []


def test_a_description_survives_a_dictionary_round_trip_and_changes_with_content(tmp_path):
    write_pack(tmp_path / "a", "p.yaml", "providers", [provider("one")])
    write_pack(tmp_path / "a", "t.yaml", "takeover", [takeover()])
    packs = packs_from(tmp_path, "a")
    again = PackSet.from_dict(packs.to_dict())
    assert again.to_dict() == packs.to_dict()
    assert again.effective_sha256 == packs.effective_sha256
    write_pack(tmp_path / "b", "p.yaml", "providers", [provider("one"), provider("extra")])
    assert packs_from(tmp_path, "b").effective_sha256 != packs.effective_sha256


def test_a_malformed_description_is_rejected_with_the_entry_that_is_wrong(tmp_path):
    write_pack(tmp_path / "a", "p.yaml", "providers", [provider("one")])
    data = packs_from(tmp_path, "a").to_dict()
    data["effective"]["providers"][0]["category"] = "email"
    with pytest.raises(PackError, match=r"effective\.providers\[0\]"):
        PackSet.from_dict(data)
    with pytest.raises(PackError):
        PackSet.from_dict({"files": "nope"})
    with pytest.raises(PackError):
        PackSet.from_dict(None)


def test_name_servers_match_on_label_boundaries_and_the_most_specific_pattern_wins(tmp_path):
    write_pack(
        tmp_path / "a",
        "p.yaml",
        "providers",
        [
            provider("wide", provider="Wide", ns=["example.net"]),
            provider("narrow", provider="Narrow", ns=["dns.example.net"]),
            provider("aws", provider="Aws", ns=["awsdns-*.com", "awsdns-*.co.uk"]),
        ],
    )
    packs = packs_from(tmp_path, "a")
    assert packs.match_provider("ns", "ns1.dns.example.net.").provider == "Narrow"
    assert packs.match_provider("ns", "NS.OTHER.EXAMPLE.NET").provider == "Wide"
    assert packs.match_provider("ns", "dns.example.net").provider == "Narrow"
    assert packs.match_provider("ns", "evildns.example.net").provider == "Wide"  # not a label boundary for "dns"
    assert packs.match_provider("ns", "ns-2048.awsdns-64.com").provider == "Aws"
    assert packs.match_provider("ns", "ns-1.awsdns-04.co.uk").provider == "Aws"
    assert packs.match_provider("ns", "ns-1.awsdns-04.org") is None
    assert packs.match_provider("ns", "example.org") is None
    assert packs.match_provider("mx", "ns1.dns.example.net") is None  # the kinds are separate


def test_asn_and_issuer_matching(tmp_path):
    write_pack(
        tmp_path / "a",
        "p.yaml",
        "providers",
        [
            provider("edge", provider="Edge", category="cdn", ns=[], asn=[64500, 64501]),
            provider("ca", provider="Example CA", category="ca", ns=[], issuer=["Example Trust"]),
            provider("ca-long", provider="Example Trust Services", category="ca", ns=[], issuer=["example trust services"]),
        ],
    )
    packs = packs_from(tmp_path, "a")
    assert packs.match_provider("asn", "AS64501").provider == "Edge"
    assert packs.match_provider("asn", 64500).provider == "Edge"
    assert packs.match_provider("asn", "as64502") is None and packs.match_provider("asn", "nonsense") is None
    assert packs.match_provider("issuer", 'C=US, O="Example Trust", CN=R1').provider == "Example CA"
    assert packs.match_provider("issuer", "C=US, O=Example  Trust Services, CN=R1").provider == "Example Trust Services"
    assert packs.match_provider("issuer", "C=US, O=Somebody Else") is None


def test_takeover_fingerprints_match_a_cname_target(tmp_path):
    write_pack(tmp_path / "a", "t.yaml", "takeover", [takeover(cname=["pages.example.net", "*.sites.example.net"])])
    packs = packs_from(tmp_path, "a")
    assert packs.match_takeover("demo.pages.example.net.").id == "example-pages"
    assert packs.match_takeover("demo.sites.example.net").id == "example-pages"
    assert packs.match_takeover("pages.example.org") is None
    assert packs.match_takeover("notpages.example.net") is None


def test_a_manifest_is_enforced_when_present(tmp_path):
    directory = write_pack(tmp_path / "a", "p.yaml", "providers", [provider("one")], manifest=True)
    assert validate_dir(directory) == []
    (directory / "p.yaml").write_text((directory / "p.yaml").read_text() + "\n# edited\n", encoding="utf-8")
    assert any("p.yaml does not match its sha256" in p for p in validate_dir(directory))
    write_manifest(directory)
    write_pack(directory, "extra.yaml", "providers", [provider("two")])
    assert any("extra.yaml is not listed" in p for p in validate_dir(directory))
    write_manifest(directory)
    (directory / "extra.yaml").unlink()
    assert any("lists extra.yaml" in p for p in validate_dir(directory))
    write_manifest(directory)
    assert validate_dir(directory) == []


def test_a_manifest_is_optional_for_user_packs_but_must_be_valid_if_present(tmp_path):
    directory = write_pack(tmp_path / "a", "p.yaml", "providers", [provider("one")])
    assert validate_dir(directory) == []
    (directory / "manifest.json").write_text("{not json", encoding="utf-8")
    assert any("not a valid manifest" in p for p in validate_dir(directory))


def test_all_problems_are_reported_together(tmp_path):
    directory = write_pack(tmp_path / "a", "one.yaml", "providers", [provider("Bad Id")])
    write_pack(directory, "two.yaml", "takeover", [takeover(cname=[])])
    problems = validate_dir(directory)
    assert any("one.yaml" in p for p in problems) and any("two.yaml" in p for p in problems)
    with pytest.raises(PackError):
        load_packs([directory], bundled=False)
    with pytest.raises(PackError, match="not a directory"):
        load_packs([tmp_path / "missing"], bundled=False)


def test_digests_ignore_line_ending_conversion(tmp_path):
    assert file_digest(b"a: 1\r\nb: 2\r\n") == file_digest(b"a: 1\nb: 2\n")
    directory = write_pack(tmp_path / "a", "p.yaml", "providers", [provider("one")], manifest=True)
    raw = (directory / "p.yaml").read_bytes().replace(b"\r\n", b"\n")  # the same text with LF endings
    (directory / "p.yaml").write_bytes(raw.replace(b"\n", b"\r\n"))
    assert validate_dir(directory) == []
    assert build_manifest(directory)["files"]["p.yaml"] == file_digest(raw)


def test_signals_load(tmp_path):
    write_pack(tmp_path / "a", "s.yaml", "signals", [signal()])
    assert packs_from(tmp_path, "a").signals[0].signal == "ns_set"
