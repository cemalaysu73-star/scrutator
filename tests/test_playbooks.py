import pytest
import yaml
from packfix import document, provider, write_pack
from pydantic import ValidationError
from riskbundlefix import forge_report, make_risky_bundle

from scrutator.agent.playbooks import MAX_OFFERED, render, retrieve, situation
from scrutator.bundle.verify import verify_bundle
from scrutator.model import Entity, EntityType, Evidence, ScopeState
from scrutator.modules.registry import load_builtin_modules
from scrutator.packs import SITUATIONS, PackError, PackSet, PlaybookEntry, bundled_dir, load_packs, validate_dir
from scrutator.packs.loader import parse_file
from scrutator.store import Store

PACKS = load_packs()


def playbook(entry_id="example-playbook", **over):
    entry = {
        "id": entry_id,
        "title": "An example",
        "when": ["mail"],
        "steps": ["Look it up."],
        "prefer": ["dns"],
        "source": "https://docs.example.net/playbook",
        "verified": False,
    }
    entry.update(over)
    return entry


# schema ---------------------------------------------------------------------------------------------------------


def test_a_valid_playbook_parses_and_unknown_keys_are_errors():
    entry = PlaybookEntry.model_validate(playbook())
    assert entry.when == ("mail",) and entry.prefer == ("dns",) and entry.verified is False
    with pytest.raises(ValidationError):
        PlaybookEntry.model_validate({**playbook(), "stepz": []})


@pytest.mark.parametrize(
    "bad",
    [
        {"when": []},
        {"when": ["the_moon_is_full"]},
        {"when": ["mail", "mail", "mail", "mail", "mail"]},
        {"steps": []},
        {"steps": ["x"] * 7},
        {"steps": ["  "]},
        {"steps": ["y" * 201]},
        {"prefer": ["Not A Module"]},
        {"prefer": ["a", "b", "c", "d", "e"]},
        {"title": ""},
        {"source": "http://docs.example.net/plain"},
    ],
)
def test_bad_playbooks_are_rejected(bad):
    with pytest.raises(ValidationError):
        PlaybookEntry.model_validate(playbook(**bad))


def test_a_playbooks_file_is_a_pack_file_like_the_others():
    info, entries = parse_file("p.yaml", yaml.safe_dump(document("playbooks", [playbook()])).encode(), "user")
    assert (info.kind, info.entries) == ("playbooks", 1) and entries[0].id == "example-playbook"
    with pytest.raises(PackError, match="when"):
        parse_file("p.yaml", yaml.safe_dump(document("playbooks", [playbook(when=["nope"])])).encode(), "user")


# loading, merging, hashing -----------------------------------------------------------------------------------------


def test_the_bundled_playbooks_validate_and_are_sensible():
    assert validate_dir() == [] and bundled_dir().joinpath("playbooks.yaml").is_file()
    assert len(PACKS.playbooks) >= 6 and len({p.id for p in PACKS.playbooks}) == len(PACKS.playbooks)
    modules = {m.name for m in load_builtin_modules()}
    for entry in PACKS.playbooks:
        assert set(entry.when) <= set(SITUATIONS) and entry.source.startswith("https://") and entry.steps
        assert set(entry.prefer) <= modules, (entry.id, entry.prefer)
        assert entry.verified is False  # procedures written for Scrutator, not yet checked against their sources by a maintainer


def test_every_situation_has_a_bundled_playbook():
    assert {tag for p in PACKS.playbooks for tag in p.when} == set(SITUATIONS)


def test_a_user_playbook_is_added_and_one_with_a_bundled_id_replaces_it(tmp_path):
    extra = write_pack(tmp_path, "mine.yaml", "playbooks", [playbook("mine"), playbook("mail-records", title="Mine instead")])
    merged = load_packs([extra])
    by_id = {p.id: p for p in merged.playbooks}
    assert "mine" in by_id and by_id["mail-records"].title == "Mine instead"
    assert len(merged.playbooks) == len(PACKS.playbooks) + 1
    assert [p.id for p in merged.playbooks] == sorted(p.id for p in merged.playbooks)


def test_playbooks_are_not_part_of_what_a_proof_depends_on(tmp_path):
    bare = PackSet(PACKS.files, PACKS.providers, PACKS.takeover, PACKS.signals)
    assert bare.effective_sha256 == PACKS.effective_sha256
    assert "playbooks" not in PACKS.effective() and "playbooks" not in PACKS.to_dict()["effective"]
    extra = write_pack(tmp_path, "mine.yaml", "playbooks", [playbook("mine")])
    assert load_packs([extra]).effective_sha256 == PACKS.effective_sha256
    rebuilt = PackSet.from_dict(PACKS.to_dict())
    assert rebuilt.playbooks == () and rebuilt.effective_sha256 == PACKS.effective_sha256
    assert any(f["kind"] == "playbooks" and f["origin"] == "bundled" for f in PACKS.files)


def test_a_provider_pack_next_to_playbooks_still_merges(tmp_path):
    write_pack(tmp_path, "p.yaml", "providers", [provider("x-dns", provider="X", ns=["x.example.net"])])
    write_pack(tmp_path, "b.yaml", "playbooks", [playbook("mine")])
    merged = load_packs([tmp_path])
    assert merged.match_provider("ns", "a.x.example.net").id == "x-dns" and "mine" in {p.id for p in merged.playbooks}


def test_a_bundle_made_before_playbooks_existed_still_verifies(tmp_path):
    fx = make_risky_bundle(tmp_path)

    def drop_from_report(report):
        report["packs"]["files"] = [f for f in report["packs"]["files"] if f["kind"] != "playbooks"]

    def drop_from_manifest(manifest):
        manifest["analysis"]["packs"] = [p for p in manifest["analysis"]["packs"] if p["kind"] != "playbooks"]

    old = forge_report(fx.path, tmp_path / "old.scrutator", fx.private, drop_from_report, drop_from_manifest)
    result = verify_bundle(old)
    assert result.ok, [c for c in result.checks if not c.ok]
    assert next(c for c in result.checks if c.name == "packs intact").ok


# situations ------------------------------------------------------------------------------------------------------------


def dom(value):
    return Entity(type=EntityType.DOMAIN, value=value)


def graph(entities, edges):
    store = Store(":memory:")
    scan = store.create_scan("example.com")
    evidence = Evidence.create("test", "test", "x")
    store.add_evidence(evidence)
    for entity, state in entities:
        store.upsert_entity(scan, entity, state)
    for src, rel, dst in edges:
        store.add_edge(scan, src, rel, dst, [evidence.id])
    return store, scan


IN, OUT, LINKED, CANDIDATE = ScopeState.IN, ScopeState.OUT, ScopeState.LINKED, ScopeState.CANDIDATE
ROOT, OTHER = dom("example.com"), dom("other.net")


@pytest.mark.parametrize(
    "rel, tag",
    [("cname_to", "cname_out"), ("related_host", "san_cohabitants"), ("mx", "mail"), ("ns", "delegated"), ("spf_include", "spf_includes")],
)
def test_each_relation_from_the_scope_makes_its_situation_true(rel, tag):
    store, scan = graph([(ROOT, IN), (OTHER, OUT)], [(ROOT.id, rel, OTHER.id)])
    assert situation(store, scan) == {tag}


def test_a_relation_from_outside_the_scope_does_not_count():
    store, scan = graph([(ROOT, IN), (OTHER, OUT), (dom("third.org"), OUT)], [(OTHER.id, "mx", "domain:third.org"), (OTHER.id, "cname_to", ROOT.id)])
    assert situation(store, scan) == frozenset()


def test_an_alias_to_a_name_inside_the_scope_is_not_an_outside_alias():
    store, scan = graph([(ROOT, IN), (dom("www.example.com"), IN)], [(ROOT.id, "cname_to", "domain:www.example.com")])
    assert situation(store, scan) == frozenset()


def test_an_address_without_a_network_and_a_candidate_are_situations_too():
    ip = Entity(type=EntityType.IP, value="192.0.2.1")
    asn = Entity(type=EntityType.ASN, value="AS64500")
    store, scan = graph([(ROOT, IN), (ip, LINKED), (dom("partner.test"), CANDIDATE)], [(ROOT.id, "resolves_to", ip.id)])
    assert situation(store, scan) == {"ip_without_network", "candidates"}
    placed, scan2 = graph([(ROOT, IN), (ip, LINKED), (asn, OUT)], [(ROOT.id, "resolves_to", ip.id), (ip.id, "announced_by", asn.id)])
    assert situation(placed, scan2) == frozenset()


def test_every_bundled_situation_can_be_reached():
    ip = Entity(type=EntityType.IP, value="192.0.2.1")
    store, scan = graph(
        [(ROOT, IN), (OTHER, OUT), (ip, LINKED), (dom("partner.test"), CANDIDATE)],
        [(ROOT.id, rel, OTHER.id) for rel in ("cname_to", "related_host", "mx", "ns", "spf_include")] + [(ROOT.id, "resolves_to", ip.id)],
    )
    assert situation(store, scan) == set(SITUATIONS)


# retrieval -------------------------------------------------------------------------------------------------------------


def entries(*specs):
    return [PlaybookEntry.model_validate(playbook(**spec)) for spec in specs]


def test_a_playbook_is_offered_only_when_every_one_of_its_situations_holds():
    found = entries({"id": "a", "when": ["mail"]}, {"id": "b", "when": ["mail", "delegated"]}, {"id": "c", "when": ["candidates"]})
    assert [p.id for p in retrieve(found, frozenset({"mail"}))] == ["a"]
    assert [p.id for p in retrieve(found, frozenset({"mail", "delegated"}))] == ["b", "a"]  # the more specific first
    assert retrieve(found, frozenset()) == [] and retrieve(found, frozenset({"mail"}), limit=0) == []


def test_at_most_three_are_offered_and_ties_are_broken_by_id():
    found = entries(*({"id": name, "when": ["mail"]} for name in "edcba"))
    assert [p.id for p in retrieve(found, frozenset({"mail"}))] == ["a", "b", "c"] and MAX_OFFERED == 3


def test_the_bundled_set_offers_something_in_every_situation_and_nothing_in_none():
    assert retrieve(PACKS.playbooks, frozenset()) == []
    for tag in SITUATIONS:
        assert retrieve(PACKS.playbooks, frozenset({tag})), tag


def test_rendering_lists_title_steps_and_the_lookups_it_is_about():
    text = render(entries({"id": "a", "title": "Mail", "steps": ["One.", "Two."], "prefer": ["dns", "rdap"]}, {"id": "b", "title": "Plain", "prefer": []}))
    assert text.splitlines()[0] == "- Mail: One. Two. (lookups: dns, rdap)" and text.splitlines()[1] == "- Plain: Look it up."
