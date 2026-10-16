import pytest
import yaml
from packfix import document, provider, signal, takeover
from pydantic import ValidationError

from scrutator.packs import PackError
from scrutator.packs.loader import parse_file
from scrutator.packs.schema import ProviderEntry, SignalEntry, TakeoverEntry


def parse(doc, name="x.yaml"):
    return parse_file(name, yaml.safe_dump(doc).encode(), "user")


def test_valid_entries_of_every_kind_parse():
    info, entries = parse(document("providers", [provider()]))
    assert (info.kind, info.version, info.entries) == ("providers", "2026.10.1", 1)
    assert entries[0].provider == "Example DNS"
    assert parse(document("takeover", [takeover()]))[1][0].dangling == "nxdomain"
    assert parse(document("signals", [signal()]))[1][0].frequency == 0.2


@pytest.mark.parametrize(
    "bad",
    [
        provider(unexpected=1),  # unknown keys are typos
        provider(entry_id="Bad Id"),
        provider(source="http://insecure.example.net/"),
        provider(source="not a url"),
        provider(category="email"),
        provider(ns=[]),  # no pattern at all
        provider(ns=["bad pattern"]),
        provider(ns=["münchen.example"]),
        provider(category="dns", ns=[], mx=["mail.example.net"]),  # an mx pattern in a dns entry
        provider(category="cdn", ns=[], asn=[0]),
        provider(category="ca", ns=[], issuer=["ca"]),  # too short, would match everything
        provider(verified="maybe"),
    ],
)
def test_bad_provider_entries_are_rejected(bad):
    with pytest.raises(ValidationError):
        ProviderEntry.model_validate(bad)


def test_wildcards_work_inside_a_label_only_and_patterns_are_lower_cased():
    assert ProviderEntry.model_validate(provider(ns=["AWSDNS-*.COM."])).ns == ("awsdns-*.com",)
    with pytest.raises(ValidationError):
        ProviderEntry.model_validate(provider(ns=["a b*.com"]))


@pytest.mark.parametrize(
    "bad",
    [
        takeover(cname=[]),
        takeover(status="not-vulnerable"),
        takeover(dangling="guess"),
        takeover(fingerprint="x" * 201),
    ],
)
def test_bad_takeover_entries_are_rejected(bad):
    with pytest.raises(ValidationError):
        TakeoverEntry.model_validate(bad)


@pytest.mark.parametrize("bad", [signal(frequency=1.5), signal(frequency=-0.1), signal(sample_size=0), signal(signal="Has Space")])
def test_bad_signal_entries_are_rejected(bad):
    with pytest.raises(ValidationError):
        SignalEntry.model_validate(bad)


def test_file_level_problems_are_reported_by_name():
    with pytest.raises(PackError, match="kind must be one of"):
        parse({"schema": 1, "kind": "recipes", "version": "2026.10.1", "updated": "2026-10-16", "entries": []})
    with pytest.raises(PackError, match="version"):
        parse(document("providers", [provider()], version="v1"))
    with pytest.raises(PackError, match="schema"):
        parse({**document("providers", []), "schema": 2})
    with pytest.raises(PackError, match="duplicate ids"):
        parse(document("providers", [provider("a"), provider("a")]))
    with pytest.raises(PackError, match="mapping"):
        parse_file("x.yaml", b"- just\n- a list\n", "user")
    with pytest.raises(PackError, match="x.yaml"):
        parse_file("x.yaml", b"key: [unclosed", "user")
    with pytest.raises(PackError, match=r"entries\.0\.id"):
        parse(document("providers", [provider("Bad Id")]))


def test_an_empty_signals_file_is_valid():
    info, entries = parse(document("signals", []))
    assert info.entries == 0 and entries == ()
