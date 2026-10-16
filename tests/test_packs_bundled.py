from collections import Counter

from packfix import provider, write_pack

from scrutator.packs import bundled_dir, load_packs, validate_dir
from scrutator.packs.schema import CATEGORIES

PACKS = load_packs()


def test_the_bundled_files_ship_with_the_package_and_validate():
    for name in ("providers.yaml", "takeover.yaml", "signals.yaml", "manifest.json"):
        assert bundled_dir().joinpath(name).is_file(), name
    assert validate_dir() == []


def test_every_category_is_covered_and_the_set_is_not_trivial():
    by_category = Counter(e.category for e in PACKS.providers)
    assert set(by_category) == set(CATEGORIES)
    assert len(PACKS.providers) >= 50 and len(PACKS.takeover) >= 20
    assert all(e.source.startswith("https://") for e in [*PACKS.providers, *PACKS.takeover])


def test_every_provider_entry_matches_its_own_examples():
    problems = []
    for entry in PACKS.providers:
        kinds = [k for k in ("ns", "mx", "spf", "cname", "asn", "issuer") if getattr(entry, k)]
        if not entry.examples:
            problems.append(f"{entry.id}: no examples")
        for example in entry.examples:
            hits = [PACKS.match_provider(kind, example) for kind in kinds]
            if not any(hit is not None and hit.id == entry.id for hit in hits):
                problems.append(f"{entry.id}: {example!r} is not matched by this entry (got {[h and h.id for h in hits]})")
    assert problems == []


def test_every_takeover_entry_matches_its_own_examples():
    problems = []
    for entry in PACKS.takeover:
        if not entry.examples:
            problems.append(f"{entry.id}: no examples")
        for example in entry.examples:
            hit = PACKS.match_takeover(example)
            if hit is None or hit.id != entry.id:
                problems.append(f"{entry.id}: {example!r} -> {hit and hit.id}")
    assert problems == []


def test_ids_are_unique_across_the_bundled_files():
    ids = [e.id for e in PACKS.providers] + [e.id for e in PACKS.takeover]
    assert len(ids) == len(set(ids))


def test_names_from_the_real_example_com_scan_resolve_to_their_providers():
    assert PACKS.match_provider("ns", "elliott.ns.cloudflare.com").provider == "Cloudflare"
    assert PACKS.match_provider("asn", "AS13335").provider == "Cloudflare"
    sectigo = "C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA OV R36"
    assert PACKS.match_provider("issuer", sectigo).provider == "Sectigo"
    assert PACKS.match_provider("issuer", 'C=US, O="thawte, Inc.", CN=thawte SSL CA - G2').category == "ca"
    assert PACKS.match_provider("mx", "example-com.mail.protection.outlook.com").provider == "Microsoft 365"
    assert PACKS.match_provider("ns", "a.iana-servers.net").provider.startswith("ICANN")


def test_dangling_cname_targets_of_claimable_services():
    azure = PACKS.match_takeover("shop-demo.azurewebsites.net")
    assert (azure.provider, azure.dangling, azure.status, azure.verified) == ("Microsoft Azure", "nxdomain", "vulnerable", True)
    assert PACKS.match_takeover("docs.example.org") is None
    assert PACKS.match_takeover("cdn.cloudfront.net") is None  # listed upstream as not vulnerable, so not here


def test_unverified_entries_stay_visible_and_the_key_ones_are_verified():
    verified = {e.id for e in PACKS.providers if e.verified}
    assert {"cloudflare-dns", "aws-route53", "azure-dns", "microsoft-365-mail", "google-workspace-mail"} <= verified
    assert any(not e.verified for e in PACKS.providers)  # honest about what was not re-checked


def test_a_data_entry_is_all_it_takes_to_teach_the_tool_a_provider(tmp_path):
    assert PACKS.match_provider("ns", "ns1.dns.example.net") is None
    write_pack(tmp_path / "mine", "mine.yaml", "providers", [provider("example-dns")])
    extended = load_packs([tmp_path / "mine"])
    assert extended.match_provider("ns", "ns1.dns.example.net").provider == "Example DNS"
    assert extended.match_provider("ns", "hera.ns.cloudflare.com").provider == "Cloudflare"  # bundled data still there
    write_pack(tmp_path / "fix", "fix.yaml", "providers", [provider("cloudflare-dns", provider="Cloudflare Inc.", ns=["ns.cloudflare.com"])])
    assert load_packs([tmp_path / "fix"]).match_provider("ns", "hera.ns.cloudflare.com").provider == "Cloudflare Inc."
