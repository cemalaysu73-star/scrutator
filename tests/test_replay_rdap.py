import json

from scrutator.bundle.replay import supports


def domain(update, expiry="2027-08-13T04:00:00Z", ns=("A.IANA-SERVERS.NET",)):
    return json.dumps(
        {
            "ldhName": "EXAMPLE.COM",
            "nameservers": [{"ldhName": n} for n in ns],
            "events": [
                {"eventAction": "expiration", "eventDate": expiry},
                {"eventAction": "last update of RDAP database", "eventDate": update},
            ],
            "links": [{"value": "https://rdap.example.test/domain/EXAMPLE.COM"}],
            "notices": [{"title": "Terms of use"}],
        }
    )


def network(address, name="CLOUDFLARENET"):
    return json.dumps(
        {
            "name": name,
            "links": [{"value": f"https://rdap.example.test/ip/{address}"}],
            "entities": [{"roles": ["registrant"], "links": [{"value": f"https://rdap.example.test/ip/{address}"}]}],
        }
    )


def test_the_database_update_stamp_does_not_count_as_a_change():
    assert supports(domain("2026-10-15T19:52:10Z"), domain("2026-10-15T19:58:10Z"))


def test_real_changes_still_count():
    base = domain("2026-10-15T19:52:10Z")
    assert not supports(base, domain("2026-10-15T19:58:10Z", expiry="2026-11-01T00:00:00Z"))
    assert not supports(base, domain("2026-10-15T19:58:10Z", ns=("EVIL.EXAMPLE.NET",)))


def test_echoed_query_addresses_in_links_do_not_count_but_the_owner_does():
    assert supports(network("104.28.224.82"), network("104.28.192.82"))
    assert not supports(network("104.28.224.82"), network("104.28.192.82", name="SOMEONE-ELSE"))
