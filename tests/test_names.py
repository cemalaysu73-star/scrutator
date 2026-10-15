from scrutator.modules._names import host_entity, hosts_from_urls, rel_for


def test_rel_for():
    assert rel_for("example.com", "www.example.com") == "has_subdomain"
    assert rel_for("example.com", "example.com.evil.net") == "related_host"
    assert rel_for("example.com", "notexample.com") == "related_host"


def test_host_entity_rejects_ips_and_junk():
    assert host_entity("WWW.Example.com").value == "www.example.com"
    assert host_entity("1.2.3.4") is None
    assert host_entity("user@example.com") is None
    assert host_entity("") is None


def test_hosts_from_urls_groups_samples_and_skips_root_and_ips():
    urls = [
        "http://blog.example.com/a",
        "https://blog.example.com/b",
        "http://blog.example.com/a",
        "http://example.com/",
        "http://1.2.3.4/x",
        "not a url",
    ]
    result = hosts_from_urls(urls, root="example.com")
    assert result == {"blog.example.com": ["http://blog.example.com/a", "https://blog.example.com/b"]}
