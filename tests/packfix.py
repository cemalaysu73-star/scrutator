"""Helpers that write small pack directories for tests."""

import json

import yaml

from scrutator.packs import build_manifest


def provider(entry_id="example-dns", **over):
    entry = {
        "id": entry_id,
        "provider": "Example DNS",
        "category": "dns",
        "ns": ["dns.example.net"],
        "source": "https://docs.example.net/nameservers",
        "verified": True,
    }
    entry.update(over)
    return entry


def takeover(entry_id="example-pages", **over):
    entry = {
        "id": entry_id,
        "provider": "Example Pages",
        "cname": ["pages.example.net"],
        "status": "vulnerable",
        "dangling": "nxdomain",
        "source": "https://docs.example.net/custom-domains",
        "verified": True,
    }
    entry.update(over)
    return entry


def signal(entry_id="shared-ns-set", **over):
    entry = {
        "id": entry_id,
        "signal": "ns_set",
        "frequency": 0.2,
        "sample_size": 1000,
        "source": "https://example.net/corpus",
        "verified": True,
    }
    entry.update(over)
    return entry


def document(kind, entries, version="2026.10.1"):
    return {"schema": 1, "kind": kind, "version": version, "updated": "2026-10-16", "entries": entries}


def write_pack(directory, name, kind, entries, *, version="2026.10.1", manifest=False):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(yaml.safe_dump(document(kind, entries, version)), encoding="utf-8")
    if manifest:
        write_manifest(directory)
    return directory


def write_manifest(directory):
    (directory / "manifest.json").write_text(json.dumps(build_manifest(directory), indent=2, sort_keys=True) + "\n", encoding="utf-8")
