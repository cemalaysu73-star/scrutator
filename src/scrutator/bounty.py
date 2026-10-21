"""Bug-bounty scope: parse a programme's scope (HackerOne CSV, Bugcrowd or bounty-targets JSON, a plain list) into a
deny-by-default scope file, and decide whether a host is in it.

A programme's scope is untrusted input copied from a web page. The parser refuses rather than guesses:

- `*` alone, `*.*`, a wildcard over a top-level or public second-level suffix (`*.com`, `*.com.tr`, `*.co.uk`), a
  wildcard anywhere but the leftmost label (`api.*.example.com`, `example.*`), `*example.com`;
- any scheme but http(s)/ws(s) (`javascript:`, `data:`, `file:`), a URL with user info (`https://example.com@evil.test`
  is evil.test), control and bidirectional-override characters, a host that is not a valid name after IDNA;
- address ranges that are not public, or wider than /8 (IPv4) or /32 (IPv6);
- files over 5 MiB or 50,000 lines, more than 5,000 rules.

Deny by default: a host is in scope only when an include rule matches it and no exclude rule does. An exclude wildcard
`*.dev.example.com` also excludes `dev.example.com`; an include wildcard `*.example.com` does not include `example.com`
(list it on its own if it is in scope). A path-level exclusion (`https://example.com/blog`) cannot be expressed for a
passive, DNS-level tool: it is kept as a note and the host stays in scope, said so in the import summary.
"""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from scrutator.model.canonical import canonical_host

MAX_BYTES = 5 * 1024 * 1024
MAX_LINES = 50_000
MAX_RULES = 5_000
FORMAT = "scrutator-bounty-scope/1"
_UNSAFE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f​-‏‪-‮⁦-⁩﻿]")
_SLD = frozenset({"co", "com", "net", "org", "gov", "edu", "ac", "gen", "web", "biz", "info", "name", "tel", "tv", "k12", "mil", "bel", "pol", "av", "dr", "bbs", "nom", "ltd", "plc", "me", "or", "ne", "go", "gob", "nic", "res"})
_SCHEMES = ("http", "https", "ws", "wss")
_H1_NETWORK = {"URL", "WILDCARD", "DOMAIN", "CIDR", "IP_ADDRESS", "API", "OTHER"}


class ScopeError(ValueError):
    """The scope input as a whole cannot be used (too large, unreadable)."""


@dataclass
class Rule:
    kind: str  # host, wildcard, cidr
    value: str
    include: bool
    origin: str  # what the input said
    note: str = ""


@dataclass
class Parsed:
    rules: list[Rule] = field(default_factory=list)
    refused: list[dict] = field(default_factory=list)  # {input, reason}
    notes: list[dict] = field(default_factory=list)


def _too_broad(base: str) -> bool:
    labels = base.split(".")
    if len(labels) < 2:
        return True
    return len(labels) == 2 and labels[0] in _SLD and len(labels[1]) == 2


def parse_target(raw: str, include: bool) -> tuple[Rule | None, str]:
    """One scope entry. Returns (rule, "") or (None, why it was refused)."""
    text = str(raw).strip().strip("\"'").strip()
    if not text:
        return None, "empty"
    if _UNSAFE.search(text):
        return None, "control or bidirectional characters"
    note = ""
    lowered = text.lower()
    if "://" in lowered:
        try:
            parts = urlsplit(text)
        except ValueError:
            return None, "not a URL"
        if parts.scheme.lower() not in _SCHEMES:
            return None, f"scheme {parts.scheme or '?'}: not allowed"
        if "@" in parts.netloc:
            return None, "a URL with user info (the host is what follows @)"
        host = parts.netloc.rsplit(":", 1)[0] if parts.netloc.count(":") == 1 else parts.netloc
        if parts.path not in ("", "/", "/*") or parts.query:
            note = f"path {parts.path or ''}{'?' + parts.query if parts.query else ''} ignored: scope is by host"
        text = host
    elif re.match(r"^[a-z][a-z0-9+.-]*:(?!\d)", lowered) and "/" not in lowered.split(":", 1)[0]:
        if not re.match(r"^[0-9a-f:]+(/\d+)?$", lowered):  # an IPv6 address or range has colons too
            return None, f"scheme {lowered.split(':', 1)[0]}: not allowed"
    text = text.rstrip("/").removesuffix("/*")
    if "/" in text and not re.match(r"^[0-9a-fA-F.:]+/\d{1,3}$", text):
        text, note = text.split("/", 1)[0], note or "path ignored: scope is by host"
    # addresses and ranges
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        network = None
    if network is not None:
        if not network.is_global:
            return None, "not a public address range"
        if network.prefixlen < (8 if network.version == 4 else 32):
            return None, "address range too wide"
        return Rule("cidr", network.compressed, include, raw.strip(), note), ""
    if text.count("*"):
        if text in ("*", "*.*") or not text.startswith("*.") or "*" in text[2:]:
            return None, "a wildcard only as the leftmost whole label (*.example.com)"
        try:
            base = canonical_host(text[2:])
        except ValueError:
            return None, "not a valid host name"
        if _too_broad(base):
            return None, f"*.{base} is a public suffix, far too broad"
        if not text.isascii():
            note = note or f"non-ASCII input normalised to *.{base} (IDNA): check it is the name the programme means"
        return Rule("wildcard", base, include, raw.strip(), note), ""
    if ":" in text and text.count(":") == 1:
        text = text.split(":", 1)[0]  # host:port
    try:
        host = canonical_host(text)
    except ValueError:
        return None, "not a valid host name"
    if "." not in host or _too_broad(host):
        return None, f"{host} is not a host an organisation owns (a public suffix)"
    if not text.isascii():
        note = note or f"non-ASCII input normalised to {host} (IDNA): check it is the name the programme means"
    return Rule("host", host, include, raw.strip(), note), ""


def _bool(value) -> bool | None:
    text = str(value).strip().lower()
    if text in ("true", "yes", "1", "in", "in scope", "in_scope"):
        return True
    if text in ("false", "no", "0", "out", "out of scope", "out_of_scope"):
        return False
    return None


def _from_h1_csv(text: str, parsed: Parsed) -> None:
    reader = csv.DictReader(io.StringIO(text))
    for line, row in enumerate(reader, 2):
        if line > MAX_LINES:
            raise ScopeError(f"more than {MAX_LINES} rows")
        kind = str(row.get("asset_type") or "").strip().upper()
        identifier = str(row.get("identifier") or "")
        if kind and kind not in _H1_NETWORK:
            parsed.notes.append({"input": identifier[:200], "reason": f"asset type {kind}: not a network asset, ignored"})
            continue
        eligible = _bool(row.get("eligible_for_submission", "true"))
        include = eligible is not False
        for token in re.split(r"[,\s]+", identifier):
            if token:
                _add(parsed, token, include)


def _walk_json(value, parsed: Parsed, include: bool | None = None, depth: int = 0) -> None:
    if depth > 12:
        return
    if isinstance(value, list):
        for item in value:
            _walk_json(item, parsed, include, depth + 1)
        return
    if not isinstance(value, dict):
        return
    for key in ("in_scope", "out_of_scope"):
        if isinstance(value.get(key), list):
            for item in value[key]:
                _walk_json(item, parsed, key == "in_scope", depth + 1)
    if isinstance(value.get("targets"), (list, dict)):
        group = _bool(value.get("in_scope")) if "in_scope" in value and not isinstance(value.get("in_scope"), list) else include
        _walk_json(value["targets"], parsed, group, depth + 1)
    if isinstance(value.get("groups"), list):
        _walk_json(value["groups"], parsed, include, depth + 1)
    target = next((value[k] for k in ("asset_identifier", "target", "uri", "endpoint", "name", "identifier") if isinstance(value.get(k), str) and value.get(k)), None)
    if target is not None and include is not None and not any(isinstance(value.get(k), list) for k in ("in_scope", "out_of_scope", "targets", "groups")):
        kind = str(value.get("asset_type") or value.get("type") or value.get("category") or "").upper()
        if kind and kind not in _H1_NETWORK | {"WEBSITE", "API", "NETWORK", "IOT", "OTHER", "WEB", "URL"}:
            parsed.notes.append({"input": target[:200], "reason": f"asset type {kind.lower()}: not a network asset, ignored"})
            return
        eligible = _bool(value.get("eligible_for_submission")) if "eligible_for_submission" in value else None
        _add(parsed, target, include and eligible is not False)


def _from_list(text: str, parsed: Parsed) -> None:
    include = True
    for number, line in enumerate(text.splitlines(), 1):
        if number > MAX_LINES:
            raise ScopeError(f"more than {MAX_LINES} lines")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        header = stripped.lower().rstrip(":").strip()
        if header in ("out of scope", "out-of-scope", "out_of_scope", "kapsam dışı", "excluded", "exclusions"):
            include = False
            continue
        if header in ("in scope", "in-scope", "in_scope", "kapsam", "kapsam içi", "targets"):
            include = True
            continue
        if stripped.startswith(("- ", "* ", "• ")):  # a list bullet: the section decides
            stripped = stripped[2:].strip()
        elif stripped[0] in "!-":  # "!host" or "-host": excluded, wherever it stands
            _add(parsed, stripped[1:].strip().split()[0] if stripped[1:].strip() else "", False)
            continue
        if stripped:
            _add(parsed, stripped.split()[0], include)


def _add(parsed: Parsed, token: str, include: bool) -> None:
    rule, reason = parse_target(token, include)
    if rule is None:
        parsed.refused.append({"input": str(token)[:200], "reason": reason, "include": include})
        return
    if rule.note:
        parsed.notes.append({"input": rule.origin[:200], "reason": rule.note})
    if len(parsed.rules) >= MAX_RULES:
        raise ScopeError(f"more than {MAX_RULES} rules")
    parsed.rules.append(rule)


def parse_scope(data: bytes, name: str = "-") -> Parsed:
    """Read a scope export: HackerOne CSV, Bugcrowd / bounty-targets JSON, or a plain list."""
    if len(data) > MAX_BYTES:
        raise ScopeError(f"{name} is larger than {MAX_BYTES // 2**20} MiB")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ScopeError(f"{name} is not UTF-8 text") from exc
    parsed = Parsed()
    head = text.lstrip()[:1]
    first = text.lstrip().splitlines()[0].lower() if text.strip() else ""
    if head in "[{":
        try:
            document = json.loads(text)
        except (ValueError, RecursionError) as exc:
            raise ScopeError(f"{name} looks like JSON but does not parse: {exc}") from exc
        _walk_json(document, parsed)
    elif "identifier" in first and "asset_type" in first:
        _from_h1_csv(text, parsed)
    else:
        _from_list(text, parsed)
    return parsed


# ------------------------------------------------------------------------------------------- the scope file


class BountyScope:
    """Deny-by-default membership test over include and exclude rules."""

    def __init__(self, rules: list[Rule], *, program: str = "", source: dict | None = None, notes: list | None = None, refused: list | None = None) -> None:
        self.program, self.source = program, source or {}
        self.notes, self.refused = list(notes or []), list(refused or [])
        self.include = {k: sorted({r.value for r in rules if r.include and r.kind == k}) for k in ("host", "wildcard", "cidr")}
        self.exclude = {k: sorted({r.value for r in rules if not r.include and r.kind == k}) for k in ("host", "wildcard", "cidr")}
        self._in_nets = [ipaddress.ip_network(c) for c in self.include["cidr"]]
        self._out_nets = [ipaddress.ip_network(c) for c in self.exclude["cidr"]]

    def contains(self, host: str) -> bool:
        host = str(host).strip().lower().rstrip(".")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if address is not None:
            if any(address in n for n in self._out_nets):
                return False
            return any(address in n for n in self._in_nets)
        if host in self.exclude["host"] or any(host == b or host.endswith("." + b) for b in self.exclude["wildcard"]):
            return False
        if host in self.include["host"]:
            return True
        return any(host.endswith("." + b) for b in self.include["wildcard"])

    def roots(self) -> list[str]:
        """The domains a passive scan starts from: every wildcard base, and every listed host not under one."""
        bases = self.include["wildcard"]
        hosts = [h for h in self.include["host"] if not any(h == b or h.endswith("." + b) for b in bases)]
        return sorted(set(bases) | set(hosts))

    def to_dict(self) -> dict:
        return {"format": FORMAT, "program": self.program, "source": self.source,
                "include": {"hosts": self.include["host"], "wildcards": self.include["wildcard"], "cidrs": self.include["cidr"]},
                "exclude": {"hosts": self.exclude["host"], "wildcards": self.exclude["wildcard"], "cidrs": self.exclude["cidr"]},
                "notes": self.notes[:200], "refused": self.refused[:200]}

    @classmethod
    def from_parsed(cls, parsed: Parsed, *, program: str, data: bytes, name: str) -> "BountyScope":
        return cls(parsed.rules, program=program, source={"file": Path(name).name, "sha256": hashlib.sha256(data).hexdigest()},
                   notes=parsed.notes, refused=parsed.refused)

    @classmethod
    def load(cls, path: str | Path) -> "BountyScope":
        """Read a scope file `bounty import` wrote; every rule is parsed again (the file may have been edited)."""
        raw = Path(path).read_bytes()
        if len(raw) > MAX_BYTES:
            raise ScopeError("the scope file is too large")
        document = yaml.safe_load(raw.decode("utf-8"))
        if not isinstance(document, dict) or document.get("format") != FORMAT:
            raise ScopeError(f"{path} is not a scope file written by `scrutator bounty import`")
        rules = []
        for include, section in ((True, document.get("include") or {}), (False, document.get("exclude") or {})):
            for key, kind in (("hosts", "host"), ("wildcards", "wildcard"), ("cidrs", "cidr")):
                for value in section.get(key) or []:
                    text = f"*.{value}" if kind == "wildcard" else str(value)
                    rule, reason = parse_target(text, include)
                    if rule is None:
                        raise ScopeError(f"{path}: {value!r} is not allowed ({reason})")
                    rules.append(rule)
        scope = cls(rules, program=str(document.get("program") or ""), source=document.get("source") or {})
        if not scope.roots() and not scope.include["cidr"]:
            raise ScopeError(f"{path} includes nothing")
        return scope


def finding_snippet(alert: dict, evidence: dict, *, program: str, bundle: str = "", key_fingerprint: str = "") -> str:
    """A ready-to-paste Markdown report draft for a takeover candidate: what the passive evidence shows, the records
    with their ids, and the commands the hunter runs by hand to confirm before reporting."""
    names = [e for e in alert["entities"] if not re.match(r"^[0-9a-f:.]+$", e)]
    alias, target = (names + ["<name>", "<target>"])[:2]
    lines = [
        f"## Subdomain takeover candidate: {alias}",
        "",
        f"**Programme:** {program or '<programme>'}  ",
        f"**Asset:** `{alias}`  ",
        f"**Weakness:** subdomain takeover (CWE-350 class; OWASP WSTG-CONF-10)  ",
        f"**Severity (Scrutator rule, to be re-rated under the programme's policy):** {alert['severity']}",
        "",
        "### Summary",
        "",
        alert["detail"],
        "",
        "### Evidence (passive, collected by Scrutator)",
        "",
    ]
    for evidence_id in alert["evidence_ids"][:6]:
        record = evidence.get(evidence_id) or {}
        excerpt = str(record.get("payload", ""))[:300].replace("`", "'")
        lines += [f"- `{evidence_id}`: {record.get('source', '?')} `{str(record.get('request', ''))[:160]}` at {record.get('collected_at', '?')}",
                  f"  ```\n  {excerpt}\n  ```"]
    lines += [
        "",
        "### Reproduce (ordinary DNS lookups, run by hand)",
        "",
        "```",
        f"dig +short CNAME {alias}",
        f"dig +short A {target}",
        f"nslookup -type=CNAME {alias}",
    ]
    if bundle:
        lines.append(f"scrutator verify {bundle}" + (f" --pin {key_fingerprint}" if key_fingerprint else ""))
    lines += [
        "```",
        "",
        "### Impact",
        "",
        "Whoever registers the missing resource at the service can serve content under the programme's domain "
        "(phishing, cookie theft scoped to the parent domain, OAuth redirect abuse).",
        "",
        "> Draft made from passive evidence only. Confirm with the commands above and the programme's rules before "
        "reporting. Do not register or claim the resource unless the programme explicitly allows a proof of concept.",
        "",
    ]
    return "\n".join(lines)
