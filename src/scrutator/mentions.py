"""Names the scan already holds without knowing it: in-scope host names written inside evidence it collected.

Sources answer with more than the field a module reads. An archived URL carries another host in its query string
(`?next=https://login.example.com/`), a TXT record names a mail host, a registration record lists a name server, a
scan service quotes the redirect it followed. Each of those is an in-scope name the scan has evidence for and has not
yet looked at. The engine reads every evidence payload it stores for host names at or under an in-scope apex and adds
the ones it does not know yet as `mentions` relations of the entity the lookup was about, citing that very record (whose
payload contains the name, so anyone can check it). No request is made for this; the new names are then resolved like
any other, and stay claims until DNS or a certificate agrees.
"""

from __future__ import annotations

import re
from urllib.parse import unquote

MAX_PER_RECORD = 200  # a record that names thousands of hosts is a list a module already reads, not a mention
_LABEL = r"(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?)"
# A text or JSON escape (\n, \t, \/, \", \\, ...): a boundary between tokens, so \nwww.example.com is not the name
# "nwww.example.com". Neutralised to a space before matching.
_ESCAPE = re.compile(r"\\[a-z/\\\"']")


def pattern(apexes: set[str]) -> "re.Pattern | None":
    if not apexes:
        return None
    roots = "|".join(re.escape(a) for a in sorted(apexes, key=len, reverse=True))
    # a name ends at the apex: not followed by another label (example.com.evil.net is not a name under example.com)
    return re.compile(rf"(?<![a-z0-9_.-])((?:{_LABEL}\.)+(?:{roots}))\.?(?!\.?[a-z0-9_-])")


def mentioned(payload: str, apexes: set[str], compiled: "re.Pattern | None" = None) -> list[str]:
    """In-scope host names below an apex written in `payload`, sorted, capped. Percent-encoding is decoded and text
    escapes are neutralised first, so an encoded or escaped delimiter cannot glue a stray character to a name."""
    regex = compiled or pattern(apexes)
    if regex is None or not payload:
        return []
    text = payload.lower()
    if "%" in text:
        text = unquote(text)  # %2Fwww.example.com is /www.example.com, never "2fwww.example.com"
    text = _ESCAPE.sub(" ", text)
    found = sorted({m.group(1) for m in regex.finditer(text)} - apexes)
    return found if len(found) <= MAX_PER_RECORD else []
