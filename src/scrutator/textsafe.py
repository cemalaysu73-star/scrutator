"""Text from sources and bundles is attacker-influenced. Before it reaches a terminal, characters a terminal would obey
(escape sequences, bell, carriage return, C1 controls) or that reorder what the reader sees (bidirectional overrides,
as in `\\u202egnp.exe`) are shown as escapes instead. Newlines and tabs pass: they are layout, not commands."""

import re

_BIDI = "‎‏‪‫‬‭‮⁦⁧⁨⁩"
_UNSAFE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f" + _BIDI + "]")


def _shown(match: re.Match) -> str:
    code = ord(match.group())
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"


def terminal_safe(text: str) -> str:
    """`text` with every control and bidirectional-override character replaced by a visible escape."""
    return _UNSAFE.sub(_shown, text)


def strip_unsafe(text: str) -> str:
    """`text` without control and bidirectional-override characters (for values that become identifiers)."""
    return _UNSAFE.sub("", text)
