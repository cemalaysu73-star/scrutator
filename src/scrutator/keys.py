"""API keys for the optional keyed sources.

Rules, all tested:
  * a key comes from an environment variable and from nowhere else: there is no command-line option, no
    config-file field and no prompt, so a key cannot end up in shell history, a process list or a file this
    tool writes;
  * a key is read when a lookup runs and sent as a header (or, where the service insists, a query parameter);
    it is never stored: not in the evidence (the recorded request is the URL without it), the report, the
    bundle, the audit log or the database;
  * anything that could still carry a key (an error message that quotes a URL) goes through `redact` first.
"""

import os
from collections.abc import Mapping
from urllib.parse import quote

MIN_SECRET = 6  # a value shorter than this is not a key; replacing it everywhere would only damage messages
REDACTED = "[redacted]"


def key_variables() -> list[str]:
    """The environment variables that hold the keys of the registered sources."""
    from scrutator.modules.registry import load_builtin_modules

    return sorted({m.needs_key for m in load_builtin_modules() if m.needs_key})


def secrets(env: Mapping[str, str] | None = None) -> list[str]:
    source = os.environ if env is None else env
    values = {source.get(name, "").strip() for name in key_variables()}
    return sorted((v for v in values if len(v) >= MIN_SECRET), key=len, reverse=True)


def redact(text: str, env: Mapping[str, str] | None = None) -> str:
    """`text` with every configured key replaced, also in the percent-encoded form a URL would carry."""
    for value in secrets(env):
        for form in {value, quote(value, safe=""), quote(value)}:
            text = text.replace(form, REDACTED)
    return text
