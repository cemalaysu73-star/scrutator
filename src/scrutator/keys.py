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

import logging
import os
from collections.abc import Mapping
from functools import lru_cache
from urllib.parse import quote

MIN_SECRET = 6  # a value shorter than this is not a key; replacing it everywhere would only damage messages
REDACTED = "[redacted]"


@lru_cache(maxsize=1)
def _variables() -> tuple[str, ...]:
    from scrutator.modules.registry import load_builtin_modules

    return tuple(sorted({m.needs_key for m in load_builtin_modules() if m.needs_key}))


def key_variables() -> list[str]:
    """The environment variables that hold the keys of the registered sources."""
    return list(_variables())


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


# Loggers of the libraries that see request URLs. httpx logs every request ("HTTP Request: GET <url> ...") at INFO,
# and Shodan takes its key in the URL; the MCP SDK sets the root logger to INFO on stderr, which an MCP client keeps
# in its log files. A filter on these loggers rewrites each record before any handler sees it.
_URL_LOGGERS = ("httpx", "httpcore")


class RedactingFilter(logging.Filter):
    """Replaces any configured key in a log record's final message. Records without one pass unchanged."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not secrets():
            return True
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - a malformed record is the logging module's problem, not a leak
            return True
        cleaned = redact(message)
        if cleaned != message:
            record.msg, record.args = cleaned, None
        return True


def install_log_redaction() -> None:
    """Attach the redacting filter to the loggers that see URLs (once; calling again is harmless)."""
    for name in _URL_LOGGERS:
        logger = logging.getLogger(name)
        if not any(isinstance(f, RedactingFilter) for f in logger.filters):
            logger.addFilter(RedactingFilter())


install_log_redaction()  # importing the module that knows the keys is enough to protect every log of a request
