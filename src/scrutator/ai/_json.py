import json
import re
from typing import Any

_FENCE = re.compile(r"^```(?:json)?\s*(.*?)\s*```$", re.S)
_THINK = re.compile(r"<think>.*?</think>", re.S)


def parse_json_text(text: str) -> Any:
    """Extract JSON from a model reply, tolerating code fences, reasoning tags and
    chatter around the object. Returns None when nothing parses."""
    cleaned = _THINK.sub("", text).strip()
    match = _FENCE.match(cleaned)
    if match:
        cleaned = match.group(1)
    try:
        return json.loads(cleaned)
    except ValueError:
        pass
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(cleaned[start : end + 1])
        except ValueError:
            return None
    return None
