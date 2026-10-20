import re

# Any spelling a model might read as the fence: any case, spaces or line breaks inside the brackets.
_FENCE = re.compile(r"<(\s*/?)\s*data\s*>", re.IGNORECASE)


def _neutral(match: re.Match) -> str:
    return "<\\/data>" if "/" in match.group(1) else "<\\data>"


def wrap_data(text: str) -> str:
    """Fence untrusted text. Delimiter look-alikes inside the text, in any case and with any whitespace, are
    neutralised so collected content cannot close the fence and masquerade as instructions."""
    return f"<data>\n{_FENCE.sub(_neutral, text)}\n</data>"
