import json
from importlib import resources


def render_html(report: dict) -> str:
    """Single-file report. The data is embedded as JSON with every `<` escaped, so evidence
    collected from hostile hosts cannot close the script element or inject markup."""
    template = resources.files("scrutator.report").joinpath("template.html").read_text(encoding="utf-8")
    data = json.dumps(report, sort_keys=True).replace("<", "\\u003c")
    return template.replace("__DATA__", data)
