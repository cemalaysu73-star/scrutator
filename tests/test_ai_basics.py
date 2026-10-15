import pytest

from scrutator.ai._json import parse_json_text
from scrutator.ai.net import is_loopback


@pytest.mark.parametrize(
    "text, expected",
    [
        ('{"a": 1}', {"a": 1}),
        ('```json\n{"a": 1}\n```', {"a": 1}),
        ('Sure! Here you go: {"a": 1} Hope that helps.', {"a": 1}),
        ('<think>hmm {"a": 2}</think>{"a": 1}', {"a": 1}),
        ("[1, 2]", [1, 2]),
        ("no json here", None),
        ("", None),
    ],
)
def test_parse_json_text(text, expected):
    assert parse_json_text(text) == expected


@pytest.mark.parametrize(
    "url, expected",
    [
        ("http://127.0.0.1:11434", True),
        ("http://localhost:1234/v1", True),
        ("http://[::1]:8080", True),
        ("http://app.localhost:9000", True),
        ("https://api.openai.com/v1", False),
        ("http://127.0.0.1.evil.com", False),
        ("http://localhost.evil.com", False),
        ("http://0.0.0.0:8080", False),
        ("", False),
    ],
)
def test_is_loopback(url, expected):
    assert is_loopback(url) is expected
