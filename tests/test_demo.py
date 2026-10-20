"""demo/run_demo.py offline: the script a newcomer runs must keep working, and its story must hold."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_the_offline_demo_runs_verifies_and_fails_on_every_tamper(tmp_path):
    done = subprocess.run(
        [sys.executable, str(ROOT / "demo" / "run_demo.py"), "--out", str(tmp_path / "out"), "--transcript", str(tmp_path / "t.txt")],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600, cwd=ROOT,
    )
    assert done.returncode == 0, done.stdout[-1500:] + done.stderr[-1500:]
    text = (tmp_path / "t.txt").read_text(encoding="utf-8")
    assert text == done.stdout.replace("\r\n", "\n")  # the transcript is what was printed
    assert "Traceback" not in text and str(tmp_path) not in text  # the working folder is shown as demo-out
    assert text.count("Verification passed.") == 2  # the genuine bundle pinned, and the substitute without a pin
    assert text.count("Verification FAILED") == 3  # a flipped bit, a re-signed forgery, the substitute pinned
    assert "published: 6 statements, of which 0 made up" in text
    assert "-> exit status 1: the pinned key is what catches it" in text
