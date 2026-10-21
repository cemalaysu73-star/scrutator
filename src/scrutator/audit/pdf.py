"""PDF through a Chromium-based browser that is already installed (headless print). Nothing is downloaded.

Looked for, in this order: the SCRUTATOR_BROWSER variable, Microsoft Edge, Google Chrome, Chromium and Brave in their
standard places, then the same names on PATH. With none found the audit says so; the HTML has a print style sheet, so
"Print > Save as PDF" in any browser gives the same document.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

_WINDOWS = [
    r"{pf86}\Microsoft\Edge\Application\msedge.exe",
    r"{pf}\Microsoft\Edge\Application\msedge.exe",
    r"{pf}\Google\Chrome\Application\chrome.exe",
    r"{pf86}\Google\Chrome\Application\chrome.exe",
    r"{local}\Google\Chrome\Application\chrome.exe",
    r"{pf}\Chromium\Application\chrome.exe",
    r"{pf}\BraveSoftware\Brave-Browser\Application\brave.exe",
]
_MAC = [
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
]
_PATH_NAMES = ["msedge", "microsoft-edge", "google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome", "brave-browser"]


def find_browser() -> str | None:
    """The path of an installed Chromium-based browser, or None."""
    override = os.environ.get("SCRUTATOR_BROWSER")
    if override:
        return override if Path(override).is_file() else None
    candidates = []
    if os.name == "nt":
        env = {"pf": os.environ.get("ProgramFiles", r"C:\Program Files"), "pf86": os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
               "local": os.environ.get("LOCALAPPDATA", "")}
        candidates = [p.format(**env) for p in _WINDOWS]
    else:
        candidates = list(_MAC)
    for path in candidates:
        if path and Path(path).is_file():
            return path
    for name in _PATH_NAMES:
        found = shutil.which(name)
        if found:
            return found
    return None


def print_pdf(html_path: Path, pdf_path: Path, *, browser: str | None = None, timeout: float = 90.0) -> str:
    """Print `html_path` to `pdf_path` with a headless browser. Returns "" on success, or why there is no PDF."""
    browser = browser or find_browser()
    if browser is None:
        return "no Chromium-based browser (Edge, Chrome, Chromium, Brave) was found; open audit.html and print it to PDF"
    pdf_path.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix="scrutator-pdf-") as profile:
        command = [
            browser, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check", "--disable-extensions",
            "--disable-background-networking", "--disable-sync", "--no-pdf-header-footer", f"--user-data-dir={profile}",
            f"--print-to-pdf={pdf_path.resolve()}", html_path.resolve().as_uri(),
        ]
        try:
            subprocess.run(command, capture_output=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return f"the browser did not print the PDF ({type(exc).__name__}); open audit.html and print it to PDF"
    if not pdf_path.is_file() or pdf_path.read_bytes()[:5] != b"%PDF-":
        return "the browser ran but wrote no PDF; open audit.html and print it to PDF"
    return ""
