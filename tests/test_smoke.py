import re
from pathlib import Path

import scrutator


def test_version():
    assert scrutator.__version__ == "1.0.0rc1"


def test_the_package_metadata_and_the_module_agree_on_the_version():
    pyproject = (Path(__file__).parent.parent / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r'^version = "([^"]+)"', pyproject, re.M).group(1) == scrutator.__version__


def test_reports_and_bundles_carry_the_same_version():
    from scrutator.report import build_report
    from scrutator.store import Store

    store = Store(":memory:")
    scan = store.create_scan("example.com")
    assert build_report(store, scan)["tool"]["version"] == scrutator.__version__
