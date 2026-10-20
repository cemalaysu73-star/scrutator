"""A CycloneDX 1.5 SBOM (JSON) of an installed Scrutator and everything it pulled in.

    python -I tools/sbom.py --out sbom.cdx.json            # the environment this python runs in
    python -I tools/sbom.py --extra mcp --out sbom.cdx.json

Run it with the interpreter of the environment you want to describe (a fresh venv with the wheel installed, as the CI
`wheel` job does): it reads the installed distributions' metadata (`importlib.metadata`), starting from `scrutator`
and following the requirements that apply on this platform and Python, so the list is what is actually installed,
with exact versions. Licences are what each package declares; nothing is looked up on the network. It does not import
scrutator and needs nothing but the standard library."""

import argparse
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from importlib import metadata

_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[([^\]]*)\])?")


def _normal(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _marker_holds(marker: str, extras: set[str]) -> bool:
    """Evaluate a requirement's environment marker without third-party code. Only the forms that appear in
    practice are understood (python_version, sys_platform, platform_system, os_name, implementation_name, extra);
    anything else counts as true, so the SBOM errs towards listing a package."""
    env = {
        "python_version": f"{sys.version_info[0]}.{sys.version_info[1]}",
        "python_full_version": ".".join(map(str, sys.version_info[:3])),
        "sys_platform": sys.platform,
        "platform_system": {"win32": "Windows", "darwin": "Darwin"}.get(sys.platform, "Linux"),
        "os_name": "nt" if sys.platform == "win32" else "posix",
        "implementation_name": sys.implementation.name,
        "platform_python_implementation": "CPython" if sys.implementation.name == "cpython" else sys.implementation.name,
    }

    def version(text: str) -> tuple:
        return tuple(int(p) for p in re.findall(r"\d+", text)[:3])

    def atom(match: re.Match) -> str:
        left, op, right = match.group(1), match.group(2), match.group(3)
        if left == "extra":
            return str((op == "==") == (_normal(right) in extras))
        value = env.get(left)
        if value is None:
            return "True"
        if left.endswith("version"):
            a, b = version(value), version(right)
            result = {"==": a == b, "!=": a != b, "<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}.get(op, True)
        else:
            result = {"==": value == right, "!=": value != right}.get(op, True)
        return str(result)

    expression = re.sub(r"""(\w+)\s*(==|!=|<=|>=|<|>)\s*['"]([^'"]*)['"]""", atom, marker)
    tokens = re.findall(r"\(|\)|True|False|and|or|not", expression)
    if not tokens or "".join(tokens) != re.sub(r"\s+", "", expression):
        return True  # a form this function does not understand
    try:
        return bool(eval(" ".join(tokens), {"__builtins__": {}}, {}))  # noqa: S307 - only True/False/and/or/not/() remain
    except Exception:  # noqa: BLE001 - unbalanced parentheses and the like
        return True


def _requirements(dist: metadata.Distribution, extras: set[str]) -> list[tuple[str, set[str]]]:
    out = []
    for text in dist.requires or []:
        requirement, _, marker = text.partition(";")
        match = _NAME.match(requirement)
        if not match:
            continue
        if marker.strip() and not _marker_holds(marker.strip(), extras):
            continue
        wanted = {_normal(e) for e in (match.group(2) or "").split(",") if e.strip()}
        out.append((match.group(1), wanted))
    return out


def _licence(dist: metadata.Distribution) -> list[dict]:
    meta = dist.metadata
    expression = meta.get("License-Expression")
    if expression:
        return [{"expression": expression.strip()}]
    names = [c.split("::")[-1].strip() for c in meta.get_all("Classifier") or [] if c.startswith("License ::")]
    text = (meta.get("License") or "").strip()
    if not names and text and len(text) < 80 and "\n" not in text:
        names = [text]
    return [{"license": {"name": n}} for n in dict.fromkeys(names)]


def build(root: str = "scrutator", extras: set[str] = frozenset()) -> dict:
    seen: dict[str, dict] = {}
    edges: dict[str, set[str]] = {}
    queue = [(root, set(extras))]
    while queue:
        name, wanted = queue.pop()
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            continue  # declared for another platform or not installed: not in this environment
        key = _normal(dist.metadata["Name"])
        known = seen.get(key)
        if known is not None and wanted <= known["_extras"]:
            continue
        ref = f"pkg:pypi/{key}@{dist.version}"
        entry = known or {"type": "library", "bom-ref": ref, "name": key, "version": dist.version, "purl": ref,
                          "licenses": _licence(dist), "_extras": set()}
        entry["_extras"] |= wanted
        seen[key] = entry
        for child, child_extras in _requirements(dist, entry["_extras"]):
            edges.setdefault(ref, set()).add(_normal(child))
            queue.append((child, child_extras))
    if _normal(root) not in seen:
        raise SystemExit(f"{root} is not installed in this environment ({sys.executable})")
    top = seen.pop(_normal(root))
    refs = {k: v["bom-ref"] for k, v in {**seen, _normal(root): top}.items()}
    for item in (top, *seen.values()):
        item.pop("_extras")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tools": [{"name": "scrutator tools/sbom.py"}],
            "component": {**top, "type": "application"},
            "properties": [{"name": "python", "value": sys.version.split()[0]}, {"name": "platform", "value": sys.platform}],
        },
        "components": sorted(seen.values(), key=lambda c: c["name"]),
        "dependencies": [
            {"ref": ref, "dependsOn": sorted(refs[c] for c in children if c in refs)} for ref, children in sorted(edges.items())
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--extra", action="append", default=[], help="an extra of scrutator to include (mcp)")
    parser.add_argument("--out", default="-", help="file to write (default: stdout)")
    args = parser.parse_args()
    bom = build("scrutator", {_normal(e) for e in args.extra})
    text = json.dumps(bom, indent=2)
    if args.out == "-":
        print(text)
    else:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
        print(f"{args.out}: {len(bom['components'])} components", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
