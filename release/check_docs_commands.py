#!/usr/bin/env python3
"""Quality gate for the documentation: it fails when the docs show something that does not exist.

    python release/check_docs_commands.py            # all three checks over every Markdown file in the repository
    python release/check_docs_commands.py --only commands
    python release/check_docs_commands.py README.md docs/use-cases.md      # only these files

Checks:
  commands  every fenced `scrutator ...` (or `$ scrutator ...`) line names a real command, and every `--option` on it
            exists on that command. Verified two ways: against the installed program's own command tree and by running
            `scrutator <command> --help` (exit status 0 and the option printed in the help text).
  links     every relative Markdown link and image resolves to a file, and a `#fragment` to a heading of that file.
  mermaid   every ```mermaid block starts with a known diagram type, has balanced brackets and quotes, and each line of
            a flowchart or state diagram is a node, an edge or a keyword (a simple syntax check, not a renderer).

Exit status 0 when everything holds, 1 otherwise (every problem is listed). Standard library plus the installed
`scrutator` package; no network."""

from __future__ import annotations

import argparse
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__", "business", ".cemal", "design", "superpowers"}
SKIP_PREFIXES = ("bench/results", "demo-out", "scrutator-out", "live")


def markdown_files(explicit: list[str]) -> list[Path]:
    if explicit:
        return [Path(p).resolve() for p in explicit]
    out = []
    for path in sorted(ROOT.rglob("*.md")):
        rel = path.relative_to(ROOT).as_posix()
        if any(part in SKIP_DIRS for part in path.relative_to(ROOT).parts) or rel.startswith(SKIP_PREFIXES):
            continue
        out.append(path)
    return out


def rel(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def fenced_blocks(text: str):
    """Yield (language, first_line_number, [lines]) for every fenced block."""
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = re.match(r"^\s*(```+|~~~+)\s*([A-Za-z0-9_+-]*)", lines[i])
        if m:
            fence, lang = m.group(1), m.group(2).lower()
            start, body = i + 1, []
            i += 1
            while i < len(lines) and not lines[i].lstrip().startswith(fence[:3]):
                body.append(lines[i])
                i += 1
            yield lang, start + 1, body
        i += 1


# ----------------------------------------------------------------------------------------------------------------------
# commands


def command_tree():
    """(group, {path tuple: {option names}}) from the program itself."""
    import typer.main

    from scrutator import cli

    group = typer.main.get_command(cli.app)
    paths: dict[tuple[str, ...], set[str]] = {}
    VALUE_OPTS.clear()

    def walk(cmd, path):
        opts = {o for p in cmd.params for o in [*p.opts, *p.secondary_opts] if o.startswith("--")}
        VALUE_OPTS.update(o for p in cmd.params if not getattr(p, "is_flag", False) and getattr(p, "param_type_name", "") == "option" for o in p.opts)
        paths[path] = opts | {"--help"}
        for name, sub in (getattr(cmd, "commands", None) or {}).items():
            walk(sub, (*path, name))

    walk(group, ())
    paths[()] |= {"--version"}
    return paths


VALUE_OPTS: set[str] = set()  # options that take a value (their next word is not a command word)
HELP_CACHE: dict[tuple[str, ...], tuple[int, str]] = {}


def help_text(path: tuple[str, ...]) -> tuple[int, str]:
    if path not in HELP_CACHE:
        env = {**os.environ, "COLUMNS": "250", "NO_COLOR": "1", "TERM": "dumb"}
        proc = subprocess.run([sys.executable, "-m", "scrutator", *path, "--help"], capture_output=True, env=env, timeout=120)
        HELP_CACHE[path] = (proc.returncode, re.sub(r"\s+", " ", proc.stdout.decode("utf-8", "replace")))
    return HELP_CACHE[path]


def logical_lines(body: list[str]):
    """Join backslash continuations; yield (offset, text)."""
    buf, start = "", 0
    for n, raw in enumerate(body):
        line = raw.rstrip()
        if not buf:
            start = n
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        yield start, (buf + line).strip()
        buf = ""
    if buf:
        yield start, buf.strip()


def check_commands(files: list[Path], problems: list[str]) -> int:
    tree = command_tree()
    checked = 0
    seen_paths: set[tuple[str, ...]] = set()
    for path in files:
        text = path.read_text(encoding="utf-8")
        for lang, first, body in fenced_blocks(text):
            if lang in ("mermaid", "json", "yaml", "yml", "toml", "ini", "python", "powershell"):
                continue
            for offset, line in logical_lines(body):
                if not line.startswith(("scrutator ", "$ scrutator ")):
                    continue
                line = line.removeprefix("$ ")
                code = re.split(r"\s+#\s", line)[0]
                try:
                    words = shlex.split(code, posix=True)[1:]
                except ValueError:
                    problems.append(f"{rel(path)}:{first + offset}: cannot parse `{line}`")
                    continue
                for stop in ("<", ">", "|", "&&", "||", ";", "2>&1"):
                    if stop in words:
                        words = words[: words.index(stop)]
                where = f"{rel(path)}:{first + offset}"
                if not words or words[0].startswith("<"):
                    continue
                checked += 1
                positional, skip = [], False
                for w in words:
                    if skip:
                        skip = False
                    elif w.startswith("-"):
                        skip = w in VALUE_OPTS
                    else:
                        positional.append(w)
                cmd_path: tuple[str, ...] = ()
                for w in positional[:2]:
                    if (*cmd_path, w) in tree:
                        cmd_path = (*cmd_path, w)
                    else:
                        break
                if not cmd_path and positional:
                    problems.append(f"{where}: `scrutator {positional[0]}` is not a command: {line}")
                    continue
                known = tree[cmd_path] | tree[()]  # a command's own options and the program's (`--proxy`, `--version`)
                if any(len(k) == len(cmd_path) + 1 and k[: len(cmd_path)] == cmd_path for k in tree) and len(positional) > len(cmd_path):
                    problems.append(f"{where}: `scrutator {' '.join(cmd_path)} {positional[len(cmd_path)]}` is not a command: {line}")
                    continue
                for w in words:
                    if w.startswith("--"):
                        opt = w.split("=")[0]
                        if opt not in known:
                            problems.append(f"{where}: {opt} is not an option of `scrutator {' '.join(cmd_path)}`: {line}")
                if cmd_path not in seen_paths:
                    seen_paths.add(cmd_path)
                    code_, out = help_text(cmd_path)
                    if code_ != 0:
                        problems.append(f"{where}: `scrutator {' '.join(cmd_path)} --help` exits {code_}")
                for w in words:
                    if w.startswith("--"):
                        opt = w.split("=")[0]
                        if opt in known and opt not in ("--version", "--help") and opt not in help_text(cmd_path)[1] and opt not in help_text(())[1]:
                            problems.append(f"{where}: {opt} is not printed by `scrutator {' '.join(cmd_path)} --help`")
    return checked


# ----------------------------------------------------------------------------------------------------------------------
# links


def slug(heading: str) -> str:
    text = re.sub(r"[`*_]", "", heading.strip().lower())
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def anchors(path: Path) -> set[str]:
    out: set[str] = set()
    counts: dict[str, int] = {}
    fenced = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
        elif not fenced and line.startswith("#"):
            s = slug(re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", line.lstrip("#")))
            n = counts.get(s, 0)
            counts[s] = n + 1
            out.add(s if n == 0 else f"{s}-{n}")
    for m in re.finditer(r'<a\s+(?:name|id)="([^"]+)"', path.read_text(encoding="utf-8")):
        out.add(m.group(1))
    return out


def check_links(files: list[Path], problems: list[str]) -> int:
    checked = 0
    for path in files:
        text = re.sub(r"```.*?```", lambda m: "\n" * m.group(0).count("\n"), path.read_text(encoding="utf-8"), flags=re.S)
        text = re.sub(r"`[^`\n]*`", "", text)
        for n, line in enumerate(text.splitlines(), 1):
            for target in re.findall(r"\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)", line):
                if re.match(r"[a-z][a-z0-9+.-]*:", target):
                    continue
                checked += 1
                dest, _, fragment = target.partition("#")
                resolved = (path.parent / dest).resolve() if dest else path
                if not resolved.exists():
                    problems.append(f"{rel(path)}:{n}: link to {target}: no such file")
                elif fragment and resolved.suffix == ".md" and fragment not in anchors(resolved):
                    problems.append(f"{rel(path)}:{n}: link to {target}: no such heading in {rel(resolved)}")
    return checked


# ----------------------------------------------------------------------------------------------------------------------
# mermaid

DIAGRAMS = ("flowchart", "graph", "stateDiagram-v2", "stateDiagram", "sequenceDiagram", "classDiagram", "erDiagram", "gantt", "pie", "journey", "timeline", "mindmap")
EDGE = re.compile(r"-->|---|-\.->|==>|--[ox]|<-->|->>|-->>")


def balanced(text: str) -> str:
    pairs = {"]": "[", ")": "(", "}": "{"}
    stack = []
    in_q = False
    for ch in text:
        if ch == '"':
            in_q = not in_q
            continue
        if in_q:
            continue
        if ch in "[({":
            stack.append(ch)
        elif ch in pairs:
            if not stack or stack.pop() != pairs[ch]:
                return f"unbalanced {ch}"
    if in_q:
        return "unterminated quote"
    if stack:
        return f"unclosed {stack[-1]}"
    return ""


def check_mermaid(files: list[Path], problems: list[str]) -> int:
    checked = 0
    for path in files:
        for lang, first, body in fenced_blocks(path.read_text(encoding="utf-8")):
            if lang != "mermaid":
                continue
            checked += 1
            where = f"{rel(path)}:{first}"
            lines = [l for l in body if l.strip() and not l.strip().startswith("%%")]
            if not lines:
                problems.append(f"{where}: empty mermaid block")
                continue
            head = lines[0].split()[0]
            if head not in DIAGRAMS:
                problems.append(f"{where}: unknown diagram type {head!r}")
                continue
            for k, line in enumerate(lines[1:], 1):
                issue = balanced(line)
                if issue:
                    problems.append(f"{where}+{k}: {issue}: {line.strip()}")
                    continue
                s = line.strip()
                if head in ("flowchart", "graph"):
                    if s.startswith(("subgraph", "end", "direction", "classDef", "class ", "style ", "linkStyle", "click ")):
                        continue
                    if not EDGE.search(s) and not re.match(r"^[A-Za-z0-9_]+(\[.*\]|\(.*\)|\{.*\})?$", s):
                        problems.append(f"{where}+{k}: not a node or an edge: {s}")
                elif head.startswith("stateDiagram"):
                    if s.startswith(("state ", "note ", "}", "direction")) or s.endswith("{"):
                        continue
                    if "-->" not in s and not re.match(r"^[A-Za-z0-9_\[\]*]+\s*:\s*.+$", s):
                        problems.append(f"{where}+{k}: not a transition: {s}")
    return checked


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("files", nargs="*", help="Markdown files (default: every tracked-style Markdown file except private folders)")
    ap.add_argument("--only", choices=("commands", "links", "mermaid"))
    args = ap.parse_args()
    files = markdown_files(args.files)
    problems: dict[str, list[str]] = {"commands": [], "links": [], "mermaid": []}
    counts = {}
    if args.only in (None, "commands"):
        counts["commands"] = check_commands(files, problems["commands"])
    if args.only in (None, "links"):
        counts["links"] = check_links(files, problems["links"])
    if args.only in (None, "mermaid"):
        counts["mermaid"] = check_mermaid(files, problems["mermaid"])
    bad = 0
    for kind, found in problems.items():
        if kind in counts:
            print(f"{kind}: checked {counts[kind]} in {len(files)} file(s): {'OK' if not found else str(len(found)) + ' problem(s)'}")
            for p in found:
                print("  " + p)
            bad += len(found)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
