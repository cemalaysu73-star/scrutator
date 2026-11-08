#!/usr/bin/env python3
"""Prepare a public, push-ready copy of this repository. It never pushes, never creates a repository and never
touches the original repository: every git command that rewrites anything runs inside a fresh clone.

    python release/make_public.py                      # clone, rewrite, scan, test, bench, build; print the clean clone's path
    python release/make_public.py --skip-tests         # scan and rewrite only (fast)
    python release/make_public.py --self-test          # prove the scanner finds planted secrets, then exit

What it does, in order:

 1. clones the current local repository (committed history only: uncommitted changes are NOT included, and it says so)
    into a new folder OUTSIDE the repository, and removes the clone's `origin` so a push cannot go anywhere by accident;
 2. rewrites the history of the CLONE ONLY (git filter-repo when installed, otherwise `git filter-branch`): drops the
    private paths (PRIVATE_PATHS), prunes bench/results down to the small summary files of the final runs, and sets
    every author and committer to `Cemal <cemalaysu73-star@users.noreply.github.com>`;
 3. scans the whole rewritten history (every blob ever reachable, every commit message, author and path) and the tree
    for secrets and personal data (RULES), including inside zip members (.scrutator bundles, wheels) and PDF streams;
    ANY finding makes the script exit non-zero and list every hit; the rewritten clone is then NOT fit to push;
 4. in a second clone and fresh virtual environments, runs the full test suite with outbound network blocked,
    `scrutator bench`, and builds the wheel, installs it into another fresh environment and runs tools/wheel_smoke.py;
 5. prints a summary and the path of the clean clone, and writes make_public.report.json next to it.

Exit status: 0 everything passed; 1 a scan finding; 2 a build, test or bench failure; 3 the script could not run.
Re-run it any time: each run makes a new folder (old ones are listed, not deleted). Standard library only."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path

PUBLIC_NAME = "Cemal"
PUBLIC_EMAIL = "cemalaysu73-star@users.noreply.github.com"

# Paths that must never be public (matched against repository-relative POSIX paths, in every commit).
PRIVATE_PATHS = [
    r"^docs/business/",
    r"^\.cemal/",
    r"^\.claude/",
    r"^design/",
    r"^live[^/]*/",
    r"^[^/]*(?:-scan|-live)\.log$",
    r"^[^/]*\.log$",
    r"^demo-out/",
    r"^scrutator-out/",
    r"^scrutator-bench/",
    r"^audit-out/",
    r"^authorisation/",
    r"^bounty-watch/",
    r"^bounty-scope\.yaml$",
    r"^bench/work/",
    r"^keys/",
    r"(?:^|/)signing\.key$",
    r".*\.key$",
    r".*\.pem$",
    r".*\.db$",
    r"^docs/superpowers/plans/",  # the agent working plans of the build: not documentation of the product
    r"(?:^|/)__pycache__/",
    r"^\.hypothesis/",
    r"^\.pytest_cache/",
]

# bench/results holds the raw output of every benchmark run, with absolute paths of the author's machine. Only these
# small summary files of the runs the docs cite survive: the tables, the scored results and the name lists.
BENCH_KEEP = [
    r"^bench/results/(?:2026-10-20-r4-a|2026-10-21-r6-final)/(?:tables\.md|variance\.md|results\.json|resolution\.json|zone\.truth\.txt|axfr\.failed\.txt)$",
    r"^bench/results/(?:2026-10-20-r4-a|2026-10-21-r6-final)/[^/]+/[^/]+\.names\.txt$",
    r"^bench/results/2026-10-21-r6/(?:ttfn-[a-z]+\.json|axfr-zonetransfer\.txt)$",
    r"^bench/results/2026-10-20-timing/set\d-times\.json$",
]

# an absolute path in the author's profile, as it appears in the kept bench files (JSON escapes the backslashes)
SCRUB_PATH = r"""[A-Za-z]:[\\/]+Users[\\/]+cemal(?:[\\/]+[^\\/\s"',;)]+)*[\\/]*"""

# What must not appear anywhere in the public tree or history. (name, regex, flags, explanation)
# "fail" rules make the script exit 1; "warn" rules are listed and do not fail (a dangling reference, not a leak).
RULES: list[tuple] = [
    ("family-company", "centrum" + "vc|why" + "back", re.I, "a private test target or the family company", "fail"),
    ("handle-without-star", "cemal" + "aysu73(?!-star)", re.I, "the personal e-mail handle", "fail"),
    ("personal-email", r"[A-Za-z0-9._%+-]+@(?:gmail|googlemail|hotmail|outlook|live|yahoo|ymail|icloud|protonmail|proton)\.(?:com|me|net)", re.I, "a personal e-mail address", "fail"),
    ("gmail-domain", r"gmail\.com", re.I, "a mention of gmail.com (allowed only in the public-mail-provider lists and fixtures of PATH_ALLOW)", "fail"),
    ("windows-user-path", r"[A-Za-z]:[\\/]+Users[\\/]+(?!Public\b|Default\b|<|%|\$|\{|\.\.\.|you\b|me\b|name\b|username\b|user\b|YOU\b|your)[^\\/\s\"'`<>|:*?]+", 0, "an absolute path in a user profile", "fail"),
    ("unix-home-path", r"/(?:Users|home)/(?:cemal|aysu)[^\s\"']*", re.I, "an absolute path in the author's home", "fail"),
    ("author-profile-dir", r"[\\/]cemal[\\/]", re.I, "a path component naming the author's profile", "fail"),
    ("claude-scratch", r"AppData[\\/]+Local[\\/]+Temp[\\/]+claude", re.I, "a local agent scratch path", "fail"),
    ("private-key-header", r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----", 0, "a private key header", "fail"),
    ("private-key-any", r"BEGIN [A-Z ]*PRIVATE KEY", 0, "a private key header (loose)", "fail"),
    ("scrutator-key-value", r"SCRUTATOR_[A-Z_]*KEY\s*[=:]\s*[\"']?(?![\"']?\s*$)(?!<|\.\.\.|\$|%|\{|your|xxx|changeme|example|test|canary|secret|key\b)[A-Za-z0-9_\-]{12,}", re.I, "an API key value", "fail"),
    ("github-token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|github_pat_[A-Za-z0-9_]{30,}", 0, "a GitHub token", "fail"),
    ("provider-token", r"\bsk-(?:ant-)?[A-Za-z0-9_\-]{30,}\b|\bAKIA[0-9A-Z]{16}\b|\bxox[baprs]-[A-Za-z0-9-]{10,}|\bAIza[0-9A-Za-z_\-]{35}\b|-----BEGIN PGP PRIVATE", 0, "a provider token", "fail"),
    ("jwt", r"\beyJ[A-Za-z0-9_\-]{15,}\.eyJ[A-Za-z0-9_\-]{15,}\.[A-Za-z0-9_\-]{10,}", 0, "a JSON web token", "fail"),
    ("private-dir-reference", r"\.cemal/", 0, "a reference to the private .cemal folder (dangling in the public repository)", "warn"),
    ("business-pack-reference", r"docs/business|\]\((?:\.\./)?business/", 0, "a reference to the private business pack", "warn"),
]

# bare gmail.com is legitimate where the code lists public mail providers or a test plants a personal address; these
# paths (in any commit) may contain it. Everything else is a finding.
PATH_ALLOW = {
    "gmail-domain": {
        "src/scrutator/engagement.py",
        "src/scrutator/benchlab/exposurelab.py",
        "src/scrutator/benchlab/run.py",
        "tests/test_org_exposure.py",
    },
    "personal-email": {
        "src/scrutator/benchlab/exposurelab.py",
        "tests/test_org_exposure.py",
    },
    # a test that writes a malformed key file (a header and the word "nope") to prove it is refused
    "private-key-header": {"tests/test_keys.py"},
    "private-key-any": {"tests/test_keys.py"},
}
# the planted fixture addresses (obviously fictional) that the exposure lab uses to prove such addresses are dropped
FIXTURE_ALLOW = {
    "anna.berg.private@gmail.com",
    "x@gmail.com",
}

# this file defines the patterns and plants test secrets in its self-test, so its own rule matches are exempt (secret
# material and key identities are still searched for in it)
SELF_PATH = "release/make_public.py"

# files that are binary on purpose and are scanned inside (zip members, PDF streams) or skipped
TEXT_LIMIT = 40 * 1024 * 1024


@dataclass
class Finding:
    rule: str
    level: str
    where: str
    snippet: str

    def line(self) -> str:
        return f"[{self.level.upper()}] {self.rule}: {self.where}: {self.snippet}"


@dataclass
class Scanner:
    secrets: list[str] = field(default_factory=list)  # literal private material to search for
    denylist_keys: dict[str, str] = field(default_factory=dict)  # literal -> description (public keys, fingerprints)
    findings: list[Finding] = field(default_factory=list)
    allowed: int = 0
    scanned_blobs: int = 0
    _compiled: list = field(default_factory=list)
    _seen: set = field(default_factory=set)

    def __post_init__(self) -> None:
        self._compiled = [(n, re.compile(rx.encode(), fl), why, level) for n, rx, fl, why, level in RULES]

    def add(self, rule: str, level: str, where: str, snippet: str) -> None:
        key = (rule, where, snippet)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(Finding(rule, level, where, snippet))

    def scan_text(self, data: bytes, where: str, path: str | None = None) -> None:
        for name, rx, _why, level in ([] if path == SELF_PATH else self._compiled):
            for m in rx.finditer(data):
                hit = m.group(0).decode("utf-8", "replace")
                if name in PATH_ALLOW and path and (path in PATH_ALLOW[name] or f"src/{path}" in PATH_ALLOW[name]):  # a wheel names files without src/
                    self.allowed += 1
                    continue
                if name in ("personal-email",) and hit.lower() in FIXTURE_ALLOW:
                    self.allowed += 1
                    continue
                self.add(name, level, where, _clip(hit, data, m.start()))
        for secret in self.secrets:
            if secret.encode() in data:
                self.add("private-key-material", "fail", where, f"contains the content of a private key file ({len(secret)} chars)")
        for literal, why in self.denylist_keys.items():
            if literal.encode() in data:
                self.add("private-key-identity", "fail", where, f"contains {why}")

    def scan_blob(self, data: bytes, where: str, path: str | None = None, depth: int = 0) -> None:
        self.scanned_blobs += 1
        self.scan_text(data, where, path)
        if depth > 2:
            return
        if data[:2] == b"PK":
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    for info in z.infolist()[:2000]:
                        if info.file_size > TEXT_LIMIT or info.is_dir():
                            continue
                        member = z.read(info)
                        self.scan_text(info.filename.encode(), f"{where}::{info.filename} (member name)", path)
                        self.scan_blob(member, f"{where}::{info.filename}", path or info.filename, depth + 1)
            except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError):
                pass
        elif data[:5] == b"%PDF-":
            for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", data, re.S):
                try:
                    inflated = zlib.decompress(m.group(1))
                except zlib.error:
                    continue
                self.scan_text(inflated, f"{where}::pdf stream", path)

    def scan_path(self, rel: str, where: str) -> None:
        for rx in PRIVATE_PATHS:
            if re.search(rx, rel):
                self.add("private-path", "fail", where, rel)
                break
        self.scan_text(rel.encode(), f"{where} (file name)", None)


def _clip(hit: str, data: bytes, start: int) -> str:
    line_start = data.rfind(b"\n", 0, start) + 1
    line_end = data.find(b"\n", start)
    line = data[line_start : line_end if line_end >= 0 else len(data)].decode("utf-8", "replace").strip()
    line = re.sub(r"\s+", " ", line)
    return (line[:140] + "...") if len(line) > 140 else line


# ----------------------------------------------------------------------------------------------------------------------
# git helpers


def clean_env() -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["FILTER_BRANCH_SQUELCH_WARNING"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def git(args: list[str], cwd: Path, *, check: bool = True, text: bool = True, input: bytes | None = None, timeout: int = 1800):
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, env=clean_env(), input=input, timeout=timeout)
    if check and proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed ({proc.returncode}): {proc.stderr.decode('utf-8', 'replace')[:2000]}")
    if text:
        return proc.stdout.decode("utf-8", "replace")
    return proc.stdout


def say(message: str = "") -> None:
    print(message, flush=True)


def step(title: str) -> None:
    say(f"\n=== {title}")


# ----------------------------------------------------------------------------------------------------------------------
# 1. private material of the original machine: what must never be found in the public clone


def collect_private_material(repo: Path, scanner: Scanner) -> list[str]:
    """Key files that exist outside the public set: their content and their public identity become search terms."""
    notes = []
    roots = [repo]
    home = Path(os.path.expanduser("~"))
    if (home / ".config" / "scrutator").is_dir():
        roots.append(home / ".config" / "scrutator")
    public_pub = {p.resolve() for p in (repo / "docs" / "examples").rglob("signing.pub")}
    skip_dirs = {".git", ".venv", "node_modules", "__pycache__"}
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]
            for name in filenames:
                path = Path(dirpath) / name
                if name == "signing.key":
                    text = _read(path).strip()
                    if len(text) >= 16:
                        scanner.secrets.append(text)
                        notes.append(f"private key file {path} ({len(text)} chars)")
                elif name == "signing.pub":
                    rel = path.resolve()
                    # the demo folders (demo-out/) hold the same throwaway keys that the public examples use; those are
                    # meant to be public. Anything else (live*/, bench/work/, the user's own key dir) is private.
                    if rel in public_pub or "demo-out" in path.parts:
                        continue
                    b64 = _read(path).strip()
                    _deny_public_key(scanner, b64, str(path), notes)
    # the examples must not use a private identity
    for pub in sorted(public_pub):
        b64 = _read(pub).strip()
        fp = _fingerprint(b64)
        if b64 in scanner.denylist_keys or (fp and fp in scanner.denylist_keys):
            scanner.add("example-signed-with-private-key", "fail", str(pub.relative_to(repo)), "the public example is signed with a non-throwaway key")
    return notes


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _fingerprint(b64: str) -> str:
    import base64

    try:
        return hashlib.sha256(base64.b64decode(b64, validate=True)).hexdigest()
    except Exception:
        return ""


def _deny_public_key(scanner: Scanner, b64: str, origin: str, notes: list[str]) -> None:
    if len(b64) < 20:
        return
    fp = _fingerprint(b64)
    scanner.denylist_keys[b64] = f"the public key of a private signing key ({Path(origin).parent.name})"
    if fp:
        scanner.denylist_keys[fp] = f"the fingerprint of a private signing key ({Path(origin).parent.name})"
    notes.append(f"private public-key {origin} (fingerprint {fp[:12] or '?'}...)")


# ----------------------------------------------------------------------------------------------------------------------
# 2. clone and rewrite


def make_clone(repo: Path, work: Path) -> Path:
    clone = work / "scrutator-public"
    git(["clone", "--no-local", "--no-hardlinks", "--quiet", str(repo), str(clone)], work)
    git(["remote", "remove", "origin"], clone)
    # only the branch of HEAD survives: other local branches of the original are not part of what is published
    return clone


INDEX_FILTER = r'''#!/usr/bin/env python3
import json, re, subprocess, sys
cfg = json.load(open(sys.argv[1], encoding="utf-8"))
drop = [re.compile(r) for r in cfg["private"]]
keep = [re.compile(r) for r in cfg["bench_keep"]]
# the kept bench files record the author's absolute paths in the commands they ran: replace each path by <path>
scrub = re.compile(cfg["scrub"].encode())
staged = subprocess.run(["git", "ls-files", "-s", "-z"], capture_output=True, check=True).stdout.decode("utf-8", "surrogateescape")
doomed, rewritten = [], []
for entry in staged.split("\0"):
    if not entry:
        continue
    meta, _, path = entry.partition("\t")
    mode, sha, _stage = meta.split()
    if path.startswith("bench/results/"):
        if not any(k.search(path) for k in keep):
            doomed.append(path)
            continue
        blob = subprocess.run(["git", "cat-file", "blob", sha], capture_output=True, check=True).stdout
        fixed = scrub.sub(b"<path>", blob)
        if fixed != blob:
            new = subprocess.run(["git", "hash-object", "-w", "--stdin"], input=fixed, capture_output=True, check=True).stdout.decode().strip()
            rewritten.append(f"{mode},{new},{path}")
    elif any(d.search(path) for d in drop):
        doomed.append(path)
if doomed:
    data = ("\0".join(doomed) + "\0").encode("utf-8", "surrogateescape")
    subprocess.run(["git", "update-index", "--force-remove", "-z", "--stdin"], input=data, check=True)
for spec in rewritten:
    subprocess.run(["git", "update-index", "--add", "--cacheinfo", spec], check=True)
'''


def rewrite_history(clone: Path, work: Path, use_filter_repo: bool = False) -> str:
    cfg = work / "filter-config.json"
    cfg.write_text(json.dumps({"private": PRIVATE_PATHS, "bench_keep": BENCH_KEEP, "scrub": SCRUB_PATH}), encoding="utf-8")
    script = work / "index_filter.py"
    script.write_text(INDEX_FILTER, encoding="utf-8")
    top = git(["rev-parse", "--show-toplevel"], clone).strip()
    if Path(top).resolve() != clone.resolve():
        raise RuntimeError(f"refusing to rewrite: {top} is not the clone {clone}")
    branch = git(["rev-parse", "--abbrev-ref", "HEAD"], clone).strip()
    if use_filter_repo:
        engine = "git filter-repo"
        callback = work / "filter-repo-callback.py"
        callback.write_text(
            "import json,re\n"
            f"cfg=json.load(open({str(cfg)!r},encoding='utf-8'))\n"
            "drop=[re.compile(r) for r in cfg['private']]; keep=[re.compile(r) for r in cfg['bench_keep']]\n"
            "p=filename.decode('utf-8','surrogateescape')\n"
            "if p.startswith('bench/results/'):\n"
            "    return filename if any(k.search(p) for k in keep) else None\n"
            "return None if any(d.search(p) for d in drop) else filename\n",
            encoding="utf-8",
        )
        git(["filter-repo", "--force", "--filename-callback", callback.read_text(encoding="utf-8"), "--name-callback", f"return {PUBLIC_NAME.encode()!r}", "--email-callback", f"return {PUBLIC_EMAIL.encode()!r}", "--prune-empty", "always"], clone)
    else:
        engine = "git filter-branch"
        py = Path(sys.executable).as_posix()
        env_filter = (
            f'export GIT_AUTHOR_NAME="{PUBLIC_NAME}" GIT_AUTHOR_EMAIL="{PUBLIC_EMAIL}" '
            f'GIT_COMMITTER_NAME="{PUBLIC_NAME}" GIT_COMMITTER_EMAIL="{PUBLIC_EMAIL}"'
        )
        index_filter = f'"{py}" "{script.as_posix()}" "{cfg.as_posix()}"'
        git(["filter-branch", "-f", "--index-filter", index_filter, "--env-filter", env_filter, "--prune-empty", "--tag-name-filter", "cat", "--", branch], clone)
        shutil.rmtree(clone / ".git" / "refs" / "original", ignore_errors=True)
    git(["reflog", "expire", "--expire=now", "--all"], clone)
    git(["gc", "--prune=now", "--quiet"], clone)
    # keep only the branch that was HEAD
    for ref in git(["for-each-ref", "--format=%(refname)", "refs/heads", "refs/remotes", "refs/tags"], clone).split():
        if ref not in (f"refs/heads/{branch}",) and not ref.startswith("refs/tags/"):
            git(["update-ref", "-d", ref], clone, check=False)
    git(["reflog", "expire", "--expire=now", "--all"], clone)
    git(["gc", "--prune=now", "--quiet"], clone)
    return engine


# ----------------------------------------------------------------------------------------------------------------------
# 3. scan the rewritten history and the tree


def scan_clone(clone: Path, scanner: Scanner) -> dict:
    stats: dict = {}
    # commit metadata: names, e-mails, messages
    meta = git(["log", "--all", "--format=%H%x00%an%x00%ae%x00%cn%x00%ce%x00%B%x01"], clone, text=False)
    commits = [c for c in meta.split(b"\x01") if c.strip()]
    stats["commits"] = len(commits)
    identities = set()
    for c in commits:
        parts = c.lstrip(b"\n").split(b"\x00", 5)
        if len(parts) < 6:
            continue
        sha = parts[0].decode()[:10]
        for i in (1, 3):
            identities.add((parts[i].decode("utf-8", "replace"), parts[i + 1].decode("utf-8", "replace")))
        scanner.scan_text(b" ".join(parts[1:5]) + b"\n" + parts[5], f"commit {sha} (author, committer, message)")
    stats["identities"] = sorted(identities)
    for name, email in identities:
        if (name, email) != (PUBLIC_NAME, PUBLIC_EMAIL):
            scanner.add("author-identity", "fail", "commit metadata", f"{name} <{email}>")
    # tags, branches
    refs = git(["for-each-ref", "--format=%(refname) %(contents)"], clone)
    scanner.scan_text(refs.encode(), "refs and tag messages")
    # every path ever committed
    paths = git(["log", "--all", "--name-only", "--format=", "-z"], clone, text=False).split(b"\x00")
    seen_paths = set()
    for raw in paths:
        rel = raw.decode("utf-8", "replace").strip("\n")
        if rel and rel not in seen_paths:
            seen_paths.add(rel)
            scanner.scan_path(rel, "history path")
    stats["paths_ever"] = len(seen_paths)
    # every blob ever reachable, once, with the path it was seen at
    listing = git(["rev-list", "--objects", "--all"], clone, text=False).decode("utf-8", "surrogateescape").splitlines()
    blob_paths: dict[str, str] = {}
    for line in listing:
        sha, _, path = line.partition(" ")
        if path:
            blob_paths.setdefault(sha, path)
    batch_in = "\n".join(blob_paths).encode() + b"\n"
    proc = subprocess.Popen(["git", "cat-file", "--batch"], cwd=clone, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=clean_env())
    out, _ = proc.communicate(batch_in)
    pos, count = 0, 0
    while pos < len(out):
        nl = out.index(b"\n", pos)
        header = out[pos:nl].split()
        pos = nl + 1
        if len(header) < 3:
            continue
        sha, kind, size = header[0].decode(), header[1], int(header[2])
        body = out[pos : pos + size]
        pos += size + 1
        if kind != b"blob":
            continue
        count += 1
        path = blob_paths.get(sha, "")
        scanner.scan_blob(body, f"blob {sha[:10]} ({path or '?'})", path)
    stats["blobs"] = count
    # the working tree must equal HEAD (no stray untracked files)
    status = git(["status", "--porcelain"], clone)
    if status.strip():
        scanner.add("dirty-clone", "fail", "working tree", status.strip()[:200])
    return stats


# ----------------------------------------------------------------------------------------------------------------------
# 4. tests, bench, wheel in fresh environments


BLOCK_NET = '''"""pytest plugin: record (and refuse) every outbound network attempt made inside the test process."""
import ipaddress, os, socket
_LOG = os.environ.get("MAKE_PUBLIC_NETLOG")
def _local(host):
    if host in (None, "", "localhost"):
        return True
    try:
        ip = ipaddress.ip_address(str(host).split("%")[0])
    except ValueError:
        return False
    return ip.is_loopback or ip.is_unspecified
def _record(kind, target):
    if _LOG:
        with open(_LOG, "a", encoding="utf-8") as f:
            f.write(f"{kind} {target}\\n")
def _guard(kind, orig):
    def wrapper(self, address, *a, **k):
        host = address[0] if isinstance(address, tuple) else address
        if isinstance(address, str) or (isinstance(address, bytes)) or _local(host):
            return orig(self, address, *a, **k)
        _record(kind, address)
        raise OSError(f"network blocked by make_public: {kind} {address}")
    return wrapper
socket.socket.connect = _guard("connect", socket.socket.connect)
socket.socket.connect_ex = _guard("connect_ex", socket.socket.connect_ex)
_orig_sendto = socket.socket.sendto
def _sendto(self, data, *args):
    address = args[-1]
    host = address[0] if isinstance(address, tuple) else address
    if _local(host):
        return _orig_sendto(self, data, *args)
    _record("sendto", address)
    raise OSError(f"network blocked by make_public: sendto {address}")
socket.socket.sendto = _sendto
_orig_gai = socket.getaddrinfo
def _gai(host, *a, **k):
    if _local(host):
        return _orig_gai(host, *a, **k)
    try:
        ipaddress.ip_address(str(host))
        return _orig_gai(host, *a, **k)
    except ValueError:
        pass
    _record("getaddrinfo", host)
    raise socket.gaierror(f"network blocked by make_public: {host}")
socket.getaddrinfo = _gai
'''


def run(cmd: list[str], cwd: Path, *, env: dict | None = None, timeout: int = 3600, log: Path | None = None) -> tuple[int, str]:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, env={**clean_env(), **(env or {})}, timeout=timeout)
    text = (proc.stdout + b"\n" + proc.stderr).decode("utf-8", "replace")
    if log:
        log.write_text(text, encoding="utf-8")
    return proc.returncode, text


def venv_python(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def venv_exe(venv: Path, name: str) -> Path:
    if os.name == "nt":
        return venv / "Scripts" / f"{name}.exe"
    return venv / "bin" / name


def build_and_test(clone: Path, work: Path, args: argparse.Namespace, scanner: Scanner) -> dict:
    results: dict = {}
    verify = work / "verify"
    git(["clone", "--quiet", str(clone), str(verify)], work)
    py = args.python or sys.executable
    plugin_dir = work / "plugin"
    plugin_dir.mkdir(exist_ok=True)
    (plugin_dir / "blocknet.py").write_text(BLOCK_NET, encoding="utf-8")
    netlog = work / "network-attempts.log"
    netlog.write_text("", encoding="utf-8")
    venv = work / "venv"
    step("Fresh virtual environment from the clean clone (installing dependencies needs network)")
    code, text = run([py, "-m", "venv", str(venv)], work, log=work / "venv.log")
    if code:
        results["venv"] = {"ok": False, "detail": text[-400:]}
        return results
    vpy = str(venv_python(venv))
    code, text = run([vpy, "-m", "pip", "install", "--quiet", "-e", f"{verify}[dev]"], verify, log=work / "pip-install.log")
    results["install"] = {"ok": code == 0, "detail": "" if code == 0 else text[-600:]}
    say(f"  pip install -e .[dev]: {'ok' if code == 0 else 'FAILED'}")
    if code:
        return results

    if not args.skip_tests:
        step("Full test suite in the clean clone, outbound network blocked")
        started = dt.datetime.now()
        env = {"PYTHONPATH": str(plugin_dir), "MAKE_PUBLIC_NETLOG": str(netlog), "PYTHONDONTWRITEBYTECODE": "1"}
        code, text = run([vpy, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "blocknet", "--maxfail=50"], verify, env=env, timeout=3600, log=work / "pytest.log")
        tail = "\n".join(text.strip().splitlines()[-6:])
        attempts = [l for l in netlog.read_text(encoding="utf-8").splitlines() if l.strip()]
        results["tests"] = {"ok": code == 0, "seconds": round((dt.datetime.now() - started).total_seconds()), "tail": tail, "network_attempts_blocked": len(attempts), "network_attempt_samples": sorted(set(attempts))[:10]}
        say(tail)
        say(f"  network attempts blocked during the tests: {len(attempts)}")
    else:
        results["tests"] = {"ok": None, "detail": "skipped"}

    if not args.skip_bench:
        step("scrutator bench (offline) in the clean clone")
        out = work / "bench-out"
        code, text = run([str(venv_exe(venv, "scrutator")), "bench", "--out", str(out)], verify, timeout=1800, log=work / "bench.log")
        summary = next((l for l in text.splitlines() if l.startswith("OSINT-Bench")), text.strip().splitlines()[-1] if text.strip() else "")
        results["bench"] = {"ok": code == 0, "summary": summary}
        say(f"  exit {code}: {summary}")
        if code == 0 and (out / "bench.json").exists():
            scanner.scan_text((out / "bench.json").read_bytes(), "bench output bench.json")
            scanner.scan_text((out / "bench.md").read_bytes() if (out / "bench.md").exists() else b"", "bench output bench.md")

    if not args.skip_wheel:
        step("Wheel from the clean clone, installed in another fresh environment")
        wheels = work / "wheel"
        code, text = run([vpy, "-m", "pip", "wheel", ".", "--no-deps", "-w", str(wheels), "--quiet"], verify, log=work / "wheel-build.log")
        built = sorted(wheels.glob("scrutator-*.whl"))
        if code or not built:
            results["wheel"] = {"ok": False, "detail": text[-600:]}
            say("  wheel build FAILED")
            return results
        wheel = built[-1]
        wheel_scan_before = len(scanner.findings)
        scanner.scan_blob(wheel.read_bytes(), f"wheel {wheel.name}")
        venv2 = work / "venv-wheel"
        run([py, "-m", "venv", str(venv2)], work)
        code, text = run([str(venv_python(venv2)), "-m", "pip", "install", "--quiet", f"{wheel}[mcp]"], work, log=work / "wheel-install.log")
        if code:
            results["wheel"] = {"ok": False, "detail": "install: " + text[-600:]}
            return results
        smoke_dir = work / "smoke"
        code, text = run([str(venv_python(venv2)), "-I", str(verify / "tools" / "wheel_smoke.py"), "--scrutator", str(venv_exe(venv2, "scrutator")), "--work", str(smoke_dir)], work, timeout=1800, log=work / "wheel-smoke.log")
        passed = sum(1 for l in text.splitlines() if l.startswith("PASS"))
        failed = sum(1 for l in text.splitlines() if l.startswith("FAIL"))
        results["wheel"] = {"ok": code == 0, "file": wheel.name, "bytes": wheel.stat().st_size, "smoke_passed": passed, "smoke_failed": failed, "private_findings_in_wheel": len(scanner.findings) - wheel_scan_before}
        say(f"  {wheel.name} ({wheel.stat().st_size // 1024} KiB): smoke {passed} passed, {failed} failed")
    return results


# ----------------------------------------------------------------------------------------------------------------------
# self test: the scanner must find what it is for


def self_test() -> int:
    work = Path(tempfile.mkdtemp(prefix="make_public_selftest_"))
    try:
        repo = work / "r"
        repo.mkdir()
        git(["init", "-q", "-b", "main"], repo)
        git(["config", "user.name", "x"], repo)
        git(["config", "user.email", "x@example.com"], repo)
        planted = {
            "a.txt": "see centrum" + "vcaschool.nl for details",
            "b.txt": "contact me: someone.private@gmail.com",
            "c.txt": "C:\\Users\\jdoe\\project\\out",
            "d.txt": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n",
            "e.txt": "SCRUTATOR_SHODAN_KEY=abcdefghijklmnop1234",
            "f.txt": "token ghp_" + "a" * 36,
            "g.txt": "scanned why" + "back.nl last week",
        }
        for name, body in planted.items():
            (repo / name).write_text(body, encoding="utf-8")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("report.json", '{"seed": "centrum' + 'vcaschool.nl"}')
        (repo / "bundle.scrutator").write_bytes(buf.getvalue())
        (repo / "live03").mkdir()
        (repo / "live03" / "x.txt").write_text("ok", encoding="utf-8")
        git(["add", "-A"], repo)
        git(["commit", "-q", "-m", "planted"], repo)
        scanner = Scanner()
        stats = scan_clone(repo, scanner)
        rules = {f.rule for f in scanner.findings}
        expected = {"family-company", "personal-email", "windows-user-path", "private-key-header", "scrutator-key-value", "github-token", "private-path", "author-identity"}
        missing = expected - rules
        zip_hit = any("::report.json" in f.where for f in scanner.findings)
        ok = not missing and zip_hit
        say(f"self-test: {len(scanner.findings)} findings, rules seen {sorted(rules)}; missing {sorted(missing)}; found inside the zip member: {zip_hit}")
        say("self-test " + ("PASSED" if ok else "FAILED"))
        return 0 if ok else 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


# ----------------------------------------------------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--repo", type=Path, default=Path(__file__).resolve().parent.parent, help="the local repository (default: this one)")
    ap.add_argument("--out", type=Path, default=None, help="parent folder for the clean clone (default: a new temp folder outside the repository)")
    ap.add_argument("--python", default=None, help="python used to create the fresh virtual environments (default: this interpreter)")
    ap.add_argument("--skip-tests", action="store_true")
    ap.add_argument("--skip-bench", action="store_true")
    ap.add_argument("--skip-wheel", action="store_true")
    ap.add_argument("--self-test", action="store_true", help="plant secrets in a scratch repository and check the scanner finds them")
    ap.add_argument("--use-filter-repo", action="store_true", help="rewrite with git filter-repo (must be installed) instead of git filter-branch; filter-branch is the tested default")
    ap.add_argument("--keep-going", action="store_true", help="run tests, bench and wheel even when the scan found something")
    args = ap.parse_args()
    if args.self_test:
        return self_test()

    repo = args.repo.resolve()
    if not (repo / ".git").exists():
        say(f"not a git repository: {repo}")
        return 3
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    parent = (args.out or Path(tempfile.gettempdir())).resolve()
    work = parent / f"scrutator-public-{stamp}"
    if repo == work or repo in work.parents:
        say("the output folder must be outside the repository")
        return 3
    work.mkdir(parents=True)
    report: dict = {"started": stamp, "repo": str(repo)}

    head = git(["rev-parse", "HEAD"], repo).strip()
    branch = git(["rev-parse", "--abbrev-ref", "HEAD"], repo).strip()
    dirty = [l for l in git(["status", "--porcelain"], repo).splitlines() if l.strip()]
    report.update(head=head, branch=branch, uncommitted_paths=len(dirty))
    step(f"Source: {repo} at {head[:10]} on {branch}")
    if dirty:
        say(f"  NOTE: {len(dirty)} uncommitted path(s) in the original are NOT in the clone (only committed history is published), for example:")
        for l in dirty[:6]:
            say(f"    {l}")

    step("Clone (outside the repository) and rewrite its history")
    clone = make_clone(repo, work)
    say(f"  clone: {clone}")
    engine = rewrite_history(clone, work, args.use_filter_repo)
    commits_after = len(git(["rev-list", "--all"], clone).split())
    report.update(engine=engine, commits_after=commits_after, clone=str(clone))
    say(f"  history rewritten with {engine}: {commits_after} commits; authors set to {PUBLIC_NAME} <{PUBLIC_EMAIL}>")
    say(f"  size of the clone's .git: {sum(f.stat().st_size for f in (clone / '.git').rglob('*') if f.is_file()) // 1024} KiB")

    step("Scan the whole rewritten history and the tree for secrets and personal data")
    scanner = Scanner()
    notes = collect_private_material(repo, scanner)
    say(f"  private material of this machine that must not appear: {len(scanner.secrets)} key file(s), {len(scanner.denylist_keys)} key identities")
    for n in notes:
        say(f"    - {n}")
    stats = scan_clone(clone, scanner)
    report["scan"] = {**{k: v for k, v in stats.items() if k != "identities"}, "allowed_fixture_hits": scanner.allowed}
    fails = [f for f in scanner.findings if f.level == "fail"]
    warns = [f for f in scanner.findings if f.level == "warn"]
    say(f"  scanned {stats['commits']} commits, {stats['paths_ever']} paths ever committed, {stats['blobs']} blobs (and zip members, PDF streams)")
    say(f"  allowed fixture hits (public mail provider lists, planted test addresses): {scanner.allowed}")
    say(f"  FINDINGS: {len(fails)} failing, {len(warns)} warnings")
    for f in fails:
        say("   " + f.line())
    for f in warns[:60]:
        say("   " + f.line())
    if len(warns) > 60:
        say(f"   ... and {len(warns) - 60} more warnings (see the report file)")
    report["findings"] = [f.__dict__ for f in scanner.findings]

    results: dict = {}
    exit_code = 0
    if fails:
        exit_code = 1
        say("\n  THE SCAN FOUND PROBLEMS: the clone is NOT fit to push. Fix the tree in the original repository (or extend PRIVATE_PATHS) and run again.")
    if not fails or args.keep_going:
        results = build_and_test(clone, work, args, scanner)
        report["checks"] = results
        # the wheel scan may have added findings
        new_fails = [f for f in scanner.findings if f.level == "fail" and f not in fails]
        for f in new_fails:
            say("   " + f.line())
        if new_fails:
            exit_code = 1
        if any(v.get("ok") is False for v in results.values() if isinstance(v, dict)):
            exit_code = max(exit_code, 2)
    report["exit_code"] = exit_code
    (work / "make_public.report.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

    step("Summary")
    say(f"  source HEAD            {head[:10]} ({branch})")
    say(f"  history engine         {engine}")
    say(f"  commits in the clone   {commits_after}")
    say(f"  scan                   {'FAILED: ' + str(len(fails)) + ' finding(s)' if fails else 'clean'}; {len(warns)} warning(s)")
    for name in ("install", "tests", "bench", "wheel"):
        r = results.get(name)
        if r:
            ok = {True: "ok", False: "FAILED", None: "skipped"}[r.get("ok")]
            extra = r.get("summary") or (f"{r.get('seconds')} s; network attempts blocked: {r.get('network_attempts_blocked')}" if name == "tests" and r.get("seconds") is not None else "") or (f"{r.get('file')}: smoke {r.get('smoke_passed')} passed" if name == "wheel" else "")
            say(f"  {name:<22} {ok} {extra}")
    say(f"  report                 {work / 'make_public.report.json'}")
    say(f"  logs and work folder   {work}")
    if exit_code == 0:
        say(f"\nREADY (not pushed): {clone}")
        say("  cd there, then: git remote add origin https://github.com/cemalaysu73-star/scrutator.git && git push -u origin main")
    else:
        say(f"\nNOT READY (exit {exit_code}). The rewritten clone is at {clone} for inspection only.")
    return exit_code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as exc:
        print(f"make_public: {exc}", file=sys.stderr)
        sys.exit(3)
