"""Smoke test of an installed Scrutator (a wheel in a fresh virtual environment, not the checkout).

    python tools/wheel_smoke.py --scrutator /path/to/venv/bin/scrutator --work /tmp/smoke [--live]

Offline checks: --version, keygen (plain and with a passphrase from the environment), packs validate (the knowledge
packs are package data), `scrutator bench` (offline lab scans, report, HTML template and bundle from
package data), verify of that bundle with --pin, and the MCP server over stdio (initialize, tools/list,
verify_bundle). With --live it also scans example.com passively (AI off) and verifies the bundle; that needs
network access and queries only public sources about example.com. Prints one line per check and exits 1 on any
failure. It never imports scrutator itself, so it cannot pass by reading the checkout."""

import argparse
import json
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    RESULTS.append((name, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""), flush=True)
    return ok


def run(exe: str, *args: str, cwd: Path, env: dict | None = None, timeout: float = 900) -> subprocess.CompletedProcess:
    return subprocess.run([exe, *args], cwd=cwd, capture_output=True, text=True, timeout=timeout, env={**os.environ, **(env or {})})


def mcp_session(exe: str, cwd: Path, db: Path, bundle: Path) -> None:
    proc = subprocess.Popen([exe, "mcp", "--db", str(db)], cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    frames: queue.Queue = queue.Queue()
    threading.Thread(target=lambda: [frames.put(line) for line in proc.stdout] and frames.put(None), daemon=True).start()

    def call(ident: int, method: str, params: dict) -> dict:
        proc.stdin.write((json.dumps({"jsonrpc": "2.0", "id": ident, "method": method, "params": params}) + "\n").encode())
        proc.stdin.flush()
        while True:
            line = frames.get(timeout=60)
            if line is None:
                raise EOFError(proc.stderr.read().decode(errors="replace")[-500:])
            message = json.loads(line)
            if message.get("id") == ident:
                return message

    try:
        init = call(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "smoke", "version": "1"}})
        check("mcp initialize", "result" in init, init.get("result", {}).get("serverInfo", {}).get("version", str(init)[:120]))
        proc.stdin.write((json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n").encode())
        proc.stdin.flush()
        tools = call(2, "tools/list", {})
        names = sorted(t["name"] for t in tools.get("result", {}).get("tools", []))
        check("mcp tools/list (read-only by default)", names == ["attribution", "list_candidates", "risk", "verify_bundle"], ",".join(names))
        verified = call(3, "tools/call", {"name": "verify_bundle", "arguments": {"path": str(bundle)}})
        text = json.dumps(verified.get("result", {}))
        check("mcp verify_bundle", '\\"ok\\": true' in text or '"ok": true' in text, text[:120])
    except Exception as exc:  # noqa: BLE001
        check("mcp session", False, f"{type(exc).__name__}: {exc}")
    finally:
        proc.kill()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scrutator", required=True, help="the installed scrutator executable")
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--live", action="store_true", help="also scan example.com over the network")
    args = parser.parse_args()
    exe, work = args.scrutator, args.work
    work.mkdir(parents=True, exist_ok=True)

    done = run(exe, "--version", cwd=work)
    check("--version", done.returncode == 0 and done.stdout.startswith("scrutator "), done.stdout.strip())
    done = run(exe, "keygen", "--key-dir", "keys", cwd=work)
    check("keygen (plain)", done.returncode == 0 and (work / "keys" / "signing.pub").exists(), done.stderr.strip()[:120])
    done = run(exe, "keygen", "--key-dir", "keys-protected", "--passphrase", cwd=work, env={"SCRUTATOR_KEY_PASSPHRASE": "smoke test passphrase"})
    check("keygen --passphrase (from the environment)", done.returncode == 0, done.stderr.strip()[:120])
    done = run(exe, "packs", "validate", cwd=work)
    check("packs validate (package data)", done.returncode == 0 and "valid" in done.stdout, done.stdout.strip()[:120])

    done = run(exe, "bench", "--out", "bench-out", "--key-dir", "keys-protected", cwd=work,
               env={"SCRUTATOR_KEY_PASSPHRASE": "smoke test passphrase"})
    check("bench (offline labs, report, bundle, OSINT-Bench thresholds)", done.returncode == 0, (done.stdout.strip().splitlines() or [done.stderr.strip()])[-1][:160])
    bundle = work / "bench-out" / "lab" / "proof.scrutator"
    html = work / "bench-out" / "lab" / "report.html"
    check("HTML report rendered from the packaged template", html.exists() and '<script type="application/json" id="data">' in html.read_text(encoding="utf-8"))
    done = run(exe, "verify", str(bundle), "--pin", str(work / "keys-protected" / "signing.pub"), cwd=work)
    check("verify --pin of the bench bundle", done.returncode == 0 and "Verification passed." in done.stdout, done.stdout.strip().splitlines()[-1] if done.stdout.strip() else done.stderr[-200:])
    mcp_session(exe, work, work / "bench-out" / "lab" / "scrutator.db", bundle)

    if args.live:
        done = run(exe, "scan", "example.com", "--ai", "off", "--out", "live", "--bundle", "--key-dir", "keys", cwd=work, timeout=900)
        check("live scan example.com --ai off --bundle", done.returncode == 0, (done.stdout.strip().splitlines() or [done.stderr[-200:]])[0][:160])
        (work / "live-scan.txt").write_text(done.stdout + "\n" + done.stderr, encoding="utf-8")
        done = run(exe, "verify", str(work / "live" / "proof.scrutator"), "--pin", str(work / "keys" / "signing.pub"), cwd=work)
        check("verify --pin of the live bundle", done.returncode == 0, done.stdout.strip().splitlines()[-1] if done.stdout.strip() else done.stderr[-200:])
        (work / "live-verify.txt").write_text(done.stdout + "\n" + done.stderr, encoding="utf-8")

    failed = [name for name, ok, _ in RESULTS if not ok]
    print(f"{len(RESULTS) - len(failed)} of {len(RESULTS)} checks passed" + (f"; failed: {', '.join(failed)}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
