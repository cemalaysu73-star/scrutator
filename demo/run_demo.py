"""The two-minute Scrutator demo: scan, follow a claim to its evidence, watch a made-up claim get rejected, export a
signed proof bundle, then tamper with it and watch `scrutator verify` fail.

    python demo/run_demo.py                      # offline, on a fixture zone: no network at all
    python demo/run_demo.py --live               # the same on example.com: passive, public sources only
    python demo/run_demo.py --model qwen3:8b     # also let a local Ollama model play the verifier in step 3
    python demo/run_demo.py --transcript demo/transcripts/offline.txt

Everything printed is the program's real output; `--transcript` writes the same text to a file. What is a fixture and
what is real is said at the point where it matters:

- Offline, the scan runs in this process against a planted lab zone (a fake resolver and recorded answers of the
  public sources, see src/scrutator/benchlab/risklab.py), because the command line scans the real network. The key,
  export, verify and tamper steps are the real command line.
- Step 3 uses a scripted writer that proposes statements, some of them invented, and a verifier. Without --model the
  verifier is a mechanical stand-in, not a language model; with --model it is a model on this machine (loopback only).
- With --live, the scan itself is the real command line against example.com."""

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if (SRC / "scrutator").is_dir() and str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))  # run from a checkout without installing

from scrutator.benchlab import halluc, risklab  # noqa: E402
from scrutator.benchlab.run import _flip, _forge, _rewrite  # noqa: E402
from scrutator.bundle.writer import create_bundle  # noqa: E402
from scrutator.bundle.keys import generate_keypair, load_private_key, private_key_path  # noqa: E402
from scrutator.model import Entity, EntityType  # noqa: E402
from scrutator.modules.base import ModuleContext  # noqa: E402
from scrutator.modules.registry import load_builtin_modules  # noqa: E402
from scrutator.packs import load_packs  # noqa: E402
from scrutator.report import build_report, render_html, render_json  # noqa: E402
from scrutator.scan import run_scan  # noqa: E402
from scrutator.scope import ScopePolicy  # noqa: E402
from scrutator.store import Store  # noqa: E402


class Tee:
    def __init__(self, path: Path | None, hide: Path | None = None):
        self.file = open(path, "w", encoding="utf-8", newline="\n") if path else None
        self.hide = str(hide) if hide else None  # the working folder is shown as `demo-out`, not as this machine's path

    def write(self, text: str = "") -> None:
        if self.hide:
            text = text.replace(self.hide, "demo-out")
        text = text.encode("ascii", "replace").decode("ascii") if sys.stdout.encoding and "ascii" in sys.stdout.encoding.lower() else text
        sys.stdout.write(text + "\n")
        sys.stdout.flush()
        if self.file:
            self.file.write(text + "\n")
            self.file.flush()


def step(out: Tee, number: int, title: str) -> None:
    out.write("")
    out.write(f"== Step {number}: {title}")


def say(out: Tee, text: str) -> None:
    out.write(f"   {text}")


def cli(out: Tee, *args: str, shown: str | None = None, env: dict | None = None, timeout: float = 900) -> int:
    """Run `scrutator ARGS` for real and print the command and what it printed."""
    out.write(f"$ scrutator {shown if shown is not None else ' '.join(args)}")
    done = subprocess.run(
        [sys.executable, "-m", "scrutator", *args], capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=timeout, env={**os.environ, "PYTHONPATH": str(SRC), "PYTHONIOENCODING": "utf-8", **(env or {})}, cwd=ROOT,
    )
    for line in (done.stdout + done.stderr).splitlines():
        out.write(line)
    out.write(f"[exit status {done.returncode}]")
    return done.returncode


async def scan_fixture(work: Path) -> tuple[Path, int]:
    """The planted lab zone, scanned in this process: fake DNS, recorded answers of the public sources."""
    modules = [m for m in load_builtin_modules() if not m.needs_key]
    resolver, router = risklab.lab_zone(), risklab.lab_router()
    packs = load_packs([risklab.lab_packs_dir(work / "packs")])
    db = work / "scrutator.db"
    store = Store(db)
    async with httpx.AsyncClient(transport=router.transport()) as http:
        scan_id, _ = await run_scan(
            Entity(type=EntityType.DOMAIN, value="example.com"), ScopePolicy(domains=list(risklab.SCOPE_DOMAINS)), store,
            ModuleContext(http=http, resolver=resolver), modules=modules, packs=packs, max_steps=800,
        )
    report = build_report(store, scan_id)
    (work / "report.json").write_text(render_json(report), encoding="utf-8")
    (work / "report.html").write_text(render_html(report), encoding="utf-8")
    store.close()
    return db, scan_id


def show_a_claim(out: Tee, report: dict) -> None:
    """Pick the most severe risk and print the raw record it rests on."""
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    risk = sorted(report["risks"], key=lambda r: (order[r["severity"]], r["rule_id"]))[0]
    say(out, f"the most severe risk: [{risk['severity']}] {risk['title']}")
    say(out, f"   about {', '.join(risk['entity_ids'])}")
    say(out, f"   {risk['explanation']}")
    evidence = report["evidence"][risk["evidence_ids"][0]]
    say(out, f"it cites {len(risk['evidence_ids'])} evidence record(s); the first is id {risk['evidence_ids'][0][:16]}... (sha256 of source, request, payload):")
    say(out, f"   source   {evidence['source']}")
    say(out, f"   request  {evidence['request']}")
    say(out, f"   payload  {evidence['payload'][:160]!r}")
    say(out, "open report.html and click the risk to see the same record in the browser")


async def invented_claims(out: Tee, model: str | None, ollama_url: str) -> None:
    """A scripted writer proposes statements about a tiny scan; some are made up. Count what gets published."""
    if model:
        from scrutator.ai.net import is_loopback
        from scrutator.ai.ollama import OllamaProvider

        if not is_loopback(ollama_url):
            raise SystemExit("--ollama-url must be this machine")
        client = httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=5.0), follow_redirects=False)
        make, label = (lambda: OllamaProvider(client, model, ollama_url)), f"the local model {model}"
    else:
        make, label = halluc.facts_only_verifier, "a mechanical stand-in verifier (not a language model)"
    say(out, f"a scripted writer proposes {len(halluc.CORPUS)} statements about a tiny scan; {sum(1 for c in halluc.CORPUS if c[1] != 'supported')} of them are made up")
    say(out, "(an invented host, address, port, CVE id, date; a planted instruction in a TXT record obeyed; a negation; ...)")
    say(out, f"the verifier is {label}; before it, a deterministic check drops statements naming anything the facts do not")
    outcome = await halluc.run_config(make)
    made_up = {text for _k, kind, text, _c in halluc.CORPUS if kind != "supported" and text}
    published_made_up = [t for t in outcome.published if t in made_up]
    say(out, f"published: {len(outcome.published)} statements, of which {len(published_made_up)} made up")
    say(out, "rejected, with the reason:")
    for text, reason in sorted(outcome.rejected.items()):
        say(out, f"   x {text}")
        say(out, f"       {reason}")
    for text in published_made_up:
        say(out, f"   ! survived: {text}")
    if model:
        await client.aclose()


async def substitute_bundle(work: Path, attacker_key) -> Path:
    """An internally consistent bundle of a different scan (the planted clean zone, no risks), signed with another key."""
    modules = [m for m in load_builtin_modules() if not m.needs_key]
    store = Store(work / "other.db")
    async with httpx.AsyncClient(transport=risklab.clean_router().transport()) as http:
        scan_id, _ = await run_scan(
            Entity(type=EntityType.DOMAIN, value="example.com"), ScopePolicy(domains=["example.com"]), store,
            ModuleContext(http=http, resolver=risklab.clean_zone()), modules=modules, packs=load_packs(), max_steps=800,
        )
    path = work / "substitute.scrutator"
    create_bundle(store, scan_id, attacker_key, path)
    store.close()
    return path


def tamper(out: Tee, bundle: Path, pin: Path, work: Path) -> None:
    pinned = f"--pin signing.pub"
    flipped = _rewrite(bundle, work / "flipped.scrutator", "report.json", _flip)
    say(out, "A. flip one bit in the middle of report.json inside the bundle")
    status = cli(out, "verify", str(flipped), "--pin", str(pin), shown=f"verify flipped.scrutator {pinned}")
    say(out, f"-> exit status {status}: verification {'FAILED, as it must' if status else 'PASSED (this would be a bug)'}")

    def hide_risks(data: bytes) -> bytes:
        report = json.loads(data)
        report["risks"] = report["risks"][1:]
        return json.dumps(report, sort_keys=True).encode()

    attacker_dir = work / "attacker-keys"
    shutil.rmtree(attacker_dir, ignore_errors=True)
    generate_keypair(attacker_dir)
    attacker = load_private_key(private_key_path(attacker_dir))
    forged = _forge(bundle, work / "forged.scrutator", attacker, {"report.json": hide_risks})
    out.write("")
    say(out, "B. a forger deletes a risk from the report, rebuilds every file hash and re-signs with their own key")
    status = cli(out, "verify", str(forged), shown="verify forged.scrutator   (no --pin)")
    say(out, f"-> exit status {status}: caught even without a pin, because verify recomputes the risks from the evidence" if status else "-> PASSED (this would be a bug)")

    out.write("")
    say(out, "C. a different, internally consistent bundle (another scan, signed by another key) offered in its place")
    substitute = asyncio.run(substitute_bundle(work, attacker))
    status = cli(out, "verify", str(substitute), shown="verify substitute.scrutator   (no --pin)")
    say(out, f"-> exit status {status}: every check passes; a reader who does not pin the key is only warned" if not status else "-> failed")
    status = cli(out, "verify", str(substitute), "--pin", str(pin), shown=f"verify substitute.scrutator {pinned}")
    say(out, f"-> exit status {status}: the pinned key is what catches it" if status else "-> PASSED (this would be a bug)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--live", action="store_true", help="scan example.com for real (passive, public sources only)")
    parser.add_argument("--out", type=Path, default=ROOT / "demo-out", help="where the demo writes (default: demo-out/)")
    parser.add_argument("--transcript", type=Path, help="also write everything printed to this file")
    parser.add_argument("--model", help="an Ollama model to use as the verifier in step 3 (loopback only)")
    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    args = parser.parse_args()

    out = Tee(args.transcript, args.out.resolve())
    work = args.out.resolve() / ("live" if args.live else "offline")
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    keys = work / "keys"
    started = time.perf_counter()

    out.write(f"Scrutator demo ({'live: example.com, public sources, passive' if args.live else 'offline: a planted fixture zone, no network'})")
    out.write(f"working folder: {work}")

    step(out, 1, "scan" + (" example.com (the real command line)" if args.live else " the fixture zone"))
    if args.live:
        say(out, "this asks public services (certificate transparency, DNS, RDAP, archives) about example.com; nothing touches example.com's servers beyond DNS")
        cli(out, "keygen", "--key-dir", str(keys), shown="keygen --key-dir keys")
        status = cli(out, "scan", "example.com", "--ai", "off", "--out", str(work), "--bundle", "--key-dir", str(keys),
                     shown="scan example.com --ai off --bundle --key-dir keys")
        if status:
            return status
        db, scan_id = work / "scrutator.db", None
        report = json.loads((work / "report.json").read_text(encoding="utf-8"))
        bundle = work / "proof.scrutator"
    else:
        say(out, "the scan runs in this process against a planted zone: a fake resolver and recorded answers of the public sources")
        say(out, "(the command line scans the real network; the key, export, verify and tamper steps below are the real command line)")
        db, scan_id = asyncio.run(scan_fixture(work))
        report = json.loads((work / "report.json").read_text(encoding="utf-8"))
        say(out, f"names: {report['summary']['headline']}")
        say(out, f"{report['summary']['entities']} entities, {report['summary']['findings']} findings, {len(report['evidence'])} evidence records, "
                 f"{len(report['risks'])} risks (the zone has 22 planted issues; `scrutator bench` checks every one is among them)")
        say(out, f"wrote {work / 'report.html'} and report.json")
        bundle = work / "proof.scrutator"

    step(out, 2, "follow a claim to its evidence")
    show_a_claim(out, report)

    step(out, 3, "a model invents claims; the verifier has to stop them")
    asyncio.run(invented_claims(out, args.model, args.ollama_url))

    step(out, 4, "export a signed proof bundle")
    if args.live:
        say(out, f"already written by the scan: {bundle}")
        pin = keys / "signing.pub"
    else:
        cli(out, "keygen", "--key-dir", str(keys), shown="keygen --key-dir keys")
        cli(out, "export", str(scan_id), "--db", str(db), "--bundle", str(bundle), "--key-dir", str(keys),
            shown=f"export {scan_id} --db scrutator.db --bundle proof.scrutator --key-dir keys")
        pin = keys / "signing.pub"
    say(out, f"{bundle.name}: {bundle.stat().st_size // 1024} KiB (report, every raw evidence record, hash-chained audit log, signed manifest)")

    step(out, 5, "verify it, pinning the signer's key")
    status = cli(out, "verify", str(bundle), "--pin", str(pin), shown="verify proof.scrutator --pin signing.pub")
    say(out, f"-> exit status {status}")

    step(out, 6, "tamper with it")
    tamper(out, bundle, pin, work)

    out.write("")
    out.write(f"Done in {time.perf_counter() - started:.0f} s. Open {work / 'report.html'} in a browser; the bundle is {bundle}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
