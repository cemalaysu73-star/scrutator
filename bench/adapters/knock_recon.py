"""Run only the passive collector of knockpy (the `Recon` class behind `knockpy --recon`).

The knockpy CLI in recon mode also attempts a zone transfer against the target's name servers
and probes every discovered host over HTTP(S). Those are active steps, so the benchmark calls the
passive collector directly through the tool's own Python API, with its default settings
(timeout 3 s, 40 workers, keyless services only). Prints one JSON object on stdout.

Usage (inside the benchmark venv): python knock_recon.py <domain>
"""

import asyncio
import json
import sys
import time

from knockpy.knockpy import Recon


def main() -> int:
    domain = sys.argv[1].strip().lower()
    started = time.monotonic()
    engine = Recon(domain, timeout=3.0, max_concurrency=40)
    services = [s.get("name") for s in engine.services()]
    names = asyncio.run(engine.start())
    print(json.dumps({"domain": domain, "services": services, "names": names, "seconds": round(time.monotonic() - started, 2)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
