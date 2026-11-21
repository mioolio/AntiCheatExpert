"""
re_all.py -- drive pe_rebuild over every ACE component and collect a summary.

usage:
  python tools/re_all.py [--only NAME[,NAME...]] [--max-size MB] [--rounds N]

Order is by file size (small first) so early results are available quickly.
Per-component output goes to out_rebuild/<name>/ ; the running table is written
to out_rebuild/summary.json and printed after each component.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = r"<ACE_ROOT>"
OUT = os.path.join(ROOT, "work")

EXCLUDE_DIRS = {"__pycache__"}


def discover():
    rows = []
    for dp, dirs, files in os.walk(SRC):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for fn in files:
            if fn.lower().endswith((".sys", ".exe", ".dll")):
                p = os.path.join(dp, fn)
                rows.append((os.path.getsize(p), p))
    rows.sort()
    return rows


def main():
    only = None
    if "--only" in sys.argv:
        only = {x.strip().lower() for x in sys.argv[sys.argv.index("--only") + 1].split(",")}
    max_mb = None
    if "--max-size" in sys.argv:
        max_mb = float(sys.argv[sys.argv.index("--max-size") + 1])
    rounds = 18
    if "--rounds" in sys.argv:
        rounds = int(sys.argv[sys.argv.index("--rounds") + 1])

    os.makedirs(OUT, exist_ok=True)
    targets = discover()
    if only:
        targets = [t for t in targets if os.path.splitext(os.path.basename(t[1]))[0].lower() in only]
    if max_mb:
        targets = [t for t in targets if t[0] <= max_mb * 1024 * 1024]
    if "--ext" in sys.argv:
        want = {x.strip().lower() for x in sys.argv[sys.argv.index("--ext") + 1].split(",")}
        targets = [t for t in targets if os.path.splitext(t[1])[1].lower() in want]

    summary = []
    print(f"{'component':24s} {'size':>10s} {'result':>10s} {'diff':>6s} {'cov':>12s} {'rounds':>6s}")
    for size, path in targets:
        name = os.path.splitext(os.path.basename(path))[0]
        work = os.path.join(OUT, name)
        t0 = time.time()
        cmd = [sys.executable, os.path.join(HERE, "pe_rebuild.py"), path,
               "--work", work, "--rounds", str(rounds)]
        r = subprocess.run(cmd, capture_output=True, text=True)
        dt = time.time() - t0
        rep_path = os.path.join(work, "report.json")
        if os.path.exists(rep_path):
            rep = json.load(open(rep_path, encoding="utf-8"))
            rep["name"] = name
            rep["path"] = path
            rep["seconds"] = round(dt, 1)
            summary.append(rep)
            cov = f"{rep['mnemonic']}/{rep['insns']}"
            print(f"{name:24s} {size:10,d} {'IDENTICAL' if rep['identical'] else 'DIFF':>10s} "
                  f"{rep['differing_bytes']:6d} {cov:>12s} {rep['rounds']:6d}")
        else:
            err = (r.stdout + r.stderr).strip().splitlines()[-3:]
            summary.append(dict(name=name, path=path, error=" | ".join(err), seconds=round(dt, 1)))
            print(f"{name:24s} {size:10,d} {'FAILED':>10s}   {'-':>6s} {'-':>12s} {'-':>6s}")
            print("   " + " | ".join(err))
        json.dump(summary, open(os.path.join(OUT, "summary.json"), "w"), indent=1)

    ok = sum(1 for s in summary if s.get("identical"))
    print(f"\n{ok}/{len(summary)} byte-identical")
    return 0 if ok == len(summary) else 1


if __name__ == "__main__":
    sys.exit(main())
