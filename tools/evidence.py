"""
evidence.py -- compact per-component evidence sheet used to write the functional
report: import modules, kernel API surface, and the string categories
(device / dosdevice / pipe / registry / url / mutex / path / service).

Reads out/profiles/*.json (produced by component_profile.py) and writes
out/evidence.json plus a readable dump.
"""
from __future__ import annotations

import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CATS = ("device", "dosdevice", "pipe", "registry", "url", "mutex", "path",
        "service", "module", "other")


def main():
    rows = []
    for p in sorted(glob.glob(os.path.join(ROOT, "out", "profiles", "*.json"))):
        d = json.load(open(p, encoding="utf-8"))
        name = os.path.splitext(os.path.basename(p))[0]
        strings = d.get("strings") or {}
        rows.append(dict(
            name=name,
            size=d.get("size"),
            subsystem=d.get("subsystem"),
            modules=d.get("import_modules") or {},
            kernel=d.get("kernel_api") or [],
            crypto=d.get("crypto_api") or [],
            net=d.get("net_api") or [],
            win32=d.get("win32_hot") or [],
            sections=d.get("sections") or [],
            strings={k: v for k, v in strings.items() if v},
        ))
    json.dump(rows, open(os.path.join(ROOT, "out", "evidence.json"), "w",
                         encoding="utf-8"), indent=1, ensure_ascii=False)

    for r in rows:
        print(f"\n=== {r['name']}  {r['size']:,} B  subsystem={r['subsystem']} ===")
        mods = sorted(r["modules"].items(), key=lambda x: -(x[1] or 0))
        print("  modules:", ", ".join(f"{k}({v})" for k, v in mods[:7]))
        if r["kernel"]:
            print("  kernel :", ", ".join(r["kernel"][:16]))
        if r["crypto"]:
            print("  crypto :", ", ".join(r["crypto"]))
        if r["net"]:
            print("  net    :", ", ".join(r["net"]))
        for cat in CATS:
            vals = r["strings"].get(cat)
            if vals:
                print(f"  {cat:9s}: " + " | ".join(str(v)[:90] for v in vals[:6]))


if __name__ == "__main__":
    main()
