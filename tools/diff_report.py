"""
diff_report.py -- show where a rebuilt image differs from its reference.

usage: python tools/diff_report.py <reference> <rebuilt> [--max 20]

Prints file offset, owning section, RVA and the bytes on both sides, plus a
verdict (header / section data / overlay) so the cause is obvious.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile  # noqa: E402


def main():
    ref = PEFile(sys.argv[1])
    new = PEFile(sys.argv[2])
    a, b = ref.data, new.data
    n = min(len(a), len(b))
    diffs = [(i, a[i], b[i]) for i in range(n) if a[i] != b[i]]
    print(f"size {len(a):,} / {len(b):,}   differing bytes: {len(diffs)}")
    limit = 20
    if "--max" in sys.argv:
        limit = int(sys.argv[sys.argv.index("--max") + 1])
    for off, x, y in diffs[:limit]:
        owner = "headers"
        rva = None
        for s in ref.sections:
            if s["raw_ptr"] <= off < s["raw_ptr"] + s["raw_size"]:
                owner = s["name"]
                rva = s["va"] + (off - s["raw_ptr"])
                break
        if rva is None and off >= ref.body_end:
            owner = "overlay (signature)"
        print(f"  file {off:#08x} [{owner}]"
              + (f" rva {rva:#x}" if rva is not None else "")
              + f"  ref {x:02x} != new {y:02x}")


if __name__ == "__main__":
    main()
