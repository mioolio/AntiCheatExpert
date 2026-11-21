"""
packmeta.py -- emit the per-component metadata that makes a rebuild possible
without the original binary.

For each component it writes, next to the assembly source:

    asm/<name>.hdr.bin     the original PE headers (DOS stub + COFF + optional + section table)
    asm/<name>.sig.bin     the Authenticode blob that follows the sections
    asm/<name>.pack.json   section table, SizeOfImage, expected SHA-256, file name

With those three files plus the assembly source, `rebuild_from_repo.py` produces a
byte-identical copy without ever reading the original executable again.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from pe_model import PEFile  # noqa: E402

SRC = os.environ.get("ACE_SRC_ROOT", r"<ACE_ROOT>")
OUT = os.path.join(ROOT, "asm")


def main():
    os.makedirs(OUT, exist_ok=True)
    targets = []
    for p in sorted(glob.glob(os.path.join(ROOT, "out", "*", "report.json"))):
        rep = json.load(open(p, encoding="utf-8"))
        name = os.path.basename(os.path.dirname(p))
        targets.append((name, rep.get("target", ""), rep))

    for name, target, rep in targets:
        path = target if target and os.path.exists(target) else None
        if path is None:
            cand = os.path.join(SRC, name + ".sys")
            path = cand if os.path.exists(cand) else None
        if path is None:
            print(f"  {name}: 找不到原始文件，跳过元数据")
            continue
        pe = PEFile(path)
        hdr = pe.data[:pe.size_of_headers]
        open(os.path.join(OUT, f"{name}.hdr.bin"), "wb").write(hdr)

        cert_off, cert_size = pe.directories[4]
        sig = pe.data[cert_off:cert_off + cert_size] if cert_off and cert_size else b""
        open(os.path.join(OUT, f"{name}.sig.bin"), "wb").write(sig)

        meta = dict(
            name=name,
            original=os.path.basename(path),
            size=len(pe.data),
            sha256=hashlib.sha256(pe.data).hexdigest(),
            size_of_headers=pe.size_of_headers,
            size_of_image=pe.size_of_image,
            org=pe.sections[0]["va"],
            sections=[dict(name=s["name"], va=s["va"], vsize=s["vsize"],
                           raw_size=s["raw_size"], raw_ptr=s["raw_ptr"]) for s in pe.sections],
            cert_offset=cert_off,
            cert_size=cert_size,
        )
        json.dump(meta, open(os.path.join(OUT, f"{name}.pack.json"), "w"), indent=1)
        print(f"  {name}: hdr {len(hdr)} B, sig {len(sig)} B, {len(pe.sections)} sections")


if __name__ == "__main__":
    main()
