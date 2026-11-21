"""
rebuild_from_repo.py -- reproduce a component from repository content only.

Inputs (all inside the repo, no original binary required):
    asm/<name>.asm | <name>.asm.gz   assembly source of the whole image
    asm/<name>.pack.json             section table + expected hash
    asm/<name>.hdr.bin               original PE headers (1024 bytes)
    asm/<name>.sig.bin               Authenticode blob appended after the sections

Steps: decompress -> ml64 /c -> apply REL32 fixups -> slice per section ->
concatenate headers + body + signature -> verify SHA-256 against pack.json.

usage:
    python tools/rebuild_from_repo.py ACE-BASE
    python tools/rebuild_from_repo.py --all
"""
from __future__ import annotations

import glob
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from coff import COFF, apply_relocations  # noqa: E402

ML64 = os.environ.get("ML64", r"<ML64>")
OUT = os.path.join(ROOT, "build_out")


def load_asm(name, work):
    plain = os.path.join(ROOT, "asm", f"{name}.asm")
    if os.path.exists(plain):
        shutil.copyfile(plain, os.path.join(work, "image.asm"))
        return
    gz = os.path.join(ROOT, "asm", f"{name}.asm.gz")
    if not os.path.exists(gz):
        raise SystemExit(f"缺少汇编源：asm/{name}.asm 或 {name}.asm.gz")
    with gzip.open(gz, "rb") as f, open(os.path.join(work, "image.asm"), "wb") as o:
        shutil.copyfileobj(f, o)


def build(name, work):
    meta = json.load(open(os.path.join(ROOT, "asm", f"{name}.pack.json"), encoding="utf-8"))
    load_asm(name, work)
    obj = os.path.join(work, "image.obj")

    cmd = [ML64, "/c", "/nologo", "/Fo" + obj, os.path.join(work, "image.asm")]
    r = subprocess.run(cmd, cwd=work, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout + r.stderr)
        raise SystemExit(f"{name}: 汇编失败")

    coff = COFF(obj)
    sec = next(s for s in coff.sections if s["raw_size"])
    flat = bytearray(coff.data[sec["raw_ptr"]:sec["raw_ptr"] + sec["raw_size"]])
    apply_relocations(coff, sec, flat)

    org = meta["org"]
    body = bytearray()
    for s in meta["sections"]:
        start = s["va"] - org
        chunk = bytes(flat[start:start + s["raw_size"]])
        if len(chunk) < s["raw_size"]:
            chunk += b"\0" * (s["raw_size"] - len(chunk))
        body += chunk

    hdr = open(os.path.join(ROOT, "asm", f"{name}.hdr.bin"), "rb").read()
    sig_path = os.path.join(ROOT, "asm", f"{name}.sig.bin")
    sig = open(sig_path, "rb").read() if os.path.exists(sig_path) else b""
    img = hdr + bytes(body) + sig

    got = hashlib.sha256(img).hexdigest()
    want = meta["sha256"]
    ok = got == want and len(img) == meta["size"]
    out = os.path.join(OUT, meta["original"])
    os.makedirs(OUT, exist_ok=True)
    open(out, "wb").write(img)
    print(f"{name:16s} {'IDENTICAL' if ok else 'DIFF':9s} {len(img):>10,} B  {got[:16]}")
    if not ok:
        print(f"   期望 {want}")
        print(f"   实际 {got}")
    return ok


def main():
    if "--all" in sys.argv:
        names = [os.path.basename(p).split(".pack.json")[0]
                 for p in sorted(glob.glob(os.path.join(ROOT, "asm", "*.pack.json")))]
    else:
        names = [a for a in sys.argv[1:] if not a.startswith("-")]
    if not names:
        print(__doc__)
        return 1
    ok = 0
    for n in names:
        work = tempfile.mkdtemp(prefix="rebuild_")
        try:
            if build(n, work):
                ok += 1
        finally:
            shutil.rmtree(work, ignore_errors=True)
    print(f"\n{ok}/{len(names)} 与原文件逐字节一致")
    return 0 if ok == len(names) else 1


if __name__ == "__main__":
    sys.exit(main())
