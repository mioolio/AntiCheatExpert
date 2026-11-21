"""
log_bruteforce.py -- the log key must be deterministic.

Evidence: logs from 2026-11-18 and 2026-11-21 share the same 24-byte ciphertext
prefix, so the key/nonce pair is fixed and cannot be per-boot random.  That means
it is either a constant inside ACE-BOOT.sys or derived deterministically from one.

Candidates tried (RC4 and ChaCha20, nonce = zeros / payload head / first 12 bytes
of the key):
  * md5 / sha1 / sha256 of the interesting strings in the binary
  * every 16- and 32-byte window of the high-entropy .rdata constants
  * the 128-byte block from ace-boot.dat in both byte orders

Scoring: printable ratio of the first 4 KB and of the first 256 bytes; a correct
key gives > 0.9.
"""
from __future__ import annotations

import hashlib
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile  # noqa: E402
from log_crypt import rc4, chacha20, printable_ratio  # noqa: E402

BIN = r"<ACE_ROOT>\ACE-BOOT.sys"
DAT = r"<ACE_ROOT>\ace-boot.dat"
LOG = r"<ACE_ROOT>\ace-boot-20261121-010547.log"

WORDS = [
    "ace-boot", "ACE-BOOT", "ace_boot", "ACEBOOT", "AntiCheatExpert", "ACE",
    "jacy", "IRONMACE", "ace-guard", "SGuard", "ace-boot-log", "ACE-BOOT-LOG",
    "ace", "boot", "log", "tencent", "Tencent", "ACE-ADVT", "ace-advt",
]


def windows(buf, n, step=4, limit=4000):
    out = []
    for i in range(0, len(buf) - n + 1, step):
        w = buf[i:i + n]
        if len(set(w)) >= n * 0.6:          # skip low-entropy windows
            out.append((f"win{n}@{i:x}", w))
    return out[:limit]


def main():
    pe = PEFile(BIN)
    log = open(LOG, "rb").read()
    head = log[:4096]
    dat = open(DAT, "rb").read()

    keys = []
    for w in WORDS:
        b = w.encode()
        keys.append((f"md5({w})", hashlib.md5(b).digest()))
        keys.append((f"sha1({w})[:16]", hashlib.sha1(b).digest()[:16]))
        keys.append((f"sha256({w})", hashlib.sha256(b).digest()))
        keys.append((f"raw({w})", b[:32].ljust(32, b"\0")))

    # constants from the binary: .rdata and .data
    for sec in pe.sections:
        if sec["name"] not in (".rdata", ".data"):
            continue
        blob = pe.data[sec["raw_ptr"]:sec["raw_ptr"] + sec["raw_size"]]
        keys += windows(blob, 16, step=8, limit=2000)
        keys += windows(blob, 32, step=8, limit=2000)

    # the dat middle block
    mid = dat[0x10:0x90]
    keys.append(("dat[0x10:0x20]", mid[:16]))
    keys.append(("dat[0x10:0x30]", mid[:32]))
    keys.append(("dat[0x20:0x40]", mid[0x10:0x30]))

    print(f"candidates: {len(keys)}")
    best = []
    for name, k in keys:
        if len(k) not in (16, 32):
            continue
        d = rc4(k, head)
        best.append((printable_ratio(d[:256]), printable_ratio(d), "RC4", name, d[:64]))
        if len(k) == 32:
            for nn, n in (("zero", b"\0" * 12), ("keyhead", k[:12])):
                for ctr in (0, 1):
                    d = chacha20(k, n, head, ctr)
                    best.append((printable_ratio(d[:256]), printable_ratio(d),
                                 f"ChaCha20/{nn}/ctr{ctr}", name, d[:64]))

    best.sort(reverse=True)
    print("\ntop 12 by head printable ratio:")
    for r256, r4k, alg, name, sample in best[:12]:
        print(f"  256B={r256:.2f} 4KB={r4k:.2f}  {alg:22s} {name:22s} {sample[:40]!r}")


if __name__ == "__main__":
    main()
