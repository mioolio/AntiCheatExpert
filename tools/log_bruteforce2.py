"""
log_bruteforce2.py -- same candidate keys, but allow the ciphertext to start at a
header offset.

The first 24 bytes of every log are identical; if that is a plaintext header
(magic + key id + flags) rather than ciphertext, the keystream begins at 0x18 and
every earlier attempt was misaligned.  This run tries starts 0 / 16 / 24 / 32 and
also both ChaCha counter values, scoring the first 256 bytes and 4 KB.
"""
from __future__ import annotations

import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile  # noqa: E402
from log_crypt import rc4, chacha20, printable_ratio  # noqa: E402
from log_bruteforce import WORDS, windows, BIN, DAT, LOG  # noqa: E402


def main():
    pe = PEFile(BIN)
    log = open(LOG, "rb").read()
    dat = open(DAT, "rb").read()

    keys = []
    for w in WORDS:
        b = w.encode()
        keys.append((f"md5({w})", hashlib.md5(b).digest()))
        keys.append((f"sha256({w})", hashlib.sha256(b).digest()))
    for sec in pe.sections:
        if sec["name"] not in (".rdata", ".data"):
            continue
        blob = pe.data[sec["raw_ptr"]:sec["raw_ptr"] + sec["raw_size"]]
        keys += windows(blob, 32, step=8, limit=1500)
        keys += windows(blob, 16, step=8, limit=1500)
    mid = dat[0x10:0x90]
    keys += [("dat16", mid[:16]), ("dat32", mid[:32])]

    best = []
    for start in (0, 16, 24, 32):
        body = log[start:]
        head = body[:4096]
        for name, k in keys:
            if len(k) == 16:
                d = rc4(k, head)
                best.append((printable_ratio(d[:256]), printable_ratio(d),
                             f"RC4@{start}", name, d[:48]))
            elif len(k) == 32:
                for ctr in (0, 1):
                    d = chacha20(k, b"\0" * 12, head, ctr)
                    best.append((printable_ratio(d[:256]), printable_ratio(d),
                                 f"ChaCha20@0@{start}/ctr{ctr}", name, d[:48]))
    best.sort(reverse=True)
    print(f"tested {len(best)} combinations")
    for r256, r4k, how, name, sample in best[:10]:
        print(f"  256B={r256:.2f} 4KB={r4k:.2f}  {how:22s} {name:22s} {sample!r}")


if __name__ == "__main__":
    main()
