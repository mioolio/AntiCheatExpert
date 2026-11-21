"""
log_crypt.py -- structure of ace-boot.dat and decryption attempts for the logs.

Dat layout hypothesis (dwords at 0): 0x10 | 0x80 | 0x90 | 0x14B88
  0x000..0x010   16-byte header
  0x010..0x090   128 bytes (candidate key material)
  0x090..EOF     payload (0x14B88 = 84,872 bytes; 0x90 + 0x14B88 == file size)

Attempts, scored by printable ratio of the first 4 KB:
  * RC4 with every 16/32-byte window of the 128-byte region
  * ChaCha20 (RFC 7539) same keys, nonce = zeros / first 12 bytes of payload /
    first 12 bytes of the key region, counter 0 and 1
  * AES-256-CTR with the same keys (needs `cryptography`, skipped if absent)
"""
from __future__ import annotations

import os
import struct
import sys

DAT = r"<ACE_ROOT>\ace-boot.dat"
LOGS = [
    r"<ACE_ROOT>\ace-boot-20261121-010547.log",
    r"<ACE_ROOT>\ace-boot-20261118-130717.log",
]


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    h = [0] * 256
    for c in b:
        h[c] += 1
    n = len(b)
    import math
    return -sum((x / n) * math.log2(x / n) for x in h if x)


def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray(len(data))
    i = j = 0
    for k, c in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out[k] = c ^ S[(S[i] + S[j]) & 0xFF]
    return bytes(out)


def _rotl(v, n):
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def chacha_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    st = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    st += list(struct.unpack("<8I", key))
    st += [counter & 0xFFFFFFFF, (counter >> 32) & 0xFFFFFFFF]
    st += list(struct.unpack("<3I", nonce))

    def qr(x, a, b, c, d):
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF
        x[d] = _rotl(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF
        x[b] = _rotl(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF
        x[d] = _rotl(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF
        x[b] = _rotl(x[b] ^ x[c], 7)

    w = st[:]
    for _ in range(10):
        qr(w, 0, 4, 8, 12)
        qr(w, 1, 5, 9, 13)
        qr(w, 2, 6, 10, 14)
        qr(w, 3, 7, 11, 15)
        qr(w, 0, 5, 10, 15)
        qr(w, 1, 6, 11, 12)
        qr(w, 2, 7, 8, 13)
        qr(w, 3, 4, 9, 14)
    return struct.pack("<16I", *[(w[i] + st[i]) & 0xFFFFFFFF for i in range(16)])


def chacha20(key: bytes, nonce: bytes, data: bytes, counter: int = 0) -> bytes:
    out = bytearray()
    c = counter
    for i in range(0, len(data), 64):
        ks = chacha_block(key, c, nonce)
        chunk = data[i:i + 64]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
        c += 1
    return bytes(out)


def printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    ok = sum(1 for c in b if 9 <= c <= 13 or 32 <= c < 127)
    return ok / len(b)


def main():
    dat = open(DAT, "rb").read()
    print(f"dat size {len(dat):,}  entropy {entropy(dat):.2f}")
    hdr = struct.unpack_from("<8I", dat, 0)
    print("header dwords:", [hex(x) for x in hdr])
    print(f"  0x10 + 0x80 = 0x90 ; 0x90 + 0x{0x14B88:x} = 0x{0x90 + 0x14B88:x} (file 0x{len(dat):x})")

    key_region = dat[0x10:0x90]
    payload = dat[0x90:]
    print(f"key region  128 B  entropy {entropy(key_region):.2f}")
    print(f"payload    {len(payload):,} B  entropy {entropy(payload):.2f}")

    log = open(LOGS[0], "rb").read()
    head = log[:4096]
    print(f"\nlog head entropy {entropy(head):.2f}  printable {printable_ratio(head):.3f}")

    best = []
    keys = []
    for ln in (16, 32):
        for off in range(0, 128 - ln + 1, 8):
            keys.append((f"win({ln})@0x{0x10+off:x}", key_region[off:off + ln]))
    import hashlib
    keys.append(("sha256(keyregion)", hashlib.sha256(key_region).digest()))
    keys.append(("md5(keyregion)x2", hashlib.md5(key_region).digest() * 2))

    nonces = [("zero", b"\0" * 12), ("payload12", payload[:12]), ("key12", key_region[:12])]

    for kn, k in keys:
        d = rc4(k, head)
        best.append((printable_ratio(d), "RC4", kn, "-", d[:80]))
        if len(k) == 32:
            for nn, n in nonces:
                for ctr in (0, 1):
                    d = chacha20(k, n, head, ctr)
                    best.append((printable_ratio(d), "ChaCha20", kn, f"{nn}/ctr{ctr}", d[:80]))

    best.sort(reverse=True)
    print("\ntop candidates by printable ratio:")
    for ratio, alg, kn, nn, sample in best[:10]:
        print(f"  {ratio:.3f}  {alg:9s} {kn:22s} {nn:12s} {sample[:56]!r}")


if __name__ == "__main__":
    main()
