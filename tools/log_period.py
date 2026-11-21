"""
log_period.py -- test whether the keystream repeats with a short period.

The log header is built by copying 0x80 bytes (see 0x48AE4), so the keystream may
be a repeating table of 0x10/0x20/0x40/0x80/0x100/0x118/0x200 bytes.  If so,
using the first block of ciphertext as the keystream decrypts the following
blocks into readable text.

Scoring: printable ratio per block; text logs are > 0.9.
"""
from __future__ import annotations

import sys

LOG = r"<ACE_ROOT>\ace-boot-20261121-010547.log"


def printable(b: bytes) -> float:
    if not b:
        return 0.0
    return sum(1 for c in b if 9 <= c <= 13 or 32 <= c < 127) / len(b)


def main():
    d = open(LOG, "rb").read()
    print(f"log {len(d):,} bytes")
    for period in (0x10, 0x20, 0x40, 0x80, 0x100, 0x118, 0x200, 0x400):
        ks = d[:period]
        out = bytes(d[i] ^ ks[i % period] for i in range(len(d[:period * 8])))
        blocks = [printable(out[i:i + period]) for i in range(period, len(out), period)]
        print(f"  period {period:#06x}: block printable ratios "
              + " ".join(f"{b:.2f}" for b in blocks[:6])
              + f"   (max {max(blocks):.2f})")

    # also try: header plaintext = zeros + magic 0x013525DD at 0, 0x118 at 4
    print("\nassuming header plaintext [magic 0x013525DD][0x118][...]:")
    guess = bytearray(0x118)
    guess[0:4] = (0x013525DD).to_bytes(4, "little")
    guess[4:8] = (0x118).to_bytes(4, "little")
    print("  implied keystream[0:16]:", bytes(d[i] ^ guess[i] for i in range(16)).hex())
    for period in (0x80, 0x100):
        ks = bytes(d[i] ^ guess[i] for i in range(period))
        out = bytes(d[i] ^ ks[i % period] for i in range(period, period * 8))
        print(f"  period {period:#x} with that guess: max printable "
              f"{max(printable(out[i:i + period]) for i in range(0, len(out), period)):.2f}")


if __name__ == "__main__":
    main()
