"""
ioctl_table.py -- find (code, handler) dispatch tables in the ACE drivers.

Many drivers dispatch on IOCTL code through a table of
    { DWORD ioctl_code; DWORD pad; QWORD handler; }   (16 bytes)
or
    { DWORD ioctl_code; QWORD handler; }              (12 bytes)

The scanner looks for runs of these where every code shares a realistic
DEVICE_TYPE and every handler lands inside an executable section.
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile, IMAGE_BASE  # noqa: E402

DEV_OK = {0x22, 0x8000, 0x8001, 0x8002, 0x8003, 0x8004, 0x8005, 0x9C40, 0x9C41, 0x0022}


def looks_code(v):
    if v == 0 or v > 0xFFFFFFFF:
        return False
    dev = (v >> 16) & 0xFFFF
    fn = (v >> 2) & 0xFFF
    return dev in DEV_OK and 0 < fn < 0x1000


def is_code_ptr(pe, v):
    if not (pe.image_base <= v < pe.image_base + pe.size_of_image):
        return False
    s = pe.section_of_rva(v - pe.image_base)
    return s is not None and (s["chars"] & 0x20000000) != 0


def scan(pe, stride, code_at, ptr_at, span):
    hits = []
    for sec in pe.sections:
        if sec["name"] not in (".data", ".rdata"):
            continue
        blob = pe.data[sec["raw_ptr"]:sec["raw_ptr"] + sec["raw_size"]]
        base = sec["va"]
        i = 0
        while i + span <= len(blob):
            code = struct.unpack_from("<I", blob, i + code_at)[0]
            ptr = struct.unpack_from("<Q", blob, i + ptr_at)[0]
            if looks_code(code) and is_code_ptr(pe, ptr):
                run = []
                j = i
                while j + span <= len(blob):
                    c = struct.unpack_from("<I", blob, j + code_at)[0]
                    p = struct.unpack_from("<Q", blob, j + ptr_at)[0]
                    if not (looks_code(c) and is_code_ptr(pe, p)):
                        break
                    run.append((c, p - pe.image_base))
                    j += stride
                if len(run) >= 2:
                    hits.append((base + i, stride, run))
                    i = j
                    continue
            i += 4
    return hits


def main():
    for path in sys.argv[1:]:
        pe = PEFile(path)
        print(f"\n=== {os.path.basename(path)} ({len(pe.data):,} B) ===")
        found = False
        for stride, code_at, ptr_at, span in ((12, 0, 4, 12), (16, 0, 8, 16), (16, 4, 8, 16)):
            for rva, st, run in scan(pe, stride, code_at, ptr_at, span):
                found = True
                print(f"  table @ {rva:#08x}  stride={st}  entries={len(run)}")
                for code, handler in run[:24]:
                    d = dict(dev=(code >> 16) & 0xFFFF, fn=(code >> 2) & 0xFFF,
                             method=code & 3, access=(code >> 14) & 3)
                    print(f"     {code:#010x}  dev={d['dev']:#06x} fn={d['fn']:#05x} "
                          f"m={d['method']} a={d['access']}  -> {handler:#08x}")
        if not found:
            print("  no (code, handler) table matched")


if __name__ == "__main__":
    main()
