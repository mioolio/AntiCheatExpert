"""
pe_model.py -- shared PE model for the ACE-ADVT.sys lossless reconstruction.

Responsibilities:
  * parse the reference image into a stable, JSON-serialisable description
  * section <-> file offset mapping
  * PE checksum algorithm (image checksum, the one link.exe writes)
  * authenticode blob extraction

Nothing here modifies the reference file: the reference is read-only ground truth.
"""
from __future__ import annotations

import json
import os
import struct
import hashlib

IMAGE_BASE = 0x140000000


class PEFile:
    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        self._parse()

    # ---------------- parsing ----------------
    def _parse(self) -> None:
        d = self.data
        e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
        assert d[e_lfanew : e_lfanew + 4] == b"PE\0\0", "not a PE file"
        fh = e_lfanew + 4
        (self.machine, self.nsections, self.timestamp, self.ptr_symtab,
         self.nsyms, self.size_opt, self.characteristics) = struct.unpack_from("<HHIIIHH", d, fh)
        oh = fh + 20
        self.opt_off = oh
        (self.magic,) = struct.unpack_from("<H", d, oh)
        assert self.magic == 0x20B, "expected PE32+"
        self.entry_point = struct.unpack_from("<I", d, oh + 16)[0]
        self.base_of_code = struct.unpack_from("<I", d, oh + 20)[0]
        self.image_base = struct.unpack_from("<Q", d, oh + 24)[0]
        self.section_alignment = struct.unpack_from("<I", d, oh + 32)[0]
        self.file_alignment = struct.unpack_from("<I", d, oh + 36)[0]
        self.size_of_image = struct.unpack_from("<I", d, oh + 56)[0]
        self.size_of_headers = struct.unpack_from("<I", d, oh + 60)[0]
        self.checksum = struct.unpack_from("<I", d, oh + 64)[0]
        self.subsystem = struct.unpack_from("<H", d, oh + 68)[0]
        self.dll_characteristics = struct.unpack_from("<H", d, oh + 70)[0]
        self.size_of_stack_reserve = struct.unpack_from("<Q", d, oh + 72)[0]
        self.size_of_stack_commit = struct.unpack_from("<Q", d, oh + 80)[0]
        self.size_of_heap_reserve = struct.unpack_from("<Q", d, oh + 88)[0]
        self.size_of_heap_commit = struct.unpack_from("<Q", d, oh + 96)[0]
        self.number_of_rva_and_sizes = struct.unpack_from("<I", d, oh + 108)[0]
        ndirs = min(self.number_of_rva_and_sizes, 16)
        self.directories = []
        for i in range(ndirs):
            rva, size = struct.unpack_from("<II", d, oh + 112 + i * 8)
            self.directories.append((rva, size))

        sec_off = oh + self.size_opt
        self.sections = []
        for i in range(self.nsections):
            base = sec_off + i * 40
            name = d[base : base + 8].rstrip(b"\0").decode("ascii", "replace")
            vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", d, base + 8)
            (chars,) = struct.unpack_from("<I", d, base + 36)
            self.sections.append(
                dict(idx=i, name=name, va=vaddr, vsize=vsize, raw_ptr=rptr,
                     raw_size=rsize, chars=chars)
            )

    # ---------------- helpers ----------------
    def section_of_rva(self, rva: int):
        for s in self.sections:
            if s["va"] <= rva < s["va"] + max(s["vsize"], s["raw_size"]):
                return s
        return None

    def rva2off(self, rva: int):
        s = self.section_of_rva(rva)
        if s is None or rva >= s["va"] + s["raw_size"]:
            return None
        return s["raw_ptr"] + (rva - s["va"])

    def bytes_at_rva(self, rva: int, size: int) -> bytes:
        off = self.rva2off(rva)
        if off is None:
            raise ValueError(f"rva {rva:#x} not file-backed")
        return self.data[off : off + size]

    def directory(self, idx: int):
        return self.directories[idx]

    @property
    def cert_offset(self) -> int:
        rva, size = self.directories[4]
        return rva  # certificate directory is a file offset, not an RVA

    @property
    def body_end(self) -> int:
        return max(s["raw_ptr"] + s["raw_size"] for s in self.sections)

    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    def md5(self) -> str:
        return hashlib.md5(self.data).hexdigest()

    # ---------------- checksum ----------------
    def computed_checksum(self) -> int:
        return pe_checksum(self.data, self.opt_off + 64)


def pe_checksum(image: bytes, checksum_field_off: int) -> int:
    """Standard Windows image checksum (sum of 16-bit words + folded carry)."""
    total = 0
    n = len(image)
    limit = n & ~1
    skip = {checksum_field_off, checksum_field_off + 2}
    for i in range(0, limit, 2):
        if i in skip:
            continue  # the checksum field itself counts as zero
        total += image[i] | (image[i + 1] << 8)
        total = (total & 0xFFFFFFFF) + (total >> 32)
    if n & 1:
        total += image[n - 1]
        total = (total & 0xFFFFFFFF) + (total >> 32)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (total + n) & 0xFFFFFFFF


def dump_model(pe: PEFile, out_path: str) -> dict:
    model = dict(
        path=os.path.abspath(pe.path),
        sha256=pe.sha256(),
        md5=pe.md5(),
        size=len(pe.data),
        image_base=pe.image_base,
        entry_point=pe.entry_point,
        timestamp=pe.timestamp,
        checksum=pe.checksum,
        computed_checksum=pe.computed_checksum(),
        size_of_image=pe.size_of_image,
        size_of_headers=pe.size_of_headers,
        section_alignment=pe.section_alignment,
        file_alignment=pe.file_alignment,
        subsystem=pe.subsystem,
        dll_characteristics=pe.dll_characteristics,
        characteristics=pe.characteristics,
        machine=pe.machine,
        directories=[dict(index=i, rva=r, size=s) for i, (r, s) in enumerate(pe.directories)],
        sections=pe.sections,
        body_end=pe.body_end,
        cert_offset=pe.cert_offset,
    )
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(model, f, indent=2)
    return model


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else r"<TARGET_SYS>"
    outdir = sys.argv[2] if len(sys.argv) > 2 else r"<PROJECT_ROOT>\out"
    pe = PEFile(target)
    m = dump_model(pe, os.path.join(outdir, "pe_model.json"))
    print(json.dumps({k: v for k, v in m.items() if k not in ("sections",)}, indent=2, default=str))
    print("checksum stored=%#x computed=%#x" % (pe.checksum, pe.computed_checksum()))
