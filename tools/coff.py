"""
coff.py -- minimal COFF object reader + REL32 relocation applier.

Only what the reconstruction needs:
  * section raw data
  * symbol table (section number + value)
  * relocations (IMAGE_REL_AMD64_REL32 .. REL32_5, ADDR64, ADDR32)

The object is a single flat segment, so a resolved relocation is
    target = section_base + symbol.value
and the stored dword is `target - (reloc_rva + 4 + extra)` where `extra` is
implied by the REL32_n type.  Section bases are irrelevant for REL32 (it is
position independent), which is exactly why the flat-image trick works.
"""
from __future__ import annotations

import struct

REL32 = 0x0004
REL32_1 = 0x0005
REL32_2 = 0x0006
REL32_3 = 0x0007
REL32_4 = 0x0008
REL32_5 = 0x0009
ADDR64 = 0x0001
ADDR32 = 0x0002


class COFF:
    def __init__(self, path):
        self.data = open(path, "rb").read()
        d = self.data
        (self.machine, self.nsections, self.timestamp, self.ptr_symtab,
         self.nsyms, self.opt_size, self.characteristics) = struct.unpack_from("<HHIIIHH", d, 0)
        assert self.machine == 0x8664, hex(self.machine)
        self.sections = []
        off = 20 + self.opt_size
        for i in range(self.nsections):
            b = off + i * 40
            name = d[b : b + 8].rstrip(b"\0").decode("ascii", "replace")
            vsize, vaddr, rawsize, rawptr, relptr, lnptr, nrel, nln, chars = struct.unpack_from(
                "<IIIIIIHHI", d, b + 8)
            self.sections.append(dict(index=i + 1, name=name, vsize=vsize, vaddr=vaddr,
                                      raw_size=rawsize, raw_ptr=rawptr,
                                      rel_ptr=relptr, nrel=nrel, chars=chars))
        self.symbols = []
        if self.ptr_symtab:
            for i in range(self.nsyms):
                b = self.ptr_symtab + i * 18
                if b + 18 > len(d):
                    break
                raw_name = d[b : b + 8]
                value, secnum, typ, storage, naux = struct.unpack_from("<IhHBB", d, b + 8)
                if raw_name[:4] == b"\0\0\0\0":
                    stroff = struct.unpack_from("<I", raw_name, 4)[0]
                    end = d.index(b"\0", stroff)
                    name = d[stroff:end].decode("ascii", "replace")
                else:
                    name = raw_name.rstrip(b"\0").decode("ascii", "replace")
                self.symbols.append(dict(name=name, value=value, section=secnum,
                                         type=typ, storage=storage, naux=naux))
        self.aux = {}
        i = 0
        while i < len(self.symbols):
            self.aux[i] = self.symbols[i]["naux"]
            i += 1 + self.symbols[i]["naux"]

    def relocations(self, sec):
        out = []
        if not sec["rel_ptr"]:
            return out
        for i in range(sec["nrel"]):
            b = sec["rel_ptr"] + i * 10
            va, symidx, typ = struct.unpack_from("<IIH", self.data, b)
            out.append((va, symidx, typ))
        return out


def apply_relocations(coff: COFF, sec, blob: bytearray) -> int:
    fixed = 0
    for va, symidx, typ in coff.relocations(sec):
        sym = coff.symbols[symidx]
        if sym["section"] == 0:      # undefined external
            raise SystemExit(f"external relocation against {sym['name']} at {va:#x}")
        target = sym["value"]        # flat space: one section, base 0
        if typ in (REL32, REL32_1, REL32_2, REL32_3, REL32_4, REL32_5):
            extra = typ - REL32
            value = target - (va + 4 + extra)
            struct.pack_into("<i", blob, va, value)
        elif typ == ADDR64:
            struct.pack_into("<Q", blob, va, target)
        elif typ == ADDR32:
            struct.pack_into("<I", blob, va, target)
        else:
            raise SystemExit(f"unsupported relocation type {typ:#x} at {va:#x}")
        fixed += 1
    return fixed
