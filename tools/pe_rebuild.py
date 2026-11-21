"""
pe_rebuild.py -- generic byte-exact reconstruction engine for any ACE component.

Pipeline (same maths as docs/04, but parameterised by target):
  1  partition   executable sections -> instructions, everything else -> db blobs
                 (sections named .tvm0 are kept as data: they are obfuscated and
                 the db path is byte-exact anyway)
  2  emit        one flat MASM source in RVA space (org = first section VA)
  3  assemble    ml64 /c  ->  COFF object
  4  relink      apply REL32 fixups (single segment => position independent)
  5  pack        headers (rebuilt field by field) + sections + signature blob
  6  settle      length defects -> encoding defects -> syntax defects, each
                 demoted to `db <original bytes>`; repeat until 0 differences
  7  verify      sha256 / md5 / checksum / coverage

usage:
  python tools/pe_rebuild.py <target> [--work DIR] [--rounds N] [--no-pack]

Outputs under the work dir (default out_rebuild/<basename>/):
  model.json, image.asm, image.obj, image.lst, overrides.json, rebuilt.bin,
  report.json
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
from collections import deque

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile, pe_checksum  # noqa: E402
from coff import COFF, apply_relocations  # noqa: E402

MD = Cs(CS_ARCH_X86, CS_MODE_64)
MD.detail = True

ML64 = os.environ.get("ML64", r"E:\VisualStudio2026\VC\Tools\MSVC\14.52.36815\bin\Hostx64\x64\ml64.exe")
DATA_ONLY = {".tvm0", ".rsrc", ".reloc", ".pdata", ".rdata", ".data", ".CRT", ".gfids",
             ".giats", ".detourc", ".detourd", ".tls", ".fptable", ".K{b", ".cave"}
# Only conventional code sections are disassembled; everything else (including the
# protector payload sections, whose names vary per component) is transcribed as
# data.  ACE-DRV64.dll for instance keeps 25 MB of packed payload in ".A;6".
CODE_NAMES = {".text", "INIT", "PAGE", ".cave", ".text$mn", ".detourc"}

SIZE_KW = [("xmmword ptr ", "oword "), ("ymmword ptr ", "yword "), ("tbyte ptr ", "tword "),
           ("qword ptr ", "qword "), ("dword ptr ", "dword "), ("word ptr ", "word "),
           ("byte ptr ", "byte "), ("mmword ptr ", "qword ")]


# ---------------------------------------------------------------- helpers
def hb(b: int) -> str:
    t = f"{b:02X}"
    return ("0" + t if t[0] in "ABCDEF" else t) + "h"


def hexs(b: bytes) -> str:
    return ", ".join(hb(x) for x in b)


def masm_num(m):
    d = m.group(1).upper()
    if d[0] in "ABCDEF":
        d = "0" + d
    return d + "h"


class Layout:
    def __init__(self, pe: PEFile):
        self.pe = pe
        self.sections = pe.sections
        self.org = self.sections[0]["va"]
        self.flat_size = pe.size_of_image - self.org
        self.code = [s for s in self.sections
                     if s["name"] in CODE_NAMES and s["raw_size"]]
        self.code_names = {s["name"] for s in self.code}

    def is_code(self, rva):
        s = self.pe.section_of_rva(rva)
        return s is not None and s["name"] in self.code_names


# ---------------------------------------------------------------- partition
class Partition:
    """strict byte partition of every executable section"""

    def __init__(self, lay: Layout):
        self.lay = lay
        self.pe = lay.pe
        self.items = {}
        self.cov = {}
        for sec in lay.code:
            self.cov[sec["va"]] = dict(base=sec["va"], size=sec["raw_size"],
                                       starts=[], sizes={})

    def cov_for(self, rva):
        for c in self.cov.values():
            if c["base"] <= rva < c["base"] + c["size"]:
                return c
        return None

    def covering_end(self, rva):
        c = self.cov_for(rva)
        if c is None:
            return None
        import bisect
        i = bisect.bisect_right(c["starts"], rva) - 1
        if i >= 0:
            s = c["starts"][i]
            if s + c["sizes"][s] > rva:
                return s + c["sizes"][s]
        return None

    def free(self, rva):
        return self.cov_for(rva) is not None and self.covering_end(rva) is None

    def next_start(self, rva):
        import bisect
        c = self.cov_for(rva)
        if c is None:
            return None
        i = bisect.bisect_right(c["starts"], rva)
        return c["starts"][i] if i < len(c["starts"]) else None

    def add(self, item):
        import bisect
        c = self.cov_for(item["rva"])
        assert c is not None, f"{item['rva']:#x} outside code sections"
        assert self.free(item["rva"]), f"overlap at {item['rva']:#x}"
        ns = self.next_start(item["rva"])
        assert ns is None or ns >= item["rva"] + item["size"], "swallows neighbour"
        bisect.insort(c["starts"], item["rva"])
        c["sizes"][item["rva"]] = item["size"]
        self.items[item["rva"]] = item


def rec_of(insn):
    rva = insn.address
    rec = dict(rva=rva, size=insn.size, kind="insn", mnem=insn.mnemonic,
               ops=insn.op_str, bytes=insn.bytes.hex(), branch=None, ripref=None)
    ops = insn.operands
    if ops and (insn.mnemonic in ("call", "jmp") or insn.mnemonic.startswith("j")):
        if ops[0].type == X86_OP_IMM:
            rec["branch"] = ops[0].imm
        elif ops[0].type == X86_OP_MEM and ops[0].mem.base == X86_REG_RIP:
            rec["ripref"] = insn.address + insn.size + ops[0].mem.disp
    if rec["ripref"] is None:
        for op in ops:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                rec["ripref"] = insn.address + insn.size + op.mem.disp
                break
    return rec


def build_partition(lay: Layout) -> Partition:
    pe = lay.pe
    part = Partition(lay)
    img_lo, img_hi = pe.image_base, pe.image_base + pe.size_of_image

    def decode_seq(start_va, limit_va):
        pos = start_va
        while pos < limit_va:
            if not part.free(pos):
                nxt = part.covering_end(pos)
                if nxt is None:
                    break
                pos = nxt
                continue
            if pe.data[pe.rva2off(pos)] == 0xCC and pos + 1 < limit_va and \
                    pe.data[pe.rva2off(pos + 1)] == 0xCC:
                break
            room = limit_va - pos
            ns = part.next_start(pos)
            if ns is not None:
                room = min(room, ns - pos)
            try:
                insn = next(MD.disasm(pe.bytes_at_rva(pos, min(16, room)), pos))
            except StopIteration:
                break
            if insn.address != pos:
                break
            part.add(rec_of(insn))
            pos += insn.size
            if insn.mnemonic in ("ret", "retn", "ud2"):
                break
            if insn.mnemonic == "jmp" and rec_of(insn)["branch"] is not None:
                break

    # seeds: entry point + unwind records that land in executable sections
    seeds = [pe.entry_point]
    rva, size = pe.directories[3]
    if rva and size:
        off = pe.rva2off(rva)
        for i in range(size // 12):
            b, e, _u = struct.unpack_from("<III", pe.data, off + i * 12)
            if b and e > b and lay.is_code(b):
                seeds.append(b)

    work = deque(sorted(set(seeds)))
    guard = 0
    while work and guard < 2_000_000:
        guard += 1
        va = work.pop()
        if not lay.is_code(va) or not part.free(va):
            continue
        sec = lay.pe.section_of_rva(va)
        limit = sec["va"] + sec["raw_size"]
        pos = va
        while pos < limit:
            if not part.free(pos):
                break
            if lay.pe.data[lay.pe.rva2off(pos)] == 0xCC:
                break
            room = limit - pos
            ns = part.next_start(pos)
            if ns is not None:
                room = min(room, ns - pos)
            try:
                insn = next(MD.disasm(lay.pe.bytes_at_rva(pos, min(16, room)), pos))
            except StopIteration:
                break
            if insn.address != pos:
                break
            r = rec_of(insn)
            part.add(r)
            if r["branch"] is not None and img_lo <= r["branch"] < img_hi:
                work.append(r["branch"])
            pos += insn.size
            if insn.mnemonic in ("ret", "retn", "ud2"):
                break
            if insn.mnemonic == "jmp" and r["branch"] is not None:
                break

    # fill the rest
    for sec in lay.code:
        base, size = sec["va"], sec["raw_size"]
        end = base + size
        pos = base
        while pos < end:
            ce = part.covering_end(pos)
            if ce is not None:
                pos = ce
                continue
            run = 0
            while pos + run < end and part.free(pos + run) and \
                    lay.pe.data[lay.pe.rva2off(pos + run)] == 0xCC:
                run += 1
            if run:
                part.add(dict(rva=pos, size=run, kind="pad",
                              bytes=lay.pe.bytes_at_rva(pos, run).hex()))
                pos += run
                continue
            room = end - pos
            ns = part.next_start(pos)
            if ns is not None:
                room = min(room, ns - pos)
            try:
                insn = next(MD.disasm(lay.pe.bytes_at_rva(pos, min(16, room)), pos))
            except StopIteration:
                part.add(dict(rva=pos, size=1, kind="data",
                              bytes=lay.pe.bytes_at_rva(pos, 1).hex(), note="undecodable"))
                pos += 1
                continue
            if insn.address != pos:
                part.add(dict(rva=pos, size=1, kind="data",
                              bytes=lay.pe.bytes_at_rva(pos, 1).hex(), note="undecodable"))
                pos += 1
                continue
            r = rec_of(insn)
            r["note"] = "swept"
            part.add(r)
            pos += insn.size
    return part


# ---------------------------------------------------------------- emit
class Emitter:
    def __init__(self, lay: Layout, part: Partition, work: str):
        self.lay, self.part, self.work = lay, part, work
        self.pe = lay.pe
        self.labels = {}
        self.overrides = {}
        self.lines = []
        self.stats = dict(insn=0, raw=0, db=0, pad=0)
        ov = os.path.join(work, "overrides.json")
        if os.path.exists(ov):
            self.overrides = json.load(open(ov, encoding="utf-8"))

    # -- label set ------------------------------------------------------
    def collect_labels(self):
        used = set()
        for it in self.part.items.values():
            if it.get("branch") is not None:
                used.add(it["branch"])
            if it.get("ripref") is not None:
                used.add(it["ripref"])
        lo, hi = self.pe.image_base, self.pe.image_base + self.pe.size_of_image
        for va in sorted(used):
            if not (lo <= va < hi):
                continue
            it = self.part.items.get(va)
            if it is None:
                self.labels[va] = f"dat_{va:x}"
            elif it["kind"] == "insn":
                self.labels[va] = f"loc_{va:x}"
            elif it["kind"] == "pad":
                self.labels[va] = f"pad_{va:x}"
            else:
                self.labels[va] = f"dat_{va:x}"

    # -- instruction text ----------------------------------------------
    def insn_text(self, va, it):
        key = f"{va:x}"
        raw = "db " + hexs(bytes.fromhex(it["bytes"]))
        if self.overrides.get(key) == "db":
            self.stats["raw"] += 1
            return raw
        mnem = "mov" if it["mnem"] == "movabs" else it["mnem"]
        ops = it["ops"]
        if it.get("ripref") is not None:
            lab = self.labels.get(it["ripref"])
            if lab is None:
                self.overrides[key] = "db"
                self.stats["raw"] += 1
                return raw
            ops = re.sub(r"\[rip [+-] 0x[0-9a-f]+\]", f"[{lab}]", ops)
        if it.get("branch") is not None:
            lab = self.labels.get(it["branch"])
            if lab is None:
                self.overrides[key] = "db"
                self.stats["raw"] += 1
                return raw
            ops = re.sub(r"0x[0-9a-f]+$", lab, ops)
        # MASM keeps capstone's `qword ptr [...]` spelling; only numeric literals change
        ops = re.sub(r"0x([0-9a-fA-F]+)", masm_num, ops)
        self.stats["insn"] += 1
        return (mnem + (" " + ops if ops else "")).strip()

    # -- whole image ----------------------------------------------------
    def emit(self):
        self.collect_labels()
        out = ["OPTION CASEMAP:NONE", "", "FLAT SEGMENT ALIGN(16) 'CODE'"]
        linemap = {}
        labels_by_va = {}
        for va, lab in self.labels.items():
            labels_by_va.setdefault(va, lab)

        def push(text, va=None):
            out.append(text)
            if va is not None:
                linemap[len(out)] = va

        for sec in self.lay.sections:
            va0, size = sec["va"], sec["raw_size"]
            out.append(f"; ---- {sec['name']} @ {va0:#x} ----")
            if sec["name"] in self.lay.code_names:
                pos = va0
                while pos < va0 + size:
                    it = self.part.items.get(pos)
                    if it is None:
                        ce = self.part.covering_end(pos)
                        if ce is None:
                            break
                        pos = ce
                        continue
                    if pos in labels_by_va:
                        out.append(f"{labels_by_va[pos]}:")
                    if it["kind"] == "insn":
                        push(self.insn_text(pos, it) + f"  ;@{pos:x}", pos)
                    elif it["kind"] == "pad":
                        push(f"db {it['size']} dup(0CCh)  ;@{pos:x}", pos)
                        self.stats["pad"] += it["size"]
                    else:
                        data = bytes.fromhex(it["bytes"])
                        for i in range(0, len(data), 16):
                            push("db " + hexs(data[i:i + 16]) + f"  ;@{pos + i:x}", pos + i)
                            self.stats["db"] += 1
                    pos += it["size"]
            else:
                data = self.pe.data[sec["raw_ptr"]:sec["raw_ptr"] + size]
                # split blobs at label boundaries
                cuts = sorted(v - va0 for v in labels_by_va if va0 <= v < va0 + size)
                cur = 0
                for c in cuts + [size]:
                    while cur < c:
                        if va0 + cur in labels_by_va:
                            out.append(f"{labels_by_va[va0 + cur]}:")
                        n = min(16, c - cur)
                        push("db " + hexs(data[cur:cur + n]) + f"  ;@{va0 + cur:x}", va0 + cur)
                        self.stats["db"] += 1
                        cur += n
                    if cur < size and va0 + cur in labels_by_va:
                        out.append(f"{labels_by_va[va0 + cur]}:")
                if cur < size:
                    out.append("db " + hexs(data[cur:]))

            nxt = None
            for s2 in self.lay.sections:
                if s2["va"] > va0:
                    nxt = s2["va"]
                    break
            if nxt is not None and nxt > va0 + size:
                out.append(f"db {nxt - (va0 + size)} dup(0)")

        out += ["FLAT ENDS", "", "END", ""]
        path = os.path.join(self.work, "image.asm")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(out))
        json.dump(self.overrides, open(os.path.join(self.work, "overrides.json"), "w"),
                  indent=1, sort_keys=True)
        json.dump(linemap, open(os.path.join(self.work, "linemap.json"), "w"))
        return path


# ---------------------------------------------------------------- build
def assemble(asm_path, obj_path, lst_path):
    obj_path, lst_path = os.path.abspath(obj_path), os.path.abspath(lst_path)
    cmd = [ML64, "/c", "/nologo", "/Fo" + obj_path, "/Fl" + lst_path, os.path.basename(asm_path)]
    r = subprocess.run(cmd, cwd=os.path.dirname(os.path.abspath(asm_path)),
                       capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


MARK = re.compile(r";@([0-9a-f]+)")


def listing_offsets(lst_path):
    """va -> output offset, taken from the `;@va` markers MASM copies into the listing"""
    offs = {}
    with open(lst_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = MARK.search(line)
            if not m:
                continue
            head = re.match(r"^\s*([0-9A-Fa-f]{8})\s", line)
            if head:
                offs[int(m.group(1), 16)] = int(head.group(1), 16)
    return offs


def parse_errors(text, asm_path):
    """return [(line_no, msg)] ; ml64 prints 'image.asm(123) : error A2070: ...'"""
    out = []
    for line in text.splitlines():
        m = re.search(r"\((\d+)\)\s*:\s*(?:error|fatal)\s+\w+:\s*(.*)", line)
        if m:
            out.append((int(m.group(1)), m.group(2).strip()))
    return out


def line_map(asm_path):
    lm = {}
    for n, line in enumerate(open(asm_path, encoding="utf-8"), start=1):
        lm[n] = line
    return lm


def pack(lay: Layout, flat: bytes, work: str) -> bytes:
    pe = lay.pe
    chunks = []
    for s in lay.sections:
        start = s["va"] - lay.org
        c = flat[start:start + s["raw_size"]]
        if len(c) < s["raw_size"]:
            c = c + b"\0" * (s["raw_size"] - len(c))
        chunks.append(c)
    body = b"".join(chunks)
    sig = b""
    cert_off, cert_size = pe.directories[4]
    if cert_off and cert_size:
        sig = pe.data[cert_off:cert_off + cert_size]
    img = headers(lay, work) + body + sig
    if len(img) != len(pe.data):
        raise SystemExit(f"packed size {len(img):#x} != original {len(pe.data):#x}")
    # NOTE: some ACE components ship a stale PE checksum (stored value does not
    # match the file).  Byte-exactness takes priority, so the stored value is kept
    # verbatim; the report records both for the curious.
    return img


def headers(lay: Layout, work: str) -> bytes:
    """rebuild the PE headers field by field, verify against the original"""
    pe = lay.pe
    d = pe.data
    e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
    stub = d[0x40:e_lfanew]
    dos = bytearray(0x40)
    struct.pack_into("<H", dos, 0, 0x5A4D)
    struct.pack_into("<H", dos, 2, struct.unpack_from("<H", d, 2)[0])
    struct.pack_into("<H", dos, 4, struct.unpack_from("<H", d, 4)[0])
    struct.pack_into("<H", dos, 6, 0)
    struct.pack_into("<H", dos, 8, 4)
    struct.pack_into("<H", dos, 0xA, 0)
    struct.pack_into("<H", dos, 0xC, 0xFFFF)
    struct.pack_into("<H", dos, 0xE, 0)
    struct.pack_into("<H", dos, 0x10, 0xB8)
    struct.pack_into("<H", dos, 0x12, 0)
    struct.pack_into("<H", dos, 0x14, 0)
    struct.pack_into("<H", dos, 0x16, 0)
    struct.pack_into("<H", dos, 0x18, 0x40)
    struct.pack_into("<H", dos, 0x1A, 0)
    struct.pack_into("<I", dos, 0x3C, e_lfanew)

    coff = b"PE\0\0" + struct.pack("<HHIIIHH", pe.machine, pe.nsections, pe.timestamp,
                                   pe.ptr_symtab, pe.nsyms, pe.size_opt, pe.characteristics)
    opt = bytearray(d[pe.opt_off:pe.opt_off + pe.size_opt])
    # keep every field but re-write the checksum slot from the model
    struct.pack_into("<I", opt, 64, pe.checksum)
    secs = bytearray()
    for s in pe.sections:
        secs += s["name"].encode("ascii").ljust(8, b"\0")
        secs += struct.pack("<IIII", s["vsize"], s["va"], s["raw_size"], s["raw_ptr"])
        secs += struct.pack("<II", 0, 0)
        secs += struct.pack("<HHI", 0, 0, s["chars"])
    blob = bytes(dos) + stub + coff + bytes(opt) + bytes(secs)
    if len(blob) < pe.size_of_headers:
        blob += b"\0" * (pe.size_of_headers - len(blob))
    ref = d[:pe.size_of_headers]
    if blob != ref:
        diffs = [(i, a, b) for i, (a, b) in enumerate(zip(blob, ref)) if a != b][:6]
        raise SystemExit(f"header rebuild differs at {diffs}")
    return blob


# ---------------------------------------------------------------- main
def rebuild(target, work, rounds=10):
    os.makedirs(work, exist_ok=True)
    lay = Layout(PEFile(target))
    ref = lay.pe.data

    # partition once, cache the model
    mpath = os.path.join(work, "model.json")
    if os.path.exists(mpath):
        model = json.load(open(mpath, encoding="utf-8"))
    else:
        print("  partition ...", flush=True)
        part = build_partition(lay)
        model = dict(items=sorted(part.items.values(), key=lambda i: i["rva"]))
        json.dump(model, open(mpath, "w"))
        print(f"  items={len(model['items'])}", flush=True)

    for rnd in range(1, rounds + 1):
        part = Partition(lay)
        for it in model["items"]:
            # re-register into the coverage structure
            c = part.cov_for(it["rva"])
            import bisect
            bisect.insort(c["starts"], it["rva"])
            c["sizes"][it["rva"]] = it["size"]
            part.items[it["rva"]] = it

        em = Emitter(lay, part, work)
        asm = em.emit()
        rc, log = assemble(asm, os.path.join(work, "image.obj"), os.path.join(work, "image.lst"))
        if rc != 0:
            errs = parse_errors(log, asm)
            lm = json.load(open(os.path.join(work, "linemap.json")))
            # map error line -> instruction rva by scanning backwards for a known label
            fixed = 0
            for ln, msg in errs[:400]:
                target_va = lm.get(str(ln))
                if target_va is None:
                    # nearest preceding emitted line that carries a VA
                    for k in sorted((int(k) for k in lm), reverse=True):
                        if k <= ln:
                            target_va = lm[str(k)]
                            break
                if target_va is not None:
                    # MASM stops after 100 errors, so demote the whole 4 KB page
                    # around each offending line.  This clears dense bad regions in
                    # one round instead of 100 items per round.
                    page = target_va & ~0xFFF
                    for it in model["items"]:
                        if page <= it["rva"] < page + 0x1000:
                            if em.overrides.get(f"{it['rva']:x}") != "db":
                                fixed += 1
                            em.overrides[f"{it['rva']:x}"] = "db"
            json.dump(em.overrides, open(os.path.join(work, "overrides.json"), "w"),
                      indent=1, sort_keys=True)
            print(f"  round {rnd}: ml64 errors {len(errs)}, demoted {fixed}", flush=True)
            if fixed == 0:
                print(log[:2000])
                raise SystemExit("unmappable assembler error")
            continue

        # relink
        coff = COFF(os.path.join(work, "image.obj"))
        secs = [s for s in coff.sections if s["raw_size"]]
        sec = secs[0]
        flat = bytearray(coff.data[sec["raw_ptr"]:sec["raw_ptr"] + sec["raw_size"]])
        relocs = apply_relocations(coff, sec, flat)

        # stage 1: length defects (shift invariant: difference of marker offsets)
        offs = listing_offsets(os.path.join(work, "image.lst"))
        seq = sorted((va, off) for va, off in offs.items())
        len_bad = []
        for i in range(len(seq) - 1):
            va, off = seq[i]
            nva = seq[i + 1][0]
            it = part.items.get(va)
            if it is None:
                continue
            if nva - va > it["size"] * 8:      # section boundary
                continue
            if seq[i + 1][1] - off != it["size"]:
                len_bad.append(va)
        if len_bad:
            print(f"  round {rnd}: length defects {len(len_bad)}", flush=True)
            for va in len_bad:
                em.overrides[f"{va:x}"] = "db"
            json.dump(em.overrides, open(os.path.join(work, "overrides.json"), "w"),
                      indent=1, sort_keys=True)
            continue

        # stage 2: bytes at the offset the assembler actually used
        bad = []
        for it in model["items"]:
            off = offs.get(it["rva"])
            if off is None:
                continue
            want = bytes.fromhex(it["bytes"])
            if bytes(flat[off:off + it["size"]]) != want:
                bad.append(it["rva"])
        print(f"  round {rnd}: assembled {len(flat):#x}, relocs {relocs}, mismatches {len(bad)}",
              flush=True)
        if bad:
            for va in bad[:6]:
                print(f"    {va:#x}", flush=True)
            for va in bad:
                em.overrides[f"{va:x}"] = "db"
            json.dump(em.overrides, open(os.path.join(work, "overrides.json"), "w"),
                      indent=1, sort_keys=True)
            continue

        # stage 3: alignment check -- every item must sit at rva-org, otherwise an
        # earlier length defect would silently shift the whole image
        shifted = [it["rva"] for it in model["items"]
                   if offs.get(it["rva"], it["rva"] - lay.org) != it["rva"] - lay.org]
        if shifted:
            print(f"  round {rnd}: {len(shifted)} items misplaced, demoting first", flush=True)
            em.overrides[f"{shifted[0]:x}"] = "db"
            json.dump(em.overrides, open(os.path.join(work, "overrides.json"), "w"),
                      indent=1, sort_keys=True)
            continue

        img = pack(lay, bytes(flat), work)
        out = os.path.join(work, "rebuilt.bin")
        open(out, "wb").write(img)
        diff = sum(1 for a, b in zip(img, ref) if a != b) + abs(len(img) - len(ref))
        rep = dict(target=target, size=len(img), sha256=hashlib.sha256(img).hexdigest(),
                   ref_sha256=hashlib.sha256(ref).hexdigest(),
                   md5=hashlib.md5(img).hexdigest(), ref_md5=hashlib.md5(ref).hexdigest(),
                   identical=img == ref, differing_bytes=diff,
                   checksum=pe_checksum(img, lay.pe.opt_off + 64),
                   ref_checksum=lay.pe.checksum,
                   insns=sum(1 for i in model["items"] if i["kind"] == "insn"),
                   mnemonic=sum(1 for i in model["items"] if i["kind"] == "insn") - len(em.overrides),
                   raw=len(em.overrides), rounds=rnd)
        json.dump(rep, open(os.path.join(work, "report.json"), "w"), indent=1)
        print(f"  -> identical={rep['identical']} diff={diff} sha={rep['sha256'][:16]} "
              f"cov={rep['mnemonic']}/{rep['insns']}", flush=True)
        return rep
    raise SystemExit("did not converge")


if __name__ == "__main__":
    tgt = sys.argv[1]
    name = os.path.splitext(os.path.basename(tgt))[0]
    work = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "out_rebuild", name)
    if "--work" in sys.argv:
        work = sys.argv[sys.argv.index("--work") + 1]
    rounds = int(sys.argv[sys.argv.index("--rounds") + 1]) if "--rounds" in sys.argv else 10
    print(f"== {name} ==", flush=True)
    rebuild(tgt, work, rounds)
