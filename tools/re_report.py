"""
re_report.py -- build docs/15-全组件字节保真.md from out_rebuild/*/report.json.

For every rebuilt component it also asks Windows for the Authenticode status of
the rebuilt file, so the table proves that signature validity survived the
round-trip (it must: the bytes are identical).
"""
from __future__ import annotations

import glob
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT_DIR = os.path.join(ROOT, "out_rebuild")
DOC = os.path.join(ROOT, "docs", "15-全组件字节保真.md")

import sys as _sys
_sys.path.insert(0, HERE)
from pe_model import PEFile  # noqa: E402


def auth_status(path):
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            f"(Get-AuthenticodeSignature -LiteralPath '{path}').Status"],
                           capture_output=True, text=True, timeout=60)
        return r.stdout.strip() or "?"
    except Exception:
        return "?"


def main():
    rows = []
    for p in sorted(glob.glob(os.path.join(OUT_DIR, "*", "report.json"))):
        r = json.load(open(p, encoding="utf-8"))
        r["name"] = os.path.basename(os.path.dirname(p))
        rebuilt = os.path.join(os.path.dirname(p), "rebuilt.bin")
        r["rebuilt"] = rebuilt
        r["signature"] = auth_status(rebuilt) if os.path.exists(rebuilt) else "?"
        rows.append(r)

    rows.sort(key=lambda r: r["size"])
    total = len(rows)
    ok = sum(1 for r in rows if r.get("identical"))
    lines = [
        "# 15 · 全组件字节保真重建",
        "",
        "对 `AntiCheatExpert` 目录下每个组件执行同一条管线：",
        "严格字节分区 → MASM 单段汇编 → REL32 回填 → 头部字段重建 → 签名块转录 →",
        "三阶段收敛（长度缺陷 / 编码缺陷 / 对齐缺陷）。判据是**逐字节相同**，",
        "因此原始 Authenticode 签名必然继续有效（签名覆盖的字节没有变化）。",
        "",
        f"**结果：{ok} / {total} 个组件逐字节一致。**",
        "",
        "| 组件 | 大小 | 差异字节 | 助记符覆盖 | 收敛轮次 | 重建后签名 |",
        "|---|---|---|---|---|---|",
    ]
    for r in rows:
        mark = "IDENTICAL" if r.get("identical") else "DIFF"
        lines.append(
            f"| `{r['name']}` | {r['size']:,} | {r['differing_bytes']} ({mark}) | "
            f"{r['mnemonic']:,} / {r['insns']:,} "
            f"({r['mnemonic'] * 100.0 / max(1, r['insns']):.1f}%) | {r['rounds']} | {r['signature']} |")

    lines += [
        "",
        "## 合计",
        "",
        f"- 组件：{total} 个，逐字节一致 {ok} 个",
        f"- 重建总字节：{sum(r['size'] for r in rows):,}",
        f"- 指令总数：{sum(r['insns'] for r in rows):,}，"
        f"其中由助记符汇编 {sum(r['mnemonic'] for r in rows):,} "
        f"({100.0 * sum(r['mnemonic'] for r in rows) / max(1, sum(r['insns'] for r in rows)):.1f}%)",
    ]
    zero = [r["name"] for r in rows if r["insns"] == 0]
    if zero:
        lines += ["", f"- 无指令被反汇编的组件（全部内容为打包数据）：{', '.join('`' + z + '`' for z in zero)}"]

    lines += [
        "",
        "## 说明",
        "",
        "1. **覆盖率不是 100% 是正常的**：`db` 回落只改变“源码写法”，不改变输出字节。",
        "   回落集中在 MSVC 与 MASM 编码方向不同的寄存器-寄存器指令、多字节 `nop`、",
        "   以及落在数据中间的分支目标。",
        "2. **校验和**：`ACE-ADVT.sys` 的 PE 校验和可重算一致；",
        "   `SGuardSvc64.exe` / `ACE-Trace.dll` / `SGuardUpdate64.exe` 三个文件的",
        "   厂商存储值与文件内容不符（陈旧校验和）。管线保留原值，逐字节优先。",
        "3. **签名**：重建产物保留原始签名块，字节相同则签名有效；上表 `Valid` 即实测。",
        "4. **`ACE-DRV64.dll` 为打包 EFI 载荷**：`.text` 的 `raw_size` 为 0，25 MB 实体全在",
        '   非标准段 `.A;6` 内（可执行+可写），因此该文件按数据转录，字节保真达成，',
        "   逻辑还原需要先解包载荷。",
        "",
        "## 复现",
        "",
        "```powershell",
        "$env:ML64 = '<path>\\ml64.exe'",
        "python tools\\pe_rebuild.py <目标文件>          # 单个组件",
        "python tools\\re_all.py                        # 全部组件（按体积从小到大）",
        "python tools\\re_report.py                      # 生成本文",
        "```",
        "",
        "每个组件的中间产物在 `out_rebuild/<name>/`：`model.json`（分区）、",
        "`image.asm`（反汇编源码）、`overrides.json`（回落表）、`rebuilt.bin`（重建结果）、",
        "`report.json`（验收数据）。",
    ]
    open(DOC, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    print(f"wrote {DOC}  ({ok}/{total} identical)")


if __name__ == "__main__":
    main()
