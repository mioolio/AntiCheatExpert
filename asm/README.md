# asm/ — 汇编源与重建元数据

每个组件四个文件（`<name>` = 组件名）：

| 文件 | 内容 | 大小 |
|---|---|---|
| `<name>.asm` | 汇编源（仅最小的三个组件以明文提供，GitHub 可直接查看） | 3–9 MB |
| `<name>.asm.gz` | 其余组件的汇编源（gzip -6） | 1–76 MB |
| `<name>.hdr.bin` | 原始 PE 头部 1024 字节（DOS stub + COFF + 可选头 + 段表） | 1 KB |
| `<name>.sig.bin` | 段之后的 Authenticode 签名块 | 10–21 KB |
| `<name>.pack.json` | 段表、`SizeOfImage`、`org`、原始文件 SHA-256 | 1 KB |

## 重建

```powershell
$env:ML64 = '<path>\ml64.exe'
python tools\rebuild_from_repo.py ACE-BASE
python tools\rebuild_from_repo.py --all
```

流程：解压 → `ml64 /c` 汇编 → 回填 REL32 → 按段表切片 → `头 + 段体 + 签名` → 比对 `pack.json` 里的 SHA-256。

产物写到 `build_out/<原始文件名>`。判定看输出：

```
ACE-BASE         IDENTICAL    4,125,432 B  ff81f8087108e566
18/18 与原文件逐字节一致
```

## 说明

- 汇编源是**完整镜像**（`.text` 到最后一个段），指令与原始字节一一对应。
- `db` 行表示该处按原始字节输出（MSVC 与 MASM 编码方向不同的寄存器-寄存器指令、多字节 `nop`、落在数据中间的分支目标）。这不影响输出字节。
- `ACE-DRV64.dll` 的 `.text` 在文件里没有内容（`raw_size = 0`），25 MB 实体在打包段 `.A;6`，因此其汇编源几乎全是 `db`，指令数为 0。
- 头部与签名块是重建所需的**元数据**，不含代码内容，单独成文件以便审计。
