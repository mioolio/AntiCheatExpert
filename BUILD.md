# 编译方法（BUILD）

本仓库有两条构建路线：

- **通用路线**（`tools/pe_rebuild.py`）：任意 ACE 组件 → 逐字节相同的重建文件。本文主角。
- **专用路线**（`build.ps1`）：只针对 `ACE-ADVT.sys`，多了"头部字段级重建 + 签名块转录 + 验收"三件事。

两者都用微软 MASM（`ml64.exe`）作为汇编器。

---

## 0. 前置条件

| 组件 | 要求 | 用途 |
|---|---|---|
| Python | 3.10+（实测 3.14） | 全部工具 |
| `capstone` | 5.x | 反汇编 |
| `pefile` | 2023+ | PE 解析（`tools/pe_model.py` 自带解析器，pefile 仅用于对照） |
| `ml64.exe` | MSVC 14.38+（实测 14.50 / 14.52） | 汇编 |
| Windows 10/11 x64 | — | 路径与脚本 |

```powershell
pip install capstone pefile
```

`ml64.exe` 位置：

```text
VS 2022/2026 : <VS>\VC\Tools\MSVC\<ver>\bin\Hostx64\x64\ml64.exe
EWDK 镜像    : <ISO>\Program Files\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\<ver>\bin\Hostx64\x64\ml64.exe
```

设置：

```powershell
$env:ML64 = 'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\ml64.exe'
```

---

## 1. 通用路线：任意组件

```powershell
python tools\pe_rebuild.py <目标文件> [--work 输出目录] [--rounds N]
```

| 参数 | 说明 |
|---|---|
| `<目标文件>` | 自备的 `.sys` / `.dll` / `.exe` |
| `--work` | 工作目录，默认 `out_rebuild\<文件名>` |
| `--rounds` | 最大收敛轮次，默认 10（大文件建议 18–20） |

阶段：

| 阶段 | 动作 | 产物 |
|---|---|---|
| 1 | 严格分区：代码段 → 指令，其余 → 数据块 | `model.json` |
| 2 | 生成单段 MASM 源码（RVA 空间平铺） | `image.asm` |
| 3 | `ml64 /c` 汇编 | `image.obj`、`image.lst` |
| 4 | 回填 REL32 重定位 | （内存中） |
| 5 | 切段 + 头部重建 + 签名转录 + 打包 | `rebuilt.bin` |
| 6 | 三阶段收敛（长度 / 编码 / 对齐） | `overrides.json` |
| 7 | 核验 | `report.json` |

判据：`report.json` 中 `identical: true`、`differing_bytes: 0`。

### 批量

```powershell
python tools\re_all.py                  # 全部组件，按体积升序
python tools\re_all.py --only ACE-BASE,ACE-CORE302706
python tools\re_all.py --max-size 5     # 只跑 ≤5 MB 的
```

结果写入 `out_rebuild\summary.json`，并在终端打印一表。

### 重新生成核验报告

```powershell
python tools\re_report.py               # 生成 docs/15-全组件字节保真.md
```

### 差异定位

```powershell
python tools\diff_report.py <原文件> out_rebuild\<name>\rebuilt.bin
```

会指出差异落在哪个段、哪个 RVA、两侧字节是什么。

---

## 2. 专用路线：`ACE-ADVT.sys`

```powershell
$env:ADVT_TARGET = 'D:\samples\ACE-ADVT.sys'
$env:ML64        = '<path>\ml64.exe'
.\build.ps1 -Fresh
```

六阶段：资产转录 → 头部字段级重建（1024 字节零差异）→ 分区分析 → `ml64` 汇编+重定位+打包+收敛 → 验收 → 汇总。

参数：`-Fresh`（从零）、`-Nasm`（备用 NASM 工具链）、`-SkipVerify`。

验收：

```powershell
python tools\verify.py
```

期望：

```
identical   True  differing bytes 0
checksum    stored 0x124e80 recomputed 0x124e80
signature   Valid  CN=Microsoft Windows Hardware Compatibility Publisher
coverage    42528 instructions, 41934 from mnemonics (98.6%), 594 raw
```

---

## 3. 只用分析，不做重建

```powershell
python tools\analyze.py                 # ADVT 分区 + 全量清单 out/listing/ACE-ADVT.txt
python tools\obfscan.py                 # 计算型跳转定位
python tools\trace.py 61dc6 4000        # 控制流折叠（ADVT）
python tools\trace_any.py <bin> <rva>   # 控制流折叠（任意组件）
python tools\envelope.py                # 封套编解码自测
python tools\cmdtable_full.py           # 命令表 50 条记录
python tools\component_profile.py <bin> # 单个组件画像
```

---

## 4. 常见问题

| 现象 | 原因 | 处理 |
|---|---|---|
| `ml64 找不到` | 未设 `ML64` | 设环境变量或改脚本默认路径 |
| `header rebuild differs at [...]` | 目标文件不是预期版本 | 核对文件哈希；或该版本头部含未知字段 |
| `flat size ... != expected` | 汇编器版本导致编码差异 | 正常，收敛循环会修正 |
| `length defects` 反复出现 | 某个分支目标落在数据中间 | 已自动降级为 `db`；多跑一两轮 |
| 大文件（>20 MB）多轮很慢 | 每轮要重新汇编上百 MB 源码 | 用 `--rounds 20` 一次跑完；或先 `--max-size` 分批 |
| 某个组件 `insns=0` | 其 `.text` 的 `raw_size=0`（内容在打包段） | 属正常，按数据转录仍可逐字节一致 |
| 校验和与原件不同 | 厂商存的是陈旧校验和 | 管线保留原值，不用管 |

---

## 5. 产物说明

`out_rebuild/<name>/` 下：

| 文件 | 内容 |
|---|---|
| `model.json` | 字节分区（每单元的 RVA/长度/类型/原始字节） |
| `image.asm` | 单段 MASM 源码（指令 + `db` 数据块） |
| `overrides.json` | 回落表（哪些单元按原始字节输出） |
| `image.obj` / `image.lst` | 汇编中间产物与清单 |
| `rebuilt.bin` | 重建结果（与本仓库分离保存，不入库） |
| `report.json` | 核验数据：大小、SHA-256、差异字节、覆盖率、轮次 |
