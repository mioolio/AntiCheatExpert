# AntiCheatExpert — 全组件逆向与字节保真重建

对 `AntiCheatExpert` 套件（18 个 PE 组件）做完整逆向，并用同一条管线把**每个组件重新构建成逐字节相同的文件**；其中 `ACE-ADVT.sys` 做了协议级的完整还原。

> 用途限定安全研究与教学。仓库**不包含**任何 `.sys` / `.dll` / `.exe` 二进制，也不含签名材料。详见文末。

---

## 1. 结果

**19 / 19 个组件逐字节一致**（18 个套件组件 + `ACE-ADVT.sys`），重建后 Authenticode **全部 Valid**（字节相同，签名自然继续有效）。

| 合计 | 数值 |
|---|---|
| 重建字节 | 117.5 MB |
| 指令总数 | 5,902,049 |
| 由助记符汇编通过 | 4,555,509（77.2%） |
| 逐字节一致 | 19 / 19 |

逐组件表格（含每个组件的收敛轮次与签名实测）见 **[docs/15-全组件字节保真.md](docs/15-全组件字节保真.md)**，机器可读结果在 `out/re_rebuild_summary.json`。

---

## 2. 套件结构

| 层 | 组件 | 关键能力（导入/字符串证据） |
|---|---|---|
| 引导 | `ACE-BOOT.sys` | 裸磁盘 `\Device\Harddisk%d\Partition0`、注册表回调 `CmRegisterCallbackEx`、`win32kbase.sys` |
| 基座 | `ACE-BASE.sys` | 安全设备（SDDL）、物理内存、APC 注入、栈校验、`expand 32-byte k`（ChaCha） |
| 网络 | `ACE-CORE302706.sys` | `fwpkclnt.sys`（WFP 过滤）、`NDIS`、`NETIO`、`HalGetBusSetDataByOffset`（PCI 配置空间） |
| 通道 | `ACE-ADVT.sys` | `\Device\ACE-ADVT`，588 字节封套 + token 命令空间（本仓库重点） |
| 扫描 | `ACE-SSC-DRV64.sys` | 同步 FSD、句柄表枚举、`\Device\PhysicalMemory` |
| 用户态 | `ACE-Service64.exe` / `ACE-Tray.exe` / `SGuard64.exe` / `SGuardSvc64.exe` / `SGuardUpdate64.exe` / `Uninstaller.exe` / `Uninstall64.exe` | 服务、自启、GUID 命名管道与互斥体、自更新 |
| 插件 | `ACE-CSI64.dll` / `ACE-DFS64.dll` / `ACE-ATS64.dll` / `ACE-SSC64.dll` / `ACE-Safe.dll` / `ACE-Trace.dll` | 命令客户端、文件扫描、节映射、GPU 厂商枚举（Khronos 键）、下载通道 |
| UEFI | `ACE-DRV64.dll` | 子系统 3（EFI 应用），25 MB 载荷在打包段 `.A;6` |

跨组件发现：WFP 网络过滤、PCI 配置空间读写、GPU 厂商枚举、注册表回调、`http://%s/d?dn=%s` 下载通道、未随包下发的 `ACE-GAME.sys`。详见 `docs/11`、`docs/12`、`docs/14`。

---

## 3. `ACE-ADVT.sys` 协议（完整还原）

| 项 | 值 |
|---|---|
| 设备 | `\Device\ACE-ADVT` ↔ `\DosDevices\Global\ACE-ADVT` |
| 控制码 | `0x00222824` / `0x0022282C` / `0x00222834`（BUFFERED）+ 2 个 METHOD_NEITHER |
| 封套 | 588 字节：`+0x00` status / `+0x24` len ≤ 0x200 / `+0x28` payload / `+0x228` key[8] / `+0x248` key_select |
| 载荷编码 | XOR + 二次同余状态机（模 `0xDC6A2367`），可逆，实现见 `tools/envelope.py` |
| 命令空间 | `token = 0x63AE442D + k`（main）/ `0x623782AB + k`（aux），掩码 `0x907` |
| 命令表 | `.data 0x35020`：50 条 `{magic 0x013500CA, flag, token}` 记录，两个家族 |
| 语义 | main = 状态查询（7 条可执行，谓词逐条还原）；aux = 缓冲区字节混合（22 条形态分类） |
| 回包 | 48 字节 `{0x01343BEB, 0x30, status}` |
| 保护段 | `.tvm0` 917,504 字节，975 处计算型跳转，111 个登记函数 |

推导过程：`docs/06`–`docs/10`。

---

## 4. 仓库结构

```
├─ README.md / BUILD.md
├─ docs/                    15 份报告
│  ├─ 01-05   PE 结构、反汇编方法、TVM 保护段、重建管线、验收
│  ├─ 06-07   驱动功能与接口、绕过面分析
│  ├─ 08-10   封套协议、命令表与分派、aux 语义
│  ├─ 11-12   用户态组件与协议对接、ACE-BASE 能力字典
│  ├─ 13-14   套件总报告、全组件能力画像
│  └─ 15      全组件字节保真核验表
├─ tools/                   52 个 Python 工具
│  ├─ pe_rebuild.py          通用字节保真引擎（任意组件）
│  ├─ re_all.py / re_report.py / diff_report.py   批量与验收
│  ├─ analyze.py / emit_masm.py / coff.py / mkheaders.py    ADVT 专用管线
│  ├─ trace.py / trace_any.py / obfscan.py     控制流折叠与混淆分析
│  ├─ envelope.py / cmdtable_full.py / token_chain.py      协议提取
│  └─ component_profile.py / ustrings.py / flt_matrix.py   组件画像
├─ src/
│  ├─ masm/ace_advt.asm      ADVT 的 MASM 源码（108,011 行）
│  └─ asm/                   NASM 备用源码（parts/ 54 个部件）
└─ out/
   ├─ listing/               ADVT 全量反汇编清单（47,270 行）
   ├─ profiles/              18 个组件的导入/字符串画像
   ├─ re_rebuild_summary.json  19 个组件的核验结果
   └─ *.json                 协议与命令表结构化产物
```

---

## 5. 快速开始

```powershell
pip install capstone pefile
$env:ML64 = '<path>\ml64.exe'          # VS 2022/2026 或 EWDK 自带
```

单个组件重建：

```powershell
python tools\pe_rebuild.py D:\samples\ACE-BASE.sys
# 产物：out_rebuild\ACE-BASE\{model.json, image.asm, rebuilt.bin, report.json}
```

全部组件：

```powershell
python tools\re_all.py                 # 按体积从小到大
python tools\re_report.py              # 重新生成 docs/15
```

ADVT 专用管线（含头部字段级重建与签名转录）：

```powershell
$env:ADVT_TARGET = 'D:\samples\ACE-ADVT.sys'
.\build.ps1 -Fresh
python tools\verify.py
```

编译细节、参数与排错见 **[BUILD.md](BUILD.md)**。

---

## 6. 方法论要点

1. **严格分区**：把每个可执行段切成字节单元，和 = 段大小，无空洞无重叠。
2. **平铺 RVA 空间**：`org` 起点到 `SizeOfImage`，段间虚拟空洞用 `db` 填补，RIP 相对引用与分支目标自然正确。
3. **单段汇编 + 迷你链接器**：只留少量 REL32 重定位，由 `tools/coff.py` 回填。
4. **三阶段收敛**：长度缺陷（listing 偏移差，位移无关）→ 编码缺陷（按实际输出偏移比对）→ 对齐缺陷（确保整镜像未位移）。
5. **逐字节优先**：厂商陈旧 PE 校验和、非常规编码一律保留原值，不"修正"。

---

## 7. 声明

- 仓库只含文本（源码、脚本、文档、清单）与结构化 JSON，**不含任何可执行二进制**。
- 分析对象为用户自备的软件副本，用于理解商业反作弊驱动的接口设计、混淆与完整性保护机制。
- 重建产物与我们自己的安全研究工具都不会在此分发；请自行遵守所涉软件的服务条款与当地法律。
- 商标与产品名归其所有者。
