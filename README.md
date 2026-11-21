# AntiCheatExpert — 全组件逆向与字节保真重建

对 `AntiCheatExpert` 套件（18 个 PE 组件）做完整逆向，并用同一条管线把**每个组件重新构建成逐字节相同的文件**。

> `ACE-ADVT.sys` 是独立项目，见 **mioolio/ACE-ADVT**（该仓库含协议级还原与专用构建管线）。
> 用途限定安全研究与教学。仓库**不包含**任何 `.sys` / `.dll` / `.exe` 二进制，也不含签名材料。详见文末。

---

## 1. 结果

**18 / 18 个组件逐字节一致**，重建后 Authenticode **全部 Valid**（字节相同，签名自然继续有效）。

| 合计 | 数值 |
|---|---|
| 重建字节 | 116.3 MB |
| 指令总数 | 5,858,466 |
| 由助记符汇编通过 | 4,521,227（77.2%） |
| 逐字节一致 | 18 / 18 |

逐组件表格（含每个组件的收敛轮次与签名实测）见 **[docs/15-全组件字节保真.md](docs/15-全组件字节保真.md)**，机器可读结果在 `out/re_rebuild_summary.json`。

---

## 2. 套件结构

| 层 | 组件 | 关键能力（导入/字符串证据） |
|---|---|---|
| 引导 | `ACE-BOOT.sys` | 裸磁盘 `\Device\Harddisk%d\Partition0`、注册表回调 `CmRegisterCallbackEx`、`win32kbase.sys` |
| 基座 | `ACE-BASE.sys` | 安全设备（SDDL）、物理内存、APC 注入、栈校验、`expand 32-byte k`（ChaCha） |
| 网络 | `ACE-CORE302706.sys` | `fwpkclnt.sys`（WFP 过滤）、`NDIS`、`NETIO`、`HalGetBusSetDataByOffset`（PCI 配置空间） |
| 通道 | `ACE-ADVT.sys` | 独立仓库 **mioolio/ACE-ADVT**（设备、封套、token 命令空间、命令表） |
| 扫描 | `ACE-SSC-DRV64.sys` | 同步 FSD、句柄表枚举、`\Device\PhysicalMemory` |
| 用户态 | `ACE-Service64.exe` / `ACE-Tray.exe` / `SGuard64.exe` / `SGuardSvc64.exe` / `SGuardUpdate64.exe` / `Uninstaller.exe` / `Uninstall64.exe` | 服务、自启、GUID 命名管道与互斥体、自更新 |
| 插件 | `ACE-CSI64.dll` / `ACE-DFS64.dll` / `ACE-ATS64.dll` / `ACE-SSC64.dll` / `ACE-Safe.dll` / `ACE-Trace.dll` | 命令客户端、文件扫描、节映射、GPU 厂商枚举（Khronos 键）、下载通道 |
| UEFI | `ACE-DRV64.dll` | 子系统 3（EFI 应用），25 MB 载荷在打包段 `.A;6` |

跨组件发现：WFP 网络过滤、PCI 配置空间读写、GPU 厂商枚举、注册表回调、`http://%s/d?dn=%s` 下载通道、未随包下发的 `ACE-GAME.sys`。详见 `docs/11`、`docs/12`、`docs/14`。

**每个组件的功能、拦截点、绕过方法**见 **[docs/18-组件功能与对抗矩阵.md](docs/18-组件功能与对抗矩阵.md)**（18 个组件逐个，含证据来源与验证方式）。

---

## 3. 仓库结构

```
├─ README.md / BUILD.md
├─ docs/                    7 份报告
│  ├─ 11      用户态组件与协议对接
│  ├─ 12      ACE-BASE 能力字典
│  ├─ 14      全组件能力画像（18 个组件）
│  ├─ 15      全组件字节保真核验表
│  ├─ 16      日志加密分析
│  ├─ 17      剩余三项完成路径
│  └─ 18      组件功能、拦截点与绕过方法（18 个组件逐个）
├─ tools/                   13 个 Python 工具
│  ├─ pe_rebuild.py          通用字节保真引擎（任意组件）
│  ├─ re_all.py              批量驱动（--ext .sys/.dll/.exe、--only、--max-size）
│  ├─ re_report.py           重新生成 docs/15
│  ├─ diff_report.py         差异定位
│  ├─ pe_model.py / coff.py  PE 与 COFF 基础
│  ├─ ioctl_table.py         IOCTL 派发表扫描
│  ├─ log_crypt.py / log_bruteforce.py / log_bruteforce2.py / log_period.py
│  │                         日志加密分析与密钥候选穷举
│  ├─ logapi.py / logfunc.py 日志子系统定位
│  └─ log_kd.txt             WinDbg 断点序列
└─ out/
   ├─ <组件>/report.json     18 份逐组件验收数据
   └─ re_rebuild_summary.json  机器可读汇总
```

---

## 4. 快速开始

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
python tools\re_all.py --ext .sys      # 只跑驱动
python tools\re_report.py              # 重新生成 docs/15
```

编译细节、参数与排错见 **[BUILD.md](BUILD.md)**。

---

## 5. 方法论要点

1. **严格分区**：把每个可执行段切成字节单元，和 = 段大小，无空洞无重叠。
2. **平铺 RVA 空间**：`org` 起点到 `SizeOfImage`，段间虚拟空洞用 `db` 填补，RIP 相对引用与分支目标自然正确。
3. **单段汇编 + 迷你链接器**：只留少量 REL32 重定位，由 `tools/coff.py` 回填。
4. **三阶段收敛**：长度缺陷（listing 偏移差，位移无关）→ 编码缺陷（按实际输出偏移比对）→ 对齐缺陷（确保整镜像未位移）。
5. **逐字节优先**：厂商陈旧 PE 校验和、非常规编码一律保留原值，不"修正"。

---

## 6. 声明

- 仓库只含文本（源码、脚本、文档、清单）与结构化 JSON，**不含任何可执行二进制**。
- 分析对象为用户自备的软件副本，用于理解商业反作弊驱动的接口设计、混淆与完整性保护机制。
- 重建产物与我们自己的安全研究工具都不会在此分发；请自行遵守所涉软件的服务条款与当地法律。
- 商标与产品名归其所有者。
