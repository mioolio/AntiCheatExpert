# 12 · ACE-BASE.sys 分析：设备面、能力字典、FltMgr 使用

`ACE-BASE.sys`（4,125,432 字节，x64 Native，linker 14.0，PDB `ACE-BASE.pdb`）是整个套件的**基座驱动**。它自己注册设备、暴露 IOCTL，并把几乎所有敏感内核 API 都改成**运行时解析**。

---

## 1. 身份：三个设备名

| 名字 | RVA | 说明 |
|---|---|---|
| `\Device\ACE-BASE` | `0x0AB540` | 设备对象名 |
| `\DosDevices\Global\ACE-BASE` | `0x0AB500` | 全局符号链接（会话隔离穿透） |
| `\\.\ACE-BASE` | `0x0ADA50` | 用户态打开路径 |
| `\Device\{TF9AC12E-S60X-E25G-N67G-IC8A82086DAN}` | `0x0AD9F0` | **混淆 GUID 名**（字符集超出十六进制范围，运行时还原） |
| `\DosDevices\Global\{同上}` | `0x0AD970` | 混淆 GUID 的符号链接 |

`DriverEntry`（`0x393000`）只做 cookie 初始化，真正入口是 `0x3E370`，形状与 `ACE-ADVT.sys` 的 `sub_1da0` 完全一致：

```
MajorFunction[0x00] (IRP_MJ_CREATE)        = sub @ 0x3E2D6
MajorFunction[0x02] (IRP_MJ_CLOSE)         = sub @ 0x3E2F0
MajorFunction[0x0E] (IRP_MJ_DEVICE_CONTROL) = sub @ 0x3E3E0 附近
MajorFunction[0x10] (IRP_MJ_SHUTDOWN)      = sub @ 0x3E330
DriverObject->DriverUnload (0x68)          = sub @ 0x3DF60
RtlInitUnicodeString(&dev,   L"\\Device\\ACE-BASE")
RtlInitUnicodeString(&link,  L"\\DosDevices\\Global\\ACE-BASE")
```

设备是**安全设备**：字符串表里有 `IoCreateDeviceSecure` 与 `SeConvertStringSecurityDescriptorToSecurityDescriptor`，说明它用 SDDL 建立 DACL；配 `IoValidateDeviceIoControlAccess` 逐 IOCTL 校验访问权限。这与 `ACE-ADVT.sys` 只靠"单实例门禁"相比是**更强的访问控制**。

---

## 2. 能力字典：动态解析的 80+ 个内核 API（明文表）

`.rdata 0x0AE380..0x0AF4A0` 是一张**明文 UTF-16 API 名表**，配 `MmGetSystemRoutineAddress` 使用。这张表等于"它能做什么"的权威清单：

### 2.1 内存与物理内存

| API | 用途 |
|---|---|
| `MmCopyMemory` | 任意内核地址拷贝（含物理地址） |
| `MmGetPhysicalAddress` / `MmGetVirtualForPhysical` | 虚实转换 |
| `MmGetPhysicalMemoryRanges` | 物理内存布局枚举 |
| `MmMapIoSpace` / `MmMapIoSpaceEx` / `MmUnmapIoSpace` | 物理页映射进内核 |
| `MmAllocateMappingAddress` / `MmFreeMappingAddress` | 映射地址预留 |
| `ZwOpenSection` / `ZwMapViewOfSection` / `ZwUnmapViewOfSection` | 物理内存 / 共享节映射 |

### 2.2 进程与线程

| API | 用途 |
|---|---|
| `PsSetCreateProcessNotifyRoutineEx` | 进程创建/退出通知（带 Ex 版本，可阻止） |
| `PsAcquireProcessExitSynchronization` / `PsRelease...` | 与进程退出同步（防竞态篡改） |
| `PsGetProcessExitProcessCalled` / `PsGetProcessExitStatus` | 退出状态探测 |
| `PsGetProcessPeb` / `PsGetProcessWow64Process` / `PsGetProcessImageFileName` | PEB / 路径识别 |
| `PsReferenceProcessFilePointer` / `SeLocateProcessImageName` | 镜像路径 |
| `KeStackAttachProcess` / `KeUnstackDetachProcess` | 跨进程内存访问 |
| `ZwOpenThread` / `PsLookupThreadByThreadId` / `PsIsThreadTerminating` / `PsIsSystemThread` | 线程操作 |
| `ZwTerminateProcess` | **终止进程** |

### 2.3 反调试 / 栈校验

| API | 用途 |
|---|---|
| `KdRefreshDebuggerNotPresent` | 刷新"无调试器"状态（对抗调试附加） |
| `RtlWalkFrameChain` | 遍历调用栈（检测返回地址伪造） |
| `IoGetStackLimits` / `PsGetCurrentThreadStackBase` / `PsGetCurrentThreadStackLimit` / `IoGetInitialStack` | 栈边界（检测栈切换/伪造调用者） |
| `RtlPcToFileHeader` | 地址→模块归属（识别未知模块调用） |

### 2.4 执行原语（最高风险项）

| API | 用途 |
|---|---|
| `KeInitializeApc` / `KeInsertQueueApc` / `KeRemoveQueueApc` | **APC 注入** |
| `KeGenericCallDpc` / `KeSignalCallDpcDone` / `KeSignalCallDpcSynchronize` / `KeSetTargetProcessorDpc` | 全核 DPC 广播（改页表 / 刷 TLB 形状） |
| `KeInitializeTimer` / `KeSetTimer` / `KeCancelTimer` / `KeFlushQueuedDpcs` | 定时执行 |
| `KeAreApcsDisabled` | 环境自检 |

### 2.5 对象与驱动枚举

| API | 用途 |
|---|---|
| `ExEnumHandleTable` | 枚举全系统句柄表 |
| `ObGetObjectType` / `ObQueryNameString` / `ObReferenceObjectByName` | 对象识别与命名 |
| `IoDriverObjectType` / `IoDeviceObjectType` / `IoFileObjectType` / `MmSectionObjectType` / `PsProcessType` | 类型对象（遍历驱动/设备/节） |
| `IoGetDeviceObjectPointer` / `IoQueryFullDriverPath` | 定位设备与驱动文件 |
| `ZwQuerySystemInformation` / `ZwQueryInformationProcess` / `ZwQueryInformationThread` / `ZwQueryVirtualMemory` | 系统/进程/线程/内存信息 |

---

## 3. FltMgr 的真实用法（修正一个初判）

**导入表里没有 `FltRegisterFilter` / `FltStartFiltering`**，也没有对应字符串。但导入了 16 个 FltMgr 函数，全部在 `0x75276..0x752D0` 编成 thunk 块，共 **36 个调用点**：

| 类别 | 函数 |
|---|---|
| 文件名信息 | `FltGetFileNameInformation`、`FltGetFileNameInformationUnsafe`、`FltParseFileNameInformation`、`FltReleaseFileNameInformation` |
| 文件 I/O | `FltCreateFileEx`、`FltReadFile`、`FltWriteFile`、`FltSetInformationFile`、`FltClose` |
| 卷/实例 | `FltGetVolumeFromInstance`、`FltGetVolumeProperties` |
| 进程识别 | `FltGetRequestorProcessId` |
| 池 | `FltAllocatePoolAlignedWithTag`、`FltFreePoolAlignedWithTag` |
| 生命周期 | `FltUnregisterFilter`、`FltObjectDereference` |

调用点的形状**是 minifilter 回调**：

```asm
0x41550  mov [rsp+0x10], rdx        ; FltObjects
0x41555  mov [rsp+8],   rcx         ; CallbackData
0x4155e  mov byte [rsp+0x20], 0
0x41563  cmp qword [rsp+0x50], 0
0x4156d  mov rcx, [rsp+0x50]
0x41572  call FltGetRequestorProcessId
```

`FltGetRequestorProcessId(CallbackData)` 只接受真实的 `FLT_CALLBACK_DATA`，因此这些函数**确实被 FltMgr 当作回调调用**。

**因此**：注册动作不在导入表、名字也不在明文字符串表里。可能性只有两种：

1. `FltRegisterFilter` 由**另一个组件**调用，然后把 `FLT_FILTER` 句柄/实例通过驱动间回调传给 ACE-BASE；
2. 名字由 `ACE-BASE` 自己的加密字符串表构造（同 `ACE-ADVT` 的做法），在 `.tvm0` 里完成注册。

这两种都需要跟 `.tvm0`（3 MB）内部才能定论——列为遗留，不作结论。

---

## 4. 行为侧面：字符串表里的"证据碎片"

| 字符串 | RVA | 含义 |
|---|---|---|
| `dxgi.dll` | `0x0ADAA0` | 监视/识别 DXGI 相关模块（覆盖层、截图） |
| `dwm.exe` | `0x0ADAD8` | 桌面窗口管理器（覆盖层检测） |
| `gTimerHashTable` | `0x0ADAF0` | 定时器哈希表（调试器/断点检测） |
| `expand 32-byte k` | `0x0AF490` | **ChaCha20/Salsa20 常量** → 使用流密码 |
| `IRONMACE` | `0x0AD5C0` 附近 | 项目/产品代号 |
| `NdisWdfRegisterM` / `NdisMRegisterMin` / `StorPortInitialize` / `AtaPortInitialize` | `0x0EE830` | 网络/存储小端口相关（枚举或过滤） |
| `\device\physicalmemory` | `0x0AE670`、`0x0AB4C0` | 物理内存对象访问 |
| `\Registry\Machine\System\CurrentControlSet\Control\Class` | `0x0AE4D0` | 设备类注册表（枚举隐藏设备） |
| `ACE-BASE.pdb` | `0x0EEBC0` | 未剥离的 PDB 名 |

乱码串（`IsDfkkefdlUbsru`、`RhOiolyrxHtny}x`、`[gxt[zlkmpf^ssp`）是**加密字符串**在字节层面泄漏的样本，说明 `.rdata` 里还有一张密文表。

---

## 5. 与其他组件的对照

| 组件 | 设备/关键字符串 | 说明 |
|---|---|---|
| `ACE-BOOT.sys` | `\Device\ACE-BOOT`、`\DosDevices\Global\ACE-BOOT`、`\Device\Harddisk%d\Partition0`、`\Device\HarddiskVolume`、`\device\physicalmemory` | **裸磁盘访问**：MBR/引导区校验 |
| `ACE-CORE302706.sys` | `IoCreateDeviceSecure`、`IoValidateDeviceIoControlAccess` | 同样是安全设备，名字在密文表里 |
| `ACE-ADVT.sys` | `\Device\ACE-ADVT`、`ACE-ADVT` | 已完整逆向（docs/06–10） |

三个内核驱动**结构同源**：安全设备 + 运行时 API 解析 + `.tvm0` 保护 + 无明文能力名。

---

## 6. 能力结论（按证据强度分级）

| 结论 | 证据 | 强度 |
|---|---|---|
| 通过安全设备暴露 IOCTL，且逐 IOCTL 校验访问 | `IoCreateDeviceSecure` + `IoValidateDeviceIoControlAccess` + SDDL 转换 API | 强 |
| 能读写任意物理内存 | `MmMapIoSpace`/`MmCopyMemory`/`ZwMapViewOfSection(\device\physicalmemory)` | 强 |
| 能枚举并操作任意进程/线程（含终止） | `PsSetCreateProcessNotifyRoutineEx`、`KeStackAttachProcess`、`ZwTerminateProcess` | 强 |
| 具备 APC 注入能力 | `KeInitializeApc`/`KeInsertQueueApc` | 强 |
| 做反调试与栈完整性校验 | `KdRefreshDebuggerNotPresent`、`RtlWalkFrameChain`、`IoGetStackLimits` | 强 |
| 用 ChaCha/Salsa 流密码保护数据 | `expand 32-byte k` | 中强 |
| 注册了文件系统微过滤器 | 16 个 Flt* 导入 + 回调形状 + 36 个调用点 | 中（注册方式未见） |
| 监视覆盖层/截图类进程 | `dxgi.dll`、`dwm.exe` 字符串 | 中 |

---

## 7. 工具

```powershell
python tools\iat_refs.py   ACE-BASE.sys flt        # 16 个 Flt* 槽位与引用点
python tools\flt_callers.py ACE-BASE.sys           # 36 个调用点的参数准备
python tools\flt_matrix.py                         # 四个驱动的回调/过滤 API 矩阵
python tools\ustrings.py   ACE-BASE.sys 6          # 明文 UTF-16 表（能力字典）
python tools\um_dis.py     ACE-BASE.sys 0x3E370    # 主初始化
python tools\trace_any.py  ACE-BASE.sys 0x410535   # 折叠 .tvm0（已验证可用）
```

## 8. 遗留

| 项 | 说明 |
|---|---|
| `FltRegisterFilter` 的调用点 | 需在 `.tvm0`（3 MB）内追；或从 `FltUnregisterFilter` 的引用反推 filter 句柄来源 |
| `IRP_MJ_DEVICE_CONTROL` 的控制码表 | ACE-BASE 有自己的 IOCTL 空间（与 ADVT 不同），需按其派发函数提取 |
| 密文串表 | `.rdata` 有乱码样本，需找密钥派生点 |
