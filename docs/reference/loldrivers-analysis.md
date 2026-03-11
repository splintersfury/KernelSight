# LOLDrivers Deep Analysis

> Automated deep analysis of every driver in the [LOLDrivers.io](https://www.loldrivers.io/) catalog, powered by [DriverAtlas](https://github.com/splintersfury/DriverAtlas).

**Last updated:** 2026-03-11  
**Drivers analyzed:** 1775 (Tier 1) / 1775 (Tier 2 deep)  


## TL;DR

1,775 drivers from [LOLDrivers](https://loldrivers.io) analyzed with automated PE parsing (Tier 1) and Ghidra headless decompilation (Tier 2). Key findings:

- **84.6%** score Critical risk (10+/15)
- **76%** have all 5 mitigations disabled (no ASLR, no CFG, no stack cookies)
- **806 drivers** use `METHOD_NEITHER` I/O (raw user pointers, no kernel buffering)
- **1,468** classified as vulnerable, **294** as malicious

## Key Statistics

| Metric | Count |
|--------|-------|
| Vulnerable drivers | 1468 |
| Malicious drivers | 294 |
| Missing CFG | 1775 |
| Missing FORCE_INTEGRITY | 1548 |
| NEITHER I/O (raw user ptrs) | 806 |
| High risk (score >= 8.0) | 1559 |


## Notable Findings

### Perfect 15.0/15.0 scores: 805 rows across 161 unique drivers

The scoring algorithm caps at 15.0 when a driver combines dangerous imports, high gadget counts, weak mitigations, and accessible IOCTLs. Drivers hitting this ceiling include:

- **iqvw64e.sys / NalDrv.sys** (Intel NAL) -- the single most abused BYOVD driver in ransomware campaigns, with `METHOD_NEITHER` IOCTLs and full physical memory R/W
- **RTCore64.sys** (Micro-Star) -- used by BlackByte, AvosLocker, and others to disable EDR
- **driver7-x86-withoutdbg.sys** -- 192 IOCTLs, 46 using `METHOD_NEITHER`, the highest NEITHER count in the dataset
- **HpPortIox64.sys** (HP) -- 13 IOCTLs, 500 gadgets, signed by DigiCert
- **ComputerZ.Sys** (Qihoo 360) -- 44 separate samples, all scoring 15.0

### NEITHER I/O + all mitigations disabled: 547 rows

The most dangerous combination: `METHOD_NEITHER` passes raw user-mode pointers directly to the driver with zero kernel buffering, and all five mitigations (ASLR, NX, CFG, ForceIntegrity, stack cookies) are off. These are effectively open doors to kernel memory.

### Microsoft WHQL-signed drivers scoring 10+: 68 rows (36 unique drivers)

WHQL signing verifies hardware compatibility, not security. Notable WHQL-signed entries:

- **EneIo64.sys** -- 15.0, ENE Technology I/O driver, full port/memory access
- **hw.sys** -- 15.0, Marvin Test Solutions, physical memory mapping
- **procexp.Sys** -- Sysinternals Process Explorer, scores high due to broad kernel access
- **POORTRY1.sys** -- Microsoft-signed malicious driver used in real attacks (stolen/leaked signing cert)
- **Mhyprot2.sys** -- miHoYo (Genshin Impact) anti-cheat, widely abused as BYOVD weapon

### Security product drivers that appear in LOLDrivers

Ironic but instructive -- security products need deep kernel access, making them high-value BYOVD targets:

- **aswArPot.sys / avgArPot.sys** (Avast/AVG) -- 15.0, anti-rootkit driver abused by AvosLocker ransomware
- **ngiodriver.sys** (Avast/Norton) -- 14.5-15.0, 8 separate samples in the dataset
- **TmComm.sys** (Trend Micro) -- communication driver, lower score but still catalogued

## Driver Analysis Table

> Showing top 30 drivers by score (one row per unique driver name). Full dataset: 1,775 rows.

| Driver | Category | Score | Arch | Mitigations OFF | IOCTLs | NEITHER | Gadgets | Dangerous Imports | Signer |
|--------|----------|-------|------|-----------------|--------|---------|---------|-------------------|--------|
| Netfilter.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 6 | 474 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPages... | 上海喔噻互联网科技有限公司 |
| EneIo64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 306 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | Microsoft Windows Hardwar |
| GtcKmdfBs.sys | vulnerable d | **15.0** | x86 | GUARD_CF, GS_COOKIE | 10 | 1 | 413 | MmMapIoSpace, READ_PORT_UCHAR, READ_PORT_ULONG... | Symantec Class 3 Extended |
| HpPortIox64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | DigiCert SHA2 Assured ID  |
| BS_RCIOW1064.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 22 | 0 | 500 | HalGetBusDataByOffset, MmMapIoSpace, ObReferenceObjectByHandle... | Biostar Microtech Int'l C |
| OpenLibSys.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 0 | 183 | HalGetBusDataByOffset, MmMapIoSpace | Noriyuki MIYAZAKI |
| mydrivers.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 11 | 0 | 189 | HalGetBusDataByOffset, MmMapIoSpace, READ_PORT_UCHAR... | Beijing Kingsoft Security |
| HWiNFO64I.SYS | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | REALiX |
| driver7-x86-withoutdbg.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 192 | 46 | 180 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | VeriSign Class 3 Public P |
| directio32_legacy.sys, DirectIo32.sys | vulnerable d | **15.0** | x86 | GUARD_CF, GS_COOKIE | 18 | 0 | 413 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | PassMark Software Pty Ltd |
| iqvw64e.sys, iQVW64.SYS, IQVW32.sys, NalDrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 4 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | AddTrust External CA Root |
| rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapIoSpace... | Realtek Semiconductor Cor |
| sfdrvx32.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 0 | 485 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Code Sig |
| ComputerZ.Sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 34 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 31 | 1 | 467 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| PhlashNT.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapIoSpace... | VeriSign Class 3 Code Sig |
| AsrRapidStartDrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 24 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | VeriSign Class 3 Public P |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 20 | MmAllocateContiguousMemory, MmGetPhysicalAddress, ObReferenceObjectByHandle... | Microsoft Windows Hardwar |
| cpuz_x64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 168 | HalGetBusDataByOffset, MmMapIoSpace | VeriSign Class 3 Code Sig |
| WinFlash64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 17 | 0 | 330 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapIoSpace... | VeriSign Class 3 Code Sig |
| ene.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 306 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | Microsoft Windows Hardwar |
| PanIOx64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 14 | 0 | 197 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| nvaudio.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Code Sig |
| DirectIo.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 12 | 0 | 43 | ExAllocatePool, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Code Sig |
| BS_I2cIo.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 17 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Code Sig |
| AMDPowerProfiler.sys | vulnerable d | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | Advanced Micro Devices In |
| HwRwDrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 0 | 216 | HalGetBusDataByOffset, MmMapIoSpace | Shuttle Inc. |
| ElbyCDIO.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 207 | ExAllocatePool, MmMapLockedPages, MmProbeAndLockPages... | Elaborate Bytes AG |
| hw.sys | vulnerable | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Microsoft Windows Hardwar |
| MsIo32.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 293 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | Symantec Class 3 Extended |
| ... | *1,745 more drivers -- [download full dataset](#download)* | ... | ... | ... | ... | ... | ... | ... | ... |

## Deep Dive: Top Drivers by Attack Surface Score

### Netfilter.sys

**SHA256:** `93d99a5fbfc888c0a40a18946933121ae110229dcf206b4d17116a57e7cf4dc9`  
**Score:** 15.0 | **Category:** vulnerable driver | **Signer:** 上海喔噻互联网科技有限公司  
**Mitigations ON:**   
**Mitigations OFF:** DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE  
**Devices:** \Device\CaesarKbd  
**Dangerous imports:** `ExAllocatePool`, `ExFreePoolWithTag`, `MmMapLockedPages`, `MmMapLockedPagesSpecifyCache`, `ObReferenceObjectByHandle`  

| IOCTL | Method | Access | Label |
|-------|--------|--------|-------|
| `0x1001200F` | **NEITHER** | ANY | ref handle |
| `0x10012013` | **NEITHER** | ANY | ref handle |
| `0x10012017` | **NEITHER** | ANY |  |
| `0x1001201B` | **NEITHER** | ANY |  |
| `0x1001201F` | **NEITHER** | ANY |  |
| `0x10012020` | BUFFERED | ANY | map pages |
| `0x10012024` | BUFFERED | ANY |  |
| `0x2B992DDF` | **NEITHER** | ANY |  |

**Risk highlights:**

- `0x1001200F`: NEITHER I/O with no buffer validation; no IRP completion
- `0x10012013`: NEITHER I/O with no buffer validation; no IRP completion
- `0x10012017`: NEITHER I/O with no buffer validation; no IRP completion
- `0x1001201B`: NEITHER I/O with no buffer validation; no IRP completion
- `0x1001201F`: NEITHER I/O with no buffer validation; no IRP completion

**Gadgets:** 474 (reg-control: 173, misc: 209, memory-read: 1, memory-write: 64, stack-pivot: 27)

---

### EneIo64.sys

**SHA256:** `9fc29480407e5179aa8ea41682409b4ea33f1a42026277613d6484e5419de374`  
**Score:** 15.0 | **Category:** vulnerable driver | **Signer:** Microsoft Windows Hardware Compatibility Publisher  
**Mitigations ON:**   
**Mitigations OFF:** DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE  
**Devices:** \Device\EneIo, \Device\PhysicalMemory  
**Dangerous imports:** `ObReferenceObjectByHandle`, `ZwMapViewOfSection`, `ZwUnmapViewOfSection`  

| IOCTL | Method | Access | Label |
|-------|--------|--------|-------|
| `0x80102040` | BUFFERED | ANY | mem copy |
| `0x80102044` | BUFFERED | ANY | mem copy |
| `0x80102050` | BUFFERED | ANY | mem copy |
| `0x80102058` | BUFFERED | ANY |  |

**Risk highlights:**

- `0x80102040`: no IRP completion
- `0x80102044`: no IRP completion
- `0x80102050`: no IRP completion
- `0x80102058`: no IRP completion

**Gadgets:** 306 (reg-control: 35, misc: 177, memory-read: 1, memory-write: 48, stack-pivot: 45)

---

### GtcKmdfBs.sys

**SHA256:** `e6d1ee0455068b74cf537388c874acb335382876aa9d74586efb05d6cc362ae5`  
**Score:** 15.0 | **Category:** vulnerable driver | **Signer:** Symantec Class 3 Extended Validation Code Signing CA - G2  
**Mitigations ON:** DYNAMIC_BASE, NX_COMPAT, NO_SEH, FORCE_INTEGRITY, RETPOLINE  
**Mitigations OFF:** GUARD_CF, GS_COOKIE  
**Devices:** \Device\MTC0303  
**Dangerous imports:** `MmMapIoSpace`, `READ_PORT_UCHAR`, `READ_PORT_ULONG`, `WRITE_PORT_UCHAR`, `WRITE_PORT_ULONG`, `memcpy`  

| IOCTL | Method | Access | Label |
|-------|--------|--------|-------|
| `0x426F6541` | IN_DIRECT | READ |  |
| `0x80000002` | OUT_DIRECT | ANY |  |
| `0x80000003` | **NEITHER** | ANY |  |
| `0x80000004` | BUFFERED | ANY |  |
| `0x88892800` | BUFFERED | ANY |  |
| `0x88892804` | BUFFERED | ANY |  |
| `0x88892808` | BUFFERED | ANY |  |
| `0x88892814` | BUFFERED | ANY |  |
| `0x88892818` | BUFFERED | ANY |  |
| `0x8889281C` | BUFFERED | ANY |  |

**Risk highlights:**

- `0x426F6541`: no IRP completion
- `0x80000002`: no IRP completion
- `0x80000003`: NEITHER I/O with no buffer validation; no IRP completion
- `0x80000004`: no IRP completion
- `0x88892800`: no IRP completion

**Gadgets:** 413 (reg-control: 142, misc: 167, memory-read: 43, memory-write: 25, stack-pivot: 36)

---

### HpPortIox64.sys

**SHA256:** `c5050a2017490fff7aa53c73755982b339ddb0fd7cef2cde32c81bc9834331c5`  
**Score:** 15.0 | **Category:** vulnerable driver | **Signer:** DigiCert SHA2 Assured ID Code Signing CA  
**Mitigations ON:**   
**Mitigations OFF:** DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE  
**Devices:** \Device\HpPortIO  
**Dangerous imports:** `ExAllocatePool`, `ExAllocatePoolWithTag`, `ExFreePoolWithTag`, `HalGetBusDataByOffset`, `MmIsAddressValid`, `ObReferenceObjectByHandle`, `ZwCreateFile`, `ZwReadFile`  

| IOCTL | Method | Access | Label |
|-------|--------|--------|-------|
| `0x9C402000` | BUFFERED | ANY |  |
| `0x9C40208C` | BUFFERED | ANY |  |
| `0x9C402090` | BUFFERED | ANY |  |
| `0x9C4060C4` | BUFFERED | READ |  |
| `0x9C4060CC` | BUFFERED | READ |  |
| `0x9C4060D0` | BUFFERED | READ |  |
| `0x9C4060D4` | BUFFERED | READ |  |
| `0x9C406144` | BUFFERED | READ |  |
| `0x9C40A0C8` | BUFFERED | WRITE |  |
| `0x9C40A0D8` | BUFFERED | WRITE |  |
| `0x9C40A0DC` | BUFFERED | WRITE |  |
| `0x9C40A0E0` | BUFFERED | WRITE |  |
| `0x9C40A148` | BUFFERED | WRITE |  |

**Risk highlights:**

- `0x9C402000`: no IRP completion
- `0x9C40208C`: no IRP completion
- `0x9C402090`: no IRP completion
- `0x9C4060C4`: no IRP completion
- `0x9C4060CC`: no IRP completion

**Gadgets:** 500 (reg-control: 73, misc: 271, memory-write: 103, stack-pivot: 53)

---

### BS_RCIOW1064.sys

**SHA256:** `6191c20426dd9b131122fb97e45be64a4d6ce98cc583406f38473434636ddedc`  
**Score:** 15.0 | **Category:** vulnerable driver | **Signer:** Biostar Microtech Int'l Corp  
**Mitigations ON:**   
**Mitigations OFF:** DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE  
**Devices:** \Device\BS_RCIO  
**Dangerous imports:** `HalGetBusDataByOffset`, `MmMapIoSpace`, `ObReferenceObjectByHandle`, `PsCreateSystemThread`  

| IOCTL | Method | Access | Label |
|-------|--------|--------|-------|
| `0x226000` | BUFFERED | READ |  |
| `0x226004` | BUFFERED | READ |  |
| `0x226008` | BUFFERED | READ |  |
| `0x22600C` | BUFFERED | READ |  |
| `0x226010` | BUFFERED | READ |  |
| `0x226014` | BUFFERED | READ |  |
| `0x226018` | BUFFERED | READ |  |
| `0x22601C` | BUFFERED | READ |  |
| `0x226020` | BUFFERED | READ |  |
| `0x226024` | BUFFERED | READ |  |
| `0x226028` | BUFFERED | READ |  |
| `0x22602C` | BUFFERED | READ |  |
| `0x226030` | BUFFERED | READ |  |
| `0x226034` | BUFFERED | READ |  |
| `0x226038` | BUFFERED | READ |  |
| `0x226040` | BUFFERED | READ |  |
| `0x226044` | BUFFERED | READ |  |
| `0x226048` | BUFFERED | READ |  |
| `0x22604C` | BUFFERED | READ |  |
| `0x226050` | BUFFERED | READ |  |
| `0x226054` | BUFFERED | READ |  |
| `0x226058` | BUFFERED | READ |  |

**Risk highlights:**

- `0x226000`: no IRP completion
- `0x226004`: no IRP completion
- `0x226008`: no IRP completion
- `0x22600C`: no IRP completion
- `0x226010`: no IRP completion

**Gadgets:** 500 (reg-control: 193, misc: 174, memory-read: 93, memory-write: 14, stack-pivot: 26)

---

### OpenLibSys.sys

**SHA256:** `91314768da140999e682d2a290d48b78bb25a35525ea12c1b1f9634d14602b2c`  
**Score:** 15.0 | **Category:** vulnerable driver | **Signer:** Noriyuki MIYAZAKI  
**Mitigations ON:**   
**Mitigations OFF:** DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE  
**Devices:** \Device\OpenLibSys  
**Dangerous imports:** `HalGetBusDataByOffset`, `MmMapIoSpace`  

| IOCTL | Method | Access | Label |
|-------|--------|--------|-------|
| `0x9C402000` | BUFFERED | ANY |  |
| `0x9C402084` | BUFFERED | ANY |  |
| `0x9C402088` | BUFFERED | ANY |  |
| `0x9C40208C` | BUFFERED | ANY |  |
| `0x9C402090` | BUFFERED | ANY |  |
| `0x9C4060C4` | BUFFERED | READ |  |
| `0x9C406104` | BUFFERED | READ |  |
| `0x9C406144` | BUFFERED | READ |  |
| `0x9C40A0C8` | BUFFERED | WRITE |  |
| `0x9C40A108` | BUFFERED | WRITE |  |

**Risk highlights:**

- `0x9C402000`: no IRP completion
- `0x9C402084`: no IRP completion
- `0x9C402088`: no IRP completion
- `0x9C40208C`: no IRP completion
- `0x9C402090`: no IRP completion

**Gadgets:** 183 (reg-control: 81, misc: 87, memory-write: 11, stack-pivot: 4)

---

### OpenLibSys.sys

**SHA256:** `f0605dda1def240dc7e14efa73927d6c6d89988c01ea8647b671667b2b167008`  
**Score:** 15.0 | **Category:** vulnerable driver | **Signer:** Noriyuki MIYAZAKI  
**Mitigations ON:**   
**Mitigations OFF:** DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE  
**Devices:** \Device\OpenLibSys  
**Dangerous imports:** `HalGetBusDataByOffset`, `MmMapIoSpace`  

| IOCTL | Method | Access | Label |
|-------|--------|--------|-------|
| `0x9C402000` | BUFFERED | ANY |  |
| `0x9C402084` | BUFFERED | ANY |  |
| `0x9C402088` | BUFFERED | ANY |  |
| `0x9C40208C` | BUFFERED | ANY |  |
| `0x9C402090` | BUFFERED | ANY |  |
| `0x9C4060CC` | BUFFERED | READ |  |
| `0x9C4060D0` | BUFFERED | READ |  |
| `0x9C4060D4` | BUFFERED | READ |  |
| `0x9C406104` | BUFFERED | READ |  |
| `0x9C406144` | BUFFERED | READ |  |
| `0x9C40A0C8` | BUFFERED | WRITE |  |
| `0x9C40A0D8` | BUFFERED | WRITE |  |
| `0x9C40A0DC` | BUFFERED | WRITE |  |
| `0x9C40A0E0` | BUFFERED | WRITE |  |
| `0x9C40A108` | BUFFERED | WRITE |  |

**Risk highlights:**

- `0x9C402000`: no IRP completion
- `0x9C402084`: no IRP completion
- `0x9C402088`: no IRP completion
- `0x9C40208C`: no IRP completion
- `0x9C402090`: no IRP completion

**Gadgets:** 214 (reg-control: 79, misc: 120, memory-write: 11, stack-pivot: 4)

---

### mydrivers.sys

**SHA256:** `08eb2d2aa25c5f0af4e72a7e0126735536f6c2c05e9c7437282171afe5e322c6`  
**Score:** 15.0 | **Category:** vulnerable driver | **Signer:** Beijing Kingsoft Security software Co.\  
**Mitigations ON:**   
**Mitigations OFF:** DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE  
**Devices:** \Device\MyDrivers0_0_1  
**Dangerous imports:** `HalGetBusDataByOffset`, `MmMapIoSpace`, `READ_PORT_UCHAR`, `READ_PORT_ULONG`, `WRITE_PORT_UCHAR`, `WRITE_PORT_ULONG`  

| IOCTL | Method | Access | Label |
|-------|--------|--------|-------|
| `0x9C402000` | BUFFERED | ANY |  |
| `0x9C402084` | BUFFERED | ANY |  |
| `0x9C402088` | BUFFERED | ANY |  |
| `0x9C40208C` | BUFFERED | ANY |  |
| `0x9C402090` | BUFFERED | ANY |  |
| `0x9C406104` | BUFFERED | READ |  |
| `0x9C406144` | BUFFERED | READ |  |
| `0x9C40A108` | BUFFERED | WRITE |  |
| `0x9C40A148` | BUFFERED | WRITE |  |
| `0xBB40E64E` | OUT_DIRECT | READ_WRITE |  |
| `0xFFFFFFFE` | OUT_DIRECT | READ_WRITE |  |

**Risk highlights:**

- `0x9C402000`: no IRP completion
- `0x9C402084`: no IRP completion
- `0x9C402088`: no IRP completion
- `0x9C40208C`: no IRP completion
- `0x9C402090`: no IRP completion

**Gadgets:** 189 (reg-control: 61, misc: 44, jmp-reg: 16, memory-write: 34, stack-pivot: 34)

---

### HWiNFO64I.SYS

**SHA256:** `33c6c622464f80a8d8017a03ff3aa196840da8bb03bfb5212b51612b5cf953dc`  
**Score:** 15.0 | **Category:** vulnerable driver | **Signer:** REALiX  
**Mitigations ON:**   
**Mitigations OFF:** DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE  
**Devices:** \Device\HWiNFO32  
**Dangerous imports:** `ExAllocatePoolWithTag`, `ExFreePoolWithTag`, `HalGetBusDataByOffset`, `IoGetDeviceObjectPointer`, `MmMapIoSpace`, `READ_PORT_UCHAR`, `READ_PORT_ULONG`, `WRITE_PORT_UCHAR`, `WRITE_PORT_ULONG`  

---

### driver7-x86-withoutdbg.sys

**SHA256:** `927c2a580d51a598177fa54c65e9d2610f5f212f1b6cb2fbf2740b64368f010a`  
**Score:** 15.0 | **Category:** vulnerable driver | **Signer:** VeriSign Class 3 Public Primary Certification Authority - G5  
**Mitigations ON:** NO_SEH  
**Mitigations OFF:** DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE  
**Devices:** \Device\PhysicalMemory, \Device\iteacc  
**Dangerous imports:** `ExAllocatePoolWithTag`, `ExFreePoolWithTag`, `MmGetPhysicalAddress`, `ObReferenceObjectByHandle`, `READ_PORT_UCHAR`, `READ_PORT_ULONG`, `WRITE_PORT_UCHAR`, `WRITE_PORT_ULONG`, `ZwMapViewOfSection`, `ZwUnmapViewOfSection`, `memcpy`  

| IOCTL | Method | Access | Label |
|-------|--------|--------|-------|
| `0x1020304` | BUFFERED | ANY |  |
| `0x9C40C004` | BUFFERED | READ_WRITE |  |
| `0x9C40C008` | BUFFERED | READ_WRITE |  |
| `0x9C40C00C` | BUFFERED | READ_WRITE |  |
| `0x9C40E050` | BUFFERED | READ_WRITE |  |
| `0x9C40E054` | BUFFERED | READ_WRITE |  |
| `0x9C40E055` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E056` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E057` | **NEITHER** | READ_WRITE |  |
| `0x9C40E058` | BUFFERED | READ_WRITE |  |
| `0x9C40E059` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E05A` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E05B` | **NEITHER** | READ_WRITE |  |
| `0x9C40E05C` | BUFFERED | READ_WRITE |  |
| `0x9C40E05D` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E05E` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E05F` | **NEITHER** | READ_WRITE |  |
| `0x9C40E060` | BUFFERED | READ_WRITE |  |
| `0x9C40E061` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E062` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E063` | **NEITHER** | READ_WRITE |  |
| `0x9C40E064` | BUFFERED | READ_WRITE |  |
| `0x9C40E065` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E066` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E067` | **NEITHER** | READ_WRITE |  |
| `0x9C40E068` | BUFFERED | READ_WRITE |  |
| `0x9C40E069` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E06A` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E06B` | **NEITHER** | READ_WRITE |  |
| `0x9C40E06C` | BUFFERED | READ_WRITE |  |
| `0x9C40E06D` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E06E` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E06F` | **NEITHER** | READ_WRITE |  |
| `0x9C40E070` | BUFFERED | READ_WRITE |  |
| `0x9C40E071` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E072` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E073` | **NEITHER** | READ_WRITE |  |
| `0x9C40E074` | BUFFERED | READ_WRITE |  |
| `0x9C40E075` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E076` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E077` | **NEITHER** | READ_WRITE |  |
| `0x9C40E078` | BUFFERED | READ_WRITE |  |
| `0x9C40E079` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E07A` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E07B` | **NEITHER** | READ_WRITE |  |
| `0x9C40E07C` | BUFFERED | READ_WRITE |  |
| `0x9C40E07D` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E07E` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E07F` | **NEITHER** | READ_WRITE |  |
| `0x9C40E080` | BUFFERED | READ_WRITE |  |
| `0x9C40E081` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E082` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E083` | **NEITHER** | READ_WRITE |  |
| `0x9C40E084` | BUFFERED | READ_WRITE |  |
| `0x9C40E085` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E086` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E087` | **NEITHER** | READ_WRITE |  |
| `0x9C40E088` | BUFFERED | READ_WRITE |  |
| `0x9C40E089` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E08A` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E08B` | **NEITHER** | READ_WRITE |  |
| `0x9C40E08C` | BUFFERED | READ_WRITE |  |
| `0x9C40E08D` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E08E` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E08F` | **NEITHER** | READ_WRITE |  |
| `0x9C40E090` | BUFFERED | READ_WRITE |  |
| `0x9C40E091` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E092` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E093` | **NEITHER** | READ_WRITE |  |
| `0x9C40E094` | BUFFERED | READ_WRITE |  |
| `0x9C40E095` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E096` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E097` | **NEITHER** | READ_WRITE |  |
| `0x9C40E098` | BUFFERED | READ_WRITE |  |
| `0x9C40E099` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E09A` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E09B` | **NEITHER** | READ_WRITE |  |
| `0x9C40E09C` | BUFFERED | READ_WRITE |  |
| `0x9C40E09D` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E09E` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E09F` | **NEITHER** | READ_WRITE |  |
| `0x9C40E0A0` | BUFFERED | READ_WRITE |  |
| `0x9C40E0A1` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E0A2` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E0A3` | **NEITHER** | READ_WRITE |  |
| `0x9C40E0A4` | BUFFERED | READ_WRITE |  |
| `0x9C40E0A5` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E0A6` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E0A7` | **NEITHER** | READ_WRITE |  |
| `0x9C40E0A8` | BUFFERED | READ_WRITE |  |
| `0x9C40E0A9` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E0AA` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E0AB` | **NEITHER** | READ_WRITE |  |
| `0x9C40E0AC` | BUFFERED | READ_WRITE |  |
| `0x9C40E0AD` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E0AE` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E0AF` | **NEITHER** | READ_WRITE |  |
| `0x9C40E0B0` | BUFFERED | READ_WRITE |  |
| `0x9C40E0B1` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E0B2` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E0B3` | **NEITHER** | READ_WRITE |  |
| `0x9C40E0B4` | BUFFERED | READ_WRITE |  |
| `0x9C40E0B5` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E0B6` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E0B7` | **NEITHER** | READ_WRITE |  |
| `0x9C40E0B8` | BUFFERED | READ_WRITE |  |
| `0x9C40E0B9` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E0BA` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E0BB` | **NEITHER** | READ_WRITE |  |
| `0x9C40E0BC` | BUFFERED | READ_WRITE |  |
| `0x9C40E0BD` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E0BE` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E0BF` | **NEITHER** | READ_WRITE |  |
| `0x9C40E0C0` | BUFFERED | READ_WRITE |  |
| `0x9C40E0C1` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E0C2` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E0C3` | **NEITHER** | READ_WRITE |  |
| `0x9C40E0C4` | BUFFERED | READ_WRITE |  |
| `0x9C40E0C5` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E0C6` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E0C7` | **NEITHER** | READ_WRITE |  |
| `0x9C40E0C8` | BUFFERED | READ_WRITE |  |
| `0x9C40E0C9` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E0CA` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E0CB` | **NEITHER** | READ_WRITE |  |
| `0x9C40E0CC` | BUFFERED | READ_WRITE |  |
| `0x9C40E404` | BUFFERED | READ_WRITE | port I/O |
| `0x9C40E405` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E406` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E407` | **NEITHER** | READ_WRITE |  |
| `0x9C40E408` | BUFFERED | READ_WRITE | alloc mem |
| `0x9C40E409` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E40A` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E40B` | **NEITHER** | READ_WRITE |  |
| `0x9C40E40C` | BUFFERED | READ_WRITE | mem copy + alloc mem |
| `0x9C40E40D` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E40E` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E40F` | **NEITHER** | READ_WRITE |  |
| `0x9C40E410` | BUFFERED | READ_WRITE | mem copy + alloc mem |
| `0x9C40E411` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E412` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E413` | **NEITHER** | READ_WRITE |  |
| `0x9C40E414` | BUFFERED | READ_WRITE |  |
| `0x9C40E415` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E416` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E417` | **NEITHER** | READ_WRITE |  |
| `0x9C40E418` | BUFFERED | READ_WRITE |  |
| `0x9C40E419` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E41A` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E41B` | **NEITHER** | READ_WRITE |  |
| `0x9C40E41C` | BUFFERED | READ_WRITE |  |
| `0x9C40E41D` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E41E` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E41F` | **NEITHER** | READ_WRITE |  |
| `0x9C40E420` | BUFFERED | READ_WRITE |  |
| `0x9C40E421` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E422` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E423` | **NEITHER** | READ_WRITE |  |
| `0x9C40E424` | BUFFERED | READ_WRITE |  |
| `0x9C40E425` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E426` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E427` | **NEITHER** | READ_WRITE |  |
| `0x9C40E428` | BUFFERED | READ_WRITE |  |
| `0x9C40E429` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E42A` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E42B` | **NEITHER** | READ_WRITE |  |
| `0x9C40E42C` | BUFFERED | READ_WRITE |  |
| `0x9C40E42D` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E42E` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E42F` | **NEITHER** | READ_WRITE |  |
| `0x9C40E430` | BUFFERED | READ_WRITE |  |
| `0x9C40E431` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E432` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E433` | **NEITHER** | READ_WRITE |  |
| `0x9C40E434` | BUFFERED | READ_WRITE |  |
| `0x9C40E435` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E436` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E437` | **NEITHER** | READ_WRITE |  |
| `0x9C40E438` | BUFFERED | READ_WRITE |  |
| `0x9C40E439` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E43A` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E43B` | **NEITHER** | READ_WRITE |  |
| `0x9C40E43C` | BUFFERED | READ_WRITE |  |
| `0x9C40E43D` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E43E` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E43F` | **NEITHER** | READ_WRITE |  |
| `0x9C40E440` | BUFFERED | READ_WRITE |  |
| `0x9C40E441` | IN_DIRECT | READ_WRITE |  |
| `0x9C40E442` | OUT_DIRECT | READ_WRITE |  |
| `0x9C40E443` | **NEITHER** | READ_WRITE |  |
| `0x9C40E444` | BUFFERED | READ_WRITE |  |
| `0xBB40E64E` | OUT_DIRECT | READ_WRITE |  |

**Risk highlights:**

- `0x1020304`: no IRP completion
- `0x9C40C004`: no IRP completion
- `0x9C40C008`: no IRP completion
- `0x9C40C00C`: no IRP completion
- `0x9C40E050`: no IRP completion

**Gadgets:** 180 (reg-control: 47, misc: 45, memory-write: 13, stack-pivot: 75)

---

### directio32_legacy.sys, DirectIo32.sys

**SHA256:** `035b96ff8b85d312be0f9df6271714392a802ec8bab59ae8229812ddc67ced5a`  
**Score:** 15.0 | **Category:** vulnerable driver | **Signer:** PassMark Software Pty Ltd  
**Mitigations ON:** DYNAMIC_BASE, NX_COMPAT, FORCE_INTEGRITY, RETPOLINE  
**Mitigations OFF:** GUARD_CF, GS_COOKIE  
**Devices:** \Device\LoopLpt, \Device\ParallelPort, \Device\PhysicalMemory  
**Dangerous imports:** `ExAllocatePoolWithTag`, `ExFreePoolWithTag`, `IoGetDeviceObjectPointer`, `KeStackAttachProcess`, `KeUnstackDetachProcess`, `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `ObReferenceObjectByHandle`, `READ_PORT_UCHAR`, `READ_PORT_ULONG`, `WRITE_PORT_UCHAR`, `WRITE_PORT_ULONG`, `ZwCreateFile`, `ZwMapViewOfSection`, `ZwOpenKey`, `ZwUnmapViewOfSection`, `ZwWriteFile`, `memcpy`, `memmove`  

| IOCTL | Method | Access | Label |
|-------|--------|--------|-------|
| `0x80116058` | BUFFERED | READ |  |
| `0x8011605C` | BUFFERED | READ | mem copy |
| `0x80116078` | BUFFERED | READ | mem copy |
| `0x8011E044` | BUFFERED | READ_WRITE | mem copy |
| `0x8011E048` | BUFFERED | READ_WRITE |  |
| `0x8011E04C` | BUFFERED | READ_WRITE |  |
| `0x8011E050` | BUFFERED | READ_WRITE | port I/O |
| `0x8011E064` | BUFFERED | READ_WRITE |  |
| `0x8011E068` | BUFFERED | READ_WRITE |  |
| `0x8011E080` | BUFFERED | READ_WRITE |  |
| `0x8011E08C` | BUFFERED | READ_WRITE | mem copy |
| `0x8011E090` | BUFFERED | READ_WRITE | mem copy |
| `0x8011E094` | BUFFERED | READ_WRITE | mem copy |
| `0x8011E098` | BUFFERED | READ_WRITE | mem copy |
| `0x8011E09C` | BUFFERED | READ_WRITE | mem copy |
| `0xBB40E64E` | OUT_DIRECT | READ_WRITE |  |
| `0xC0010015` | IN_DIRECT | ANY |  |
| `0xFFFFFFFE` | OUT_DIRECT | READ_WRITE |  |

**Risk highlights:**

- `0x80116058`: no IRP completion
- `0x8011605C`: no IRP completion
- `0x80116078`: no IRP completion
- `0x8011E044`: no IRP completion
- `0x8011E048`: no IRP completion

**Gadgets:** 413 (reg-control: 89, misc: 168, jmp-reg: 16, memory-write: 56, stack-pivot: 84)

---

### iqvw64e.sys, iQVW64.SYS, IQVW32.sys, NalDrv.sys

**SHA256:** `37c637a74bf20d7630281581a8fae124200920df11ad7cd68c14c26cc12c5ec9`  
**Score:** 15.0 | **Category:** vulnerable driver | **Signer:** AddTrust External CA Root  
**Mitigations ON:**   
**Mitigations OFF:** DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE  
**Devices:** \Device\Nal  
**Dangerous imports:** `ExAllocatePoolWithTag`, `ExFreePoolWithTag`, `IoGetDeviceObjectPointer`, `MmAllocateContiguousMemory`, `MmAllocateNonCachedMemory`, `MmGetPhysicalAddress`, `MmIsAddressValid`, `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `ObOpenObjectByPointer`, `ZwCreateKey`, `ZwOpenKey`, `ZwSetValueKey`  

| IOCTL | Method | Access | Label |
|-------|--------|--------|-------|
| `0x80862007` | **NEITHER** | ANY |  |
| `0x8086200B` | **NEITHER** | ANY |  |
| `0x8086200F` | **NEITHER** | ANY |  |
| `0x80862013` | **NEITHER** | ANY |  |

**Risk highlights:**

- `0x80862007`: NEITHER I/O with no buffer validation; no IRP completion
- `0x8086200B`: NEITHER I/O with no buffer validation; no IRP completion
- `0x8086200F`: NEITHER I/O with no buffer validation; no IRP completion
- `0x80862013`: NEITHER I/O with no buffer validation; no IRP completion

**Gadgets:** 500 (reg-control: 102, misc: 199, memory-read: 7, memory-write: 186, stack-pivot: 6)

---

### iqvw64e.sys, iQVW64.SYS, IQVW32.sys, NalDrv.sys

**SHA256:** `4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b`  
**Score:** 15.0 | **Category:** vulnerable driver | **Signer:** Intel Corporation  
**Mitigations ON:**   
**Mitigations OFF:** DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE  
**Devices:** \Device\Nal  
**Dangerous imports:** `ExAllocatePoolWithTag`, `ExFreePoolWithTag`, `IoGetDeviceObjectPointer`, `MmAllocateContiguousMemory`, `MmGetPhysicalAddress`, `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `ZwOpenKey`  

| IOCTL | Method | Access | Label |
|-------|--------|--------|-------|
| `0x80862007` | **NEITHER** | ANY |  |
| `0x8086200B` | **NEITHER** | ANY |  |
| `0x8086200F` | **NEITHER** | ANY |  |
| `0x80862013` | **NEITHER** | ANY |  |

**Risk highlights:**

- `0x80862007`: NEITHER I/O with no buffer validation; no IRP completion
- `0x8086200B`: NEITHER I/O with no buffer validation; no IRP completion
- `0x8086200F`: NEITHER I/O with no buffer validation; no IRP completion
- `0x80862013`: NEITHER I/O with no buffer validation

**Gadgets:** 500 (reg-control: 110, misc: 195, memory-read: 7, memory-write: 181, stack-pivot: 7)

---

### rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys

**SHA256:** `074ae477c8c7ae76c6f2b0bf77ac17935a8e8ee51b52155d2821d93ab30f3761`  
**Score:** 15.0 | **Category:** vulnerable driver | **Signer:** Realtek Semiconductor Corp.  
**Mitigations ON:**   
**Mitigations OFF:** DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE  
**Devices:** \Device\rtkio  
**Dangerous imports:** `ExAllocatePoolWithTag`, `ExFreePoolWithTag`, `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `ZwOpenKey`  

| IOCTL | Method | Access | Label |
|-------|--------|--------|-------|
| `0x80002000` | BUFFERED | ANY |  |
| `0x80002004` | BUFFERED | ANY | alloc mem |
| `0x80002008` | BUFFERED | ANY |  |
| `0x8000200C` | BUFFERED | ANY |  |
| `0x80002018` | BUFFERED | ANY |  |
| `0x8000201C` | BUFFERED | ANY |  |
| `0x80002024` | BUFFERED | ANY |  |
| `0x80002028` | BUFFERED | ANY |  |
| `0x8000202C` | BUFFERED | ANY |  |
| `0x80002030` | BUFFERED | ANY |  |
| `0x80002034` | BUFFERED | ANY |  |
| `0x813610EC` | BUFFERED | ANY |  |
| `0x813710EC` | BUFFERED | ANY |  |
| `0x816110EC` | BUFFERED | ANY |  |
| `0x816610EC` | BUFFERED | ANY |  |
| `0x816710EC` | BUFFERED | ANY |  |
| `0x816810EC` | BUFFERED | ANY |  |
| `0x816910EC` | BUFFERED | ANY |  |
| `0xFFFFFFFF` | **NEITHER** | READ_WRITE |  |

**Risk highlights:**

- `0x80002000`: no IRP completion
- `0x80002004`: no IRP completion
- `0x80002008`: no IRP completion
- `0x8000200C`: no IRP completion
- `0x80002018`: no IRP completion

**Gadgets:** 500 (reg-control: 125, misc: 238, memory-read: 80, memory-write: 35, stack-pivot: 22)

---

### rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys

**SHA256:** `916c535957a3b8cbf3336b63b2260ea4055163a9e6b214f2a7005d6d36a4a677`  
**Score:** 15.0 | **Category:** vulnerable driver | **Signer:** VeriSign Class 3 Code Signing 2009-2 CA  
**Mitigations ON:**   
**Mitigations OFF:** DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE  
**Devices:** \Device\rtkio  
**Dangerous imports:** `ExAllocatePool`, `ExFreePoolWithTag`, `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `READ_PORT_UCHAR`, `READ_PORT_ULONG`, `WRITE_PORT_UCHAR`, `WRITE_PORT_ULONG`  

| IOCTL | Method | Access | Label |
|-------|--------|--------|-------|
| `0x80002000` | BUFFERED | ANY | map pages |
| `0x80002004` | BUFFERED | ANY |  |
| `0x80002008` | BUFFERED | ANY | port I/O |
| `0x80002018` | BUFFERED | ANY |  |
| `0x8000201C` | BUFFERED | ANY | port I/O |
| `0x80002024` | BUFFERED | ANY | port I/O |
| `0x816810EC` | BUFFERED | ANY |  |
| `0xBB40E64E` | OUT_DIRECT | READ_WRITE |  |
| `0xFFFFFFFE` | OUT_DIRECT | READ_WRITE |  |

**Risk highlights:**

- `0x80002000`: maps physical/locked pages to usermode; no IRP completion
- `0x80002004`: no IRP completion
- `0x80002008`: direct I/O port access; no IRP completion
- `0x80002018`: no IRP completion
- `0x8000201C`: direct I/O port access; no IRP completion

**Gadgets:** 289 (reg-control: 78, misc: 108, jmp-reg: 16, memory-write: 52, stack-pivot: 35)

---

### rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys

**SHA256:** `ab8f2217e59319b88080e052782e559a706fa4fb7b8b708f709ff3617124da89`  
**Score:** 15.0 | **Category:** vulnerable driver | **Signer:** Realtek Semiconductor Corp.  
**Mitigations ON:** HIGH_ENTROPY_VA, DYNAMIC_BASE, NX_COMPAT, FORCE_INTEGRITY, RETPOLINE  
**Mitigations OFF:** GUARD_CF, GS_COOKIE  
**Devices:** \Device\rtkio  
**Dangerous imports:** `ExAllocatePoolWithTag`, `ExFreePoolWithTag`, `MmMapLockedPagesSpecifyCache`, `ObOpenObjectByPointer`, `ZwCreateKey`, `ZwOpenKey`, `ZwSetValueKey`  

| IOCTL | Method | Access | Label |
|-------|--------|--------|-------|
| `0x80002000` | BUFFERED | ANY |  |
| `0x80002004` | BUFFERED | ANY | alloc mem |
| `0x80002008` | BUFFERED | ANY |  |
| `0x80002018` | BUFFERED | ANY |  |
| `0x8000201C` | BUFFERED | ANY |  |
| `0x80002024` | BUFFERED | ANY |  |
| `0x80002028` | BUFFERED | ANY |  |
| `0x8000202C` | BUFFERED | ANY |  |
| `0x80002030` | BUFFERED | ANY |  |
| `0x812510EC` | BUFFERED | ANY |  |
| `0x813610EC` | BUFFERED | ANY |  |
| `0x813710EC` | BUFFERED | ANY |  |
| `0x816110EC` | BUFFERED | ANY |  |
| `0x816610EC` | BUFFERED | ANY |  |
| `0x816710EC` | BUFFERED | ANY |  |
| `0x816810EC` | BUFFERED | ANY |  |
| `0x816910EC` | BUFFERED | ANY |  |
| `0x822510EC` | BUFFERED | ANY |  |
| `0xFFFFFFFF` | **NEITHER** | READ_WRITE |  |

**Risk highlights:**

- `0x80002000`: no IRP completion
- `0x80002004`: no IRP completion
- `0x80002008`: no IRP completion
- `0x80002018`: no IRP completion
- `0x8000201C`: no IRP completion

**Gadgets:** 500 (reg-control: 121, misc: 279, memory-read: 66, memory-write: 7, stack-pivot: 27)

---

### rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys

**SHA256:** `caa85c44eb511377ea7426ff10df00a701c07ffb384eef8287636a4bca0b53ab`  
**Score:** 15.0 | **Category:** vulnerable driver | **Signer:** VeriSign Class 3 Code Signing 2009-2 CA  
**Mitigations ON:**   
**Mitigations OFF:** DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE  
**Devices:** \Device\rtkio  
**Dangerous imports:** `ExAllocatePool`, `ExFreePoolWithTag`, `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`  

| IOCTL | Method | Access | Label |
|-------|--------|--------|-------|
| `0x80002000` | BUFFERED | ANY | map pages |
| `0x80002004` | BUFFERED | ANY |  |
| `0x80002008` | BUFFERED | ANY |  |
| `0x8000200C` | BUFFERED | ANY |  |
| `0x80002018` | BUFFERED | ANY |  |
| `0x8000201C` | BUFFERED | ANY |  |
| `0x80002024` | BUFFERED | ANY |  |
| `0x80002028` | BUFFERED | ANY |  |
| `0x816810EC` | BUFFERED | ANY |  |

**Risk highlights:**

- `0x80002000`: maps physical/locked pages to usermode; no IRP completion
- `0x80002004`: no IRP completion
- `0x80002008`: no IRP completion
- `0x8000200C`: no IRP completion
- `0x80002018`: no IRP completion

**Gadgets:** 500 (reg-control: 118, misc: 224, memory-read: 151, stack-pivot: 7)

---

### rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys

**SHA256:** `7133a461aeb03b4d69d43f3d26cd1a9e3ee01694e97a0645a3d8aa1a44c39129`  
**Score:** 15.0 | **Category:** vulnerable driver | **Signer:** Realtek Semiconductor Corp.  
**Mitigations ON:**   
**Mitigations OFF:** DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE  
**Devices:** \Device\rtkio  
**Dangerous imports:** `ExAllocatePoolWithTag`, `ExFreePoolWithTag`, `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `ZwOpenKey`  

| IOCTL | Method | Access | Label |
|-------|--------|--------|-------|
| `0x80002000` | BUFFERED | ANY |  |
| `0x80002004` | BUFFERED | ANY | alloc mem |
| `0x80002008` | BUFFERED | ANY |  |
| `0x8000200C` | BUFFERED | ANY |  |
| `0x80002018` | BUFFERED | ANY |  |
| `0x8000201C` | BUFFERED | ANY |  |
| `0x80002024` | BUFFERED | ANY |  |
| `0x80002028` | BUFFERED | ANY |  |
| `0x8000202C` | BUFFERED | ANY |  |
| `0x80002030` | BUFFERED | ANY |  |
| `0x80002034` | BUFFERED | ANY |  |
| `0x813610EC` | BUFFERED | ANY |  |
| `0x813710EC` | BUFFERED | ANY |  |
| `0x816110EC` | BUFFERED | ANY |  |
| `0x816610EC` | BUFFERED | ANY |  |
| `0x816710EC` | BUFFERED | ANY |  |
| `0x816810EC` | BUFFERED | ANY |  |
| `0x816910EC` | BUFFERED | ANY |  |
| `0xFFFFFFFF` | **NEITHER** | READ_WRITE |  |

**Risk highlights:**

- `0x80002000`: no IRP completion
- `0x80002004`: no IRP completion
- `0x80002008`: no IRP completion
- `0x8000200C`: no IRP completion
- `0x80002018`: no IRP completion

**Gadgets:** 500 (reg-control: 126, misc: 237, memory-read: 80, memory-write: 35, stack-pivot: 22)

---

### rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys

**SHA256:** `478917514be37b32d5ccf76e4009f6f952f39f5553953544f1b0688befd95e82`  
**Score:** 15.0 | **Category:** vulnerable driver | **Signer:** Realtek Semiconductor Corp.  
**Mitigations ON:**   
**Mitigations OFF:** DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE  
**Devices:** \Device\rtkio  
**Dangerous imports:** `ExAllocatePool`, `ExFreePoolWithTag`, `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `READ_PORT_UCHAR`, `READ_PORT_ULONG`, `WRITE_PORT_UCHAR`, `WRITE_PORT_ULONG`  

| IOCTL | Method | Access | Label |
|-------|--------|--------|-------|
| `0x80002000` | BUFFERED | ANY | map pages |
| `0x80002004` | BUFFERED | ANY |  |
| `0x80002008` | BUFFERED | ANY | port I/O |
| `0x80002018` | BUFFERED | ANY |  |
| `0x8000201C` | BUFFERED | ANY | port I/O |
| `0x80002024` | BUFFERED | ANY | port I/O |
| `0x816810EC` | BUFFERED | ANY |  |
| `0xBB40E64E` | OUT_DIRECT | READ_WRITE |  |
| `0xFFFFFFFE` | OUT_DIRECT | READ_WRITE |  |

**Risk highlights:**

- `0x80002000`: maps physical/locked pages to usermode; no IRP completion
- `0x80002004`: no IRP completion
- `0x80002008`: direct I/O port access; no IRP completion
- `0x80002018`: no IRP completion
- `0x8000201C`: direct I/O port access; no IRP completion

**Gadgets:** 289 (reg-control: 78, misc: 108, jmp-reg: 16, memory-write: 52, stack-pivot: 35)

---

### rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys

**SHA256:** `32e1a8513eee746d17eb5402fb9d8ff9507fb6e1238e7ff06f7a5c50ff3df993`  
**Score:** 15.0 | **Category:** vulnerable driver | **Signer:** Realtek Semiconductor Corp.  
**Mitigations ON:** HIGH_ENTROPY_VA, DYNAMIC_BASE, NX_COMPAT, FORCE_INTEGRITY, RETPOLINE  
**Mitigations OFF:** GUARD_CF, GS_COOKIE  
**Devices:** \Device\rtkio  
**Dangerous imports:** `ExAllocatePoolWithTag`, `ExFreePoolWithTag`, `MmMapLockedPagesSpecifyCache`, `ZwOpenKey`  

| IOCTL | Method | Access | Label |
|-------|--------|--------|-------|
| `0x80002000` | BUFFERED | ANY |  |
| `0x80002004` | BUFFERED | ANY | alloc mem |
| `0x80002008` | BUFFERED | ANY |  |
| `0x80002018` | BUFFERED | ANY |  |
| `0x8000201C` | BUFFERED | ANY |  |
| `0x80002024` | BUFFERED | ANY |  |
| `0x80002028` | BUFFERED | ANY |  |
| `0x8000202C` | BUFFERED | ANY |  |
| `0x80002030` | BUFFERED | ANY |  |
| `0x813610EC` | BUFFERED | ANY |  |
| `0x813710EC` | BUFFERED | ANY |  |
| `0x816110EC` | BUFFERED | ANY |  |
| `0x816610EC` | BUFFERED | ANY |  |
| `0x816710EC` | BUFFERED | ANY |  |
| `0x816810EC` | BUFFERED | ANY |  |
| `0x816910EC` | BUFFERED | ANY |  |
| `0xFFFFFFFF` | **NEITHER** | READ_WRITE |  |

**Risk highlights:**

- `0x80002000`: no IRP completion
- `0x80002004`: no IRP completion
- `0x80002008`: no IRP completion
- `0x80002018`: no IRP completion
- `0x8000201C`: no IRP completion

**Gadgets:** 500 (reg-control: 175, misc: 223, memory-read: 41, memory-write: 8, stack-pivot: 53)

---

## Download

The complete results for all 1,775 drivers are available as JSON:

- **Full results**: `~/.driveratlas/loldrivers/results.json` (34MB)
- **Run your own**: [DriverAtlas](https://github.com/splintersfury/DriverAtlas)
