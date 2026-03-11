# LOLDrivers Deep Analysis

> Automated deep analysis of every driver in the [LOLDrivers.io](https://www.loldrivers.io/) catalog, powered by [DriverAtlas](https://github.com/splintersfury/DriverAtlas).

**Last updated:** 2026-03-11  
**Drivers analyzed:** 1775 (Tier 1) / 1775 (Tier 2 deep)  

## Key Statistics

| Metric | Count |
|--------|-------|
| Vulnerable drivers | 1468 |
| Malicious drivers | 294 |
| Missing CFG | 1775 |
| Missing FORCE_INTEGRITY | 1548 |
| NEITHER I/O (raw user ptrs) | 806 |
| High risk (score >= 8.0) | 1559 |

## Driver Analysis Table

| Driver | Category | Score | Arch | Mitigations OFF | IOCTLs | NEITHER | Gadgets | Dangerous Imports | Signer |
|--------|----------|-------|------|-----------------|--------|---------|---------|-------------------|--------|
| Netfilter.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 6 | 474 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPages... | 上海喔噻互联网科技有限公司 |
| EneIo64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 306 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | Microsoft Windows Hardwar |
| GtcKmdfBs.sys | vulnerable d | **15.0** | x86 | GUARD_CF, GS_COOKIE | 10 | 1 | 413 | MmMapIoSpace, READ_PORT_UCHAR, READ_PORT_ULONG... | Symantec Class 3 Extended |
| HpPortIox64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | DigiCert SHA2 Assured ID  |
| BS_RCIOW1064.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 22 | 0 | 500 | HalGetBusDataByOffset, MmMapIoSpace, ObReferenceObjectByHandle... | Biostar Microtech Int'l C |
| OpenLibSys.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 0 | 183 | HalGetBusDataByOffset, MmMapIoSpace | Noriyuki MIYAZAKI |
| OpenLibSys.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 214 | HalGetBusDataByOffset, MmMapIoSpace | Noriyuki MIYAZAKI |
| mydrivers.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 11 | 0 | 189 | HalGetBusDataByOffset, MmMapIoSpace, READ_PORT_UCHAR... | Beijing Kingsoft Security |
| HWiNFO64I.SYS | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | REALiX |
| driver7-x86-withoutdbg.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 192 | 46 | 180 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | VeriSign Class 3 Public P |
| directio32_legacy.sys, DirectIo32.sys | vulnerable d | **15.0** | x86 | GUARD_CF, GS_COOKIE | 18 | 0 | 413 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | PassMark Software Pty Ltd |
| iqvw64e.sys, iQVW64.SYS, IQVW32.sys, NalDrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 4 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | AddTrust External CA Root |
| iqvw64e.sys, iQVW64.SYS, IQVW32.sys, NalDrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 4 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Intel Corporation |
| rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapIoSpace... | Realtek Semiconductor Cor |
| rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 289 | ExAllocatePool, ExFreePoolWithTag, MmMapIoSpace... | VeriSign Class 3 Code Sig |
| rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 19 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Realtek Semiconductor Cor |
| rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapIoSpace... | VeriSign Class 3 Code Sig |
| rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapIoSpace... | Realtek Semiconductor Cor |
| rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 289 | ExAllocatePool, ExFreePoolWithTag, MmMapIoSpace... | Realtek Semiconductor Cor |
| rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 17 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Realtek Semiconductor Cor |
| rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 17 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapIoSpace... | Realtek Semiconductor Cor |
| rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 11 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapIoSpace... | Realtek Semiconductor Cor |
| rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapIoSpace... | VeriSign Class 3 Code Sig |
| rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapIoSpace... | Realtek Semiconductor Cor |
| rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys | vulnerable d | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapIoSpace... | Realtek Semiconductor Cor |
| rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapIoSpace... | Realtek Semiconductor Cor |
| rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapIoSpace... | Realtek Semiconductor Cor |
| sfdrvx32.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 0 | 485 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Code Sig |
| ComputerZ.Sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 34 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| ComputerZ.Sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 38 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | Qihoo 360 Software (Beiji |
| ComputerZ.Sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 0 | 269 | IoGetDeviceObjectPointer, MmIsAddressValid, MmMapIoSpace | VeriSign Class 3 Code Sig |
| ComputerZ.Sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| ComputerZ.Sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| ComputerZ.Sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 31 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| ComputerZ.Sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | 360.cn |
| ComputerZ.Sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | 360.cn |
| ComputerZ.Sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | 360.cn |
| ComputerZ.Sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 7 | 4 | 500 | HalGetBusDataByOffset, IoGetDeviceObjectPointer, MmIsAddressValid... | 成都奇鲁科技有限公司 |
| ComputerZ.Sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 14 | 0 | 109 | IoGetDeviceObjectPointer, MmIsAddressValid, MmMapIoSpace | VeriSign Class 3 Code Sig |
| ComputerZ.Sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 30 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | unsigned |
| ComputerZ.Sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 30 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| ComputerZ.Sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 40 | 0 | 500 | HalGetBusDataByOffset, IoGetDeviceObjectPointer, MmIsAddressValid... | 成都奇鲁科技有限公司 |
| ComputerZ.Sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 31 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| ComputerZ.Sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 35 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | Qihoo 360 Software (Beiji |
| ComputerZ.Sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 36 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | Qihoo 360 Software (Beiji |
| ComputerZ.Sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| ComputerZ.Sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 0 | 269 | IoGetDeviceObjectPointer, MmIsAddressValid, MmMapIoSpace | VeriSign Class 3 Code Sig |
| ComputerZ.Sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 1 | 418 | IoGetDeviceObjectPointer, MmIsAddressValid, MmMapIoSpace | VeriSign Class 3 Code Sig |
| ComputerZ.Sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 36 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | QIHU 360 SOFTWARE CO. LIM |
| ComputerZ.Sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 356 | MmMapIoSpace | VeriSign Class 3 Code Sig |
| ComputerZ.Sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 76 | MmMapIoSpace | unsigned |
| ComputerZ.Sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 38 | 0 | 500 | HalGetBusDataByOffset, IoGetDeviceObjectPointer, MmIsAddressValid... | Chengdu Qilu Technology C |
| ComputerZ.Sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 7 | 4 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | Qihoo 360 Software (Beiji |
| ComputerZ.Sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 30 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| ComputerZ.Sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 36 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | QIHU 360 SOFTWARE CO. LIM |
| ComputerZ.Sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 7 | 4 | 500 | HalGetBusDataByOffset, IoGetDeviceObjectPointer, MmIsAddressValid... | Chengdu Qilu Technology C |
| ComputerZ.Sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| ComputerZ.Sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| ComputerZ.Sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | QIHU 360 SOFTWARE CO. LIM |
| ComputerZ.Sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 109 | IoGetDeviceObjectPointer, MmIsAddressValid, MmMapIoSpace | VeriSign Class 3 Code Sig |
| ComputerZ.Sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 30 | 0 | 489 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | 360.cn |
| ComputerZ.Sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| ComputerZ.Sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 30 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| ComputerZ.Sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| ComputerZ.Sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 30 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | 360.cn |
| ComputerZ.Sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 232 | IoGetDeviceObjectPointer, MmIsAddressValid, MmMapIoSpace | VeriSign Class 3 Code Sig |
| ComputerZ.Sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| ComputerZ.Sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 0 | 259 | IoGetDeviceObjectPointer, MmIsAddressValid, MmMapIoSpace | VeriSign Class 3 Code Sig |
| ComputerZ.Sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 0 | 255 | IoGetDeviceObjectPointer, MmIsAddressValid, MmMapIoSpace | VeriSign Class 3 Code Sig |
| ComputerZ.Sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 35 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| ComputerZ.Sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 1 | 412 | IoGetDeviceObjectPointer, MmIsAddressValid, MmMapIoSpace | VeriSign Class 3 Code Sig |
| ComputerZ.Sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 30 | 0 | 489 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | 360.cn |
| ComputerZ.Sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 1 | 437 | IoGetDeviceObjectPointer, MmIsAddressValid, MmMapIoSpace | VeriSign Class 3 Code Sig |
| ComputerZ.Sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 36 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| ComputerZ.Sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | QIHU 360 SOFTWARE CO. LIM |
| ComputerZ.Sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 36 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| ComputerZ.Sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | Qihoo 360 Software (Beiji |
| ComputerZ.Sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 5 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | Qihoo 360 Software (Beiji |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 31 | 1 | 467 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 31 | 1 | 467 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 30 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 30 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 30 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 29 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 35 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 33 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 30 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 30 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 28 | 0 | 403 | HalGetBusDataByOffset, IoGetDeviceObjectPointer, MmIsAddressValid... | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 45 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 32 | 1 | 483 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 35 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 28 | 0 | 428 | HalGetBusDataByOffset, IoGetDeviceObjectPointer, MmIsAddressValid... | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 31 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | HalGetBusDataByOffset, MmMapIoSpace, READ_PORT_UCHAR... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 30 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | HalGetBusDataByOffset, MmMapIoSpace, READ_PORT_UCHAR... | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 30 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 34 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 29 | 0 | 487 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 30 | 0 | 500 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | HalGetBusDataByOffset, MmMapIoSpace, READ_PORT_UCHAR... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | HalGetBusDataByOffset, MmMapIoSpace, READ_PORT_UCHAR... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 31 | 1 | 467 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 29 | 0 | 474 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 34 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 34 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 22 | 0 | 269 | HalGetBusDataByOffset, IoGetDeviceObjectPointer, MmIsAddressValid... | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 38 | 1 | 495 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 33 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 30 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 34 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | HalGetBusDataByOffset, MmMapIoSpace, READ_PORT_UCHAR... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 45 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 29 | 0 | 470 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 31 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 22 | 0 | 264 | HalGetBusDataByOffset, IoGetDeviceObjectPointer, MmIsAddressValid... | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 35 | 1 | 496 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 30 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 37 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 30 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 45 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 34 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| PhlashNT.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapIoSpace... | VeriSign Class 3 Code Sig |
| AsrRapidStartDrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 24 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | VeriSign Class 3 Public P |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 20 | MmAllocateContiguousMemory, MmGetPhysicalAddress, ObReferenceObjectByHandle... | Microsoft Windows Hardwar |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 20 | MmAllocateContiguousMemory, MmGetPhysicalAddress, ObReferenceObjectByHandle... | VeriSign Class 3 Public P |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 68 | ObReferenceObjectByHandle, READ_PORT_UCHAR, READ_PORT_ULONG... | VeriSign Class 3 Code Sig |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 20 | ObReferenceObjectByHandle, READ_PORT_UCHAR, READ_PORT_ULONG... | VeriSign Class 3 Code Sig |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 68 | ObReferenceObjectByHandle, READ_PORT_UCHAR, READ_PORT_ULONG... | VeriSign Class 3 Code Sig |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 20 | MmAllocateContiguousMemory, MmGetPhysicalAddress, ObReferenceObjectByHandle... | Microsoft Windows Hardwar |
| cpuz_x64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 168 | HalGetBusDataByOffset, MmMapIoSpace | VeriSign Class 3 Code Sig |
| WinFlash64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 17 | 0 | 330 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapIoSpace... | VeriSign Class 3 Code Sig |
| WinFlash64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 286 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapIoSpace... | VeriSign Class 3 Code Sig |
| WinFlash64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 133 | 33 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | VeriSign Class 3 Code Sig |
| ene.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 306 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | Microsoft Windows Hardwar |
| ene.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 306 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | AddTrust External CA Root |
| PanIOx64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 14 | 0 | 197 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| nvaudio.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Code Sig |
| DirectIo.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 12 | 0 | 43 | ExAllocatePool, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Code Sig |
| DirectIo.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 16 | ExAllocatePoolWithTag, IoGetDeviceObjectPointer, ObReferenceObjectByHandle... | Thawte Code Signing CA |
| DirectIo.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 1 | 121 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | PassMark Software Pty Ltd |
| DirectIo.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 43 | ExAllocatePool, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Code Sig |
| DirectIo.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 16 | ExAllocatePoolWithTag, IoGetDeviceObjectPointer, ObReferenceObjectByHandle... | VeriSign Class 3 Code Sig |
| BS_I2cIo.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 17 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Code Sig |
| AMDPowerProfiler.sys | vulnerable d | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | Advanced Micro Devices In |
| HwRwDrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 0 | 216 | HalGetBusDataByOffset, MmMapIoSpace | Shuttle Inc. |
| ElbyCDIO.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 207 | ExAllocatePool, MmMapLockedPages, MmProbeAndLockPages... | Elaborate Bytes AG |
| ElbyCDIO.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 353 | ExAllocatePool, MmMapLockedPages, MmProbeAndLockPages... | Elaborate Bytes AG |
| ElbyCDIO.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 207 | ExAllocatePool, MmMapLockedPages, MmProbeAndLockPages... | Elaborate Bytes AG |
| ElbyCDIO.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 21 | 500 | ExAllocatePool, MmMapLockedPages, MmProbeAndLockPages... | Elaborate Bytes AG |
| ElbyCDIO.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 368 | ExAllocatePool, MmMapLockedPages, MmProbeAndLockPages... | Elaborate Bytes AG |
| ElbyCDIO.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 207 | ExAllocatePool, MmMapLockedPages, MmProbeAndLockPages... | Elaborate Bytes AG |
| hw.sys | vulnerable | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Microsoft Windows Hardwar |
| MsIo32.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 293 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | Symantec Class 3 Extended |
| iscflashx64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | Insyde Software Corp. |
| hwdetectng.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 22 | 0 | 500 | HalGetBusDataByOffset, IoGetDeviceObjectPointer, MmIsAddressValid... | iNFERRE |
| hwdetectng.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 11 | 4 | 409 | HalGetBusDataByOffset, IoGetCurrentProcess, IoGetDeviceObjectPointer... | iNFERRE |
| hwdetectng.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 11 | 4 | 411 | HalGetBusDataByOffset, IoGetCurrentProcess, IoGetDeviceObjectPointer... | iNFERRE |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 497 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 497 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 493 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 497 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 497 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 0 | 500 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 493 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 0 | 500 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 493 | HalGetBusDataByOffset, MmMapIoSpace | Micro-Star Int'l Co. Ltd. |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 493 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 0 | 500 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 497 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 497 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 493 | HalGetBusDataByOffset, MmMapIoSpace | Micro-Star Int'l Co. Ltd. |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 493 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 0 | 500 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 497 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 493 | HalGetBusDataByOffset, MmMapIoSpace | Micro-Star Int'l Co. Ltd. |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 493 | HalGetBusDataByOffset, MmMapIoSpace | Micro-Star Int'l Co. Ltd. |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 493 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 493 | HalGetBusDataByOffset, MmMapIoSpace | Micro-Star Int'l Co. Ltd. |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 0 | 500 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 493 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 497 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 0 | 500 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 493 | HalGetBusDataByOffset, MmMapIoSpace | Micro-Star Int'l Co. Ltd. |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 493 | HalGetBusDataByOffset, MmMapIoSpace | Micro-Star Int'l Co. Ltd. |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 493 | HalGetBusDataByOffset, MmMapIoSpace | Micro-Star Int'l Co. Ltd. |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 497 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 493 | HalGetBusDataByOffset, MmMapIoSpace | Micro-Star Int'l Co. Ltd. |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 497 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 497 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 0 | 500 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 497 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 493 | HalGetBusDataByOffset, MmMapIoSpace | Micro-Star Int'l Co. Ltd. |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 493 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 497 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 0 | 500 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 0 | 500 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 497 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 497 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 493 | HalGetBusDataByOffset, MmMapIoSpace | Micro-Star Int'l Co. Ltd. |
| AsrDrv101.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 26 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | VeriSign Class 3 Public P |
| cpuz141.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 38 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| driver7-x64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | VeriSign Class 3 Public P |
| bs_rcio64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 20 | 0 | 500 | HalGetBusDataByOffset, MmMapIoSpace, ObReferenceObjectByHandle... | BIOSTAR MICROTECH INT'L C |
| CtiIo64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 158 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | Microsoft Windows Hardwar |
| msio32.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 75 | IoGetCurrentProcess, MmAllocateNonCachedMemory, ObReferenceObjectByHandle... | unsigned |
| directio64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | PassMark Software Pty Ltd |
| directio64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | PassMark Software Pty Ltd |
| directio64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 17 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | PassMark Software Pty Ltd |
| directio64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | PassMark Software Pty Ltd |
| directio64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | PassMark Software Pty Ltd |
| directio64.sys | vulnerable d | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 17 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Thawte Code Signing CA -  |
| directio64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 17 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Thawte Code Signing CA -  |
| directio64.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 17 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | PassMark Software Pty Ltd |
| directio64.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 18 | 0 | 500 | ExAllocatePool2, ExFreePoolWithTag, IoGetDeviceObjectPointer... | PassMark Software Pty Ltd |
| directio64.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 18 | 0 | 500 | ExAllocatePool2, ExFreePoolWithTag, IoGetDeviceObjectPointer... | PassMark Software Pty Ltd |
| phymem64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 359 | ExAllocatePool, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| AsrDrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 26 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | VeriSign Class 3 Public P |
| AsrDrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 31 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | VeriSign Class 3 Public P |
| AsrDrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 31 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | unsigned |
| AsrDrv.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 41 | 1 | 411 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | VeriSign Class 3 Public P |
| PDFWKRNL.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 45 | 11 | 230 | ExFreePoolWithTag, MmGetPhysicalAddress, MmMapIoSpace... | Advanced Micro Devices In |
| PDFWKRNL.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 45 | 11 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | Advanced Micro Devices In |
| PDFWKRNL.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 45 | 11 | 230 | ExFreePoolWithTag, MmGetPhysicalAddress, MmMapIoSpace... | Advanced Micro Devices In |
| PDFWKRNL.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 45 | 11 | 230 | ExFreePoolWithTag, MmGetPhysicalAddress, MmMapIoSpace... | Advanced Micro Devices In |
| VBoxUSB.Sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 39 | 5 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Microsoft Windows |
| HWiNFO32.SYS | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | REALiX |
| HWiNFO32.SYS | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | REALiX |
| HWiNFO32.SYS | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | REALiX |
| HWiNFO32.SYS | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | HalGetBusDataByOffset, MmMapIoSpace, READ_PORT_UCHAR... | VeriSign Class 3 Code Sig |
| HWiNFO32.SYS | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | REALiX |
| HWiNFO32.SYS | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | REALiX |
| HWiNFO32.SYS | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | HalGetBusDataByOffset, MmMapIoSpace, READ_PORT_UCHAR... | REALiX |
| HWiNFO32.SYS | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | REALiX |
| HWiNFO32.SYS | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | REALiX |
| HWiNFO32.SYS | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | REALiX |
| HWiNFO32.SYS | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | HalGetBusDataByOffset, MmMapIoSpace, READ_PORT_UCHAR... | REALiX |
| dbutil_2_3.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 0 | 500 | MmGetPhysicalAddress, MmMapIoSpace | VeriSign Class 3 Code Sig |
| dbutil_2_3.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 12 | 0 | 120 | MmGetPhysicalAddress, MmMapIoSpace, memcpy | VeriSign Class 3 Code Sig |
| BS_HWMIO64_W10.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 20 | 0 | 500 | HalGetBusDataByOffset, MmMapIoSpace, ObReferenceObjectByHandle... | Microsoft Windows Hardwar |
| HwOs2Ec10x64.sys | vulnerable d | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Symantec Class 3 Extended |
| BSMEMx64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Code Sig |
| iomem64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 1 | 373 | HalGetBusDataByOffset, MmAllocateNonCachedMemory, MmMapIoSpace | DT RESEARCH\ |
| iomem64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 1 | 373 | HalGetBusDataByOffset, MmAllocateNonCachedMemory, MmMapIoSpace | DT RESEARCH\ |
| dellbios.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 7 | 0 | 288 | MmGetPhysicalAddress, MmMapIoSpace | unsigned |
| dellbios.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 364 | MmGetPhysicalAddress, MmMapIoSpace | VeriSign Class 3 Code Sig |
| dellbios.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 359 | MmGetPhysicalAddress, MmMapIoSpace | unsigned |
| dellbios.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | MmGetPhysicalAddress, MmMapIoSpace | VeriSign Class 3 Code Sig |
| dellbios.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 0 | 105 | MmGetPhysicalAddress, MmMapIoSpace | unsigned |
| dellbios.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 364 | MmGetPhysicalAddress, MmMapIoSpace | VeriSign Class 3 Code Sig |
| dellbios.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 265 | MmGetPhysicalAddress, MmMapIoSpace | VeriSign Class 3 Code Sig |
| dellbios.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 417 | MmGetPhysicalAddress, MmMapIoSpace | VeriSign Class 3 Code Sig |
| dellbios.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 109 | MmGetPhysicalAddress, MmMapIoSpace | unsigned |
| dellbios.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 265 | MmGetPhysicalAddress, MmMapIoSpace | unsigned |
| dellbios.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 118 | MmGetPhysicalAddress, MmMapIoSpace | unsigned |
| rtkiow8x64.sys  | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 19 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapIoSpace... | Realtek Semiconductor Cor |
| BSMIx64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 233 | MmGetPhysicalAddress, MmMapIoSpace | VeriSign Class 3 Code Sig |
| AsrDrv102.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 26 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | VeriSign Class 3 Public P |
| sysconp.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 24 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| sysconp.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 28 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| DirectIo.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 1 | 121 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | PassMark Software Pty Ltd |
| psmounterex.sys | vulnerable | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 17 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | GlobalSign CodeSigning CA |
| viragt.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 63 | 5 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Public P |
| aswArPot.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 26 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Avast Software s.r.o. |
| mtcBSv64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 55 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Code Sig |
| etdsupp.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 9 | 1 | 444 | HalGetBusDataByOffset, MmGetPhysicalAddress | DigiCert Trusted G4 Code  |
| CITMDRV_IA64.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_IA64.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_IA64.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_IA64.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_IA64.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_IA64.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_IA64.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_IA64.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_IA64.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_IA64.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_IA64.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_IA64.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_IA64.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_IA64.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_IA64.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_IA64.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_IA64.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_IA64.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_IA64.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_IA64.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| sfdrvx64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Public P |
| sfdrvx64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Code Sig |
| sfdrvx64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 20 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | GlobalSign CodeSigning CA |
| semav6msr.sys, semav6msr64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 0 | 248 | MmMapIoSpace | Intel(R) Code Signing Ext |
| semav6msr.sys, semav6msr64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 0 | 248 | MmMapIoSpace | SEMA Software |
| AsrDrv103.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 31 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | VeriSign Class 3 Public P |
| MsIo64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 319 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | Microsoft Windows Hardwar |
| ampa.sys | vulnerable | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 7 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | CHENGDU AOMEI Tech Co.\ |
| AODDriver.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 43 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Code Sig |
| AODDriver.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 0 | HalGetBusDataByOffset, MmMapIoSpace, MmMapLockedPages... | unsigned |
| AODDriver.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 270 | HalGetBusDataByOffset, MmMapIoSpace, MmMapLockedPages | VeriSign Class 3 Code Sig |
| AODDriver.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 0 | 318 | HalGetBusDataByOffset, MmMapIoSpace, MmMapLockedPages | VeriSign Class 3 Code Sig |
| AODDriver.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 11 | 0 | 28 | HalGetBusDataByOffset, MmMapIoSpace, MmMapLockedPages... | unsigned |
| AODDriver.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 0 | 318 | HalGetBusDataByOffset, MmMapIoSpace, MmMapLockedPages | VeriSign Class 3 Code Sig |
| AODDriver.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Code Sig |
| AODDriver.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 270 | HalGetBusDataByOffset, MmMapIoSpace, MmMapLockedPages | VeriSign Class 3 Code Sig |
| AODDriver.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 14 | 0 | 23 | HalGetBusDataByOffset, MmMapIoSpace, MmMapLockedPages... | unsigned |
| AODDriver.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 1 | 355 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | unsigned |
| AODDriver.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 7 | 0 | 101 | HalGetBusDataByOffset, MmMapIoSpace, MmMapLockedPages | unsigned |
| AODDriver.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 0 | HalGetBusDataByOffset, MmMapIoSpace, MmMapLockedPages... | unsigned |
| AODDriver.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Code Sig |
| nvflsh32.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 151 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | NVIDIA Corporation |
| nvflsh32.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 151 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | VeriSign Class 3 Public P |
| nvflsh32.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 151 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | VeriSign Class 3 Code Sig |
| nvflsh32.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 151 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | VeriSign Class 3 Public P |
| nvflsh32.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 151 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | VeriSign Class 3 Code Sig |
| nvflsh32.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 151 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | NVIDIA Corporation |
| nvflsh32.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 151 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | VeriSign Class 3 Code Sig |
| nvflsh32.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 151 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | VeriSign Class 3 Public P |
| nvflsh32.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 151 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | NVIDIA Corporation |
| nvflsh32.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 151 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | VeriSign Class 3 Code Sig |
| AsmIo64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 0 | 411 | ExAllocatePool, ExFreePoolWithTag, IoGetDeviceObjectPointer... | ASMedia Technology Inc. |
| phydmaccx64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 217 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign Primary Object |
| AsrDrv106.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 31 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | GlobalSign Code Signing R |
| DirectIo32.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 1 | 189 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | PassMark Software Pty Ltd |
| DirectIo32.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 1 | 121 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | PassMark Software Pty Ltd |
| DirectIo32.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Thawte Code Signing CA -  |
| DirectIo32.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 1 | 121 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | PassMark Software Pty Ltd |
| DirectIo32.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 1 | 227 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | PassMark Software Pty Ltd |
| DirectIo32.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | PassMark Software Pty Ltd |
| DirectIo32.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 1 | 191 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | PassMark Software Pty Ltd |
| DirectIo32.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 1 | 191 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | PassMark Software Pty Ltd |
| ngiodriver.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 222 | READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR... | AVAST Software a.s. |
| ngiodriver.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 222 | READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR... | AVAST Software a.s. |
| ngiodriver.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 222 | READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR... | AVAST Software a.s. |
| ngiodriver.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 500 | ExFreePoolWithTag, MmMapIoSpace | AVAST Software a.s. |
| ngiodriver.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 12 | 0 | 238 | ExFreePoolWithTag, MmMapIoSpace, READ_PORT_UCHAR... | AVAST Software a.s. |
| ngiodriver.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 500 | ExFreePoolWithTag, MmMapIoSpace | AVAST Software a.s. |
| ngiodriver.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 12 | 0 | 238 | ExFreePoolWithTag, MmMapIoSpace, READ_PORT_UCHAR... | AVAST Software a.s. |
| ngiodriver.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 12 | 0 | 238 | ExFreePoolWithTag, MmMapIoSpace, READ_PORT_UCHAR... | AVAST Software a.s. |
| amifldrv64.sys, amifldrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 14 | 0 | 500 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmMapIoSpace... | American Megatrends\ |
| amifldrv64.sys, amifldrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 11 | 0 | 500 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmIsAddressValid... | American Megatrends\ |
| amifldrv64.sys, amifldrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 14 | 0 | 500 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmMapIoSpace... | American Megatrends\ |
| amifldrv64.sys, amifldrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 11 | 0 | 500 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmIsAddressValid... | American Megatrends\ |
| amifldrv64.sys, amifldrv.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 10 | 0 | 500 | ExFreePoolWithTag, MmAllocateContiguousMemory, MmGetPhysicalAddress... | American Megatrends\ |
| amifldrv64.sys, amifldrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmIsAddressValid... | VeriSign Class 3 Code Sig |
| amifldrv64.sys, amifldrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 0 | 485 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmIsAddressValid... | VeriSign Class 3 Code Sig |
| amifldrv64.sys, amifldrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 14 | 0 | 500 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmMapIoSpace... | American Megatrends\ |
| amifldrv64.sys, amifldrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 7 | 0 | 500 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmIsAddressValid... | American Megatrends\ |
| amifldrv64.sys, amifldrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 0 | 446 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmIsAddressValid... | VeriSign Class 3 Code Sig |
| amifldrv64.sys, amifldrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 0 | 466 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmIsAddressValid... | VeriSign Class 3 Code Sig |
| amifldrv64.sys, amifldrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 0 | 500 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmMapIoSpace... | American Megatrends\ |
| amifldrv64.sys, amifldrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 14 | 0 | 500 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmMapIoSpace... | American Megatrends\ |
| amifldrv64.sys, amifldrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 0 | 423 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmIsAddressValid... | VeriSign Class 3 Code Sig |
| amifldrv64.sys, amifldrv.sys | vulnerable d | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 0 | 500 | ExFreePoolWithTag, MmAllocateContiguousMemory, MmGetPhysicalAddress... | American Megatrends\ |
| amifldrv64.sys, amifldrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 500 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmIsAddressValid... | American Megatrends\ |
| amifldrv64.sys, amifldrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 0 | 423 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmIsAddressValid... | NOVENTI Health SE |
| amifldrv64.sys, amifldrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 0 | 500 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmIsAddressValid... | American Megatrends\ |
| amifldrv64.sys, amifldrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 0 | 422 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmIsAddressValid... | VeriSign Class 3 Code Sig |
| amifldrv64.sys, amifldrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 7 | 0 | 500 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmIsAddressValid... | American Megatrends\ |
| amifldrv64.sys, amifldrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 0 | 485 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmIsAddressValid... | VeriSign Class 3 Code Sig |
| amifldrv64.sys, amifldrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 0 | 434 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmIsAddressValid... | VeriSign Class 3 Code Sig |
| amifldrv64.sys, amifldrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 7 | 0 | 500 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmIsAddressValid... | unsigned |
| amifldrv64.sys, amifldrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 0 | 423 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmIsAddressValid... | unsigned |
| AsrSetupDrv103.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 31 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | GlobalSign Code Signing R |
| AsrSetupDrv103.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 31 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | VeriSign Class 3 Public P |
| phydmaccx86.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 11 | 0 | 189 | HalGetBusDataByOffset, MmMapIoSpace, READ_PORT_UCHAR... | GlobalSign Primary Object |
| PanIO.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 11 | 0 | 194 | HalGetBusDataByOffset, MmMapIoSpace, READ_PORT_UCHAR... | GlobalSign CodeSigning CA |
| sfdrvx32.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 20 | 0 | 464 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Public P |
| sfdrvx32.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 22 | 0 | 426 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | GlobalSign CodeSigning CA |
| VBoxMouseNT.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 23 | 10 | 500 | ExAllocatePool, IoGetDeviceObjectPointer, MmAllocateContiguousMemory... | innotek GmbH |
| Bs_Def.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmMapIoSpace... | VeriSign Class 3 Code Sig |
| TPwSav.sys | vulnerable d | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Compal electronic \ |
| TSDRVX64.sys | vulnerable | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 150 | MmMapIoSpace | Microsoft Windows Hardwar |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 70 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | Microsoft Windows Hardwar |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 346 | MmMapIoSpace | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 31 | 1 | 469 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 32 | 1 | 483 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 31 | 1 | 466 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 35 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 31 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 30 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 38 | 1 | 500 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 29 | 0 | 489 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | HalGetBusDataByOffset, MmMapIoSpace, READ_PORT_UCHAR... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 30 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 27 | 0 | 378 | HalGetBusDataByOffset, IoGetDeviceObjectPointer, MmIsAddressValid... | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | HalGetBusDataByOffset, MmMapIoSpace, READ_PORT_UCHAR... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 202 | MmMapIoSpace | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 27 | 0 | 378 | HalGetBusDataByOffset, IoGetDeviceObjectPointer, MmIsAddressValid... | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 29 | 0 | 493 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 46 | 0 | 500 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 34 | 1 | 500 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 37 | 1 | 500 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 32 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 30 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 30 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 37 | 1 | 500 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 37 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | HalGetBusDataByOffset, MmMapIoSpace, READ_PORT_UCHAR... | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 46 | 0 | 500 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 42 | 0 | 500 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 35 | 1 | 500 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 30 | 0 | 500 | HalGetBusDataByOffset, IoGetDeviceObjectPointer, MmIsAddressValid... | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 34 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | CPUID |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 31 | 1 | 500 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | HalGetBusDataByOffset, MmMapIoSpace, READ_PORT_UCHAR... | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | HalGetBusDataByOffset, MmMapIoSpace, READ_PORT_UCHAR... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 31 | 1 | 469 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 28 | 0 | 500 | HalGetBusDataByOffset, IoGetDeviceObjectPointer, MmIsAddressValid... | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 41 | 0 | 483 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 41 | 0 | 481 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 32 | 1 | 500 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 29 | 0 | 483 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 38 | 1 | 495 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | CPUID |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 31 | 1 | 500 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 31 | 1 | 500 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 30 | 0 | 500 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | VeriSign Class 3 Code Sig |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 35 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 46 | 0 | 500 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 38 | 1 | 495 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 38 | 1 | 495 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | HalGetBusDataByOffset, MmMapIoSpace, READ_PORT_UCHAR... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | HalGetBusDataByOffset, MmMapIoSpace, READ_PORT_UCHAR... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 32 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | HalGetBusDataByOffset, MmMapIoSpace, READ_PORT_UCHAR... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | HalGetBusDataByOffset, MmMapIoSpace, READ_PORT_UCHAR... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 31 | 1 | 467 | ExAllocatePoolWithTag, HalGetBusDataByOffset, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| cpuz.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 24 | 0 | 383 | HalGetBusDataByOffset, IoGetDeviceObjectPointer, MmIsAddressValid... | VeriSign Class 3 Code Sig |
| superbmc.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePool, ExFreePoolWithTag, ObReferenceObjectByHandle... | VeriSign Class 3 Public P |
| superbmc.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 2 | 500 | ExAllocatePool, ExFreePoolWithTag, ObReferenceObjectByHandle... | VeriSign Class 3 Public P |
| superbmc.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 2 | 500 | ExAllocatePool, ExFreePoolWithTag, ObReferenceObjectByHandle... | VeriSign Class 3 Public P |
| superbmc.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 2 | 500 | ExAllocatePool, ExFreePoolWithTag, ObReferenceObjectByHandle... | VeriSign Class 3 Code Sig |
| superbmc.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 489 | ExAllocatePool, ExFreePoolWithTag, ObReferenceObjectByHandle... | VeriSign Class 3 Public P |
| superbmc.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 2 | 500 | ExAllocatePool, ExFreePoolWithTag, ObReferenceObjectByHandle... | VeriSign Class 3 Public P |
| viragt64.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Code Sig |
| viragt64.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 59 | 4 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Code Sig |
| viragt64.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 66 | 5 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Public P |
| viragt64.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 57 | 4 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Code Sig |
| viragt64.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 47 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Code Sig |
| viragt64.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 72 | 5 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Public P |
| AsrSmartConnectDrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 24 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | VeriSign Class 3 Public P |
| EIO.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 500 | ExAllocatePoolWithTag, MmMapIoSpace | unsigned |
| EIO.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 11 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapIoSpace | unsigned |
| EIO.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 25 | 0 | 457 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapIoSpace... | ASUSTEK COMPUTER INC. |
| EIO.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 11 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapIoSpace | ASUSTEK COMPUTER INC. |
| aswArPot.sys, avgArPot.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 26 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | AVG Technologies USA\ |
| aswArPot.sys, avgArPot.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 26 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | AVG Technologies USA\ |
| aswArPot.sys, avgArPot.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 23 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | AVAST Software s.r.o. |
| aswArPot.sys, avgArPot.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 23 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | AVG Technologies USA\ |
| aswArPot.sys, avgArPot.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 26 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Avast Software s.r.o. |
| aswArPot.sys, avgArPot.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 26 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | AVG Technologies USA\ |
| aswArPot.sys, avgArPot.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 23 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | AVAST Software s.r.o. |
| aswArPot.sys, avgArPot.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 26 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | AVG Technologies USA\ |
| aswArPot.sys, avgArPot.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 26 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | AVG Technologies USA\ |
| aswArPot.sys, avgArPot.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 26 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Avast Software s.r.o. |
| aswArPot.sys, avgArPot.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 26 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Avast Software s.r.o. |
| aswArPot.sys, avgArPot.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 26 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | AVG Technologies USA\ |
| aswArPot.sys, avgArPot.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 23 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | AVAST Software s.r.o. |
| aswArPot.sys, avgArPot.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 23 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | AVG Technologies USA\ |
| aswArPot.sys, avgArPot.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 23 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | AVG Technologies USA\ |
| aswArPot.sys, avgArPot.sys | vulnerable d | **15.0** | x86 | GUARD_CF, GS_COOKIE | 35 | 6 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Avast Software s.r.o. |
| aswArPot.sys, avgArPot.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 23 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | AVG Technologies USA\ |
| aswArPot.sys, avgArPot.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 26 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | AVG Technologies USA\ |
| aswArPot.sys, avgArPot.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 32 | 5 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | AVG Technologies USA\ |
| aswArPot.sys, avgArPot.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 26 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Avast Software s.r.o. |
| aswArPot.sys, avgArPot.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 23 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | AVAST Software s.r.o. |
| aswArPot.sys, avgArPot.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 23 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | AVG Technologies USA\ |
| aswArPot.sys, avgArPot.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 23 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | AVAST Software s.r.o. |
| SysInfo.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 0 | 500 | HalGetBusDataByOffset, MmMapIoSpace | Noriyuki MIYAZAKI |
| bs_hwmio64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 116 | MmMapIoSpace | VeriSign Class 3 Code Sig |
| RadHwMgr.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 37 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | unsigned |
| RadHwMgr.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 41 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | NCR Corporation |
| RadHwMgr.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 45 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | unsigned |
| RadHwMgr.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 43 | 3 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | Microsoft Windows Hardwar |
| RadHwMgr.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 47 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | NCR Corporation |
| RadHwMgr.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 48 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | NCR Corporation |
| atillk64.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | HalGetBusDataByOffset, MmMapIoSpace, MmMapLockedPages... | VeriSign Class 3 Code Sig |
| atillk64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 17 | 0 | 149 | HalGetBusDataByOffset, MmMapIoSpace, MmMapLockedPages | VeriSign Class 3 Code Sig |
| physmem.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapIoSpace... | GlobalSign CodeSigning CA |
| magdrvamd64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 0 | 205 | MmMapIoSpace | GlobalSign CodeSigning CA |
| nvflash.sys | vulnerable d | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | NVIDIA Corporation |
| nvflash.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 151 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | NVIDIA Corporation |
| FPCIE2COM.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 157 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Symantec Class 3 Extended |
| FPCIE2COM.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Symantec Class 3 Extended |
| FPCIE2COM.sys | vulnerable d | **15.0** | x86 | GUARD_CF, GS_COOKIE | 15 | 0 | 77 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Feature Integration Techn |
| FPCIE2COM.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 160 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Symantec Class 3 Extended |
| FPCIE2COM.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 14 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Feature Integration Techn |
| AsrDrv10.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 25 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | VeriSign Class 3 Public P |
| Agent64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePool, ExFreePoolWithTag, MmAllocateContiguousMemory... | GlobalSign CodeSigning CA |
| Agent64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePool, ExFreePoolWithTag, MmAllocateContiguousMemory... | GlobalSign Primary Object |
| Agent64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePool, ExFreePoolWithTag, MmAllocateContiguousMemory... | GlobalSign Primary Object |
| Agent64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePool, ExFreePoolWithTag, MmAllocateContiguousMemory... | GlobalSign CodeSigning CA |
| Agent64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePool, ExFreePoolWithTag, MmAllocateContiguousMemory... | GlobalSign Extended Valid |
| Agent64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePool, ExFreePoolWithTag, MmAllocateContiguousMemory... | unsigned |
| ADRMDRVSYS.sys | vulnerable | **15.0** | x64 | GUARD_CF, GS_COOKIE | 5 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, HalGetBusDataByOffset... | Microsoft Windows Hardwar |
| driver7-x86.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 28 | 0 | 380 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | VeriSign Class 3 Public P |
| AsrAutoChkUpdDrv_1_0_32.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 26 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | VeriSign Class 3 Public P |
| elrawdsk.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | EldoS Corporation |
| elrawdsk.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | EldoS Corporation |
| WinRing0.sys, WinRing0x64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 214 | HalGetBusDataByOffset, MmMapIoSpace | VeriSign Class 3 Code Sig |
| WinRing0.sys, WinRing0x64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 214 | HalGetBusDataByOffset, MmMapIoSpace | Noriyuki MIYAZAKI |
| WinRing0.sys, WinRing0x64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 217 | HalGetBusDataByOffset, MmMapIoSpace | EVGA |
| WinRing0.sys, WinRing0x64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 14 | 0 | 195 | HalGetBusDataByOffset, MmMapIoSpace | Noriyuki MIYAZAKI |
| atlAccess.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 265 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapIoSpace... | Aquantia Corp. |
| BS_HWMIo64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 20 | 0 | 500 | HalGetBusDataByOffset, MmMapIoSpace, ObReferenceObjectByHandle... | BIOSTAR MICROTECH INT'L C |
| UCOREW64.SYS | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 379 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmIsAddressValid... | VeriSign Class 3 Code Sig |
| SysDrv3S.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ObReferenceObjectByHandle, ZwCreateFile... | GlobalSign Extended Valid |
| BSMI.sys, BSMIXP64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 237 | MmGetPhysicalAddress, MmMapIoSpace | VeriSign Class 3 Code Sig |
| rtport.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 17 | 0 | 40 | HalGetBusDataByOffset, MmMapIoSpace, READ_PORT_UCHAR... | VeriSign Class 3 Code Sig |
| rtport.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 33 | READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR... | unsigned |
| rtport.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 322 | HalGetBusDataByOffset, MmMapIoSpace | VeriSign Class 3 Code Sig |
| rtport.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 322 | HalGetBusDataByOffset, MmMapIoSpace | unsigned |
| rtport.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 33 | READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR... | unsigned |
| rtport.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 33 | READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR... | unsigned |
| rtport.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 33 | READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR... | unsigned |
| rtport.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 49 | READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR... | unsigned |
| directio.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | PassMark Software Pty Ltd |
| BS_RCIO.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 17 | 0 | 82 | HalGetBusDataByOffset, MmMapIoSpace, ObReferenceObjectByHandle... | Biostar Microtech Int'l C |
| asrdrv104.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 41 | 1 | 411 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | VeriSign Class 3 Public P |
| SMARTEIO64.SYS | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 500 | MmMapIoSpace, MmMapLockedPages | VeriSign Class 3 Code Sig |
| atillk64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 137 | HalGetBusDataByOffset, MmMapIoSpace, MmMapLockedPages | VeriSign Class 3 Code Sig |
| atillk64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 17 | 0 | 149 | HalGetBusDataByOffset, MmMapIoSpace, MmMapLockedPages | unsigned |
| atillk64.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | HalGetBusDataByOffset, MmMapIoSpace, MmMapLockedPages... | unsigned |
| atillk64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 17 | 0 | 149 | HalGetBusDataByOffset, MmMapIoSpace, MmMapLockedPages | unsigned |
| atillk64.sys | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | HalGetBusDataByOffset, MmMapIoSpace, MmMapLockedPages... | unsigned |
| atillk64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 17 | 0 | 149 | HalGetBusDataByOffset, MmMapIoSpace, MmMapLockedPages | unsigned |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 150 | 4 | 500 | HalGetBusDataByOffset, IoGetDeviceObjectPointer, MmIsAddressValid... | VeriSign Class 3 Code Sig |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 67 | 0 | 500 | MmMapIoSpace | unsigned |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 132 | 4 | 500 | HalGetBusDataByOffset, IoGetDeviceObjectPointer, MmIsAddressValid... | VeriSign Class 3 Code Sig |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 88 | 4 | 395 | IoGetDeviceObjectPointer, MmIsAddressValid, MmMapIoSpace | VeriSign Class 3 Code Sig |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 129 | 5 | 500 | IoGetDeviceObjectPointer, MmIsAddressValid, MmMapIoSpace | VeriSign Class 3 Code Sig |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 88 | 4 | 433 | IoGetDeviceObjectPointer, MmIsAddressValid, MmMapIoSpace | VeriSign Class 3 Code Sig |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 151 | 5 | 500 | HalGetBusDataByOffset, IoGetDeviceObjectPointer, MmIsAddressValid... | FinalWire |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 64 | 0 | 500 | MmMapIoSpace | unsigned |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 107 | 4 | 400 | IoGetDeviceObjectPointer, MmIsAddressValid, MmMapIoSpace | VeriSign Class 3 Code Sig |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 126 | 4 | 410 | IoGetDeviceObjectPointer, MmIsAddressValid, MmMapIoSpace | VeriSign Class 3 Code Sig |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 130 | 5 | 500 | IoGetDeviceObjectPointer, MmIsAddressValid, MmMapIoSpace | VeriSign Class 3 Code Sig |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 151 | 5 | 500 | HalGetBusDataByOffset, IoGetDeviceObjectPointer, MmIsAddressValid... | VeriSign Class 3 Code Sig |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 129 | 5 | 500 | IoGetDeviceObjectPointer, MmIsAddressValid, MmMapIoSpace | VeriSign Class 3 Code Sig |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 94 | 4 | 455 | IoGetDeviceObjectPointer, MmIsAddressValid, MmMapIoSpace | VeriSign Class 3 Code Sig |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 133 | 4 | 500 | HalGetBusDataByOffset, IoGetDeviceObjectPointer, MmIsAddressValid... | VeriSign Class 3 Code Sig |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 131 | 5 | 500 | IoGetDeviceObjectPointer, MmIsAddressValid, MmMapIoSpace | VeriSign Class 3 Code Sig |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 130 | 4 | 500 | IoGetDeviceObjectPointer, MmIsAddressValid, MmMapIoSpace | VeriSign Class 3 Code Sig |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 98 | 4 | 364 | IoGetDeviceObjectPointer, MmIsAddressValid, MmMapIoSpace | VeriSign Class 3 Code Sig |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 151 | 5 | 500 | HalGetBusDataByOffset, IoGetDeviceObjectPointer, MmIsAddressValid... | VeriSign Class 3 Code Sig |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 473 | MmMapIoSpace | unsigned |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 130 | 4 | 500 | IoGetDeviceObjectPointer, MmIsAddressValid, MmMapIoSpace | VeriSign Class 3 Code Sig |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 132 | 4 | 500 | HalGetBusDataByOffset, IoGetDeviceObjectPointer, MmIsAddressValid... | FinalWire |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 126 | 4 | 412 | IoGetDeviceObjectPointer, MmIsAddressValid, MmMapIoSpace | VeriSign Class 3 Code Sig |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 98 | 4 | 361 | IoGetDeviceObjectPointer, MmIsAddressValid, MmMapIoSpace | VeriSign Class 3 Code Sig |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 454 | MmMapIoSpace | unsigned |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 127 | 4 | 447 | IoGetDeviceObjectPointer, MmIsAddressValid, MmMapIoSpace | VeriSign Class 3 Code Sig |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 77 | 1 | 500 | MmMapIoSpace | unsigned |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 95 | 4 | 500 | IoGetDeviceObjectPointer, MmIsAddressValid, MmMapIoSpace | VeriSign Class 3 Code Sig |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 151 | 5 | 500 | HalGetBusDataByOffset, IoGetDeviceObjectPointer, MmIsAddressValid... | FinalWire |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 89 | 4 | 441 | IoGetDeviceObjectPointer, MmIsAddressValid, MmMapIoSpace | VeriSign Class 3 Code Sig |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 131 | 4 | 500 | HalGetBusDataByOffset, IoGetDeviceObjectPointer, MmIsAddressValid... | VeriSign Class 3 Code Sig |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 109 | 4 | 399 | IoGetDeviceObjectPointer, MmIsAddressValid, MmMapIoSpace | VeriSign Class 3 Code Sig |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 67 | 0 | 500 | MmMapIoSpace | unsigned |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 131 | 4 | 500 | HalGetBusDataByOffset, IoGetDeviceObjectPointer, MmIsAddressValid... | VeriSign Class 3 Code Sig |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 67 | 0 | 500 | MmMapIoSpace | unsigned |
| kerneld.amd64 | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 77 | 1 | 500 | MmMapIoSpace | unsigned |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 203 | MmMapIoSpace, ObReferenceObjectByHandle, ZwMapViewOfSection... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 0 | 219 | HalGetBusDataByOffset, MmMapIoSpace, ObReferenceObjectByHandle... | GlobalSign Extended Valid |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 203 | MmMapIoSpace, ObReferenceObjectByHandle, ZwMapViewOfSection... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 0 | 204 | HalGetBusDataByOffset, MmMapIoSpace, ObReferenceObjectByHandle... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 0 | 219 | HalGetBusDataByOffset, MmMapIoSpace, ObReferenceObjectByHandle... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 0 | 204 | HalGetBusDataByOffset, MmMapIoSpace, ObReferenceObjectByHandle... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 203 | MmMapIoSpace, ObReferenceObjectByHandle, ZwMapViewOfSection... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 0 | 204 | HalGetBusDataByOffset, MmMapIoSpace, ObReferenceObjectByHandle... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 203 | MmMapIoSpace, ObReferenceObjectByHandle, ZwMapViewOfSection... | EVGA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 203 | MmMapIoSpace, ObReferenceObjectByHandle, ZwMapViewOfSection... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 203 | MmMapIoSpace, ObReferenceObjectByHandle, ZwMapViewOfSection... | VeriSign Class 3 Public P |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 203 | MmMapIoSpace, ObReferenceObjectByHandle, ZwMapViewOfSection... | EVGA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 206 | MmMapIoSpace, ObReferenceObjectByHandle, ZwMapViewOfSection... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 206 | MmMapIoSpace, ObReferenceObjectByHandle, ZwMapViewOfSection... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 206 | MmMapIoSpace, ObReferenceObjectByHandle, ZwMapViewOfSection... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 206 | MmMapIoSpace, ObReferenceObjectByHandle, ZwMapViewOfSection... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 206 | MmMapIoSpace, ObReferenceObjectByHandle, ZwMapViewOfSection... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 203 | MmMapIoSpace, ObReferenceObjectByHandle, ZwMapViewOfSection... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 0 | 320 | HalGetBusDataByOffset, MmMapIoSpace, ObReferenceObjectByHandle... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 0 | 320 | HalGetBusDataByOffset, MmMapIoSpace, ObReferenceObjectByHandle... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 203 | MmMapIoSpace, ObReferenceObjectByHandle, ZwMapViewOfSection... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 203 | MmMapIoSpace, ObReferenceObjectByHandle, ZwMapViewOfSection... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 203 | MmMapIoSpace, ObReferenceObjectByHandle, ZwMapViewOfSection... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 0 | 204 | HalGetBusDataByOffset, MmMapIoSpace, ObReferenceObjectByHandle... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 0 | 320 | HalGetBusDataByOffset, MmMapIoSpace, ObReferenceObjectByHandle... | Sectigo Public Code Signi |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 203 | MmMapIoSpace, ObReferenceObjectByHandle, ZwMapViewOfSection... | VeriSign Class 3 Public P |
| truesight.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Adlice |
| kbdcap64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 6 | 474 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPages... | 上海喔噻互联网科技有限公司 |
| kbdcap64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 6 | 474 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPages... | 上海喔噻互联网科技有限公司 |
| VdBSv64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 500 | ExAllocatePool, MmMapIoSpace | VeriSign Class 3 Code Sig |
| AMDRyzenMasterDriver.sys | vulnerable d | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | Advanced Micro Devices In |
| AMDRyzenMasterDriver.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 30 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | Advanced Micro Devices IN |
| AMDRyzenMasterDriver.sys | vulnerable d | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | Advanced Micro Devices\ |
| AMDRyzenMasterDriver.sys | vulnerable d | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | Advanced Micro Devices\ |
| AMDRyzenMasterDriver.sys | vulnerable d | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | Advanced Micro Devices\ |
| AMDRyzenMasterDriver.sys | vulnerable d | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | Advanced Micro Devices IN |
| AMDRyzenMasterDriver.sys | vulnerable d | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | Advanced Micro Devices IN |
| VBoxDrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 55 | 8 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Code Sig |
| VBoxDrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 54 | 8 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Microsoft Windows |
| VBoxDrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 54 | 8 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Code Sig |
| iQVW64.SYS | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Code Sig |
| iQVW64.SYS | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 4 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | AddTrust External CA Root |
| iQVW64.SYS | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 4 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Intel Corporation |
| iQVW64.SYS | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Code Sig |
| iQVW64.SYS | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Code Sig |
| iQVW64.SYS | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 4 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Intel(R) INTELND1617 |
| iQVW64.SYS | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 4 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Intel(R) INTELNPG1 |
| iQVW64.SYS | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 4 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Code Sig |
| iQVW64.SYS | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 4 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | AddTrust External CA Root |
| iQVW64.SYS | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 4 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Code Sig |
| iQVW64.SYS | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 4 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Intel Corporation |
| iQVW64.SYS | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 4 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Code Sig |
| iQVW64.SYS | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 4 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Code Sig |
| iQVW64.SYS | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 4 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Intel(R) INTELNPG1 |
| iQVW64.SYS | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Code Sig |
| iQVW64.SYS | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 4 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Intel(R) INTELNPG1 |
| iQVW64.SYS | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 4 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Intel(R) Intel Network Dr |
| iQVW64.SYS | vulnerable d | **15.0** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Code Sig |
| nvflash.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 151 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | VeriSign Class 3 Public P |
| vboxdrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 54 | 8 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Code Sig |
| vboxdrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 39 | 5 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | innotek GmbH |
| vboxdrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 39 | 5 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | innotek GmbH |
| vboxdrv.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 38 | 5 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | innotek GmbH |
| vboxdrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 39 | 5 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | innotek GmbH |
| vboxdrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 39 | 5 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | innotek GmbH |
| vboxdrv.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 38 | 5 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | innotek GmbH |
| eneio64.sys | vulnerable d | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 302 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | VeriSign Class 3 Public P |
| TdkLib64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Public P |
| TdkLib64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 25 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Public P |
| TdkLib64.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 18 | 1 | 498 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Symantec Class 3 Extended |
| TdkLib64.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 1 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | Symantec Class 3 Extended |
| TdkLib64.sys | vulnerable d | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 20 | 1 | 499 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Public P |
| TdkLib64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Public P |
| TdkLib64.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 1 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | Phoenix Technologies Inc |
| TdkLib64.sys | vulnerable d | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 1 | 461 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Symantec Class 3 Extended |
| TdkLib64.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 1 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | Phoenix Technologies Inc |
| TdkLib64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Public P |
| TdkLib64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Public P |
| TdkLib64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | Phoenix Technologies Ltd. |
| TdkLib64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Public P |
| TdkLib64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Public P |
| TdkLib64.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 1 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | DigiCert Trusted G4 Code  |
| TdkLib64.sys | vulnerable d | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Public P |
| TdkLib64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Public P |
| gpcidrv64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 0 | 338 | MmMapIoSpace, ObReferenceObjectByHandle, ZwMapViewOfSection... | VeriSign Class 3 Code Sig |
| vboxguest.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmAllocateContiguousMemory... | InnoTek Systemberatung Gm |
| vboxguest.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 1 | 500 | ExAllocatePool, MmAllocateContiguousMemory, MmGetPhysicalAddress... | innotek GmbH |
| directio64.sys, utiA2D4.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 17 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | PassMark Software Pty Ltd |
| inpout32.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 0 | 106 | ObReferenceObjectByHandle, READ_PORT_UCHAR, READ_PORT_ULONG... | VeriSign Class 3 Code Sig |
| inpout32.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 0 | 106 | ObReferenceObjectByHandle, READ_PORT_UCHAR, READ_PORT_ULONG... | RISINTECH INC. |
| inpout32.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 0 | 106 | ObReferenceObjectByHandle, READ_PORT_UCHAR, READ_PORT_ULONG... | RISINTECH INC. |
| inpout32.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 0 | 106 | ObReferenceObjectByHandle, READ_PORT_UCHAR, READ_PORT_ULONG... | unsigned |
| inpout32.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 0 | 106 | ObReferenceObjectByHandle, READ_PORT_UCHAR, READ_PORT_ULONG... | unsigned |
| LenovoDiagnosticsDriver.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 7 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | DigiCert Trusted G4 Code  |
| AsrAutoChkUpdDrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 26 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | VeriSign Class 3 Public P |
| ProcObsrvesx.sys | vulnerable | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | MicroWorld Technologies I |
| Monitor_win10_x64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 14 | 0 | 197 | HalGetBusDataByOffset, MmMapIoSpace | IObit Information Technol |
| HpPortIox64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 14 | 0 | 197 | HalGetBusDataByOffset, MmMapIoSpace | HP Inc. |
| AsrOmgDrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 25 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | VeriSign Class 3 Public P |
| phymem_ext64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 7 | 0 | 285 | ExAllocatePool, ExFreePoolWithTag, IoGetDeviceObjectPointer... | DigiCert Trusted G4 Code  |
| phymem_ext64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 7 | 0 | 285 | ExAllocatePool, ExFreePoolWithTag, IoGetDeviceObjectPointer... | DigiCert Trusted G4 Code  |
| phymem_ext64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 7 | 0 | 285 | ExAllocatePool, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Shenzhen Moyea Software |
| phymem_ext64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 7 | 0 | 285 | ExAllocatePool, ExFreePoolWithTag, IoGetDeviceObjectPointer... | DigiCert Trusted G4 Code  |
| IOMap64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 11 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapIoSpace | VeriSign Class 3 Code Sig |
| NTIOLib.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 11 | 0 | 500 | HalGetBusDataByOffset, MmMapIoSpace, READ_PORT_UCHAR... | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 11 | 0 | 500 | HalGetBusDataByOffset, MmMapIoSpace, READ_PORT_UCHAR... | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 0 | 500 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 11 | 0 | 500 | HalGetBusDataByOffset, MmMapIoSpace, READ_PORT_UCHAR... | GlobalSign CodeSigning CA |
| NTIOLib.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 11 | 0 | 500 | HalGetBusDataByOffset, MmMapIoSpace, READ_PORT_UCHAR... | GlobalSign CodeSigning CA |
| SysInfoDetectorX64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 0 | 144 | MmMapIoSpace | VeriSign Class 3 Public P |
| BS_RCIO64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 0 | 500 | HalGetBusDataByOffset, MmMapIoSpace, ObReferenceObjectByHandle... | Microsoft Windows Hardwar |
| BS_Def64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmMapIoSpace... | VeriSign Class 3 Code Sig |
| BS_Def64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmMapIoSpace... | VeriSign Class 3 Code Sig |
| BS_Def64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmMapIoSpace... | VeriSign Class 3 Code Sig |
| hw.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 42 | 1 | 103 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | GlobalSign Extended Valid |
| hw.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | GlobalSign CodeSigning CA |
| hw.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | GlobalSign CodeSigning CA |
| hw.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | GlobalSign Extended Valid |
| rwdrv.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 0 | 186 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | GlobalSign CodeSigning CA |
| rwdrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 26 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | GlobalSign CodeSigning CA |
| rwdrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 25 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | GlobalSign CodeSigning CA |
| rwdrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | GlobalSign CodeSigning CA |
| CupFixerx64.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 10 | 0 | 500 | ExFreePoolWithTag, MmAllocateContiguousMemory, MmGetPhysicalAddress... | Xinyi Electronic Technolo |
| SBIOSIO64.sys | vulnerable d | **15.0** | x86 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 43 | MmMapIoSpace, READ_PORT_UCHAR, READ_PORT_ULONG... | Samsung Electronics CO.\ |
| SBIOSIO64.sys | vulnerable d | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 0 | 314 | MmMapIoSpace | Samsung Electronics CO.\ |
| SBIOSIO64.sys | vulnerable d | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 0 | 298 | MmMapIoSpace | Samsung Electronics CO.\ |
| SBIOSIO64.sys | vulnerable d | **15.0** | x86 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 43 | MmMapIoSpace, READ_PORT_UCHAR, READ_PORT_ULONG... | Samsung Electronics CO.\ |
| CITMDRV_AMD64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 336 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_AMD64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 336 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_AMD64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 336 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_AMD64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 336 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_AMD64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 336 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_AMD64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 336 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_AMD64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 336 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_AMD64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 336 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_AMD64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 336 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_AMD64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 336 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_AMD64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 336 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_AMD64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 336 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_AMD64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 336 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_AMD64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 336 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_AMD64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 336 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| CITMDRV_AMD64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 336 | MmProbeAndLockPages, ZwCreateFile, ZwMapViewOfSection... | IBM Polska Sp. z o.o. |
| WiRwaDrv.sys | vulnerable d | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 439 | MmMapIoSpace | Symantec Class 3 Extended |
| avalueio.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 12 | 0 | 109 | MmMapIoSpace | Avalue Technology Inc. |
| avalueio.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 0 | 40 | MmMapIoSpace, READ_PORT_UCHAR, READ_PORT_ULONG... | Avalue Technology Inc. |
| MsIo64.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 75 | IoGetCurrentProcess, MmAllocateNonCachedMemory, ObReferenceObjectByHandle... | Symantec Class 3 Extended |
| MsIo64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 108 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | Symantec Class 3 Extended |
| MsIo64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 125 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | Microsoft Windows Hardwar |
| rtif.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 29 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | TenAsys Corporation |
| rtif.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 29 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | TenAsys Corporation |
| stdcdrvws64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 46 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | Intel(R) Tools and Techno |
| ATSZIO.sys | vulnerable d | **15.0** | x86 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 0 | 235 | ExAllocatePool, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| ATSZIO.sys | vulnerable d | **15.0** | x86 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 0 | 237 | ExAllocatePool, HalGetBusDataByOffset, MmAllocateContiguousMemory... | VeriSign Class 3 Public P |
| ATSZIO.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 22 | 0 | 13 | HalGetBusDataByOffset, MmAllocateContiguousMemory, MmGetPhysicalAddress... | VeriSign Class 3 Code Sig |
| tdeio64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 12 | 0 | 500 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmMapIoSpace... | PEGATRON CORPORATION |
| tdeio64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 12 | 0 | 500 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmMapIoSpace... | VeriSign Class 3 Code Sig |
| nvoclock.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 1 | 180 | MmGetPhysicalAddress, MmMapIoSpace, MmMapLockedPages | VeriSign Class 3 Code Sig |
| nvoclock.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 85 | MmGetPhysicalAddress, MmMapIoSpace, MmMapLockedPages | unsigned |
| nvoclock.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 1 | 161 | MmGetPhysicalAddress, MmMapIoSpace, MmMapLockedPages | unsigned |
| nvoclock.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 128 | MmGetPhysicalAddress, MmMapIoSpace, MmMapLockedPages | unsigned |
| nvoclock.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 122 | MmGetPhysicalAddress, MmMapIoSpace, MmMapLockedPages | unsigned |
| nvoclock.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 444 | MmGetPhysicalAddress, MmMapIoSpace, MmMapLockedPages | VeriSign Class 3 Code Sig |
| nvoclock.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 85 | MmGetPhysicalAddress, MmMapIoSpace, MmMapLockedPages | unsigned |
| nvoclock.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmGetPhysicalAddress, MmMapIoSpace, MmMapLockedPages... | VeriSign Class 3 Code Sig |
| nvoclock.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 122 | MmGetPhysicalAddress, MmMapIoSpace, MmMapLockedPages | unsigned |
| nvoclock.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 444 | MmGetPhysicalAddress, MmMapIoSpace, MmMapLockedPages | VeriSign Class 3 Code Sig |
| nvoclock.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmGetPhysicalAddress, MmMapIoSpace, MmMapLockedPages | VeriSign Class 3 Code Sig |
| nvoclock.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 122 | MmGetPhysicalAddress, MmMapIoSpace, MmMapLockedPages | unsigned |
| nvoclock.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 1 | 161 | MmGetPhysicalAddress, MmMapIoSpace, MmMapLockedPages | unsigned |
| nvoclock.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 444 | MmGetPhysicalAddress, MmMapIoSpace, MmMapLockedPages | VeriSign Class 3 Code Sig |
| nvoclock.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 71 | MmMapIoSpace, MmMapLockedPages | unsigned |
| nvoclock.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmGetPhysicalAddress, MmMapIoSpace, MmMapLockedPages | VeriSign Class 3 Code Sig |
| nvoclock.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmGetPhysicalAddress, MmMapIoSpace, MmMapLockedPages | VeriSign Class 3 Code Sig |
| nvoclock.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 1 | 144 | MmGetPhysicalAddress, MmMapIoSpace, MmMapLockedPages | unsigned |
| nvoclock.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmGetPhysicalAddress, MmMapIoSpace, MmMapLockedPages... | VeriSign Class 3 Code Sig |
| nvoclock.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmGetPhysicalAddress, MmMapIoSpace, MmMapLockedPages | VeriSign Class 3 Code Sig |
| nvoclock.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 441 | MmGetPhysicalAddress, MmMapIoSpace, MmMapLockedPages | GeoTrust TrustCenter Code |
| nvoclock.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 1 | 199 | MmGetPhysicalAddress, MmMapIoSpace, MmMapLockedPages | VeriSign Class 3 Code Sig |
| elbycdio.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 21 | 500 | ExAllocatePool, MmMapLockedPages, MmProbeAndLockPages... | Elaborate Bytes AG |
| elbycdio.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 207 | ExAllocatePool, MmMapLockedPages, MmProbeAndLockPages... | Elaborate Bytes AG |
| elbycdio.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 321 | ExAllocatePool, MmMapLockedPages, MmProbeAndLockPages... | unsigned |
| elbycdio.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 367 | ExAllocatePool, MmMapLockedPages, MmProbeAndLockPages... | unsigned |
| elbycdio.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 339 | ExAllocatePool, MmMapLockedPages, MmProbeAndLockPages... | unsigned |
| elbycdio.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 207 | ExAllocatePool, MmMapLockedPages, MmProbeAndLockPages... | Elaborate Bytes AG |
| elbycdio.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 15 | 269 | ExAllocatePool, MmMapLockedPages, MmProbeAndLockPages... | Elaborate Bytes AG |
| AsrIbDrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 24 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | VeriSign Class 3 Public P |
| NCHGBIOS2x64.SYS | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 11 | 0 | 454 | HalGetBusDataByOffset, MmAllocateContiguousMemory, MmGetPhysicalAddress... | VeriSign Class 3 Public P |
| NCHGBIOS2x64.SYS | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 11 | 0 | 447 | HalGetBusDataByOffset, MmAllocateContiguousMemory, MmGetPhysicalAddress... | VeriSign Class 3 Code Sig |
| BS_I2c64.sys, BS_I2cIo.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 0 | 234 | HalGetBusDataByOffset, MmMapIoSpace | VeriSign Class 3 Code Sig |
| ecsiodriverx64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 215 | HalGetBusDataByOffset, MmMapIoSpace | ELITEGROUP COMPUTER SYSTE |
| ecsiodriverx64.sys | vulnerable d | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 275 | HalGetBusDataByOffset, MmMapIoSpace | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 0 | 320 | HalGetBusDataByOffset, MmMapIoSpace, ObReferenceObjectByHandle... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 187 | HalGetBusDataByOffset, MmMapIoSpace, ObReferenceObjectByHandle... | unsigned |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | GlobalSign Extended Valid |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 203 | MmMapIoSpace, ObReferenceObjectByHandle, ZwMapViewOfSection... | VeriSign Class 3 Public P |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 206 | MmMapIoSpace, ObReferenceObjectByHandle, ZwMapViewOfSection... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 203 | MmMapIoSpace, ObReferenceObjectByHandle, ZwMapViewOfSection... | EVGA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 0 | 204 | HalGetBusDataByOffset, MmMapIoSpace, ObReferenceObjectByHandle... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 203 | MmMapIoSpace, ObReferenceObjectByHandle, ZwMapViewOfSection... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 203 | MmMapIoSpace, ObReferenceObjectByHandle, ZwMapViewOfSection... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 0 | 320 | HalGetBusDataByOffset, MmMapIoSpace, ObReferenceObjectByHandle... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 0 | 204 | HalGetBusDataByOffset, MmMapIoSpace, ObReferenceObjectByHandle... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 206 | MmMapIoSpace, ObReferenceObjectByHandle, ZwMapViewOfSection... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 206 | MmMapIoSpace, ObReferenceObjectByHandle, ZwMapViewOfSection... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 206 | MmMapIoSpace, ObReferenceObjectByHandle, ZwMapViewOfSection... | VeriSign Class 3 Public P |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 206 | MmMapIoSpace, ObReferenceObjectByHandle, ZwMapViewOfSection... | VeriSign Class 3 Public P |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 0 | 204 | HalGetBusDataByOffset, MmMapIoSpace, ObReferenceObjectByHandle... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 0 | 320 | HalGetBusDataByOffset, MmMapIoSpace, ObReferenceObjectByHandle... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 206 | MmMapIoSpace, ObReferenceObjectByHandle, ZwMapViewOfSection... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 203 | MmMapIoSpace, ObReferenceObjectByHandle, ZwMapViewOfSection... | EVGA |
| RTCore64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 206 | MmMapIoSpace, ObReferenceObjectByHandle, ZwMapViewOfSection... | GlobalSign CodeSigning CA |
| SmSerl64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 32 | 0 | 500 | ExAllocatePoolWithTag, IoGetDeviceObjectPointer, MmIsAddressValid... | unsigned |
| BS_Flash64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 303 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapIoSpace... | VeriSign Class 3 Code Sig |
| gdrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmAllocateContiguousMemory... | VeriSign Class 3 Code Sig |
| gdrv.sys | vulnerable d | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePool, ExFreePoolWithTag, MmAllocateContiguousMemory... | GIGA-BYTE TECHNOLOGY CO.\ |
| gdrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmAllocateContiguousMemory... | VeriSign Class 3 Code Sig |
| ALSysIO64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | Microsoft Windows Hardwar |
| ALSysIO64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | GlobalSign CodeSigning CA |
| ALSysIO64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 17 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | GlobalSign CodeSigning CA |
| ALSysIO64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | ALCPU (Arthur Liberman) |
| WinFlash64.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 17 | 0 | 348 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapIoSpace... | VeriSign Class 3 Code Sig |
| BioNTdrv.sys | vulnerable d | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 12 | 0 | 500 | MmMapIoSpace, MmMapLockedPages, ObReferenceObjectByHandle | Paragon Software GmbH |
| speedfan.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 137 | MmMapIoSpace | VeriSign Class 3 Code Sig |
| otipcibus.sys | vulnerable d | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 334 | ExAllocatePool, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Ours Technology Inc. |
| gdrv.sys | vulnerable d | **15.0** | x86 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 0 | 286 | ExAllocatePool, ExFreePoolWithTag, MmAllocateContiguousMemory... | Symantec Class 3 Extended |
| gdrv.sys | vulnerable d | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePool, ExFreePoolWithTag, MmAllocateContiguousMemory... | Symantec Class 3 Extended |
| gdrv.sys | vulnerable d | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePool, ExFreePoolWithTag, MmAllocateContiguousMemory... | Symantec Class 3 Extended |
| gdrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 22 | 0 | 500 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmIsAddressValid... | VeriSign Class 3 Code Sig |
| gdrv.sys | vulnerable d | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePool, ExFreePoolWithTag, MmAllocateContiguousMemory... | Symantec Class 3 Extended |
| gdrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmAllocateContiguousMemory... | GlobalSign CodeSigning CA |
| gdrv.sys | vulnerable d | **15.0** | x64 | GUARD_CF, GS_COOKIE | 12 | 1 | 500 | ExAllocatePool, ExFreePoolWithTag, MmAllocateContiguousMemory... | Symantec Class 3 Extended |
| gdrv.sys | vulnerable d | **15.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePool, ExFreePoolWithTag, MmAllocateContiguousMemory... | Symantec Class 3 Extended |
| gdrv.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 27 | 0 | 500 | ExAllocatePoolWithTag, MmAllocateContiguousMemory, MmGetPhysicalAddress... | VeriSign Class 3 Code Sig |
| gdrv.sys | vulnerable d | **15.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 22 | 0 | 500 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmMapIoSpace... | VeriSign Class 3 Code Sig |
| procexp.Sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 12 | 1 | 500 | ExAllocatePool, ExFreePoolWithTag, MmIsAddressValid... | VeriSign Class 3 Code Sig |
| procexp.Sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 14 | 1 | 500 | ExAllocatePool, ExFreePoolWithTag, MmIsAddressValid... | VeriSign Class 3 Code Sig |
| RwDrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 24 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| RwDrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 24 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | VeriSign Class 3 Public P |
| RwDrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 24 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | VeriSign Class 3 Public P |
| RwDrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 30 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | ccf(TestCo) |
| RwDrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 24 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| RwDrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 30 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | lab-z.com |
| RwDrv.sys | vulnerable d | **15.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 30 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | GlobalSign CodeSigning CA |
| GtcKmdfBs.sys | vulnerable d | **14.5** | x64 | GUARD_CF, GS_COOKIE | 9 | 1 | 500 | MmMapIoSpace | Symantec Class 3 Extended |
| GtcKmdfBs.sys | vulnerable d | **14.5** | x64 | GUARD_CF, GS_COOKIE | 9 | 1 | 500 | MmMapIoSpace | Symantec Class 3 Extended |
| GtcKmdfBs.sys | vulnerable d | **14.5** | x64 | GUARD_CF, GS_COOKIE | 9 | 1 | 500 | MmMapIoSpace | Symantec Class 3 Extended |
| GtcKmdfBs.sys | vulnerable d | **14.5** | x64 | GUARD_CF, GS_COOKIE | 9 | 1 | 500 | MmMapIoSpace | Symantec Class 3 Extended |
| gftkyj64.sys, deame.sys | malicious | **14.5** | x64 | GUARD_CF, GS_COOKIE | 5 | 0 | 494 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Zhuhai liancheng Technolo |
| echo_driver.sys | vulnerable d | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Hangzhou Shunwang Technol |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **14.5** | x64 | GUARD_CF, GS_COOKIE | 5 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmAllocateContiguousMemory... | ASUSTeK Computer Inc. |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **14.5** | x64 | GUARD_CF, GS_COOKIE | 26 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | DigiCert Trusted G4 Code  |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 250 | MmAllocateContiguousMemory, MmGetPhysicalAddress, ObReferenceObjectByHandle... | NVIDIA Corporation |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **14.5** | x64 | GUARD_CF, GS_COOKIE | 5 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmAllocateContiguousMemory... | ASUSTeK Computer Inc. |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **14.5** | x64 | GUARD_CF, GS_COOKIE | 5 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmAllocateContiguousMemory... | ASUSTeK Computer Inc. |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **14.5** | x64 | GUARD_CF, GS_COOKIE | 5 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmAllocateContiguousMemory... | ASUSTeK Computer Inc. |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **14.5** | x64 | GUARD_CF, GS_COOKIE | 26 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | DigiCert Trusted G4 Code  |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **14.5** | x64 | GUARD_CF, GS_COOKIE | 26 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | DigiCert Trusted G4 Code  |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **14.5** | x64 | GUARD_CF, GS_COOKIE | 5 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmAllocateContiguousMemory... | ASUSTeK Computer Inc. |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 285 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | VeriSign Class 3 Code Sig |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **14.5** | x64 | GUARD_CF, GS_COOKIE | 5 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmAllocateContiguousMemory... | ASUSTeK Computer Inc. |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **14.5** | x64 | GUARD_CF, GS_COOKIE | 7 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmAllocateContiguousMemory... | ASUSTeK Computer Inc. |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **14.5** | x64 | GUARD_CF, GS_COOKIE | 26 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | DigiCert Trusted G4 Code  |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **14.5** | x64 | GUARD_CF, GS_COOKIE | 8 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmAllocateContiguousMemory... | ASUSTeK Computer Inc. |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 232 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | VeriSign Class 3 Code Sig |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **14.5** | x64 | GUARD_CF, GS_COOKIE | 26 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | DigiCert Trusted G4 Code  |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 250 | MmAllocateContiguousMemory, MmGetPhysicalAddress, ObReferenceObjectByHandle... | VeriSign Class 3 Code Sig |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 250 | MmAllocateContiguousMemory, MmGetPhysicalAddress, ObReferenceObjectByHandle... | VeriSign Class 3 Public P |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 285 | MmAllocateContiguousMemory, MmGetPhysicalAddress, ObReferenceObjectByHandle... | VeriSign Class 3 Code Sig |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 250 | MmAllocateContiguousMemory, MmGetPhysicalAddress, ObReferenceObjectByHandle... | VeriSign Class 3 Code Sig |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 232 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | VeriSign Class 3 Code Sig |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 250 | MmAllocateContiguousMemory, MmGetPhysicalAddress, ObReferenceObjectByHandle... | ASUSTeK Computer Inc. |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 243 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | VeriSign Class 3 Code Sig |
| TfSysMon.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 24 | 2 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Code Sig |
| DirectIo.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 401 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Code Sig |
| ElbyCDIO.sys | vulnerable d | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 20 | 340 | ExAllocatePool, MmMapLockedPages, MmProbeAndLockPages... | Elaborate Bytes AG |
| ElbyCDIO.sys | vulnerable d | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 411 | ExAllocatePool, MmMapLockedPages, MmProbeAndLockPages... | Elaborate Bytes AG |
| ElbyCDIO.sys | vulnerable d | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 360 | ExAllocatePool, MmMapLockedPages, MmProbeAndLockPages... | Elaborate Bytes AG |
| KApcHelper_x64.sys | malicious | **14.5** | x64 | GUARD_CF, GS_COOKIE | 5 | 0 | 495 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | NVIDIA Corporation |
| driver_d9f15d91.sys | malicious | **14.5** | x64 | GUARD_CF, GS_COOKIE | 1 | 0 | 247 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | GlobalSign CodeSigning CA |
| inpoutx64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 0 | 279 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | RISINTECH INC. |
| inpoutx64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 0 | 279 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | RISINTECH INC. |
| inpoutx64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 0 | 275 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | VeriSign Class 3 Code Sig |
| tboflhelper.sys | vulnerable | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 251 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | TeraByte\ |
| driver_312c83a9.sys | malicious | **14.5** | x64 | GUARD_CF, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Shenzhen Hua’nan Xingfa E |
| driver_4f9b5a2f.sys | malicious | **14.5** | x64 | GUARD_CF, GS_COOKIE | 6 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Shenzhen Hua’nan Xingfa E |
| titidrv.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| K7RKScan.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| tfbfs3ped.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 185 | MmIsAddressValid, ObReferenceObjectByHandle, ZwMapViewOfSection... | Micro-Star Int'l Co. Ltd. |
| driver_146b8f4f.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Pinchins Technology Compa |
| WiseUnlo.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 188 | ObReferenceObjectByHandle | Lespeed Technology Ltd. |
| WiseUnlo.sys | vulnerable d | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 18 | ObReferenceObjectByHandle | COMODO RSA Extended Valid |
| WiseUnlo.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 178 | ObReferenceObjectByHandle | Beijing Lang Xingda Netwo |
| WiseUnlo.sys | vulnerable d | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 18 | ObReferenceObjectByHandle | Beijing Lang Xingda Netwo |
| WiseUnlo.sys | vulnerable d | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 0 | ObReferenceObjectByHandle | Lespeed Technology Ltd. |
| WiseUnlo.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 178 | ObReferenceObjectByHandle | COMODO RSA Extended Valid |
| WiseUnlo.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 178 | ObReferenceObjectByHandle | COMODO RSA Extended Valid |
| GLCKIO2.sys | vulnerable d | **14.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | ASUSTeK Computer Inc. |
| GLCKIO2.sys | vulnerable d | **14.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | ASUSTeK Computer Inc. |
| wnbios.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 7 | 0 | 332 | MmAllocateContiguousMemory, MmAllocateNonCachedMemory, MmGetPhysicalAddress... | Wincor Nixdorf Internatio |
| nvflsh64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 375 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | VeriSign Class 3 Public P |
| nvflsh64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 375 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | NVIDIA Corporation |
| nvflsh64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 375 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | VeriSign Class 3 Public P |
| nvflsh64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 375 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | VeriSign Class 3 Public P |
| nvflsh64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 375 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | VeriSign Class 3 Code Sig |
| nvflsh64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 375 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | NVIDIA Corporation |
| nvflsh64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 375 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | NVIDIA Corporation |
| nvflsh64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 375 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | VeriSign Class 3 Public P |
| nvflsh64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 375 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | NVIDIA Corporation |
| nvflsh64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 375 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | VeriSign Class 3 Code Sig |
| nvflsh64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 375 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | NVIDIA Corporation |
| nvflsh64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 375 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | VeriSign Class 3 Code Sig |
| nvflsh64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 375 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | VeriSign Class 3 Public P |
| nvflsh64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 375 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | VeriSign Class 3 Public P |
| nvflsh64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 375 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | VeriSign Class 3 Public P |
| HOSTNT.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 364 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | VeriSign Class 3 Code Sig |
| prokiller64.sys | malicious | **14.5** | x64 | GUARD_CF, GS_COOKIE | 5 | 0 | 494 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Zhuhai liancheng Technolo |
| iobitunlocker.sys | vulnerable d | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | VeriSign Class 3 Code Sig |
| iobitunlocker.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | VeriSign Class 3 Code Sig |
| iobitunlocker.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | VeriSign Class 3 Code Sig |
| iobitunlocker.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | IObit Information Technol |
| iobitunlocker.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | IObit CO.\ |
| iobitunlocker.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | IObit Information Technol |
| iobitunlocker.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | IObit Information Technol |
| iobitunlocker.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | IObit Information Technol |
| iobitunlocker.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | IObit Information Technol |
| LgCoreTemp.sys | vulnerable d | **14.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 231 | HalGetBusDataByOffset | Logitech |
| LgCoreTemp.sys | vulnerable d | **14.5** | x86 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 0 | 291 | HalGetBusDataByOffset | Logitech |
| VProEventMonitor.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Public P |
| AsUpIO.sys, AsUpIO64.sys | vulnerable d | **14.5** | x64 | GUARD_CF, GS_COOKIE | 5 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmAllocateContiguousMemory... | ASUSTeK Computer Inc. |
| AsUpIO.sys, AsUpIO64.sys | vulnerable d | **14.5** | x64 | GUARD_CF, GS_COOKIE | 5 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmAllocateContiguousMemory... | ASUSTeK Computer Inc. |
| AsUpIO.sys, AsUpIO64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 323 | MmAllocateContiguousMemory, MmGetPhysicalAddress, ObReferenceObjectByHandle... | VeriSign Class 3 Code Sig |
| stdcdrv64.sys | vulnerable d | **14.5** | x64 | GUARD_CF, GS_COOKIE | 15 | 0 | 500 | MmMapIoSpace | Intel Corporation |
| segwindrvx64.sys | vulnerable d | **14.5** | x86 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 57 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Public P |
| NSecKrnl.sys | vulnerable d | **14.5** | x64 | GUARD_CF, GS_COOKIE | 3 | 0 | 353 | IoGetCurrentProcess, ObOpenObjectByPointer, ObRegisterCallbacks... | Shandong Anzai Informatio |
| mimikatz.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObOpenObjectByPointer... | GlobalSign CodeSigning CA |
| mimikatz.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObOpenObjectByPointer... | GlobalSign CodeSigning CA |
| mimikatz.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObOpenObjectByPointer... | GlobalSign CodeSigning CA |
| mimikatz.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObOpenObjectByPointer... | GlobalSign CodeSigning CA |
| mimikatz.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObOpenObjectByPointer... | GlobalSign CodeSigning CA |
| mimikatz.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObOpenObjectByPointer... | GlobalSign CodeSigning CA |
| mimikatz.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObOpenObjectByPointer... | GlobalSign CodeSigning CA |
| mimikatz.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObOpenObjectByPointer... | GlobalSign CodeSigning CA |
| mimikatz.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObOpenObjectByPointer... | GlobalSign CodeSigning CA |
| mimikatz.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObOpenObjectByPointer... | GlobalSign CodeSigning CA |
| mimikatz.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObOpenObjectByPointer... | GlobalSign CodeSigning CA |
| mimikatz.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObOpenObjectByPointer... | GlobalSign CodeSigning CA |
| amigendrv64.sys | vulnerable d | **14.5** | x64 | GUARD_CF, GS_COOKIE | 10 | 0 | 500 | ExFreePoolWithTag, MmAllocateContiguousMemory, MmGetPhysicalAddress... | AMI US HOLDINGS INC |
| driver_d1ea9e16.sys | malicious | **14.5** | x64 | GUARD_CF, GS_COOKIE | 6 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Shenzhen Hua’nan Xingfa E |
| ngiodriver.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 7 | 0 | 145 |  | AVAST Software a.s. |
| ngiodriver.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 7 | 0 | 145 |  | AVAST Software a.s. |
| ngiodriver.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 7 | 0 | 145 |  | AVAST Software a.s. |
| ngiodriver.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 7 | 0 | 145 |  | AVAST Software a.s. |
| driver_16773074.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 375 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | GlobalSign CodeSigning CA |
| WINIODrv.sys | vulnerable d | **14.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 234 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | Partner Tech(Shanghai)Co. |
| WINIODrv.sys | vulnerable d | **14.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 234 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | Partner Tech(Shanghai)Co. |
| WINIODrv.sys | vulnerable d | **14.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 234 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | Partner Tech(Shanghai)Co. |
| nvflash.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 375 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | VeriSign Class 3 Code Sig |
| nvflash.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 375 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | NVIDIA Corporation |
| nvflash.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 375 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | VeriSign Class 3 Public P |
| nvflash.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 375 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | NVIDIA Corporation |
| nvflash.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 375 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | VeriSign Class 3 Code Sig |
| nvflash.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 375 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | VeriSign Class 3 Public P |
| Se64a.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 155 | HalGetBusDataByOffset, ObReferenceObjectByHandle, RtlCopyMemory... | EnTech Taiwan |
| driver_a6deeea6.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 375 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | GlobalSign CodeSigning CA |
| rtcoremini64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 12 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | GlobalSign Extended Valid |
| GLCKIO2.sys | vulnerable d | **14.5** | x64 | GUARD_CF, GS_COOKIE | 5 | 0 | 500 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | ASUSTeK Computer Inc. |
| HwOs2Ec7x64.sys | vulnerable d | **14.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 2 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Huawei Technologies Co.\ |
| RTCore64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 185 | MmIsAddressValid, ObReferenceObjectByHandle, ZwMapViewOfSection... | Micro-Star Int'l Co. Ltd. |
| RTCore64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 185 | MmIsAddressValid, ObReferenceObjectByHandle, ZwMapViewOfSection... | EVGA |
| RTCore64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 185 | MmIsAddressValid, ObReferenceObjectByHandle, ZwMapViewOfSection... | EVGA |
| RTCore64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 185 | MmIsAddressValid, ObReferenceObjectByHandle, ZwMapViewOfSection... | VeriSign Class 3 Code Sig |
| RTCore64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 185 | MmIsAddressValid, ObReferenceObjectByHandle, ZwMapViewOfSection... | VeriSign Class 3 Code Sig |
| RTCore64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 185 | MmIsAddressValid, ObReferenceObjectByHandle, ZwMapViewOfSection... | EVGA |
| asmmap64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 0 | 151 | MmAllocateContiguousMemory, MmGetPhysicalAddress, MmMapLockedPages... | VeriSign Class 3 Code Sig |
| eneio64.sys | vulnerable d | **14.5** | x64 | GUARD_CF, GS_COOKIE | 3 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | DigiCert Trusted G4 Code  |
| Driver7.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 30 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | VeriSign Class 3 Public P |
| fidpcidrv64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset | Intel(R) Processor Identi |
| WCPU.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 0 | 353 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | VeriSign Class 3 Code Sig |
| fiddrv64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 151 |  | Intel(R) Processor Identi |
| VBoxUSBMon.sys | vulnerable d | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 224 | ExAllocatePoolWithTag, IoGetDeviceObjectPointer | InnoTek Systemberatung Gm |
| VBoxUSBMon.sys | vulnerable d | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | innotek GmbH |
| SSPORT.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 108 |  | VeriSign Class 3 Code Sig |
| elbycdio.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 4 | 92 | ZwCreateFile | Elaborate Bytes AG |
| elbycdio.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 4 | 92 | ZwCreateFile | Elaborate Bytes AG |
| elbycdio.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 4 | 92 | ZwCreateFile | Elaborate Bytes AG |
| elbycdio.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 20 | 20 | 500 | ExAllocatePool, MmMapLockedPages, MmProbeAndLockPages... | Elaborate Bytes AG |
| elbycdio.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 20 | 20 | 500 | ExAllocatePool, MmMapLockedPages, MmProbeAndLockPages... | Elaborate Bytes AG |
| elbycdio.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 20 | 20 | 500 | ExAllocatePool, MmMapLockedPages, MmProbeAndLockPages... | Elaborate Bytes AG |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 13 | 499 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Certum Code Signing CA SH |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 13 | 499 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 20 | 20 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 18 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Certum Code Signing CA SH |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 18 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Certum Code Signing CA SH |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 13 | 499 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Certum Code Signing CA SH |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Certum Code Signing CA SH |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 22 | 20 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Certum Code Signing CA SH |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 20 | 20 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 22 | 20 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 20 | 20 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 20 | 18 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 22 | 20 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 20 | 18 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Certum Code Signing CA SH |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 22 | 20 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 20 | 20 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Certum Code Signing CA SH |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 20 | 20 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Benjamin Delpy |
| mimidrv.sys | malicious | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| mimidrv.sys | malicious | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| RTCore64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 185 | MmIsAddressValid, ObReferenceObjectByHandle, ZwMapViewOfSection... | EVGA |
| RTCore64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 185 | MmIsAddressValid, ObReferenceObjectByHandle, ZwMapViewOfSection... | VeriSign Class 3 Code Sig |
| RTCore64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 185 | MmIsAddressValid, ObReferenceObjectByHandle, ZwMapViewOfSection... | EVGA |
| RTCore64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 185 | MmIsAddressValid, ObReferenceObjectByHandle, ZwMapViewOfSection... | VeriSign Class 3 Code Sig |
| RTCore64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 185 | MmIsAddressValid, ObReferenceObjectByHandle, ZwMapViewOfSection... | EVGA |
| RTCore64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 185 | MmIsAddressValid, ObReferenceObjectByHandle, ZwMapViewOfSection... | EVGA |
| RTCore64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 185 | MmIsAddressValid, ObReferenceObjectByHandle, ZwMapViewOfSection... | VeriSign Class 3 Code Sig |
| RTCore64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 185 | MmIsAddressValid, ObReferenceObjectByHandle, ZwMapViewOfSection... | EVGA |
| RTCore64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 185 | MmIsAddressValid, ObReferenceObjectByHandle, ZwMapViewOfSection... | EVGA |
| RTCore64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 185 | MmIsAddressValid, ObReferenceObjectByHandle, ZwMapViewOfSection... | VeriSign Class 3 Code Sig |
| RTCore64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 185 | MmIsAddressValid, ObReferenceObjectByHandle, ZwMapViewOfSection... | Micro-Star Int'l Co. Ltd. |
| RTCore64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 185 | MmIsAddressValid, ObReferenceObjectByHandle, ZwMapViewOfSection... | Micro-Star Int'l Co. Ltd. |
| RTCore64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 185 | MmIsAddressValid, ObReferenceObjectByHandle, ZwMapViewOfSection... | Micro-Star Int'l Co. Ltd. |
| RTCore64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 185 | MmIsAddressValid, ObReferenceObjectByHandle, ZwMapViewOfSection... | VeriSign Class 3 Code Sig |
| RTCore64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 185 | MmIsAddressValid, ObReferenceObjectByHandle, ZwMapViewOfSection... | Micro-Star Int'l Co. Ltd. |
| RTCore64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 185 | MmIsAddressValid, ObReferenceObjectByHandle, ZwMapViewOfSection... | Micro-Star Int'l Co. Ltd. |
| RTCore64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 185 | MmIsAddressValid, ObReferenceObjectByHandle, ZwMapViewOfSection... | VeriSign Class 3 Code Sig |
| RTCore64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 185 | MmIsAddressValid, ObReferenceObjectByHandle, ZwMapViewOfSection... | VeriSign Class 3 Code Sig |
| RTCore64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 185 | MmIsAddressValid, ObReferenceObjectByHandle, ZwMapViewOfSection... | EVGA |
| RTCore64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 185 | MmIsAddressValid, ObReferenceObjectByHandle, ZwMapViewOfSection... | VeriSign Class 3 Code Sig |
| RTCore64.sys | vulnerable d | **14.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 185 | MmIsAddressValid, ObReferenceObjectByHandle, ZwMapViewOfSection... | EVGA |
| driver_1afc1d06.sys | malicious | **14.5** | x64 | GUARD_CF, GS_COOKIE | 6 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Shenzhen Hua’nan Xingfa E |
| BioNTdrv.sys | vulnerable d | **14.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 268 | MmMapIoSpace, MmMapLockedPages, ObReferenceObjectByHandle... | DigiCert Trusted G4 Code  |
| procexp.Sys | vulnerable d | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | Sysinternals |
| procexp.Sys | vulnerable d | **14.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 7 | 0 | 270 | ExAllocatePoolWithTag, MmIsAddressValid, ObOpenObjectByPointer... | VeriSign Class 3 Code Sig |
| cg6kwin2k.sys | vulnerable d | **14.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Microsoft Windows Hardwar |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **14.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 232 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | unsigned |
| iobitunlocker.sys | vulnerable d | **14.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | unsigned |
| iobitunlocker.sys | vulnerable d | **14.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | unsigned |
| dbk64.sys | vulnerable d | **14.0** | x64 | GUARD_CF, GS_COOKIE | 87 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | GlobalSign Extended Valid |
| bd1f381e5a3db22e88776b7873d4d2835e9a1ec620571d2b1da0c58f81c84a56 | malicious dr | **14.0** | x64 | GUARD_CF, GS_COOKIE | 2 | 0 | 455 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObOpenObjectByPointer... | unsigned |
| rtif.sys | vulnerable d | **14.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 33 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | TenAsys Corporation |
| rtif.sys | vulnerable d | **14.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 33 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | TenAsys Corporation |
| rtif.sys | vulnerable d | **14.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 29 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | TenAsys Corporation |
| nvoclock.sys | vulnerable d | **14.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 313 |  | unsigned |
| nvoclock.sys | vulnerable d | **14.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 313 |  | unsigned |
| nvoclock.sys | vulnerable d | **14.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 |  | unsigned |
| elbycdio.sys | vulnerable d | **14.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 7 | 0 | ZwCreateFile, ZwCreateKey, ZwDeleteKey... | unsigned |
| elbycdio.sys | vulnerable d | **14.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 8 | 20 | ZwCreateFile, ZwCreateKey, ZwOpenKey | unsigned |
| elbycdio.sys | vulnerable d | **14.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 25 | 25 | 297 | ExAllocatePoolWithTag, IoGetDeviceObjectPointer, MmMapLockedPages... | unsigned |
| elbycdio.sys | vulnerable d | **14.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 14 | 14 | 204 | ExAllocatePoolWithTag, MmMapLockedPages, MmProbeAndLockPages... | unsigned |
| RTCore64.sys | vulnerable d | **14.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 185 | MmIsAddressValid, ObReferenceObjectByHandle, ZwMapViewOfSection... | unsigned |
| RTCore64.sys | vulnerable d | **14.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 185 | MmIsAddressValid, ObReferenceObjectByHandle, ZwMapViewOfSection... | unsigned |
| aswVmm.sys | vulnerable d | **14.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Public P |
| LgDCatcher.sys | vulnerable d | **13.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | 雷神（武汉）信息技术有限公司 |
| wantd_6.sys | malicious | **13.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeInsertQueueApc... | Anhua Xinda (Beijing) Tec |
| wantd_5.sys | malicious | **13.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeInsertQueueApc... | Anhua Xinda (Beijing) Tec |
| wantd_4.sys | malicious | **13.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeInsertQueueApc... | Anhua Xinda (Beijing) Tec |
| iobitunlocker.sys | vulnerable d | **13.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | VeriSign Class 3 Code Sig |
| iobitunlocker.sys | vulnerable d | **13.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | VeriSign Class 3 Code Sig |
| iobitunlocker.sys | vulnerable d | **13.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | IObit Information Technol |
| iobitunlocker.sys | vulnerable d | **13.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | IObit Information Technol |
| iobitunlocker.sys | vulnerable d | **13.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | IObit Information Technol |
| driver_090d409f.sys | malicious | **13.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | WoSign EV Code Signing CA |
| viragt.sys | vulnerable d | **13.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 32 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | VeriSign Class 3 Public P |
| driver_930da474.sys | malicious | **13.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Pinchins Technology Compa |
| viraglt64.sys, viragt64.sys | vulnerable d | **13.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 34 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | VeriSign Class 3 Public P |
| jnprva.sys, neofltr.sys | vulnerable | **13.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Symantec Class 3 Extended |
| driver_206006a1.sys | malicious | **13.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Shenzhen Hua’nan Xingfa E |
| daxin_blank.sys | malicious | **13.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeInsertQueueApc... | Anhua Xinda (Beijing) Tec |
| sandra.sys | vulnerable d | **13.5** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | HalGetBusDataByOffset, MmMapIoSpace, MmMapLockedPagesSpecifyCache... | GeoTrust TrustCenter Code |
| viragt64.sys | vulnerable d | **13.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 30 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | VeriSign Class 3 Code Sig |
| viragt64.sys | vulnerable d | **13.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 32 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | VeriSign Class 3 Public P |
| rzpnk.sys | vulnerable d | **13.5** | x86 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | Razer USA Ltd. |
| rzpnk.sys | vulnerable d | **13.5** | x86 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | Razer USA Ltd. |
| rzpnk.sys | vulnerable d | **13.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | Razer Inc. |
| rzpnk.sys | vulnerable d | **13.5** | x86 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | Razer USA Ltd. |
| rzpnk.sys | vulnerable d | **13.5** | x86 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | Razer USA Ltd. |
| rzpnk.sys | vulnerable d | **13.5** | x86 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | Razer USA Ltd. |
| rzpnk.sys | vulnerable d | **13.5** | x86 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | Razer USA Ltd. |
| rzpnk.sys | vulnerable d | **13.5** | x86 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 12 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | Razer Inc. |
| rzpnk.sys | vulnerable d | **13.5** | x86 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | Razer USA Ltd. |
| rzpnk.sys | vulnerable d | **13.5** | x86 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 12 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | Razer Inc. |
| driver_89036534.sys | malicious | **13.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Shenzhen Jinxian Technolo |
| wantd.sys | malicious | **13.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeInsertQueueApc... | Anhua Xinda (Beijing) Tec |
| CP2X72C.SYS | vulnerable d | **13.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 29 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Symantec Class 3 Extended |
| CP2X72C.SYS | vulnerable d | **13.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 29 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Public P |
| truesight.sys | vulnerable d | **13.5** | x64 | GUARD_CF, GS_COOKIE | 16 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Sectigo Public Code Signi |
| ATSZIO.sys, ATSZIO64.sys | vulnerable d | **13.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 333 | ExAllocatePool, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| netfilter2.sys | vulnerable d | **13.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | 九江宏图无忧科技有限公司 |
| netfilter2.sys | vulnerable d | **13.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | 九江宏图无忧科技有限公司 |
| netfilter2.sys | vulnerable d | **13.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | 九江宏图无忧科技有限公司 |
| netfilter2.sys | vulnerable d | **13.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | 九江宏图无忧科技有限公司 |
| netfilter2.sys | vulnerable d | **13.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | 九江宏图无忧科技有限公司 |
| netfilter2.sys | vulnerable d | **13.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | 九江宏图无忧科技有限公司 |
| wantd_2.sys | malicious | **13.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeInsertQueueApc... | Anhua Xinda (Beijing) Tec |
| vmdrv.sys | vulnerable d | **13.5** | x64 | GUARD_CF, GS_COOKIE | 6 | 5 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle | Voicemod Sociedad Limitad |
| vmdrv.sys | vulnerable d | **13.5** | x64 | GUARD_CF, GS_COOKIE | 6 | 5 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle | Voicemod Sociedad Limitad |
| driver_1a74c2bd.sys | malicious | **13.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Pinchins Technology Compa |
| ATSZIO.sys | vulnerable d | **13.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 325 | ExAllocatePool, HalGetBusDataByOffset, MmAllocateContiguousMemory... | VeriSign Class 3 Public P |
| ATSZIO.sys | vulnerable d | **13.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 305 | ExAllocatePool, ExFreePoolWithTag, HalGetBusDataByOffset... | ASUSTeK COMPUTER INC. |
| ATSZIO.sys | vulnerable d | **13.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 305 | ExAllocatePool, ExFreePoolWithTag, HalGetBusDataByOffset... | VeriSign Class 3 Public P |
| ATSZIO.sys | vulnerable d | **13.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 311 | ExAllocatePool, ExFreePoolWithTag, HalGetBusDataByOffset... | ASUSTeK Computer Inc. |
| libnicm.sys | vulnerable d | **13.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 6 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Code Sig |
| procexp.Sys | vulnerable d | **13.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | Sysinternals |
| procexp.Sys | vulnerable d | **13.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | VeriSign Class 3 Code Sig |
| procexp.Sys | vulnerable d | **13.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | Sysinternals |
| procexp.Sys | vulnerable d | **13.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 14 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | Sysinternals |
| procexp.Sys | vulnerable d | **13.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | Sysinternals |
| procexp.Sys | vulnerable d | **13.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | Sysinternals |
| procexp.Sys | vulnerable d | **13.5** | unknown | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 0 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | VeriSign Class 3 Code Sig |
| procexp.Sys | vulnerable d | **13.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | Sysinternals |
| procexp.Sys | vulnerable d | **13.5** | x86 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 0 | 480 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | MSIT Test CodeSign CA 2 |
| procexp.Sys | vulnerable d | **13.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | Sysinternals |
| vmdrv.sys | vulnerable d | **13.5** | x64 | GUARD_CF, GS_COOKIE | 6 | 5 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle | DigiCert Global G3 Code S |
| echo_driver.sys | vulnerable d | **13.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Microsoft Windows Hardwar |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **13.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 250 | MmAllocateContiguousMemory, MmGetPhysicalAddress, ObReferenceObjectByHandle... | Microsoft Windows Hardwar |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **13.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 250 | MmAllocateContiguousMemory, MmGetPhysicalAddress, ObReferenceObjectByHandle... | Microsoft Windows Hardwar |
| asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys | vulnerable d | **13.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 250 | MmAllocateContiguousMemory, MmGetPhysicalAddress, ObReferenceObjectByHandle... | Microsoft Windows Hardwar |
| msr.sys | vulnerable d | **13.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 0 | 315 | HalGetBusDataByOffset, ZwMapViewOfSection, ZwUnmapViewOfSection | Microsoft Windows Hardwar |
| ene.sys | vulnerable d | **13.0** | x64 | GUARD_CF, GS_COOKIE | 3 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | Microsoft Windows Hardwar |
| FH-EtherCAT_DIO.sys | vulnerable d | **13.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 69 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapIoSpace... | unsigned |
| iobitunlocker.sys | vulnerable d | **13.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | unsigned |
| K7RKScan.sys | vulnerable d | **13.0** | x64 | GUARD_CF, GS_COOKIE | 74 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Microsoft Windows Hardwar |
| dellinstrumentation.sys | vulnerable d | **13.0** | x64 | GUARD_CF, GS_COOKIE | 16 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | Microsoft Windows Hardwar |
| DBUtilDrv2.sys | vulnerable d | **13.0** | x64 | GUARD_CF, GS_COOKIE | 12 | 0 | 500 | MmGetPhysicalAddress, MmMapIoSpace | Microsoft Windows Hardwar |
| DBUtilDrv2.sys | vulnerable d | **13.0** | x64 | GUARD_CF, GS_COOKIE | 12 | 1 | 500 | MmGetPhysicalAddress, MmMapIoSpace | Microsoft Windows Hardwar |
| 2.sys | malicious | **13.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 363 | ExAllocatePoolWithTag, ExFreePoolWithTag | Microsoft Windows Hardwar |
| POORTRY1.sys | malicious | **13.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 363 | ExAllocatePoolWithTag, ExFreePoolWithTag | Microsoft Windows Hardwar |
| VBoxDrv.sys | vulnerable d | **13.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 157 | 30 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Huiping Zhong |
| EneTechIo64.sys | vulnerable d | **13.0** | x64 | GUARD_CF, GS_COOKIE | 5 | 0 | 500 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | Microsoft Windows Hardwar |
| wantd_3.sys | malicious | **13.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 1 | 500 | ExAllocatePoolWithTag, KeInsertQueueApc, MmMapLockedPagesSpecifyCache... | unsigned |
| daxin_blank5.sys | malicious | **13.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 431 | ExAllocatePoolWithTag, IoGetCurrentProcess, KeInsertQueueApc... | unsigned |
| MsIo64.sys | vulnerable d | **13.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 113 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | Microsoft Windows Hardwar |
| rtif.sys | vulnerable d | **13.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 39 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | TenAsys Corporation |
| rtif.sys | vulnerable d | **13.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 52 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | TenAsys Corporation |
| mimidrv.sys | malicious | **13.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Microsoft Windows |
| procexp.Sys | vulnerable d | **13.0** | arm64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 0 | 0 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | Microsoft Windows Hardwar |
| LgDCatcher.sys | vulnerable d | **12.5** | x64 | GUARD_CF, GS_COOKIE | 20 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | 雷神（武汉）信息技术有限公司 |
| ProxyDrv.sys | vulnerable d | **12.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 20 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | 雷神（武汉）信息技术有限公司 |
| e939448b28a4edc81f1f974cebf6e7d2.sys | malicious | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Beijing JoinHope Image Te |
| Phymemx64.sys | vulnerable d | **12.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 360 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | Huawei Technologies Co.\ |
| Phymemx64.sys | vulnerable d | **12.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 360 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | Huawei Technologies Co.\ |
| winio64.sys | vulnerable d | **12.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 0 | 423 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | Exacq Technologies\ |
| LMIinfo.sys | vulnerable d | **12.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | LogMeIn\ |
| 6771b13a53b9c7449d4891e427735ea2.sys | malicious | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Beijing JoinHope Image Te |
| filwfp.sys | vulnerable d | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePoolWithTag, MmIsAddressValid, MmMapLockedPagesSpecifyCache... | VeriSign Class 3 Public P |
| BdApiUtil.sys | vulnerable d | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 12 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Public P |
| a9df5964635ef8bd567ae487c3d214c4.sys | malicious | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Beijing JoinHope Image Te |
| GVCIDrv64.sys | vulnerable d | **12.5** | x64 | GUARD_CF, GS_COOKIE | 3 | 0 | 414 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | GIGA-BYTE TECHNOLOGY CO.\ |
| DcProtect.sys | vulnerable d | **12.5** | x64 | GUARD_CF, GS_COOKIE | 1 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Jiangmen Eyun Network Co. |
| DcProtect.sys | vulnerable d | **12.5** | x86 | GUARD_CF, GS_COOKIE | 0 | 0 | 154 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Jiangmen Eyun Network Co. |
| DcProtect.sys | vulnerable d | **12.5** | x64 | GUARD_CF, GS_COOKIE | 1 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Jiangmen Eyun Network Co. |
| DcProtect.sys | vulnerable d | **12.5** | x86 | GUARD_CF, GS_COOKIE | 0 | 0 | 154 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Jiangmen Eyun Network Co. |
| DcProtect.sys | vulnerable d | **12.5** | x64 | GUARD_CF, GS_COOKIE | 1 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Jiangmen Eyun Network Co. |
| DcProtect.sys | vulnerable d | **12.5** | x86 | GUARD_CF, GS_COOKIE | 0 | 0 | 154 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Jiangmen Eyun Network Co. |
| DcProtect.sys | vulnerable d | **12.5** | x64 | GUARD_CF, GS_COOKIE | 1 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Jiangmen Eyun Network Co. |
| DcProtect.sys | vulnerable d | **12.5** | x86 | GUARD_CF, GS_COOKIE | 1 | 0 | 155 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Jiangmen Eyun Network Co. |
| SANDRA.sys | vulnerable d | **12.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 32 | 0 | 407 | HalGetBusDataByOffset, MmMapIoSpace, MmMapLockedPagesSpecifyCache... | GeoTrust TrustCenter Code |
| 1fc7aeeff3ab19004d2e53eae8160ab1.sys | malicious | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Beijing JoinHope Image Te |
| 4118b86e490aed091b1a219dba45f332.sys | malicious | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Beijing JoinHope Image Te |
| msrhook.sys | vulnerable d | **12.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 11 | 0 | 500 | PsCreateSystemThread | ID TECH |
| driver_4fc254af.sys | malicious | **12.5** | x64 | GUARD_CF, GS_COOKIE | 5 | 0 | 414 | IoGetCurrentProcess, KeStackAttachProcess, KeUnstackDetachProcess... | Shenzhen yundian Technolo |
| winio64.sys | vulnerable d | **12.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 0 | 423 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | Exacq Technologies\ |
| winio64.sys | vulnerable d | **12.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 0 | 423 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | Exacq Technologies\ |
| sandra.sys | vulnerable d | **12.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 29 | 0 | 278 | HalGetBusDataByOffset, MmMapIoSpace, MmMapLockedPagesSpecifyCache... | Thawte Code Signing CA |
| sandra.sys | vulnerable d | **12.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 34 | 0 | 500 | HalGetBusDataByOffset, MmMapIoSpace, MmMapLockedPagesSpecifyCache... | GeoTrust TrustCenter Code |
| rzpnk.sys | vulnerable d | **12.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 12 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Razer USA Ltd. |
| rzpnk.sys | vulnerable d | **12.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 12 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Razer USA Ltd. |
| rzpnk.sys | vulnerable d | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 11 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Razer Inc. |
| rzpnk.sys | vulnerable d | **12.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 12 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Razer USA Ltd. |
| rzpnk.sys | vulnerable d | **12.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Razer USA Ltd. |
| rzpnk.sys | vulnerable d | **12.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 12 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Razer Inc. |
| rzpnk.sys | vulnerable d | **12.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 12 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Razer Inc. |
| rzpnk.sys | vulnerable d | **12.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 12 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Razer USA Ltd. |
| rzpnk.sys | vulnerable d | **12.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 12 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Razer USA Ltd. |
| rzpnk.sys | vulnerable d | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 11 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Razer Inc. |
| rzpnk.sys | vulnerable d | **12.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 12 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Razer USA Ltd. |
| be6318413160e589080df02bb3ca6e6a.sys | malicious | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Beijing JoinHope Image Te |
| a236e7d654cd932b7d11cb604629a2d0.sys | malicious | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Beijing JoinHope Image Te |
| gvcidrv64.sys | vulnerable d | **12.5** | x64 | GUARD_CF, GS_COOKIE | 3 | 0 | 414 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | Symantec Class 3 Extended |
| ef0e1725aaf0c6c972593f860531a2ea.sys | malicious | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Beijing JoinHope Image Te |
| driver_290bc782.sys | malicious | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapIoSpace... | Shenzhen Jinxian Technolo |
| kavservice.bin | malicious | **12.5** | x64 | GUARD_CF, GS_COOKIE | 1 | 0 | 147 | ZwOpenProcess, ZwTerminateProcess | GlobalSign Code Signing R |
| CP2X72C.SYS | vulnerable d | **12.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 28 | 0 | 500 | ExAllocatePoolWithTag, HalGetBusDataByOffset, MmMapIoSpace... | VeriSign Class 3 Code Sig |
| a26363e7b02b13f2b8d697abb90cd5c3.sys | malicious | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Beijing JoinHope Image Te |
| 4748696211bd56c2d93c21cab91e82a5.sys | malicious | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Beijing JoinHope Image Te |
| nscm.sys | vulnerable d | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 1 | 500 | IoGetCurrentProcess | VeriSign Class 3 Code Sig |
| nscm.sys | vulnerable d | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 1 | 500 | IoGetCurrentProcess | VeriSign Class 3 Code Sig |
| nscm.sys | vulnerable d | **12.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 0 | 492 | IoGetCurrentProcess | VeriSign Class 3 Code Sig |
| gametersafe.sys | vulnerable d | **12.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | 大连纵梦网络科技有限公司 |
| c94f405c5929cfcccc8ad00b42c95083.sys | malicious | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Beijing JoinHope Image Te |
| e29f6311ae87542b3d693c1f38e4e3ad.sys | malicious | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Beijing JoinHope Image Te |
| netfilter2.sys | vulnerable d | **12.5** | x86 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 23 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | 九江宏图无忧科技有限公司 |
| netfilter2.sys | vulnerable d | **12.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 20 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | SYSTWEAK SOFTWARE PVT. LT |
| netfilter2.sys | vulnerable d | **12.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 20 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | 武汉内瑟斯科技有限公司 |
| netfilter2.sys | vulnerable d | **12.5** | x86 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 23 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | 浙江强云信息科技有限公司 |
| netfilter2.sys | vulnerable d | **12.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 20 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | 浙江强云信息科技有限公司 |
| netfilter2.sys | vulnerable d | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 20 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | 九江宏图无忧科技有限公司 |
| netfilter2.sys | vulnerable d | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | 浙江强云信息科技有限公司 |
| netfilter2.sys | vulnerable d | **12.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 20 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Orange |
| netfilter2.sys | vulnerable d | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Orange |
| netfilter2.sys | vulnerable d | **12.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 20 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | 武汉内瑟斯科技有限公司 |
| netfilter2.sys | vulnerable d | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 20 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | 九江宏图无忧科技有限公司 |
| netfilter2.sys | vulnerable d | **12.5** | x86 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 23 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | SYSTWEAK SOFTWARE PVT. LT |
| netfilter2.sys | vulnerable d | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 20 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | 九江宏图无忧科技有限公司 |
| wsdkd.sys | vulnerable d | **12.5** | x64 | GUARD_CF, GS_COOKIE | 4 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObReferenceObjectByHandle... | WATCHDOGDEVELOPMENT.COM\ |
| BdApiUtil64.sys | vulnerable d | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 12 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Public P |
| 5a4fe297c7d42539303137b6d75b150d.sys | malicious | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Beijing JoinHope Image Te |
| ATSZIO.sys | vulnerable d | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 268 | HalGetBusDataByOffset, MmAllocateContiguousMemory, MmGetPhysicalAddress... | VeriSign Class 3 Code Sig |
| nscm.sys | vulnerable d | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Code Sig |
| nscm.sys | vulnerable d | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Novell\ |
| nscm.sys | vulnerable d | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Novell\ |
| nscm.sys | vulnerable d | **12.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 0 | 500 | IoGetCurrentProcess | VeriSign Class 3 Code Sig |
| nscm.sys | vulnerable d | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 1 | 500 | IoGetCurrentProcess | VeriSign Class 3 Code Sig |
| nscm.sys | vulnerable d | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 1 | 500 | IoGetCurrentProcess | VeriSign Class 3 Code Sig |
| nscm.sys | vulnerable d | **12.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Novell\ |
| nscm.sys | vulnerable d | **12.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Novell\ |
| nscm.sys | vulnerable d | **12.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 0 | 500 | IoGetCurrentProcess | VeriSign Class 3 Code Sig |
| nscm.sys | vulnerable d | **12.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Novell\ |
| nscm.sys | vulnerable d | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 1 | 500 | IoGetCurrentProcess | VeriSign Class 3 Code Sig |
| nscm.sys | vulnerable d | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 1 | 500 | IoGetCurrentProcess | VeriSign Class 3 Code Sig |
| nscm.sys | vulnerable d | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Novell\ |
| nscm.sys | vulnerable d | **12.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Code Sig |
| nscm.sys | vulnerable d | **12.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Novell\ |
| nscm.sys | vulnerable d | **12.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 0 | 500 | IoGetCurrentProcess | VeriSign Class 3 Code Sig |
| nscm.sys | vulnerable d | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 1 | 500 | IoGetCurrentProcess | VeriSign Class 3 Code Sig |
| nscm.sys | vulnerable d | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Novell\ |
| nscm.sys | vulnerable d | **12.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Novell\ |
| nscm.sys | vulnerable d | **12.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 0 | 500 | IoGetCurrentProcess | VeriSign Class 3 Code Sig |
| ene.sys | vulnerable d | **12.0** | x64 | GUARD_CF, GS_COOKIE | 3 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, ObOpenObjectByPointer... | Microsoft Windows Hardwar |
| dbk64.sys | vulnerable d | **12.0** | x64 | GUARD_CF, GS_COOKIE | 86 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign Code Signing R |
| TmComm.sys | vulnerable d | **12.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 11 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Code Sig |
| TmComm.sys | vulnerable d | **12.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 11 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Code Sig |
| VBoxDrv.sys | vulnerable d | **12.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 106 | 21 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | DigiCert Assured ID CA-1 |
| VBoxDrv.sys | vulnerable d | **12.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 106 | 21 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | DigiCert Assured ID CA-1 |
| VBoxDrv.sys | vulnerable d | **12.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 106 | 21 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | DigiCert Assured ID CA-1 |
| CorsairLLAccess64.sys | vulnerable d | **12.0** | x86 | GUARD_CF, GS_COOKIE | 13 | 0 | 257 | HalGetBusDataByOffset, MmMapIoSpace, MmMapLockedPagesSpecifyCache... | Microsoft Windows Hardwar |
| CorsairLLAccess64.sys | vulnerable d | **12.0** | x86 | GUARD_CF, GS_COOKIE | 13 | 0 | 259 | HalGetBusDataByOffset, MmMapIoSpace, MmMapLockedPagesSpecifyCache... | Microsoft Windows Hardwar |
| CorsairLLAccess64.sys | vulnerable d | **12.0** | x86 | GUARD_CF, GS_COOKIE | 11 | 0 | 242 | HalGetBusDataByOffset, MmMapIoSpace, MmMapLockedPagesSpecifyCache... | Microsoft Windows Hardwar |
| ATSZIO.sys | vulnerable d | **12.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 333 | ExAllocatePool, ExFreePoolWithTag, HalGetBusDataByOffset... | Microsoft Windows Hardwar |
| procexp.Sys | vulnerable d | **12.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 17 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | Microsoft Windows Hardwar |
| procexp.Sys | vulnerable d | **12.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 17 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | Microsoft Windows Hardwar |
| procexp.Sys | vulnerable d | **12.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 17 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | Microsoft Windows Hardwar |
| procexp.Sys | vulnerable d | **12.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 17 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | Microsoft Windows Hardwar |
| procexp.Sys | vulnerable d | **12.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 17 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | Microsoft Windows Hardwar |
| procexp.Sys | vulnerable d | **12.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | Microsoft Windows Hardwar |
| procexp.Sys | vulnerable d | **12.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 17 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | Microsoft Windows Hardwar |
| procexp.Sys | vulnerable d | **12.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 17 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | Microsoft Windows Hardwar |
| procexp.Sys | vulnerable d | **12.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 17 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | Microsoft Windows Hardwar |
| procexp.Sys | vulnerable d | **12.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | Microsoft Corporation |
| procexp.Sys | vulnerable d | **12.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 17 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | Microsoft Windows Hardwar |
| procexp.Sys | vulnerable d | **12.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 17 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | Microsoft Windows Hardwar |
| procexp.Sys | vulnerable d | **12.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 17 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | Microsoft Windows Hardwar |
| procexp.Sys | vulnerable d | **12.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 17 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | Microsoft Windows Hardwar |
| ProxyDrv.sys | vulnerable d | **11.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | 雷神（武汉）信息技术有限公司 |
| ncpl.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, PsCreateSystemThread... | VeriSign Class 3 Code Sig |
| LgDataCatcher.sys | vulnerable d | **11.5** | x64 | GUARD_CF, GS_COOKIE | 19 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Wuhan Qimiao Technology C |
| LgDataCatcher.sys | vulnerable d | **11.5** | x64 | GUARD_CF, GS_COOKIE | 19 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | 雷神（武汉）信息技术有限公司 |
| LgDataCatcher.sys | vulnerable d | **11.5** | x64 | GUARD_CF, GS_COOKIE | 19 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | GlobalSign Extended Valid |
| IoAccess.sys | vulnerable d | **11.5** | x86 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 11 | 0 | 497 | MmGetPhysicalAddress, MmMapIoSpace, MmMapLockedPagesSpecifyCache... | AddTrust External CA Root |
| NICM.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, PsCreateSystemThread... | VeriSign Class 3 Code Sig |
| mhyprotect.sys | vulnerable d | **11.5** | x64 | GUARD_CF, GS_COOKIE | 17 | 2 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | miHoYo Co.\ |
| iobitunlocker.sys | vulnerable d | **11.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 0 | 500 |  | VeriSign Class 3 Code Sig |
| iobitunlocker.sys | vulnerable d | **11.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 0 | 500 |  | VeriSign Class 3 Code Sig |
| iobitunlocker.sys | vulnerable d | **11.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 0 | 500 |  | IObit Information Technol |
| iobitunlocker.sys | vulnerable d | **11.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 0 | 500 |  | IObit Information Technol |
| iobitunlocker.sys | vulnerable d | **11.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 0 | 500 |  | IObit Information Technol |
| amp.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Code Sig |
| segwindrvx64.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Public P |
| segwindrvx64.sys | vulnerable d | **11.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Insyde Software Corp. |
| segwindrvx64.sys | vulnerable d | **11.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Public P |
| segwindrvx64.sys | vulnerable d | **11.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Insyde Software Corp. |
| segwindrvx64.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Public P |
| netflt.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | 北京融汇画方科技有限公司 |
| mhyprot3.sys | vulnerable d | **11.5** | x64 | GUARD_CF, GS_COOKIE | 1 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | miHoYo Co.\ |
| mhyprot3.sys | vulnerable d | **11.5** | x64 | GUARD_CF, GS_COOKIE | 1 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | miHoYo Co.\ |
| CSAgent.sys | vulnerable d | **11.5** | x64 | GUARD_CF, GS_COOKIE | 15 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | 佛山市高明科得裕绝缘材料有限公司 |
| test2.sys | vulnerable d | **11.5** | x64 | GUARD_CF, GS_COOKIE | 17 | 2 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | 1.A Connect GmbH |
| NetFlt.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | 北京融汇画方科技有限公司 |
| aswArPot.sys, avgArPot.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 23 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | AVG Technologies USA\ |
| aswArPot.sys, avgArPot.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 23 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | AVG Technologies USA\ |
| aswArPot.sys, avgArPot.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 22 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Public P |
| aswArPot.sys, avgArPot.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 23 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | AVAST Software s.r.o. |
| aswArPot.sys, avgArPot.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 3 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | AVAST Software s.r.o. |
| aswArPot.sys, avgArPot.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 23 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Public P |
| aswArPot.sys, avgArPot.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 23 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | AVAST Software s.r.o. |
| aswArPot.sys, avgArPot.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 23 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | AVAST Software s.r.o. |
| aswArPot.sys, avgArPot.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 3 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Public P |
| aswArPot.sys, avgArPot.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 23 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | AVAST Software s.r.o. |
| aswArPot.sys, avgArPot.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 23 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | AVG Technologies USA\ |
| aswArPot.sys, avgArPot.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 23 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | AVAST Software s.r.o. |
| aswArPot.sys, avgArPot.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 23 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | AVAST Software s.r.o. |
| aswArPot.sys, avgArPot.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 23 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | AVAST Software s.r.o. |
| aswArPot.sys, avgArPot.sys | vulnerable d | **11.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 28 | 5 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | AVAST Software s.r.o. |
| aswArPot.sys, avgArPot.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 23 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Public P |
| nicm.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, PsCreateSystemThread... | VeriSign Class 3 Code Sig |
| nicm.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, PsCreateSystemThread... | Novell\ |
| nicm.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, PsCreateSystemThread... | VeriSign Class 3 Code Sig |
| nicm.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, PsCreateSystemThread... | VeriSign Class 3 Code Sig |
| nicm.sys | vulnerable d | **11.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, PsCreateSystemThread... | VeriSign Class 3 Code Sig |
| nicm.sys | vulnerable d | **11.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, PsCreateSystemThread... | VeriSign Class 3 Code Sig |
| nicm.sys | vulnerable d | **11.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, PsCreateSystemThread... | Novell\ |
| nicm.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, PsCreateSystemThread... | Novell\ |
| nicm.sys | vulnerable d | **11.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, PsCreateSystemThread... | Novell\ |
| nicm.sys | vulnerable d | **11.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, PsCreateSystemThread... | Novell\ |
| nicm.sys | vulnerable d | **11.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, PsCreateSystemThread... | VeriSign Class 3 Code Sig |
| nicm.sys | vulnerable d | **11.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, PsCreateSystemThread... | VeriSign Class 3 Code Sig |
| nicm.sys | vulnerable d | **11.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, PsCreateSystemThread... | Novell\ |
| nicm.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, PsCreateSystemThread... | Novell\ |
| nicm.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, PsCreateSystemThread... | VeriSign Class 3 Code Sig |
| nicm.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, PsCreateSystemThread... | Novell\ |
| nicm.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, PsCreateSystemThread... | Novell\ |
| nicm.sys | vulnerable d | **11.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, PsCreateSystemThread... | Novell\ |
| fildds.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 416 |  | VeriSign Class 3 Public P |
| windbg.sys | malicious | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 7 | 5 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Shenzhen Luyoudashi Techn |
| windbg.sys | malicious | **11.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 3 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Wuhan Jiajia Yiyong Techn |
| windbg.sys | malicious | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 7 | 5 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Binzhoushi Yongyu Feed Co |
| windbg.sys | malicious | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 7 | 5 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Wuhan Jiajia Yiyong Techn |
| windbg.sys | malicious | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 7 | 5 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Wuhan Jiajia Yiyong Techn |
| windbg.sys | malicious | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 7 | 5 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Wuhan Jiajia Yiyong Techn |
| windbg.sys | malicious | **11.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 3 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Shenzhen Luyoudashi Techn |
| windbg.sys | malicious | **11.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 3 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Binzhoushi Yongyu Feed Co |
| windbg.sys | malicious | **11.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 3 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Wuhan Jiajia Yiyong Techn |
| windbg.sys | malicious | **11.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 3 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Wuhan Jiajia Yiyong Techn |
| windbg.sys | malicious | **11.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 3 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Wuhan Jiajia Yiyong Techn |
| windbg.sys | malicious | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 7 | 5 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Wuhan Jiajia Yiyong Techn |
| sepdrv3_1.sys | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | Intel(R) Software Product |
| NICM.SYS | vulnerable d | **11.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 5 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, PsCreateSystemThread... | VeriSign Class 3 Code Sig |
| NICM.SYS | vulnerable d | **11.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, PsCreateSystemThread... | VeriSign Class 3 Code Sig |
| jokercontroller.sys | vulnerable d | **11.5** | x64 | GUARD_CF, GS_COOKIE | 17 | 2 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Sectigo Public Code Signi |
| netfilter2.sys | vulnerable d | **11.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | 浙江强云信息科技有限公司 |
| netfilter2.sys | vulnerable d | **11.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | LLC SOLAR SECURITY |
| netfilter2.sys | vulnerable d | **11.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | SYSTWEAK SOFTWARE PVT. LT |
| Mhyprot2.sys, mhyprot.sys | vulnerable d | **11.5** | x64 | GUARD_CF, GS_COOKIE | 17 | 2 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | miHoYo Co.\ |
| Mhyprot2.sys, mhyprot.sys | vulnerable d | **11.5** | x64 | GUARD_CF, GS_COOKIE | 7 | 2 | 500 | ExAllocatePool, ExFreePoolWithTag, IoGetCurrentProcess... | miHoYo Co.\ |
| Mhyprot2.sys, mhyprot.sys | vulnerable d | **11.5** | x64 | GUARD_CF, GS_COOKIE | 2 | 2 | 500 | ExAllocatePool, ExFreePoolWithTag, IoGetCurrentProcess... | miHoYo Co.\ |
| Mhyprot2.sys, mhyprot.sys | vulnerable d | **11.5** | x64 | GUARD_CF, GS_COOKIE | 2 | 2 | 500 | ExAllocatePool, ExFreePoolWithTag, IoGetCurrentProcess... | miHoYo Co.\ |
| Mhyprot2.sys, mhyprot.sys | vulnerable d | **11.5** | x64 | GUARD_CF, GS_COOKIE | 17 | 2 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | miHoYo Co.\ |
| Mhyprot2.sys, mhyprot.sys | vulnerable d | **11.5** | x64 | GUARD_CF, GS_COOKIE | 2 | 2 | 500 | ExAllocatePool, ExFreePoolWithTag, IoGetCurrentProcess... | miHoYo Co.\ |
| Mhyprot2.sys, mhyprot.sys | vulnerable d | **11.5** | x64 | GUARD_CF, GS_COOKIE | 3 | 2 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | miHoYo Co.\ |
| Mhyprot2.sys, mhyprot.sys | vulnerable d | **11.5** | x64 | GUARD_CF, GS_COOKIE | 6 | 2 | 500 | ExAllocatePool, ExFreePoolWithTag, IoGetCurrentProcess... | miHoYo Co.\ |
| Mhyprot2.sys, mhyprot.sys | vulnerable d | **11.5** | x64 | GUARD_CF, GS_COOKIE | 17 | 2 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | miHoYo Co.\ |
| xjokercontroller.sys | vulnerable d | **11.5** | x64 | GUARD_CF, GS_COOKIE | 17 | 2 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Sex Shop SRL |
| mhyprotrpg.Sys | vulnerable d | **11.5** | x64 | GUARD_CF, GS_COOKIE | 6 | 2 | 500 | ExAllocatePool, ExFreePoolWithTag, IoGetCurrentProcess... | miHoYo Co.\ |
| echo_driver.sys | vulnerable d | **11.0** | x64 | GUARD_CF, GS_COOKIE | 1 | 0 | 411 | IoGetCurrentProcess, ObOpenObjectByPointer, ObReferenceObjectByHandle... | Microsoft Windows Hardwar |
| ntbios.sys | malicious | **11.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | KeInsertQueueApc, NtQuerySystemInformation | unsigned |
| ElbyCDIO.sys | vulnerable d | **11.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 13 | 500 | ExAllocatePool, ObReferenceObjectByHandle, PsCreateSystemThread... | Elaborate Bytes AG |
| RtsPer.sys | vulnerable d | **11.0** | arm64 | GUARD_CF, GS_COOKIE | 1 | 0 | 0 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | DigiCert Trusted G4 Code  |
| dbutil_2_3.sys | vulnerable d | **11.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 246 |  | unsigned |
| iobitunlocker.sys | vulnerable d | **11.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 0 | 500 |  | unsigned |
| ntbios_2.sys | malicious | **11.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | KeInsertQueueApc, NtQuerySystemInformation | unsigned |
| kEvP64.sys | vulnerable d | **11.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | 北京华林保软件技术有限公司 |
| daxin_blank6.sys | malicious | **11.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | KeInsertQueueApc, NtQuerySystemInformation | unsigned |
| windbg.sys | malicious | **11.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 7 | 5 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | unsigned |
| piddrv64.sys | vulnerable d | **11.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset | Microsoft Windows Hardwar |
| ACE-BASE.sys | vulnerable d | **11.0** | x64 | GUARD_CF, GS_COOKIE | 41 | 9 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | HIGH MORALE DEVELOPMENTS  |
| gvcidrv64.sys | vulnerable d | **11.0** | x64 | GUARD_CF, GS_COOKIE | 3 | 0 | 414 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | Microsoft Windows Hardwar |
| nscm.sys | vulnerable d | **11.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Microsoft Windows Hardwar |
| nscm.sys | vulnerable d | **11.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Microsoft Corporation |
| netfilter2.sys | vulnerable d | **11.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Microsoft Windows Hardwar |
| netfilter2.sys | vulnerable d | **11.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Microsoft Windows Hardwar |
| netfilter2.sys | vulnerable d | **11.0** | x86 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 23 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Microsoft Windows Hardwar |
| ViveRRAudio.sys | vulnerable | **11.0** | x64 | GUARD_CF, GS_COOKIE | 1 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | DigiCert Trusted G4 Code  |
| elbycdio.sys | vulnerable d | **11.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 13 | 400 | ExAllocatePool, ObReferenceObjectByHandle, PsCreateSystemThread... | Elaborate Bytes AG |
| elbycdio.sys | vulnerable d | **11.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 13 | 434 | ExAllocatePool, ObReferenceObjectByHandle, PsCreateSystemThread... | Elaborate Bytes AG |
| elbycdio.sys | vulnerable d | **11.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 19 | 500 | ExAllocatePool, ObReferenceObjectByHandle, PsCreateSystemThread... | Elaborate Bytes AG |
| elbycdio.sys | vulnerable d | **11.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 15 | 500 | ExAllocatePool, ObReferenceObjectByHandle, PsCreateSystemThread... | Elaborate Bytes AG |
| kdriver.sys | vulnerable d | **11.0** | x64 | GUARD_CF, GS_COOKIE | 17 | 2 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | unsigned |
| libnicm.sys | vulnerable d | **11.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 6 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Novell\ |
| libnicm.sys | vulnerable d | **11.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 6 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Novell\ |
| libnicm.sys | vulnerable d | **11.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 6 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Novell\ |
| libnicm.sys | vulnerable d | **11.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 4 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Novell\ |
| libnicm.sys | vulnerable d | **11.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 4 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Novell\ |
| libnicm.sys | vulnerable d | **11.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 6 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Novell\ |
| libnicm.sys | vulnerable d | **11.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 4 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Novell\ |
| libnicm.sys | vulnerable d | **11.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 6 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Novell\ |
| driver_0a636606.sys | malicious | **10.5** | x64 | GUARD_CF, GS_COOKIE | 3 | 1 | 500 |  | Shenzhen Hua’nan Xingfa E |
| LHA.sys | vulnerable d | **10.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 34 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmAllocateNonCachedMemory... | LG Electronics Inc. |
| GPU-Z.sys | vulnerable d | **10.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | TechPowerUp |
| filnk.sys | vulnerable d | **10.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 23 | 3 | 500 | ExAllocatePoolWithTag, IoGetCurrentProcess, IoGetDeviceObjectPointer... | VeriSign Class 3 Public P |
| FH-EtherCAT_DIO.sys | vulnerable d | **10.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapIoSpace... | OMRON Corporation |
| ADV64DRV.sys | vulnerable d | **10.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 0 | 319 | MmMapIoSpace | VeriSign Class 3 Code Sig |
| SeasunProtect.sys | vulnerable | **10.5** | x64 | GUARD_CF, GS_COOKIE | 5 | 0 | 500 | IoGetCurrentProcess, KeStackAttachProcess, KeUnstackDetachProcess... | Microsoft Windows Hardwar |
| driver_099ef491.sys | malicious | **10.5** | x64 | GUARD_CF, GS_COOKIE | 3 | 1 | 500 |  | Shenzhen Hua’nan Xingfa E |
| SANDRA.sys | vulnerable d | **10.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 35 | 0 | 500 | HalGetBusDataByOffset, MmMapIoSpace, MmMapLockedPagesSpecifyCache... | GeoTrust TrustCenter Code |
| SANDRA.sys | vulnerable d | **10.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 34 | 0 | 500 | HalGetBusDataByOffset, MmMapIoSpace, MmMapLockedPagesSpecifyCache... | GeoTrust TrustCenter Code |
| SANDRA.sys | vulnerable d | **10.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 38 | 0 | 500 | HalGetBusDataByOffset, MmMapIoSpace, MmMapLockedPagesSpecifyCache... | Thawte Code Signing CA |
| driver_668c5bea.sys | malicious | **10.5** | x64 | GUARD_CF, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, IoGetCurrentProcess... | Shenzhen yundian Technolo |
| Chaos-Rootkit.sys | vulnerable d | **10.5** | x64 | GUARD_CF, GS_COOKIE | 13 | 0 | 485 | MmMapLockedPagesSpecifyCache, MmProbeAndLockPages, PsLookupProcessByProcessId | WDKTestCert anash\ |
| segwindrvx64.sys | vulnerable d | **10.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmGetPhysicalAddress... | VeriSign Class 3 Public P |
| sandra.sys | vulnerable d | **10.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 35 | 0 | 500 | HalGetBusDataByOffset, MmMapIoSpace, MmMapLockedPagesSpecifyCache... | GeoTrust TrustCenter Code |
| sandra.sys | vulnerable d | **10.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 34 | 0 | 500 | HalGetBusDataByOffset, MmMapIoSpace, MmMapLockedPagesSpecifyCache... | GeoTrust TrustCenter Code |
| NQrmq.sys | malicious | **10.5** | x64 | GUARD_CF, GS_COOKIE | 3 | 1 | 500 |  | Beijing Ruidongtiandi Inf |
| Chaos-Rootkit.sys | vulnerable d | **10.5** | x64 | GUARD_CF, GS_COOKIE | 12 | 0 | 372 | PsLookupProcessByProcessId | WDKTestCert anash\ |
| CP2X72C.SYS | vulnerable d | **10.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 23 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Symantec Class 3 Extended |
| CP2X72C.SYS | vulnerable d | **10.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 23 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Public P |
| Blackbone.sys | vulnerable d | **10.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Microsoft Windows Hardwar |
| MsIo64.sys | vulnerable d | **10.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 117 | ObReferenceObjectByHandle, ZwMapViewOfSection, ZwUnmapViewOfSection | Microsoft Windows Hardwar |
| ksapi.sys | vulnerable d | **10.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 30 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Public P |
| driver_5c308aed.sys | malicious | **10.0** | x64 | GUARD_CF, GS_COOKIE | 12 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Shenzhen Hua’nan Xingfa E |
| ksapi.sys | vulnerable d | **10.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 30 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Beijing Kingsoft Security |
| zam64.sys, zamguard32.sys, zamguard64.sys | vulnerable d | **10.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Zemana Ltd. |
| mhyprot3.sys | vulnerable d | **10.0** | x64 | GUARD_CF, GS_COOKIE | 1 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Microsoft Windows Hardwar |
| mhyprot3.sys | vulnerable d | **10.0** | x64 | GUARD_CF, GS_COOKIE | 1 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Microsoft Windows Hardwar |
| mhyprot3.sys | vulnerable d | **10.0** | x64 | GUARD_CF, GS_COOKIE | 5 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Microsoft Windows Hardwar |
| mhyprot3.sys | vulnerable d | **10.0** | x64 | GUARD_CF, GS_COOKIE | 5 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Microsoft Windows Hardwar |
| dcr.sys | vulnerable d | **10.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 43 | 8 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | SecurStar GmbH |
| windbg.sys | malicious | **10.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 7 | 5 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Microsoft Windows Hardwar |
| windbg.sys | malicious | **10.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 3 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Microsoft Windows Hardwar |
| nscm.sys | vulnerable d | **10.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Microsoft Windows Publish |
| NICM.SYS | vulnerable d | **10.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 6 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, PsCreateSystemThread... | Microsoft Corporation |
| Mhyprot2.sys, mhyprot.sys | vulnerable d | **10.0** | x64 | GUARD_CF, GS_COOKIE | 6 | 2 | 500 | ExAllocatePool, ExFreePoolWithTag, IoGetCurrentProcess... | Microsoft Windows Hardwar |
| mhyprotrpg.sys | vulnerable d | **10.0** | x64 | GUARD_CF, GS_COOKIE | 2 | 2 | 500 | ExAllocatePool, ExFreePoolWithTag, IoGetCurrentProcess... | Microsoft Windows Hardwar |
| elbycdio.sys | vulnerable d | **10.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 378 | ExAllocatePool, MmMapLockedPages, MmProbeAndLockPages... | Elaborate Bytes AG |
| mhyprotnap.sys | vulnerable d | **10.0** | x64 | GUARD_CF, GS_COOKIE | 2 | 2 | 500 | ExAllocatePool, ExFreePoolWithTag, IoGetCurrentProcess... | Microsoft Windows Hardwar |
| ACPIx86.sys | vulnerable d | **9.5** | x64 | GUARD_CF, GS_COOKIE | 0 | 0 | 500 | ExFreePoolWithTag, ObOpenObjectByPointer, PsLookupProcessByProcessId... | Shenzhen yundian Technolo |
| GEDevDrv.SYS | vulnerable d | **9.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 12 | 0 | 449 | MmMapIoSpace, MmMapLockedPagesSpecifyCache, READ_PORT_UCHAR... | GE Intelligent Platforms  |
| GEDevDrv.SYS | vulnerable d | **9.5** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 12 | 0 | 447 | MmMapIoSpace, MmMapLockedPagesSpecifyCache, READ_PORT_UCHAR... | GE\  |
| throttlestop.sys | vulnerable d | **9.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetBusDataByOffset... | TechPowerUp LLC |
| f.sys | malicious | **9.5** | x64 | GUARD_CF, GS_COOKIE | 18 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | AnFu NetShield Technology |
| libnicm.sys | vulnerable d | **9.5** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 6 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Microsoft Windows Hardwar |
| CorsairLLAccess64.sys | vulnerable d | **9.0** | x64 | GUARD_CF, GS_COOKIE | 11 | 0 | 500 | HalGetBusDataByOffset, MmMapIoSpace, MmMapLockedPagesSpecifyCache | Microsoft Windows Hardwar |
| BlackBoneDrv10.sys | vulnerable d | **9.0** | x64 | GUARD_CF, GS_COOKIE | 12 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Nanjing Zhixiao Informati |
| TmComm.sys | vulnerable d | **9.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 3 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Public P |
| TmComm.sys | vulnerable d | **9.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Code Sig |
| TmComm.sys | vulnerable d | **9.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 2 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Code Sig |
| TmComm.sys | vulnerable d | **9.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 17 | 3 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Code Sig |
| TmComm.sys | vulnerable d | **9.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Code Sig |
| TmComm.sys | vulnerable d | **9.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 2 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Code Sig |
| TmComm.sys | vulnerable d | **9.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 2 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Code Sig |
| TmComm.sys | vulnerable d | **9.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 2 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Code Sig |
| TmComm.sys | vulnerable d | **9.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Code Sig |
| libnicm.sys | vulnerable d | **9.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 6 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Code Sig |
| libnicm.sys | vulnerable d | **9.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 4 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Code Sig |
| CorsairLLAccess64.sys | vulnerable d | **9.0** | x64 | GUARD_CF, GS_COOKIE | 11 | 0 | 500 | HalGetBusDataByOffset, MmMapIoSpace, MmMapLockedPagesSpecifyCache | Microsoft Windows Hardwar |
| libnicm.sys | vulnerable d | **9.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 6 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Code Sig |
| libnicm.sys | vulnerable d | **9.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 4 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Code Sig |
| libnicm.sys | vulnerable d | **9.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 4 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Code Sig |
| libnicm.sys | vulnerable d | **9.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 4 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Code Sig |
| libnicm.sys | vulnerable d | **9.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 6 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Code Sig |
| libnicm.sys | vulnerable d | **9.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 4 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Code Sig |
| libnicm.sys | vulnerable d | **9.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 4 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Code Sig |
| libnicm.sys | vulnerable d | **9.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 4 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Code Sig |
| libnicm.sys | vulnerable d | **9.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 6 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Code Sig |
| Tmel.sys | vulnerable d | **9.0** | x86 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Microsoft Windows Early L |
| Tmel.sys | vulnerable d | **9.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Microsoft Windows Early L |
| Tmel.sys | vulnerable d | **9.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Microsoft Windows Early L |
| IoAccess.sys | vulnerable d | **8.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | MmGetPhysicalAddress, MmMapIoSpace, MmMapLockedPagesSpecifyCache | AddTrust External CA Root |
| irec.sys | vulnerable d | **8.5** | x64 | GUARD_CF, GS_COOKIE | 2 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Microsoft Windows Hardwar |
| windivert.sys | malicious | **8.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Sectigo Public Code Signi |
| windivert.sys | malicious | **8.5** | x86 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Sectigo Public Code Signi |
| windivert.sys | malicious | **8.5** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Sectigo Public Code Signi |
| wamsdk.sys | vulnerable d | **8.0** | x64 | GUARD_CF, GS_COOKIE | 23 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | GlobalSign Code Signing R |
| wamsdk.sys | vulnerable d | **8.0** | x64 | GUARD_CF, GS_COOKIE | 23 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | GlobalSign Code Signing R |
| amsdk.sys | vulnerable d | **8.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 29 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | GlobalSign Code Signing R |
| zam64.sys, zamguard32.sys, zamguard64.sys | vulnerable d | **8.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 888 | 221 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Zemana Ltd. |
| zam64.sys, zamguard32.sys, zamguard64.sys | vulnerable d | **8.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Zemana Ltd. |
| zam64.sys, zamguard32.sys, zamguard64.sys | vulnerable d | **8.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 888 | 221 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Zemana Ltd. |
| zam64.sys, zamguard32.sys, zamguard64.sys | vulnerable d | **8.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 888 | 221 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Zemana Ltd. |
| zam64.sys, zamguard32.sys, zamguard64.sys | vulnerable d | **8.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Zemana Ltd. |
| zam64.sys, zamguard32.sys, zamguard64.sys | vulnerable d | **8.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Zemana Ltd. |
| zam64.sys, zamguard32.sys, zamguard64.sys | vulnerable d | **8.0** | x86 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 917 | 220 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Zemana Ltd. |
| zam64.sys, zamguard32.sys, zamguard64.sys | vulnerable d | **8.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Zemana Ltd. |
| zam64.sys, zamguard32.sys, zamguard64.sys | vulnerable d | **8.0** | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 888 | 221 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Zemana Ltd. |
| TmComm.sys | vulnerable d | **8.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Code Sig |
| TmComm.sys | vulnerable d | **8.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Code Sig |
| TmComm.sys | vulnerable d | **8.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 4 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Code Sig |
| TmComm.sys | vulnerable d | **8.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Code Sig |
| TmComm.sys | vulnerable d | **8.0** | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | VeriSign Class 3 Code Sig |
| amsdk.sys | vulnerable d | **8.0** | x64 | GUARD_CF, GS_COOKIE | 27 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | GlobalSign Code Signing R |
| netfilterdrv.sys | vulnerable d | **8.0** | x86 | GUARD_CF, GS_COOKIE | 3 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | unsigned |
| LHA.sys | vulnerable d | **8.0** | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 28 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmAllocateNonCachedMemory... | Microsoft Windows Hardwar |
| echo_driver.sys | vulnerable d | 7.5 | x64 | GUARD_CF, GS_COOKIE | 7 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Microsoft Windows Hardwar |
| echo_driver.sys | vulnerable d | 7.5 | x64 | GUARD_CF, GS_COOKIE | 15 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Microsoft Windows Hardwar |
| libnicm.sys | vulnerable d | 7.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 10 | 6 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Microsoft Corporation |
| Netfilter.sys | vulnerable d | 7.0 | x64 | GUARD_CF, GS_COOKIE | 1 | 1 | 295 |  | Microsoft Windows Hardwar |
| Netfilter.sys | vulnerable d | 7.0 | x64 | GUARD_CF, GS_COOKIE | 2 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | Microsoft Windows Hardwar |
| Netfilter.sys | vulnerable d | 7.0 | x86 | GUARD_CF, GS_COOKIE | 3 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | Microsoft Windows Hardwar |
| Netfilter.sys | vulnerable d | 7.0 | x86 | GUARD_CF, GS_COOKIE | 3 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | Microsoft Windows Hardwar |
| kEvP64.sys | vulnerable d | 7.0 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | 北京华林保软件技术有限公司 |
| kEvP64.sys | vulnerable d | 7.0 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | 北京华林保软件技术有限公司 |
| msr.sys | vulnerable d | 7.0 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 3 | 0 | 194 | HalGetBusDataByOffset | Microsoft Windows Hardwar |
| kEvP64.sys | vulnerable d | 7.0 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | 北京华林保软件技术有限公司 |
| kEvP64.sys | vulnerable d | 7.0 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | 北京华林保软件技术有限公司 |
| kEvP64.sys | vulnerable d | 7.0 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | 北京华林保软件技术有限公司 |
| kEvP64.sys | vulnerable d | 7.0 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | 北京华林保软件技术有限公司 |
| kEvP64.sys | vulnerable d | 7.0 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | 北京华林保软件技术有限公司 |
| kEvP64.sys | vulnerable d | 7.0 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | 北京华林保软件技术有限公司 |
| kprocesshacker.sys | vulnerable d | 7.0 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 27 | 27 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Wen Jia Liu |
| kprocesshacker.sys | vulnerable d | 7.0 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 20 | 20 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Wen Jia Liu |
| netfilterdrv.sys | vulnerable d | 7.0 | x64 | GUARD_CF, GS_COOKIE | 1 | 1 | 351 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | Microsoft Windows Hardwar |
| netfilterdrv.sys | vulnerable d | 7.0 | x86 | GUARD_CF, GS_COOKIE | 3 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | Microsoft Windows Hardwar |
| netfilterdrv.sys | vulnerable d | 7.0 | x64 | GUARD_CF, GS_COOKIE | 2 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | Microsoft Windows Hardwar |
| driver_fdd16a94.sys | malicious | 7.0 | x64 | GUARD_CF, GS_COOKIE | 77 | 3 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Shenzhen yundian Technolo |
| mapmom.sys | vulnerable d | 6.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 119 |  | CAPCOM Co.\ |
| gmer64.sys, superman.sys | malicious | 6.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 37 | 1 | 500 | ExAllocatePool, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| gmer64.sys, superman.sys | malicious | 6.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 37 | 1 | 500 | ExAllocatePool, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign CodeSigning CA |
| GEDevDrv.SYS | vulnerable d | 6.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 11 | 1 | 500 | MmMapIoSpace, MmMapLockedPagesSpecifyCache | GE\  |
| GEDevDrv.SYS | vulnerable d | 6.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 11 | 1 | 500 | MmMapIoSpace, MmMapLockedPagesSpecifyCache | GE Intelligent Platforms  |
| capcom.sys | vulnerable d | 6.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 119 |  | CAPCOM Co.\ |
| capcom.sys | vulnerable d | 6.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 119 |  | CAPCOM Co.\ |
| capcom.sys | vulnerable d | 6.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 119 |  | NVIDIA Corporation |
| capcom.sys | vulnerable d | 6.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 119 |  | CAPCOM Co.\ |
| capcom.sys | vulnerable d | 6.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 119 |  | CAPCOM Co.\ |
| capcom.sys | vulnerable d | 6.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 119 |  | CAPCOM Co.\ |
| smep_capcom.sys | vulnerable d | 6.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 119 |  | CAPCOM Co.\ |
| smep_namco.sys | vulnerable d | 6.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 119 |  | GlobalSign CodeSigning CA |
| zam64.sys, zamguard32.sys, zamguard64.sys | vulnerable d | 6.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 888 | 221 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Microsoft Windows Hardwar |
| capcom2.sys | vulnerable d | 6.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 119 |  | CAPCOM Co.\ |
| libnicm.sys | vulnerable d | 6.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 5 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Microsoft Corporation |
| libnicm.sys | vulnerable d | 6.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 9 | 5 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Microsoft Windows Publish |
| atomicredteamcapcom.sys | vulnerable d | 6.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 119 |  | CAPCOM Co.\ |
| VBoxTAP.sys | vulnerable d | 6.5 | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 36 | 8 | 500 | MmMapLockedPages, MmMapLockedPagesSpecifyCache, MmProbeAndLockPages | InnoTek Systemberatung Gm |
| VBoxTAP.sys | vulnerable d | 6.5 | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 36 | 8 | 500 | MmMapLockedPages, MmMapLockedPagesSpecifyCache, MmProbeAndLockPages | innotek GmbH |
| TmComm.sys | vulnerable d | 6.0 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Trend Micro\ |
| capcom.sys | vulnerable d | 6.0 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 119 |  | unsigned |
| zam64.sys, zamguard32.sys, zamguard64.sys | vulnerable d | 6.0 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 4 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetDeviceObjectPointer... | Zemana Ltd. |
| TmComm.sys | vulnerable d | 6.0 | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 3 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Trend Micro\ |
| TmComm.sys | vulnerable d | 6.0 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 5 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Trend Micro\ |
| TmComm.sys | vulnerable d | 6.0 | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 3 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Trend Micro\ |
| TmComm.sys | vulnerable d | 6.0 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Trend Micro\ |
| TmComm.sys | vulnerable d | 6.0 | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 3 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Trend Micro\ |
| TmComm.sys | vulnerable d | 6.0 | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 3 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Trend Micro\ |
| TmComm.sys | vulnerable d | 6.0 | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 3 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Public P |
| TmComm.sys | vulnerable d | 6.0 | x86 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 3 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Trend Micro\ |
| TmComm.sys | vulnerable d | 6.0 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 5 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Code Sig |
| TmComm.sys | vulnerable d | 6.0 | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 3 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Code Sig |
| TmComm.sys | vulnerable d | 6.0 | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 3 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Trend Micro\ |
| TmComm.sys | vulnerable d | 6.0 | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 3 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Trend Micro\ |
| TmComm.sys | vulnerable d | 6.0 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Trend Micro\ |
| TmComm.sys | vulnerable d | 6.0 | x86 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 3 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Trend Micro\ |
| TmComm.sys | vulnerable d | 6.0 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 8 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Trend Micro\ |
| TmComm.sys | vulnerable d | 6.0 | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 3 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Trend Micro\ |
| TmComm.sys | vulnerable d | 6.0 | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 3 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Public P |
| TmComm.sys | vulnerable d | 6.0 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 7 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Trend Micro\ |
| TmComm.sys | vulnerable d | 6.0 | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 15 | 3 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Public P |
| TmComm.sys | vulnerable d | 6.0 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 5 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Public P |
| TmComm.sys | vulnerable d | 6.0 | x86 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 16 | 3 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Trend Micro\ |
| TmComm.sys | vulnerable d | 6.0 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 7 | 4 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Trend Micro\ |
| TmComm.sys | vulnerable d | 6.0 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 5 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Trend Micro\ |
| TmComm.sys | vulnerable d | 6.0 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 5 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Trend Micro\ |
| skill.sys | vulnerable d | 6.0 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 119 |  | unsigned |
| mlgbbiicaihflrnh.sys | malicious | 6.0 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 119 |  | unsigned |
| asas.sys | vulnerable d | 6.0 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 119 |  | unsigned |
| szkg64.sys | vulnerable d | 6.0 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 20 | 9 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | VeriSign Class 3 Code Sig |
| VBoxUSB.Sys | vulnerable d | 5.5 | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 274 | ExAllocatePoolWithTag, MmMapLockedPagesSpecifyCache, MmProbeAndLockPages... | InnoTek Systemberatung Gm |
| VBoxUSB.Sys | vulnerable d | 5.5 | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 375 | ExAllocatePoolWithTag, MmMapLockedPagesSpecifyCache, MmProbeAndLockPages... | innotek GmbH |
| Dh_Kernel.sys | vulnerable d | 5.0 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | YY Inc. |
| PcieCubed.sys | malicious | 5.0 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 21 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Microsoft Windows Hardwar |
| KfeCo10X64.sys | vulnerable d | 5.0 | x64 | GUARD_CF, GS_COOKIE | 36 | 5 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Rivet Networks LLC |
| wfshbr64.sys, wfshbr32.sys | malicious | 5.0 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 353 | IoGetCurrentProcess | Microsoft Windows Hardwar |
| wfshbr64.sys, wfshbr32.sys | malicious | 5.0 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 300 | IoGetCurrentProcess | Microsoft Windows Hardwar |
| KfeCo11X64.sys | vulnerable d | 5.0 | x64 | GUARD_CF, GS_COOKIE | 49 | 7 | 500 | ExAllocatePool2, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Intel Corporation |
| Dh_Kernel_10.sys | vulnerable d | 5.0 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | YY Inc. |
| malicious.sys | malicious | 4.5 | x64 | GUARD_CF, GS_COOKIE | 0 | 0 | 111 | MmIsAddressValid | WDKTestCert zezec\ |
| reddriver.sys | malicious | 4.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | thawte SHA256 Code Signin |
| typelibdE.sys | malicious | 4.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 13 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | thawte SHA256 Code Signin |
| TmComm.sys | vulnerable d | 4.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 5 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Microsoft Windows Hardwar |
| spwizimgVT.sys | malicious | 4.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | thawte SHA256 Code Signin |
| spf.sys | vulnerable d | 4.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag | WDKTestCert LuckyStrike\ |
| telephonuAfY.sys | malicious | 4.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | thawte SHA256 Code Signin |
| wsftprm.sys | vulnerable | 4.5 | x64 | GUARD_CF, GS_COOKIE | 7 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | DigiCert Trusted G4 Code  |
| ktmutil7ODM.sys | malicious | 4.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | thawte SHA256 Code Signin |
| NlsLexicons0024UvN.sys | malicious | 4.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | 湖南蓝途方鼎科技有限公司 |
| RtsUer.sys | vulnerable d | 4.0 | x64 | GUARD_CF, GS_COOKIE | 7 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | DigiCert Trusted G4 Code  |
| Sense5Ext.sys | malicious | 4.0 | x64 | GUARD_CF, GS_COOKIE | 9 | 3 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Microsoft Windows Hardwar |
| Sense5Ext.sys | malicious | 4.0 | x64 | GUARD_CF, GS_COOKIE | 5 | 4 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Microsoft Windows Hardwar |
| pxitrig64.sys | vulnerable | 4.0 | x64 | GUARD_CF, GS_COOKIE | 5 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Microsoft Windows Hardwar |
| LgDCatcher.sys | vulnerable d | 3.5 | x64 | GUARD_CF, GS_COOKIE | 19 | 0 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | DigiCert SHA2 Assured ID  |
| WinTapix.sys, SRVNET2.SYS | malicious | 3.5 | x64 | GUARD_CF, GS_COOKIE | 1 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Beijing JoinHope Image Te |
| WinTapix.sys, SRVNET2.SYS | malicious | 3.5 | x64 | GUARD_CF, GS_COOKIE | 1 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Beijing JoinHope Image Te |
| WinTapix.sys, SRVNET2.SYS | malicious | 3.5 | x64 | GUARD_CF, GS_COOKIE | 1 | 1 | 500 | ExAllocatePool, ExFreePoolWithTag, MmIsAddressValid... | Zhuhai liancheng Technolo |
| isodrivep64.sys | vulnerable d | 3.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, MmMapLockedPagesSpecifyCache, MmProbeAndLockPages... | FEI XIAO |
| driver_b4f33ffe.sys | malicious | 3.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, MmMapLockedPagesSpecifyCache, MmProbeAndLockPages... | Shenzhen yundian Technolo |
| avkiller.sys | malicious | 3.5 | x64 | GUARD_CF, GS_COOKIE | 0 | 0 | 119 | PsLookupProcessByProcessId, ZwOpenProcess, ZwTerminateProcess | thawte SHA256 Code Signin |
| ndislan.sys | malicious | 3.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Anhua Xinda (Beijing) Tec |
| mhyprotect.sys | vulnerable d | 3.5 | x64 | GUARD_CF, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | miHoYo Co.\ |
| driver_4d8bc539.sys | malicious | 3.5 | x64 | GUARD_CF, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Shenzhen Hua’nan Xingfa E |
| 927e3aef03a8355d236230cace376b3023480a40c5ac08453c07dab343dd1f11 | vulnerable d | 3.5 | x64 | GUARD_CF, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Fuzhou Dingxin Trade Co.\ |
| 8492937_2_Driver.sys | vulnerable d | 3.5 | x64 | GUARD_CF, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | 长沙恒祥信息技术有限公司 |
| driver_bfcbc010.sys | malicious | 3.5 | x64 | GUARD_CF, GS_COOKIE | 17 | 4 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Shenzhen Hua’nan Xingfa E |
| driver_981d03e1.sys | malicious | 3.5 | x64 | GUARD_CF, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Shenzhen Hua’nan Xingfa E |
| daxin_blank1.sys | malicious | 3.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Fuqing Yuntan Network Tec |
| driver_ef9d653a.sys | malicious | 3.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, MmMapLockedPagesSpecifyCache, MmProbeAndLockPages... | Shenzhen Jinxian Technolo |
| driver_ab811ca5.sys | malicious | 3.5 | x64 | GUARD_CF, GS_COOKIE | 4 | 2 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Shenzhen Hua’nan Xingfa E |
| dkrTK.sys | malicious | 3.5 | x64 | GUARD_CF, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Bopsoft |
| driver_77225a99.sys | malicious | 3.5 | x64 | GUARD_CF, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Pinchins Technology Compa |
| daxin_blank2.sys | malicious | 3.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, MmMapLockedPagesSpecifyCache, MmProbeAndLockPages... | Fuqing Yuntan Network Tec |
| driver_c3d48ddd.sys | malicious | 3.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, MmMapLockedPagesSpecifyCache, MmProbeAndLockPages... | Pinchins Technology Compa |
| driver_5d61e4ea.sys | malicious | 3.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Shenzhen Jinxian Technolo |
| driver_82d928c5.sys | malicious | 3.5 | x64 | GUARD_CF, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Shenzhen yundian Technolo |
| idmtdi.sys | malicious | 3.5 | x64 | GUARD_CF, GS_COOKIE | 8 | 4 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | FEI XIAO |
| idmtdi.sys | malicious | 3.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, MmMapLockedPagesSpecifyCache, MmProbeAndLockPages... | FEI XIAO |
| idmtdi.sys | malicious | 3.5 | x64 | GUARD_CF, GS_COOKIE | 3 | 2 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | FEI XIAO |
| idmtdi.sys | malicious | 3.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, MmMapLockedPagesSpecifyCache, MmProbeAndLockPages... | FEI XIAO |
| idmtdi.sys | malicious | 3.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, MmMapLockedPagesSpecifyCache, MmProbeAndLockPages... | FEI XIAO |
| idmtdi.sys | malicious | 3.5 | x64 | GUARD_CF, GS_COOKIE | 11 | 4 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | FEI XIAO |
| idmtdi.sys | malicious | 3.5 | x64 | GUARD_CF, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | FEI XIAO |
| idmtdi.sys | malicious | 3.5 | x64 | GUARD_CF, GS_COOKIE | 7 | 2 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | FEI XIAO |
| idmtdi.sys | malicious | 3.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, MmMapLockedPagesSpecifyCache, MmProbeAndLockPages... | FEI XIAO |
| Afd.sys | vulnerable d | 3.5 | x64 | GUARD_CF, GS_COOKIE | 48 | 26 | 500 | ExAllocatePool2, ExFreePoolWithTag, IoGetCurrentProcess... | Microsoft Windows |
| Afd.sys | vulnerable d | 3.5 | x64 | GUARD_CF, GS_COOKIE | 48 | 26 | 500 | ExAllocatePool2, ExFreePoolWithTag, IoGetCurrentProcess... | Microsoft Windows |
| yyprotect64.sys | vulnerable d | 3.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, MmMapLockedPagesSpecifyCache, MmProbeAndLockPages... | YY Inc. |
| windbg.sys | malicious | 3.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Wuhan Jiajia Yiyong Techn |
| windbg.sys | malicious | 3.5 | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Wuhan Jiajia Yiyong Techn |
| changsha | malicious | 3.5 | x64 | GUARD_CF, GS_COOKIE | 13 | 6 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | 长沙恒祥信息技术有限公司 |
| isodrivep64.sys | vulnerable d | 3.5 | x64 | GUARD_CF, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Fuzhou Dingxin Trade Co.\ |
| mJj0ge.sys | malicious | 3.5 | x64 | GUARD_CF, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Beijing JoinHope Image Te |
| driver_85ca0dcd.sys | malicious | 3.5 | x64 | GUARD_CF, GS_COOKIE | 12 | 3 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Shenzhen Hua’nan Xingfa E |
| 834761775.sys | malicious | 3.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Beijing JoinHope Image Te |
| CSAgent.sys | vulnerable d | 3.5 | x64 | GUARD_CF, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | 新疆亿事联网络科技有限公司 |
| CSAgent.sys | vulnerable d | 3.5 | x64 | GUARD_CF, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Fuzhou Dingxin Trade Co.\ |
| burntcigar.sys | malicious | 3.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Blueone Technology Co.\ |
| driver_0ffb4081.sys | malicious | 3.5 | x64 | GUARD_CF, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Shenzhen Hua’nan Xingfa E |
| cyvrlpc.sys | vulnerable d | 3.5 | x64 | GUARD_CF, GS_COOKIE | 14 | 4 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | 长沙恒祥信息技术有限公司 |
| daxin_blank3.sys | malicious | 3.0 | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 436 | KeInsertQueueApc, NtQuerySystemInformation, PsLookupProcessByProcessId... | unsigned |
| pchunter.sys | vulnerable d | 3.0 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 28 | 7 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | 安芯网盾（北京）科技有限公司 |
| daxin_blank4.sys | malicious | 3.0 | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | KeInsertQueueApc, NtQuerySystemInformation, PsLookupProcessByProcessId... | unsigned |
| blacklotus_driver.sys | malicious | 3.0 | x64 | GUARD_CF, GS_COOKIE | 0 | 0 | 500 |  | unsigned |
| blacklotus_driver.sys | malicious | 3.0 | x64 | GUARD_CF, GS_COOKIE | 0 | 0 | 500 |  | unsigned |
| PanMonFltX64.sys | vulnerable d | 2.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag | GlobalSign CodeSigning CA |
| Lv561av.sys | vulnerable d | 2.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 18 | 4 | 500 |  | VeriSign Class 3 Code Sig |
| ProtectS.sys | vulnerable d | 2.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 |  | GlobalSign CodeSigning CA |
| ProtectS.sys | vulnerable d | 2.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 |  | GlobalSign CodeSigning CA |
| PanMonFlt.sys | vulnerable d | 2.5 | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, memcpy | GlobalSign CodeSigning CA |
| probmon.sys | vulnerable d | 2.5 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | GlobalSign Primary Object |
| driver_e1123b59.sys | malicious | 2.5 | x64 | GUARD_CF, GS_COOKIE | 2 | 2 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | GlobalSign CodeSigning CA |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 1 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| bedaisy.sys | vulnerable d | 2.5 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | MmMapLockedPagesSpecifyCache | BattlEye Innovations e.K. |
| MSqPq.sys | malicious | 2.5 | x64 | GUARD_CF, GS_COOKIE | 4 | 2 | 500 |  | YI ZENG |
| Netfilter.sys | vulnerable d | 2.0 | x86 | GUARD_CF, GS_COOKIE | 3 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | unsigned |
| Netfilter.sys | vulnerable d | 2.0 | x86 | GUARD_CF, GS_COOKIE | 3 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | unsigned |
| Netfilter.sys | vulnerable d | 2.0 | x64 | GUARD_CF, GS_COOKIE | 2 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | unsigned |
| Netfilter.sys | vulnerable d | 2.0 | x64 | GUARD_CF, GS_COOKIE | 1 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | Microsoft Windows Hardwar |
| Netfilter.sys | vulnerable d | 2.0 | x64 | GUARD_CF, GS_COOKIE | 2 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | unsigned |
| d.sys | vulnerable d | 2.0 | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | unsigned |
| 4.sys | malicious | 2.0 | x64 | GUARD_CF, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Microsoft Windows Hardwar |
| NodeDriver.sys | malicious | 2.0 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Microsoft Windows Hardwar |
| LcTkA.sys | malicious | 2.0 | x64 | GUARD_CF, GS_COOKIE | 1 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Microsoft Windows Hardwar |
| 7.sys | malicious | 2.0 | x64 | GUARD_CF, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Microsoft Windows Hardwar |
| Netfilter.sys | vulnerable d | 1.0 | x86 | GUARD_CF, GS_COOKIE | 3 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | Microsoft Windows Hardwar |
| Netfilter.sys | vulnerable d | 1.0 | x64 | GUARD_CF, GS_COOKIE | 2 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | Microsoft Windows Hardwar |
| Netfilter.sys | vulnerable d | 1.0 | x64 | GUARD_CF, GS_COOKIE | 2 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | Microsoft Windows Hardwar |
| Netfilter.sys | vulnerable d | 1.0 | x86 | GUARD_CF, GS_COOKIE | 3 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | Microsoft Windows Hardwar |
| Netfilter.sys | vulnerable d | 1.0 | x64 | GUARD_CF, GS_COOKIE | 2 | 2 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | Microsoft Windows Hardwar |
| Netfilter.sys | vulnerable d | 1.0 | x86 | GUARD_CF, GS_COOKIE | 3 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | Microsoft Windows Hardwar |
| POORTRY2.sys | malicious | 1.0 | x86 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | Microsoft Windows Hardwar |
| Air_SYSTEM10.sys | malicious | 1.0 | x64 | GUARD_CF, GS_COOKIE | 3 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Microsoft Windows Hardwar |
| 2.sys | malicious | 1.0 | x64 | GUARD_CF, GS_COOKIE | 1 | 1 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, KeStackAttachProcess... | DigiCert SHA2 Assured ID  |
| fd3b7234419fafc9bdd533f48896ed73_b816c5cd.sys | vulnerable d | 1.0 | x64 | GUARD_CF, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Microsoft Windows Hardwar |
| netfilterdrv.sys | vulnerable d | 1.0 | x64 | GUARD_CF, GS_COOKIE | 1 | 1 | 411 | ExAllocatePoolWithTag, ExFreePoolWithTag, MmIsAddressValid... | Microsoft Windows Hardwar |
| fur.sys | malicious | 1.0 | x64 | GUARD_CF, GS_COOKIE | 0 | 0 | 500 | ExAllocatePool, ExFreePoolWithTag, MmMapLockedPagesSpecifyCache... | Microsoft Windows Hardwar |
| CSC.sys | vulnerable d | 0.5 | x64 | GUARD_CF, GS_COOKIE | 1 | 0 | 500 | ExAllocatePool2, ExAllocatePoolWithTag, ExFreePoolWithTag... | unsigned |
| FairplayKD.sys | vulnerable d | 0.0 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 1 | 0 | 500 | ExAllocatePoolWithTag, ExFreePoolWithTag, IoGetCurrentProcess... | Thawte Code Signing CA -  |
| POORTRY.sys | malicious | 0.0 | x64 | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 2 | 1 | 500 | ExAllocatePool, ExFreePoolWithTag, KeStackAttachProcess... | Microsoft Windows Hardwar |
| PCHunter.sys | vulnerable d | 0.0 | x64 | DYNAMIC_BASE, NX_COMPAT, GUARD_CF, FORCE_INTEGRITY, GS_COOKIE | 19 | 1 | 500 | ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag... | 一普明为(北京)信息技术有限公司 |

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
