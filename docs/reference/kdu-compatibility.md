---
title: KDU Provider Compatibility Analysis
description: Cross-referencing LOLDrivers with Kernel Driver Utility (KDU) provider requirements
---

# KDU Provider Compatibility Analysis

Automated analysis cross-referencing **1,775 LOLDrivers** against [hfiref0x/KDU](https://github.com/hfiref0x/KDU) (Kernel Driver Utility) provider requirements.

KDU uses vulnerable signed drivers to load unsigned kernel code. Each provider driver exposes specific primitives (physical memory mapping, virtual memory read/write, MSR access, or port I/O) that KDU chains to achieve kernel code execution.

## Key Findings

| Metric | Count |
|--------|-------|
| Total LOLDrivers analyzed | 1,775 |
| Known KDU providers found | 34/57 |
| **Potential new KDU providers** | **238** |
| Physical memory primitives | 784 drivers |
| Virtual memory primitives | 1,110 drivers |
| Process manipulation | 923 drivers |
| Port I/O access | 423 drivers |

## KDU Provider Primitives

KDU requires drivers to expose one or more of these callback primitives:

| Primitive | Purpose | Key Imports |
|-----------|---------|-------------|
| `ReadPhysicalMemory` / `WritePhysicalMemory` | Direct physical address R/W | `MmMapIoSpace`, `MmGetPhysicalAddress` |
| `ReadKernelVM` / `WriteKernelVM` | Kernel virtual memory R/W | `MmCopyVirtualMemory`, `ZwMapViewOfSection` |
| `VirtualToPhysical` | VA→PA translation for page table walks | `MmGetPhysicalAddress`, `MmGetVirtualForPhysical` |
| `QueryPML4Value` | Page Map Level 4 base for CR3 | Physical memory scan of low stub |
| `MapDriver` | Full kernel code loading chain | Physical + Virtual + PML4 |
| `ControlDSE` | Disable Driver Signature Enforcement | Virtual memory write to `ci.dll!g_CiOptions` |
| `OpenProcess` | Arbitrary process handle acquisition | `PsLookupProcessByProcessId`, `ObOpenObjectByPointer` |

KDU supports these actions:

- **MapDriver** — Load unsigned code into kernel (requires physical + virtual memory)
- **DKOM** — Direct Kernel Object Manipulation (requires virtual memory write)
- **DSECorruption** — Patch `ci.dll` to disable signature checks (requires virtual memory write)
- **DumpProcess** — Read arbitrary process memory (requires process + virtual memory)

## Existing KDU Providers in LOLDrivers

**34** of KDU's 57 known providers appear in the LOLDrivers catalog:

| KDU # | Driver | Vendor | CVE | Action | Score | IOCTLs |
|-------|--------|--------|-----|--------|-------|--------|
| 0 | `iqvw64e.sys, iQVW64.SYS, IQVW32.sys, NalDrv.sys` | Intel NAL | CVE-2015-2291 | MapDriver | 15 | 4 |
| 1 | `RTCore64.sys` | MSI RTCore | CVE-2019-16098 | MapDriver | 14 | 0 |
| 2 | `gdrv.sys` | Gigabyte GDRV | CVE-2018-19320 | MapDriver | 15 | 0 |
| 3 | `ATSZIO.sys, ATSZIO64.sys` | ASUSTeK WinFlash | — | MapDriver | 13 | 0 |
| 4 | `MsIo64.sys` | Patriot Viper RGB | — | MapDriver | 15 | 0 |
| 5 | `GLCKIO2.sys` | ASRock Polychrome | — | MapDriver | 14 | 0 |
| 6 | `EneIo64.sys` | G.SKILL Trident Z | — | MapDriver | 15 | 4 |
| 8 | `EneTechIo64.sys` | Thermaltake RAM | — | MapDriver | 13 | 0 |
| 9 | `Phymemx64.sys` | Huawei MateBook | — | MapDriver | 12 | 0 |
| 10 | `rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys` | Realtek Dash | — | MapDriver | 15 | 19 |
| 12 | `LHA.sys` | LG Device Mgr | — | MapDriver | 10 | 0 |
| 14 | `directio64.sys` | PassMark | — | MapDriver | 15 | 0 |
| 16 | `dbutil_2_3.sys` | Dell BIOS | CVE-2021-21551 | MapDriver | 15 | 0 |
| 17 | `mimidrv.sys` | Mimikatz | — | DumpProcess | 14 | 0 |
| 18 | `kprocesshacker.sys` | Process Hacker | — | OpenProcess | 7 | 0 |
| 20 | `DBUtilDrv2.sys` | Dell BIOS | CVE-2021-21551 | MapDriver | 13 | 0 |
| 21 | `dbk64.sys` | Cheat Engine | — | MapDriver | 14 | 0 |
| 22 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | ASUS GPU TweakII | — | MapDriver | 13 | 0 |
| 23 | `hw.sys` | Marvin HW | CVE-2023-1679 | MapDriver | 15 | 0 |
| 24 | `SysDrv3S.sys` | CODESYS | CVE-2022-22516 | MapDriver | 15 | 0 |
| 25 | `amsdk.sys` | Zemana | — | DSECorruption | 8 | 0 |
| 26 | `inpoutx64.sys` | HiRes | — | MapDriver | 14 | 0 |
| 28 | `AsrDrv106.sys` | ASRock | — | MapDriver | 15 | 0 |
| 29 | `ALSysIO64.sys` | Core Temp | — | MapDriver | 15 | 0 |
| 30 | `AMDRyzenMasterDriver.sys` | AMD RyzenMaster | CVE-2020-12928 | MapDriver | 15 | 0 |
| 31 | `physmem.sys` | Hilscher | — | MapDriver | 15 | 0 |
| 40 | `nvoclock.sys` | NVIDIA OC | — | MapDriver | 15 | 0 |
| 41 | `irec.sys` | Binalyze DFIR | — | DKOM | 8 | 0 |
| 43 | `rzpnk.sys` | Razer Synapse | CVE-2017-9769 | MapDriver | 13 | 0 |
| 44 | `PDFWKRNL.sys` | AMD Radeon | — | MapDriver | 15 | 0 |
| 45 | `AODDriver.sys` | AMD OverDrive | — | MapDriver | 15 | 0 |
| 53 | `HwRwDrv.sys` | Jun Liu HW R/W | — | MapDriver | 15 | 0 |
| 55 | `throttlestop.sys` | ThrottleStop | — | MapDriver | 9 | 0 |
| 56 | `TPwSav.sys` | Toshiba PowerSave | — | MapDriver | 15 | 0 |

## Potential New KDU Providers

**238 drivers** in LOLDrivers have primitives compatible with KDU but are not yet KDU providers.

### Tier 1 — Full Primitive Set (48 drivers)

These drivers import both physical and virtual memory APIs with additional process or port I/O capabilities. They could support `MapDriver` — the most powerful KDU action.

| Driver | Company | Primitives | Potential Action | Score |
|--------|---------|------------|-----------------|-------|
| `driver7-x86-withoutdbg.sys` | — | Physical Memory, Virtual Memory, Process, Port I/O | MapDriver | 15 |
| `directio32_legacy.sys, DirectIo32.sys` | — | Physical Memory, Virtual Memory, Process, Port I/O | MapDriver | 15 |
| `pchunter.sys` | — | Physical Memory, Virtual Memory, Process, Port I/O | MapDriver | 3 |
| `RtsPer.sys` | — | Physical Memory, Virtual Memory, Process, Port I/O | MapDriver | 11 |
| `HwOs2Ec10x64.sys` | — | Physical Memory, Virtual Memory, Process, Port I/O | MapDriver | 15 |
| `kEvP64.sys` | — | Physical Memory, Virtual Memory, Process, Port I/O | MapDriver | 11 |
| `DirectIo32.sys` | — | Physical Memory, Virtual Memory, Process, Port I/O | MapDriver | 15 |
| `driver7-x86.sys` | — | Physical Memory, Virtual Memory, Process, Port I/O | MapDriver | 15 |
| `ATSZIO.sys` | — | Physical Memory, Virtual Memory, Process, Port I/O | MapDriver | 15 |
| `cg6kwin2k.sys` | — | Physical Memory, Virtual Memory, Process | MapDriver | 14 |
| `nvaudio.sys` | — | Physical Memory, Virtual Memory, Process | MapDriver | 15 |
| `AMDPowerProfiler.sys` | — | Physical Memory, Virtual Memory, Process | MapDriver | 15 |
| `IoAccess.sys` | — | Physical Memory, Virtual Memory, Port I/O | MapDriver | 11 |
| `GEDevDrv.SYS` | — | Physical Memory, Virtual Memory, Port I/O | MapDriver | 9 |
| `driver7-x64.sys` | — | Physical Memory, Virtual Memory, Process | MapDriver | 15 |
| `CorsairLLAccess64.sys` | — | Physical Memory, Virtual Memory, Port I/O | MapDriver | 9 |
| `wnbios.sys` | — | Physical Memory, Virtual Memory, Process | MapDriver | 14 |
| `PcieCubed.sys` | — | Physical Memory, Virtual Memory, Process | MapDriver | 5 |
| `SANDRA.sys` | — | Physical Memory, Virtual Memory, Port I/O | MapDriver | 10 |
| `sysconp.sys` | — | Physical Memory, Virtual Memory, Port I/O | MapDriver | 15 |
| `AsUpIO.sys, AsUpIO64.sys` | — | Physical Memory, Virtual Memory, Process | MapDriver | 14 |
| `aswArPot.sys` | — | Physical Memory, Virtual Memory, Process | MapDriver | 15 |
| `segwindrvx64.sys` | — | Physical Memory, Virtual Memory, Port I/O | MapDriver | 14 |
| `TmComm.sys` | — | Physical Memory, Virtual Memory, Process | MapDriver | 12 |
| `amigendrv64.sys` | — | Physical Memory, Virtual Memory, Process | MapDriver | 14 |
| `amifldrv64.sys, amifldrv.sys` | — | Physical Memory, Virtual Memory, Process | MapDriver | 15 |
| `VBoxMouseNT.sys` | — | Physical Memory, Virtual Memory, Port I/O | MapDriver | 15 |
| `Bs_Def.sys` | — | Physical Memory, Virtual Memory, Process | MapDriver | 15 |
| `aswArPot.sys, avgArPot.sys` | — | Physical Memory, Virtual Memory, Process | MapDriver | 15 |
| `atillk64.sys` | — | Physical Memory, Virtual Memory, Port I/O | MapDriver | 15 |
| `driver_89036534.sys` | — | Physical Memory, Virtual Memory, Process | MapDriver | 13 |
| `Agent64.sys` | — | Physical Memory, Virtual Memory, Process | MapDriver | 15 |
| `ACE-BASE.sys` | — | Physical Memory, Virtual Memory, Process | MapDriver | 11 |
| `elrawdsk.sys` | — | Physical Memory, Virtual Memory, Process | MapDriver | 15 |
| `UCOREW64.SYS` | — | Physical Memory, Virtual Memory, Process | MapDriver | 15 |
| `kerneld.amd64` | — | Physical Memory, Virtual Memory, Port I/O | MapDriver | 15 |
| `VBoxDrv.sys` | — | Physical Memory, Virtual Memory, Process | MapDriver | 12 |
| `iQVW64.SYS` | — | Physical Memory, Virtual Memory, Port I/O | MapDriver | 15 |
| `asmmap64.sys` | — | Physical Memory, Virtual Memory, Process | MapDriver | 14 |
| `gpcidrv64.sys` | — | Physical Memory, Virtual Memory, Process | MapDriver | 15 |

### Tier 2 — Partial Primitives (52 drivers)

These drivers have either physical memory OR virtual memory + process primitives. They could support DKOM, DSECorruption, or physical-only mapping.

| Driver | Company | Primitives | Potential Action | Score |
|--------|---------|------------|-----------------|-------|
| `BS_RCIOW1064.sys` | — | Physical Memory, Process, Port I/O | MapDriver (physical only) | 15 |
| `PhlashNT.sys` | — | Physical Memory, Virtual Memory | MapDriver | 15 |
| `WinFlash64.sys` | — | Physical Memory, Virtual Memory | MapDriver | 15 |
| `BS_I2cIo.sys` | — | Physical Memory, Process, Port I/O | MapDriver (physical only) | 15 |
| `GPU-Z.sys` | — | Physical Memory, Virtual Memory | MapDriver | 10 |
| `iscflashx64.sys` | — | Physical Memory, Virtual Memory | MapDriver | 15 |
| `bs_rcio64.sys` | — | Physical Memory, Process, Port I/O | MapDriver (physical only) | 15 |
| `phymem64.sys` | — | Physical Memory, Virtual Memory | MapDriver | 15 |
| `VBoxUSB.Sys` | — | Physical Memory, Virtual Memory | MapDriver | 15 |
| `BS_HWMIO64_W10.sys` | — | Physical Memory, Process, Port I/O | MapDriver (physical only) | 15 |
| `BSMEMx64.sys` | — | Physical Memory, Process, Port I/O | MapDriver (physical only) | 15 |
| `rtkiow8x64.sys ` | — | Physical Memory, Virtual Memory | MapDriver | 15 |
| `AsmIo64.sys` | — | Physical Memory, Virtual Memory | MapDriver | 15 |
| `RadHwMgr.sys` | — | Physical Memory, Process, Port I/O | MapDriver (physical only) | 15 |
| `driver_290bc782.sys` | — | Physical Memory, Virtual Memory | MapDriver | 12 |
| `atlAccess.sys` | — | Physical Memory, Virtual Memory | MapDriver | 15 |
| `BS_HWMIo64.sys` | — | Physical Memory, Process, Port I/O | MapDriver (physical only) | 15 |
| `CP2X72C.SYS` | — | Physical Memory, Virtual Memory | MapDriver | 10 |
| `BS_RCIO.sys` | — | Physical Memory, Process, Port I/O | MapDriver (physical only) | 15 |
| `SMARTEIO64.SYS` | — | Physical Memory, Virtual Memory | MapDriver | 15 |
| `TdkLib64.sys` | — | Physical Memory, Virtual Memory | MapDriver | 15 |
| `phymem_ext64.sys` | — | Physical Memory, Virtual Memory | MapDriver | 15 |
| `tdeio64.sys` | — | Physical Memory, Virtual Memory | MapDriver | 15 |
| `SmSerl64.sys` | — | Physical Memory, Virtual Memory | MapDriver | 15 |
| `BS_Flash64.sys` | — | Physical Memory, Virtual Memory | MapDriver | 15 |
| `otipcibus.sys` | — | Physical Memory, Virtual Memory | MapDriver | 15 |
| `GtcKmdfBs.sys` | — | Physical Memory, Port I/O | MapDriver (physical only) | 15 |
| `OpenLibSys.sys` | — | Physical Memory, Port I/O | MapDriver (physical only) | 15 |
| `mydrivers.sys` | — | Physical Memory, Port I/O | MapDriver (physical only) | 15 |
| `HWiNFO64I.SYS` | — | Physical Memory, Port I/O | MapDriver (physical only) | 15 |
| `ComputerZ.Sys` | — | Physical Memory, Port I/O | MapDriver (physical only) | 15 |
| `cpuz.sys` | — | Physical Memory, Port I/O | MapDriver (physical only) | 15 |
| `cpuz_x64.sys` | — | Physical Memory, Port I/O | MapDriver (physical only) | 15 |
| `PanIOx64.sys` | — | Physical Memory, Port I/O | MapDriver (physical only) | 15 |
| `DirectIo.sys` | — | Virtual Memory, Process, Port I/O | DKOM / DSECorruption | 15 |
| `hwdetectng.sys` | — | Physical Memory, Port I/O | MapDriver (physical only) | 15 |
| `NTIOLib.sys` | — | Physical Memory, Port I/O | MapDriver (physical only) | 15 |
| `cpuz141.sys` | — | Physical Memory, Port I/O | MapDriver (physical only) | 15 |
| `msio32.sys` | — | Virtual Memory, Process, Port I/O | DKOM / DSECorruption | 15 |
| `FH-EtherCAT_DIO.sys` | — | Physical Memory, Process | MapDriver (physical only) | 13 |
| ... | ... | ... | ... | ... |
| *12 more drivers* | | | | |

### Tier 3 — Single Primitive (0 drivers)

Physical memory only — could support brute-force physical mapping but lack virtual memory for reliable exploitation.

| Driver | Company | Primitives | Score |
|--------|---------|------------|-------|

## Import Primitive Heatmap

Frequency of KDU-relevant imports across all 1,775 LOLDrivers:

| Import | Count | % of Dataset | KDU Relevance |
|--------|-------|-------------|---------------|
| `MmMapIoSpace` | 784 | 44.2% | Physical memory mapping |
| `ObReferenceObjectByHandle` | 738 | 41.6% | Handle → object pointer |
| `PsLookupProcessByProcessId` | 519 | 29.2% | PID → EPROCESS lookup |
| `MmMapLockedPagesSpecifyCache` | 481 | 27.1% | MDL-based mapping |
| `ZwMapViewOfSection` | 457 | 25.7% | Section object mapping |
| `HalGetBusDataByOffset` | 337 | 19.0% | PCI config space access |
| `MmGetPhysicalAddress` | 271 | 15.3% | VA → PA translation |
| `KeStackAttachProcess` | 269 | 15.2% | Cross-process attach |
| `READ_PORT_ULONG` | 182 | 10.3% | Hardware port read |
| `WRITE_PORT_ULONG` | 174 | 9.8% | Hardware port write |
| `MmAllocateContiguousMemory` | 153 | 8.6% | Contiguous physical alloc |
| `ZwDuplicateObject` | 103 | 5.8% | Handle duplication |
| `MmCopyVirtualMemory` | 33 | 1.9% | Cross-process memory copy |

## Methodology

1. **Dataset**: 1,775 unique driver binaries from [LOLDrivers.io](https://loldrivers.io) catalog, downloaded via VirusTotal
2. **Static analysis**: DriverAtlas Tier 1 (PE parsing, import analysis, IOCTL extraction) on all drivers
3. **KDU mapping**: Cross-referenced driver filenames against KDU's 57 known providers (indices 0–56)
4. **Primitive classification**: Categorized each driver's imports into KDU primitive groups (physical memory, virtual memory, process, port I/O)
5. **Scoring**: Ranked candidates by primitive coverage — Tier 1 (physical + virtual + extras), Tier 2 (partial), Tier 3 (single primitive)

**Important limitation**: Import presence doesn't mean IOCTL exposure. A driver importing `MmMapIoSpace` might use it internally without exposing it through an IOCTL handler. Tier 2 (Ghidra) deep analysis verifies which imports are actually reachable from user-mode IOCTLs.

---

*Generated by [DriverAtlas](https://github.com/splintersfury/DriverAtlas) × [KernelSight](https://splintersfury.github.io/KernelSight/)*