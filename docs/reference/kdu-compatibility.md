---
title: KDU Provider Compatibility Analysis
description: Which LOLDrivers could be weaponized as KDU providers? Automated analysis of 1,775 drivers.
---

# KDU Provider Compatibility Analysis

Which [LOLDrivers](https://loldrivers.io) could be weaponized as [KDU](https://github.com/hfiref0x/KDU) providers? This page maps each driver's IOCTL-reachable primitives to KDU's provider requirements.

**Last updated:** 2026-03-12
**Drivers analyzed:** 1775 (Tier 1) / 1775 (Tier 2 Ghidra)

## TL;DR

Out of 1,775 LOLDrivers, **122 are confirmed MapDriver candidates** — they have Ghidra-verified physical + virtual memory primitives reachable from IOCTL handlers. These are the highest-priority entries for driver blocklists.

The worst offenders: WinFlash64.sys (11 IOCTLs mapping physical memory, all mitigations off), ComputerZ.sys (single IOCTL to `MmMapIoSpace`, MSR read gadget), rtkio.sys (Realtek, `MmMapIoSpace` with zero validation).

## Key Findings

| Metric | Count |
|--------|-------|
| Total drivers analyzed | 1,775 |
| **KDU-compatible** | **1404** (79%) |
| Tier 2 confirmed | 354 |
| Tier 1 likely | 1050 |
| MapDriver capable | 391 |
| MapDriver (physical brute-force) | 393 |
| DKOM / DSECorruption | 620 |
| DumpProcess | 0 |

## What This Means

KDU uses vulnerable signed drivers to load unsigned kernel code. A driver is "KDU-compatible" if it exposes memory primitives through its IOCTL handlers that an attacker can chain into kernel code execution.

- **Confirmed**: Ghidra analysis verified the dangerous API is reachable from an IOCTL handler
- **Likely**: The driver imports the API, but we haven't confirmed IOCTL reachability yet

KDU supports these actions, from most to least powerful:

1. **MapDriver** - Load arbitrary unsigned code into the kernel (needs physical + virtual memory R/W)
2. **MapDriver (physical brute-force)** - Same, but uses only physical memory with PML4 brute-forcing
3. **DKOM** - Direct Kernel Object Manipulation, e.g. hiding processes (needs virtual memory write)
4. **DSECorruption** - Patch `ci.dll!g_CiOptions` to disable driver signature enforcement
5. **DumpProcess** - Read arbitrary process memory (needs process handle + virtual memory read)

## Confirmed MapDriver Candidates

These 122 drivers have Ghidra-confirmed physical + virtual memory primitives reachable from IOCTL handlers. They could load unsigned kernel code.

| # | Driver | Primitives (confirmed IOCTLs) | NEITHER I/O | Mitigations OFF |
|---|--------|------------------------------|-------------|-----------------|
| 1 | `segwindrvx64.sys` | PortIO, QueryPML4Value, ReadKVM, ReadPhysMem, VToPhys, WriteKVM, WritePhysMem |  | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 2 | `PDFWKRNL.sys` | QueryPML4Value, ReadKVM, ReadPhysMem, VToPhys, WriteKVM, WritePhysMem | YES | GUARD_CF, GS_COOKIE |
| 3 | `WinFlash64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 4 | `kerneld.amd64` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 5 | `atillk64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 6 | `TdkLib64.sys` | QueryPML4Value, ReadKVM, ReadPhysMem, VToPhys, WriteKVM, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 7 | `CP2X72C.SYS` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 8 | `hw.sys` | PortIO | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 9 | `dbk64.sys` | OpenProcess, ReadKVM, WriteKVM |  | GUARD_CF, GS_COOKIE |
| 10 | `NCHGBIOS2x64.SYS` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 11 | `asio.sys` [^asio] | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 12 | `AODDriver.sys` | PortIO, QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 13 | `ATSZIO.sys` | PortIO, QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 14 | `BioNTdrv.sys` | OpenProcess, QueryPML4Value, ReadKVM, ReadPhysMem, VToPhys, WriteKVM, WritePhysMem |  | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 15 | `driver7-x86.sys` | PortIO |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 16 | `gdrv.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 17 | `rtkio.sys` [^rtkio] | PortIO, QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 18 | `rtkiow8x64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | GUARD_CF, GS_COOKIE |
| 19 | `AsUpIO.sys` [^asup] | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 20 | `DirectIo32.sys` | PortIO | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 21 | `rtif.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 22 | `driver7-x86-withoutdbg.sys` | PortIO | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 23 | `directio32_legacy.sys` [^dio32] | PortIO |  | GUARD_CF, GS_COOKIE |
| 24 | `gpcidrv64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 25 | `directio64.sys` [^dio64] | OpenProcess |  | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 26 | `atlAccess.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 27 | `phymem_ext64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 28 | `nvoclock.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 29 | `BS_Flash64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 30 | `aswArPot.sys` [^avast] | ReadKVM, WriteKVM | YES | GUARD_CF, GS_COOKIE |
| ... | *92 more — [download full dataset](#download)* | | | |

[^asio]: Includes AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys — 14 hash variants in full dataset
[^rtkio]: Includes rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys — 9 hash variants in full dataset
[^asup]: Includes AsUpIO64.sys — 2 hash variants in full dataset
[^dio32]: Includes DirectIo32.sys — 2 hash variants in full dataset
[^dio64]: Includes utiA2D4.sys — 3 hash variants in full dataset
[^avast]: Includes avgArPot.sys — 24 hash variants in full dataset (Avast/AVG anti-rootkit)

## Confirmed Physical Brute-Force Candidates

These 157 drivers have confirmed physical memory R/W but lack virtual memory. KDU can brute-force PML4 via physical scanning to achieve MapDriver.

| # | Driver | Confirmed APIs | NEITHER I/O | Mitigations OFF |
|---|--------|---------------|-------------|-----------------|
| 1 | `kerneld.amd64` [^kerneld] | `MmMapIoSpace` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 2 | `CP2X72C.SYS` | `MmMapIoSpace, READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| ... | *155 more — [download full dataset](#download)* | | | |

[^kerneld]: 28 hash variants in full dataset, all with identical `MmMapIoSpace` primitive

## Confirmed DKOM / DSECorruption Candidates

These 75 drivers have confirmed virtual memory write primitives. They can manipulate kernel objects or patch `ci.dll` to disable signature enforcement.

| # | Driver | Confirmed APIs | NEITHER I/O | Mitigations OFF |
|---|--------|---------------|-------------|-----------------|
| 1 | `procexp.Sys` [^procexp] | `ObOpenObjectByPointer, ObReferenceObjectByHandle, ZwOpenProcess` |  | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 2 | `echo_driver.sys` | `KeStackAttachProcess, ObOpenObjectByPointer, ObReferenceObjectByHandle, PsLookupProcessByProcessId` |  | GUARD_CF, GS_COOKIE |
| 3 | `kprocesshacker.sys` | `ObReferenceObjectByHandle` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 4 | `inpout32.sys` [^inpout] | `READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR, WRITE_PORT_ULONG` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 5 | `DirectIo.sys` | `READ_PORT_UCHAR, WRITE_PORT_UCHAR, WRITE_PORT_ULONG` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 6 | `DirectIo32.sys` [^dkom_dio32] | `READ_PORT_ULONG, WRITE_PORT_UCHAR` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| ... | *69 more — [download full dataset](#download)* | | | |

[^procexp]: 14 hash variants in full dataset (Sysinternals Process Explorer)
[^inpout]: 5 hash variants in full dataset
[^dkom_dio32]: 5 hash variants in full dataset

## Likely MapDriver Candidates (Tier 1 only)

These 269 drivers import the right APIs but haven't been Ghidra-confirmed yet. The dangerous imports may be used internally rather than exposed through IOCTLs.

| # | Driver | Imported Primitives | Mitigations OFF |
|---|--------|-------------------|-----------------|
| 1 | `RtsPer.sys` | OpenProcess, PortIO, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | GUARD_CF, GS_COOKIE |
| 2 | `AODDriver.sys` | OpenProcess, PortIO, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 3 | `ATSZIO.sys` | OpenProcess, PortIO, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 4 | `gdrv.sys` | OpenProcess, PortIO, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 5 | `iqvw64e.sys` [^iqvw] | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 6 | `rtkio.sys` [^rtkio2] | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 7 | `cg6kwin2k.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 8 | `asio.sys` [^asio2] | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 9 | `nvaudio.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 10 | `AMDPowerProfiler.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 11 | `pchunter.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 12 | `hw.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 13 | `IoAccess.sys` | PortIO, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 14 | `GEDevDrv.SYS` | PortIO, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 15 | `driver7-x64.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 16 | `directio64.sys` [^dio64_2] | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| ... | *253 more — [download full dataset](#download)* | | |

[^iqvw]: Includes iQVW64.SYS, IQVW32.sys, NalDrv.sys
[^rtkio2]: Includes rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys
[^asio2]: Includes AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys — 9 hash variants in full dataset
[^dio64_2]: 5 hash variants in full dataset

## Download

The full dataset is available at:

- **Results JSON**: All 1,775 drivers with Tier 1 + Tier 2 analysis — `~/.driveratlas/loldrivers/results.json`
- **Pipeline**: Run your own analysis with [DriverAtlas](https://github.com/splintersfury/DriverAtlas)

## Methodology

1. **Tier 1** (all drivers): PE parsing extracts imports, device names, IOCTLs, and mitigations
2. **Tier 2** (Ghidra): Headless decompilation traces which imports are called from which IOCTL handlers
3. **KDU scoring**: Maps confirmed IOCTL-reachable APIs to KDU primitive types (ReadPhysicalMemory, WriteKernelVM, OpenProcess, etc.)
4. **Action assessment**: Determines which KDU actions the primitives support (MapDriver > DKOM > DSECorruption > DumpProcess)

**Confirmed** = Ghidra verified the API call exists inside an IOCTL dispatch handler
**Likely** = The driver imports the API, but IOCTL reachability is unverified

---

*Generated by [DriverAtlas](https://github.com/splintersfury/DriverAtlas) × [KernelSight](https://splintersfury.github.io/KernelSight/)*
