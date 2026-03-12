---
title: KDU Provider Compatibility Analysis
description: Which LOLDrivers could be weaponized as KDU providers? Automated analysis of 1,775 drivers.
---

# KDU Provider Compatibility Analysis

Which [LOLDrivers](https://loldrivers.io) could be weaponized as [KDU](https://github.com/hfiref0x/KDU) providers? This page answers that question by mapping each driver's confirmed IOCTL-reachable primitives to KDU's provider requirements.

**Last updated:** 2026-03-12  
**Drivers analyzed:** 1775 (Tier 1) / 1775 (Tier 2 Ghidra)  

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
| 3 | `PDFWKRNL.sys` | QueryPML4Value, ReadKVM, ReadPhysMem, VToPhys, WriteKVM, WritePhysMem | YES | GUARD_CF, GS_COOKIE |
| 4 | `PDFWKRNL.sys` | QueryPML4Value, ReadKVM, ReadPhysMem, VToPhys, WriteKVM, WritePhysMem | YES | GUARD_CF, GS_COOKIE |
| 5 | `PDFWKRNL.sys` | QueryPML4Value, ReadKVM, ReadPhysMem, VToPhys, WriteKVM, WritePhysMem | YES | GUARD_CF, GS_COOKIE |
| 6 | `WinFlash64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 7 | `kerneld.amd64` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 8 | `kerneld.amd64` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 9 | `atillk64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 10 | `atillk64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 11 | `atillk64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 12 | `atillk64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 13 | `kerneld.amd64` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 14 | `kerneld.amd64` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 15 | `kerneld.amd64` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 16 | `kerneld.amd64` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 17 | `atillk64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 18 | `TdkLib64.sys` | QueryPML4Value, ReadKVM, ReadPhysMem, VToPhys, WriteKVM, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 19 | `CP2X72C.SYS` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 20 | `CP2X72C.SYS` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 21 | `hw.sys` | PortIO | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 22 | `dbk64.sys` | OpenProcess, ReadKVM, WriteKVM |  | GUARD_CF, GS_COOKIE |
| 23 | `dbk64.sys` | OpenProcess, ReadKVM, WriteKVM |  | GUARD_CF, GS_COOKIE |
| 24 | `TdkLib64.sys` | QueryPML4Value, ReadKVM, ReadPhysMem, VToPhys, WriteKVM, WritePhysMem | YES | GUARD_CF, GS_COOKIE |
| 25 | `TdkLib64.sys` | ReadKVM, WriteKVM | YES | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 26 | `TdkLib64.sys` | QueryPML4Value, ReadKVM, ReadPhysMem, VToPhys, WriteKVM, WritePhysMem | YES | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 27 | `TdkLib64.sys` | QueryPML4Value, ReadKVM, ReadPhysMem, VToPhys, WriteKVM, WritePhysMem | YES | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 28 | `TdkLib64.sys` | ReadKVM, WriteKVM | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 29 | `TdkLib64.sys` | ReadKVM, WriteKVM | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 30 | `NCHGBIOS2x64.SYS` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 31 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 32 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 33 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 34 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 35 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 36 | `AODDriver.sys` | PortIO, QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 37 | `ATSZIO.sys` | PortIO, QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 38 | `NCHGBIOS2x64.SYS` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 39 | `BioNTdrv.sys` | OpenProcess, QueryPML4Value, ReadKVM, ReadPhysMem, VToPhys, WriteKVM, WritePhysMem |  | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 40 | `driver7-x86.sys` | PortIO |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 41 | `gdrv.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 42 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 43 | `AODDriver.sys` | PortIO, QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 44 | `gpcidrv64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 45 | `rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys` | PortIO, QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 46 | `rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys` | PortIO, QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 47 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 48 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 49 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 50 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 51 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 52 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 53 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 54 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 55 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 56 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 57 | `rtkiow8x64.sys ` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | GUARD_CF, GS_COOKIE |
| 58 | `AsUpIO.sys, AsUpIO64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 59 | `AsUpIO.sys, AsUpIO64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 60 | `DirectIo32.sys` | PortIO | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 61 | `DirectIo32.sys` | PortIO | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 62 | `rtif.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 63 | `gdrv.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 64 | `gdrv.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 65 | `gdrv.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 66 | `driver7-x86-withoutdbg.sys` | PortIO |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 67 | `directio32_legacy.sys, DirectIo32.sys` | PortIO |  | GUARD_CF, GS_COOKIE |
| 68 | `rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 69 | `rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 70 | `rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 71 | `rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 72 | `rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 73 | `rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 74 | `WinFlash64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 75 | `directio64.sys` | OpenProcess |  | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 76 | `AODDriver.sys` | PortIO | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 77 | `AODDriver.sys` | PortIO |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 78 | `AODDriver.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 79 | `AODDriver.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 80 | `atlAccess.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 81 | `TdkLib64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 82 | `TdkLib64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 83 | `TdkLib64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 84 | `TdkLib64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 85 | `TdkLib64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 86 | `phymem_ext64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 87 | `phymem_ext64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 88 | `phymem_ext64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 89 | `phymem_ext64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 90 | `nvoclock.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 91 | `nvoclock.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 92 | `nvoclock.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 93 | `nvoclock.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 94 | `BS_Flash64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 95 | `WinFlash64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 96 | `directio64.sys` | OpenProcess |  | GUARD_CF, GS_COOKIE |
| 97 | `directio64.sys` | OpenProcess |  | GUARD_CF, GS_COOKIE |
| 98 | `aswArPot.sys` | ReadKVM, WriteKVM | YES | GUARD_CF, GS_COOKIE |
| 99 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | GUARD_CF, GS_COOKIE |
| 100 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | GUARD_CF, GS_COOKIE |
| 101 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 102 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 103 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | GUARD_CF, GS_COOKIE |
| 104 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | GUARD_CF, GS_COOKIE |
| 105 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 106 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | GUARD_CF, GS_COOKIE |
| 107 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | GUARD_CF, GS_COOKIE |
| 108 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | GUARD_CF, GS_COOKIE |
| 109 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | GUARD_CF, GS_COOKIE |
| 110 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | GUARD_CF, GS_COOKIE |
| 111 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 112 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 113 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 114 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | GUARD_CF, GS_COOKIE |
| 115 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 116 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | GUARD_CF, GS_COOKIE |
| 117 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 118 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | GUARD_CF, GS_COOKIE |
| 119 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 120 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 121 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 122 | `directio64.sys, utiA2D4.sys` | OpenProcess |  | GUARD_CF, GS_COOKIE |

## Confirmed Physical Brute-Force Candidates

These 157 drivers have confirmed physical memory R/W but lack virtual memory. KDU can brute-force PML4 via physical scanning to achieve MapDriver.

| # | Driver | Confirmed APIs | NEITHER I/O | Mitigations OFF |
|---|--------|---------------|-------------|-----------------|
| 1 | `kerneld.amd64` | `MmMapIoSpace` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 2 | `kerneld.amd64` | `MmMapIoSpace` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 3 | `kerneld.amd64` | `MmMapIoSpace` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 4 | `kerneld.amd64` | `MmMapIoSpace` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 5 | `kerneld.amd64` | `MmMapIoSpace` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 6 | `kerneld.amd64` | `MmMapIoSpace` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 7 | `kerneld.amd64` | `MmMapIoSpace` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 8 | `kerneld.amd64` | `MmMapIoSpace` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 9 | `kerneld.amd64` | `MmMapIoSpace` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 10 | `kerneld.amd64` | `MmMapIoSpace` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 11 | `kerneld.amd64` | `MmMapIoSpace` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 12 | `kerneld.amd64` | `MmMapIoSpace` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 13 | `kerneld.amd64` | `MmMapIoSpace` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 14 | `kerneld.amd64` | `MmMapIoSpace` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 15 | `kerneld.amd64` | `MmMapIoSpace` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 16 | `kerneld.amd64` | `MmMapIoSpace` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 17 | `kerneld.amd64` | `MmMapIoSpace` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 18 | `kerneld.amd64` | `MmMapIoSpace` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 19 | `kerneld.amd64` | `MmMapIoSpace` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 20 | `kerneld.amd64` | `MmMapIoSpace` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 21 | `kerneld.amd64` | `MmMapIoSpace` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 22 | `kerneld.amd64` | `MmMapIoSpace` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 23 | `kerneld.amd64` | `MmMapIoSpace` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 24 | `kerneld.amd64` | `MmMapIoSpace` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 25 | `CP2X72C.SYS` | `MmMapIoSpace, READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 26 | `kerneld.amd64` | `MmMapIoSpace` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 27 | `kerneld.amd64` | `MmMapIoSpace` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 28 | `kerneld.amd64` | `MmMapIoSpace` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 29 | `kerneld.amd64` | `MmMapIoSpace` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 30 | `CP2X72C.SYS` | `MmMapIoSpace, READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| ... | *127 more* | | | |

## Confirmed DKOM / DSECorruption Candidates

These 75 drivers have confirmed virtual memory write primitives. They can manipulate kernel objects or patch `ci.dll` to disable signature enforcement.

| # | Driver | Confirmed APIs | NEITHER I/O | Mitigations OFF |
|---|--------|---------------|-------------|-----------------|
| 1 | `procexp.Sys` | `ObOpenObjectByPointer, ObReferenceObjectByHandle, ZwOpenProcess` |  | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 2 | `procexp.Sys` | `ObOpenObjectByPointer, ObReferenceObjectByHandle, ZwOpenProcess` |  | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 3 | `procexp.Sys` | `ObOpenObjectByPointer, ObReferenceObjectByHandle, ZwOpenProcess` |  | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 4 | `procexp.Sys` | `ObOpenObjectByPointer, ObReferenceObjectByHandle, ZwOpenProcess` |  | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 5 | `procexp.Sys` | `ObOpenObjectByPointer, ObReferenceObjectByHandle, ZwOpenProcess` |  | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 6 | `procexp.Sys` | `ObOpenObjectByPointer, ObReferenceObjectByHandle, ZwOpenProcess` |  | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 7 | `procexp.Sys` | `ObOpenObjectByPointer, ObReferenceObjectByHandle, ZwOpenProcess` |  | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 8 | `echo_driver.sys` | `KeStackAttachProcess, ObOpenObjectByPointer, ObReferenceObjectByHandle, PsLookupProcessByProcessId` |  | GUARD_CF, GS_COOKIE |
| 9 | `kprocesshacker.sys` | `ObReferenceObjectByHandle` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 10 | `inpout32.sys` | `READ_PORT_ULONG, WRITE_PORT_UCHAR, WRITE_PORT_ULONG` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 11 | `inpout32.sys` | `READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR, WRITE_PORT_ULONG` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 12 | `inpout32.sys` | `READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR, WRITE_PORT_ULONG` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 13 | `inpout32.sys` | `READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR, WRITE_PORT_ULONG` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 14 | `inpout32.sys` | `READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR, WRITE_PORT_ULONG` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 15 | `procexp.Sys` | `KeStackAttachProcess, ObReferenceObjectByHandle, ZwOpenProcess` |  | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 16 | `procexp.Sys` | `KeStackAttachProcess, ObReferenceObjectByHandle, ZwOpenProcess` |  | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 17 | `procexp.Sys` | `KeStackAttachProcess, ObReferenceObjectByHandle, ZwOpenProcess` |  | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 18 | `procexp.Sys` | `KeStackAttachProcess, ObReferenceObjectByHandle, ZwOpenProcess` |  | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 19 | `procexp.Sys` | `ZwOpenProcess` |  | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 20 | `procexp.Sys` | `ZwOpenProcess` |  | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 21 | `procexp.Sys` | `ZwOpenProcess` |  | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 22 | `echo_driver.sys` | `ObOpenObjectByPointer, ObReferenceObjectByHandle, PsLookupProcessByProcessId` |  | GUARD_CF, GS_COOKIE |
| 23 | `DirectIo.sys` | `READ_PORT_UCHAR, WRITE_PORT_UCHAR, WRITE_PORT_ULONG` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 24 | `DirectIo.sys` | `READ_PORT_ULONG, WRITE_PORT_UCHAR` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 25 | `DirectIo.sys` | `READ_PORT_ULONG, WRITE_PORT_UCHAR` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 26 | `DirectIo32.sys` | `READ_PORT_ULONG, WRITE_PORT_UCHAR` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 27 | `DirectIo32.sys` | `READ_PORT_ULONG, WRITE_PORT_UCHAR` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 28 | `DirectIo32.sys` | `READ_PORT_ULONG, WRITE_PORT_UCHAR` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 29 | `DirectIo32.sys` | `READ_PORT_ULONG, WRITE_PORT_UCHAR` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 30 | `DirectIo32.sys` | `READ_PORT_ULONG, WRITE_PORT_UCHAR` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| ... | *45 more* | | | |

## Likely MapDriver Candidates (Tier 1 only)

These 269 drivers import the right APIs but haven't been Ghidra-confirmed yet. The dangerous imports may be used internally rather than exposed through IOCTLs.

| # | Driver | Imported Primitives | Mitigations OFF |
|---|--------|-------------------|-----------------|
| 1 | `RtsPer.sys` | OpenProcess, PortIO, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | GUARD_CF, GS_COOKIE |
| 2 | `AODDriver.sys` | OpenProcess, PortIO, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 3 | `ATSZIO.sys` | OpenProcess, PortIO, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 4 | `ATSZIO.sys` | OpenProcess, PortIO, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 5 | `gdrv.sys` | OpenProcess, PortIO, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 6 | `iqvw64e.sys, iQVW64.SYS, IQVW32.sys, NalDrv.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 7 | `rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 8 | `cg6kwin2k.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 9 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 10 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 11 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 12 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 13 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 14 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 15 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 16 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 17 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 18 | `nvaudio.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 19 | `AMDPowerProfiler.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 20 | `pchunter.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 21 | `hw.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 22 | `IoAccess.sys` | PortIO, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 23 | `GEDevDrv.SYS` | PortIO, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 24 | `GEDevDrv.SYS` | PortIO, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 25 | `driver7-x64.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 26 | `directio64.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 27 | `directio64.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 28 | `directio64.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 29 | `directio64.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 30 | `directio64.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | GUARD_CF, GS_COOKIE |
| ... | *239 more* | | |

## Methodology

1. **Tier 1** (all drivers): PE parsing extracts imports, device names, IOCTLs, and mitigations
2. **Tier 2** (Ghidra): Headless decompilation traces which imports are called from which IOCTL handlers
3. **KDU scoring**: Maps confirmed IOCTL-reachable APIs to KDU primitive types (ReadPhysicalMemory, WriteKernelVM, OpenProcess, etc.)
4. **Action assessment**: Determines which KDU actions the primitives support (MapDriver > DKOM > DSECorruption > DumpProcess)

**Confirmed** = Ghidra verified the API call exists inside an IOCTL dispatch handler  
**Likely** = The driver imports the API, but IOCTL reachability is unverified

---

*Generated by [DriverAtlas](https://github.com/splintersfury/DriverAtlas) × [KernelSight](https://splintersfury.github.io/KernelSight/)*