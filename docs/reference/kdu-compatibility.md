---
title: KDU Provider Compatibility Analysis
description: Which LOLDrivers could be weaponized as KDU providers? Automated analysis of 1,775 drivers.
---

# KDU Provider Compatibility Analysis

Which [LOLDrivers](https://loldrivers.io) could be weaponized as [KDU](https://github.com/hfiref0x/KDU) providers? This page answers that question by mapping each driver's confirmed IOCTL-reachable primitives to KDU's provider requirements.

**Last updated:** 2026-03-11  
**Drivers analyzed:** 1045 (Tier 1) / 1045 (Tier 2 Ghidra)  

## Key Findings

| Metric | Count |
|--------|-------|
| Total drivers analyzed | 1,045 |
| **KDU-compatible** | **897** (86%) |
| Tier 2 confirmed | 245 |
| Tier 1 likely | 652 |
| MapDriver capable | 192 |
| MapDriver (physical brute-force) | 315 |
| DKOM / DSECorruption | 390 |
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

These 78 drivers have Ghidra-confirmed physical + virtual memory primitives reachable from IOCTL handlers. They could load unsigned kernel code.

| # | Driver | Primitives (confirmed IOCTLs) | NEITHER I/O | Mitigations OFF |
|---|--------|------------------------------|-------------|-----------------|
| 1 | `segwindrvx64.sys` | PortIO, QueryPML4Value, ReadKVM, ReadPhysMem, VToPhys, WriteKVM, WritePhysMem |  | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 2 | `PDFWKRNL.sys` | QueryPML4Value, ReadKVM, ReadPhysMem, VToPhys, WriteKVM, WritePhysMem | YES | GUARD_CF, GS_COOKIE |
| 3 | `PDFWKRNL.sys` | QueryPML4Value, ReadKVM, ReadPhysMem, VToPhys, WriteKVM, WritePhysMem | YES | GUARD_CF, GS_COOKIE |
| 4 | `PDFWKRNL.sys` | QueryPML4Value, ReadKVM, ReadPhysMem, VToPhys, WriteKVM, WritePhysMem | YES | GUARD_CF, GS_COOKIE |
| 5 | `PDFWKRNL.sys` | QueryPML4Value, ReadKVM, ReadPhysMem, VToPhys, WriteKVM, WritePhysMem | YES | GUARD_CF, GS_COOKIE |
| 6 | `WinFlash64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 7 | `atillk64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 8 | `CP2X72C.SYS` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 9 | `CP2X72C.SYS` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 10 | `dbk64.sys` | OpenProcess, ReadKVM, WriteKVM |  | GUARD_CF, GS_COOKIE |
| 11 | `dbk64.sys` | OpenProcess, ReadKVM, WriteKVM |  | GUARD_CF, GS_COOKIE |
| 12 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 13 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 14 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 15 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 16 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 17 | `AODDriver.sys` | PortIO, QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 18 | `driver7-x86.sys` | PortIO |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 19 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 20 | `AODDriver.sys` | PortIO, QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 21 | `rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys` | PortIO, QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 22 | `rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys` | PortIO, QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 23 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 24 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 25 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 26 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 27 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 28 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 29 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 30 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 31 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 32 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 33 | `rtkiow8x64.sys ` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | GUARD_CF, GS_COOKIE |
| 34 | `AsUpIO.sys, AsUpIO64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 35 | `AsUpIO.sys, AsUpIO64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | GUARD_CF, GS_COOKIE |
| 36 | `DirectIo32.sys` | PortIO | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 37 | `DirectIo32.sys` | PortIO | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 38 | `driver7-x86-withoutdbg.sys` | PortIO | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 39 | `directio32_legacy.sys, DirectIo32.sys` | PortIO |  | GUARD_CF, GS_COOKIE |
| 40 | `rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 41 | `rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 42 | `rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 43 | `rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 44 | `rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 45 | `rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 46 | `WinFlash64.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 47 | `directio64.sys` | OpenProcess |  | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 48 | `AODDriver.sys` | PortIO | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 49 | `AODDriver.sys` | PortIO |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 50 | `AODDriver.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 51 | `AODDriver.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 52 | `atlAccess.sys` | QueryPML4Value, ReadPhysMem, VToPhys, WritePhysMem |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 53 | `directio64.sys` | OpenProcess |  | GUARD_CF, GS_COOKIE |
| 54 | `directio64.sys` | OpenProcess |  | GUARD_CF, GS_COOKIE |
| 55 | `aswArPot.sys` | ReadKVM, WriteKVM | YES | GUARD_CF, GS_COOKIE |
| 56 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | GUARD_CF, GS_COOKIE |
| 57 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | GUARD_CF, GS_COOKIE |
| 58 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 59 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 60 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | GUARD_CF, GS_COOKIE |
| 61 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | GUARD_CF, GS_COOKIE |
| 62 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 63 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | GUARD_CF, GS_COOKIE |
| 64 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | GUARD_CF, GS_COOKIE |
| 65 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | GUARD_CF, GS_COOKIE |
| 66 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | GUARD_CF, GS_COOKIE |
| 67 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | GUARD_CF, GS_COOKIE |
| 68 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 69 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 70 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 71 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | GUARD_CF, GS_COOKIE |
| 72 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 73 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | GUARD_CF, GS_COOKIE |
| 74 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 75 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | GUARD_CF, GS_COOKIE |
| 76 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 77 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 78 | `aswArPot.sys, avgArPot.sys` | ReadKVM, WriteKVM | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |

## Confirmed Physical Brute-Force Candidates

These 115 drivers have confirmed physical memory R/W but lack virtual memory. KDU can brute-force PML4 via physical scanning to achieve MapDriver.

| # | Driver | Confirmed APIs | NEITHER I/O | Mitigations OFF |
|---|--------|---------------|-------------|-----------------|
| 1 | `CP2X72C.SYS` | `MmMapIoSpace, READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 2 | `CP2X72C.SYS` | `MmMapIoSpace, READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 3 | `CP2X72C.SYS` | `MmMapIoSpace, READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 4 | `LHA.sys` | `MmGetPhysicalAddress, MmMapIoSpace` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 5 | `cpuz.sys` | `MmMapIoSpace, READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 6 | `cpuz.sys` | `MmMapIoSpace, READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 7 | `cpuz.sys` | `MmMapIoSpace, READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 8 | `sfdrvx64.sys` | `MmMapIoSpace` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 9 | `sfdrvx64.sys` | `MmMapIoSpace` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 10 | `cpuz.sys` | `MmMapIoSpace, READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 11 | `cpuz.sys` | `MmMapIoSpace, READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 12 | `cpuz.sys` | `MmMapIoSpace, READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 13 | `sfdrvx32.sys` | `MmMapIoSpace` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 14 | `sfdrvx64.sys` | `MmMapIoSpace` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 15 | `sfdrvx32.sys` | `MmMapIoSpace` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 16 | `sfdrvx32.sys` | `MmMapIoSpace` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 17 | `cpuz.sys` | `MmMapIoSpace, READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 18 | `cpuz.sys` | `MmMapIoSpace, READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 19 | `cpuz.sys` | `MmMapIoSpace, READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 20 | `cpuz.sys` | `MmMapIoSpace, READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 21 | `cpuz.sys` | `MmMapIoSpace, READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 22 | `cpuz.sys` | `MmMapIoSpace, READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 23 | `cpuz.sys` | `MmMapIoSpace, READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 24 | `cpuz.sys` | `MmMapIoSpace, READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 25 | `cpuz.sys` | `MmMapIoSpace, READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 26 | `cpuz.sys` | `MmMapIoSpace, READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 27 | `cpuz.sys` | `MmMapIoSpace, READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 28 | `cpuz.sys` | `MmMapIoSpace, READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 29 | `cpuz.sys` | `MmMapIoSpace, READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 30 | `cpuz.sys` | `MmMapIoSpace, READ_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_UCHAR` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| ... | *85 more* | | | |

## Confirmed DKOM / DSECorruption Candidates

These 52 drivers have confirmed virtual memory write primitives. They can manipulate kernel objects or patch `ci.dll` to disable signature enforcement.

| # | Driver | Confirmed APIs | NEITHER I/O | Mitigations OFF |
|---|--------|---------------|-------------|-----------------|
| 1 | `echo_driver.sys` | `KeStackAttachProcess, ObOpenObjectByPointer, ObReferenceObjectByHandle, PsLookupProcessByProcessId` |  | GUARD_CF, GS_COOKIE |
| 2 | `kprocesshacker.sys` | `ObReferenceObjectByHandle` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 3 | `echo_driver.sys` | `ObOpenObjectByPointer, ObReferenceObjectByHandle, PsLookupProcessByProcessId` |  | GUARD_CF, GS_COOKIE |
| 4 | `DirectIo.sys` | `READ_PORT_UCHAR, WRITE_PORT_UCHAR, WRITE_PORT_ULONG` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 5 | `DirectIo.sys` | `READ_PORT_ULONG, WRITE_PORT_UCHAR` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 6 | `DirectIo.sys` | `READ_PORT_ULONG, WRITE_PORT_UCHAR` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 7 | `DirectIo32.sys` | `READ_PORT_ULONG, WRITE_PORT_UCHAR` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 8 | `DirectIo32.sys` | `READ_PORT_ULONG, WRITE_PORT_UCHAR` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 9 | `DirectIo32.sys` | `READ_PORT_ULONG, WRITE_PORT_UCHAR` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 10 | `DirectIo32.sys` | `READ_PORT_ULONG, WRITE_PORT_UCHAR` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 11 | `DirectIo32.sys` | `READ_PORT_ULONG, WRITE_PORT_UCHAR` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 12 | `DirectIo32.sys` | `READ_PORT_ULONG, WRITE_PORT_UCHAR` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 13 | `Netfilter.sys` | `MmMapLockedPages, ObReferenceObjectByHandle` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 14 | `msr.sys` | `ZwMapViewOfSection` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 15 | `DirectIo.sys` | `WRITE_PORT_UCHAR` |  | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 16 | `jnprva.sys, neofltr.sys` | `ObReferenceObjectByHandle` |  | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 17 | `nvflsh32.sys` | `WRITE_PORT_ULONG` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 18 | `nvflsh32.sys` | `WRITE_PORT_ULONG` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 19 | `nvflsh32.sys` | `WRITE_PORT_ULONG` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 20 | `nvflsh32.sys` | `WRITE_PORT_ULONG` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 21 | `nvflsh32.sys` | `WRITE_PORT_ULONG` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 22 | `nvflsh32.sys` | `WRITE_PORT_ULONG` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 23 | `nvflsh32.sys` | `WRITE_PORT_ULONG` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 24 | `nvflsh32.sys` | `WRITE_PORT_ULONG` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 25 | `nvflsh32.sys` | `WRITE_PORT_ULONG` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 26 | `nvflsh32.sys` | `WRITE_PORT_ULONG` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 27 | `nvflash.sys` | `WRITE_PORT_ULONG` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 28 | `gmer64.sys, superman.sys` | `KeStackAttachProcess, ObReferenceObjectByHandle` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 29 | `gmer64.sys, superman.sys` | `KeStackAttachProcess, ObReferenceObjectByHandle` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 30 | `K7RKScan.sys` | `PsLookupProcessByProcessId` | YES | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| ... | *22 more* | | | |

## Likely MapDriver Candidates (Tier 1 only)

These 114 drivers import the right APIs but haven't been Ghidra-confirmed yet. The dangerous imports may be used internally rather than exposed through IOCTLs.

| # | Driver | Imported Primitives | Mitigations OFF |
|---|--------|-------------------|-----------------|
| 1 | `RtsPer.sys` | OpenProcess, PortIO, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | GUARD_CF, GS_COOKIE |
| 2 | `AODDriver.sys` | OpenProcess, PortIO, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 3 | `iqvw64e.sys, iQVW64.SYS, IQVW32.sys, NalDrv.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 4 | `rtkio.sys, rtkio64.sys, rtkiow8x64.sys, rtkiow10x64.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 5 | `cg6kwin2k.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 6 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 7 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 8 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 9 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 10 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 11 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 12 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 13 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 14 | `asio.sys, AsIO32.sys, AsIO3.sys, AsIO3_64.sys, AsIO2.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 15 | `nvaudio.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 16 | `AMDPowerProfiler.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 17 | `pchunter.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 18 | `hw.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 19 | `IoAccess.sys` | PortIO, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| 20 | `GEDevDrv.SYS` | PortIO, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 21 | `GEDevDrv.SYS` | PortIO, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 22 | `driver7-x64.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 23 | `directio64.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 24 | `directio64.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 25 | `directio64.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 26 | `directio64.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 27 | `directio64.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | GUARD_CF, GS_COOKIE |
| 28 | `wnbios.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 29 | `PcieCubed.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | DYNAMIC_BASE, NX_COMPAT, GUARD_CF |
| 30 | `HwOs2Ec10x64.sys` | OpenProcess, ReadKVM, ReadPhysMem, WriteKVM, WritePhysMem | GUARD_CF, FORCE_INTEGRITY, GS_COOKIE |
| ... | *84 more* | | |

## Methodology

1. **Tier 1** (all drivers): PE parsing extracts imports, device names, IOCTLs, and mitigations
2. **Tier 2** (Ghidra): Headless decompilation traces which imports are called from which IOCTL handlers
3. **KDU scoring**: Maps confirmed IOCTL-reachable APIs to KDU primitive types (ReadPhysicalMemory, WriteKernelVM, OpenProcess, etc.)
4. **Action assessment**: Determines which KDU actions the primitives support (MapDriver > DKOM > DSECorruption > DumpProcess)

**Confirmed** = Ghidra verified the API call exists inside an IOCTL dispatch handler  
**Likely** = The driver imports the API, but IOCTL reachability is unverified

---

*Generated by [DriverAtlas](https://github.com/splintersfury/DriverAtlas) × [KernelSight](https://splintersfury.github.io/KernelSight/)*