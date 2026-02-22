# CLFS Attack Surface Deep-Dive

Comprehensive analysis of the Common Log File System as the most exploited Windows kernel attack surface.

## Overview

The Common Log File System (`clfs.sys`) is a general-purpose logging subsystem in the Windows kernel. It manages Base Log Files (BLF) and log containers for transactional logging, supporting applications like Active Directory, NTFS transactions, and the Windows Update client. Between 2018 and 2025, CLFS accumulated over 30 CVEs, making it the single most targeted kernel component in Windows. Multiple CLFS vulnerabilities have been exploited in the wild by ransomware groups and nation-state actors.

## BLF File Format

### Structure Overview

BLF files contain metadata blocks that describe the log's configuration and state. The major components are:

- **Control Record** -- Top-level structure with log file signature and pointers to other records
- **Base Record** -- Contains arrays of client context and container context structures, plus a symbol table for named log streams
- **Truncate Record** -- Manages log truncation state for circular logging

Each metadata block carries a 4-byte signature, CRC32 checksum, and an array of sector offsets used to locate sub-structures within the block. The reliance on file-embedded offsets for pointer arithmetic is the fundamental source of CLFS vulnerabilities.

### Key Structures

```
CLFS_LOG_BLOCK_HEADER
  - Signature (4 bytes)
  - TotalSectorCount
  - ValidSectorCount
  - Checksum (CRC32)

CLFS_BASE_RECORD_HEADER
  - ClientContextOffset[]
  - ContainerContextOffset[]
  - SymbolTableOffset

CLFS_CLIENT_CONTEXT
  - LogFile pointer
  - MarshalContext
  - Undo/Redo LSN tracking
```

### Container Architecture

Containers are separate files that hold actual log record data. A single log can use multiple containers for circular logging, where new records overwrite the oldest when capacity is reached. Container size and maximum count are managed through `CLFS_MGMT_POLICY` structures. Container descriptors in the base record reference the physical container files by path and store metadata about their current state.

## Why CLFS Is The #1 Target

1. **Complex file format parsing** -- BLF metadata parsing involves extensive pointer arithmetic derived from on-disk offsets. Every offset is an opportunity for corruption if validation is insufficient.

2. **User-controllable on-disk structures** -- Any user can create a log file with `CreateLogFile()` and manipulate the resulting BLF on disk. The kernel then reparses this user-modified file, trusting embedded offsets to navigate structures.

3. **Rich kernel state manipulation** -- Corrupted offsets in the BLF cause the CLFS parser to read or write relative to the base record's pool allocation, reaching into adjacent kernel pool memory.

4. **Consistent exploitation pattern** -- The same fundamental corruption technique (offset manipulation in BLF metadata) works across dozens of different CVEs. Once an attacker understands the BLF format, each new CLFS CVE is a variation on the same theme.

5. **Slow patching cycle** -- A true fix would require redesigning the BLF parser with comprehensive bounds checking or sandboxing. Microsoft has instead opted for incremental patches, fixing individual offset validations one at a time, leaving the structural weakness intact.

## CVE Timeline

| CVE | Year | Class | ITW | Notes |
|-----|------|-------|-----|-------|
| CVE-2018-8471 | 2018 | EoP | No | Early CLFS elevation of privilege |
| CVE-2019-1385 | 2019 | EoP | No | CLFS driver privilege escalation |
| CVE-2020-17136 | 2020 | EoP | No | CLFS metadata parsing flaw |
| CVE-2021-31954 | 2021 | EoP | No | CLFS base record corruption |
| CVE-2021-36955 | 2021 | EoP | No | CLFS container context issue |
| CVE-2022-21916 | 2022 | EoP | No | CLFS offset validation bypass |
| CVE-2022-24521 | 2022 | EoP | Yes | Exploited ITW, reported by NSA and CrowdStrike |
| CVE-2022-37969 | 2022 | Logic/Corruption | Yes | First widely publicized CLFS ITW exploit |
| CVE-2023-23376 | 2023 | EoP | Yes | Exploited by Nokoyawa ransomware operators |
| CVE-2023-28252 | 2023 | EoP | Yes | Also Nokoyawa campaign, different root cause |
| CVE-2023-36570 | 2023 | EoP | No | CLFS client context corruption |
| CVE-2024-49138 | 2024 | Heap Overflow | Yes | CLFS heap-based buffer overflow, exploited ITW |
| CVE-2025-29824 | 2025 | EoP | Yes | RansomEXX / Storm-2460 campaign |

## Common Corruption Patterns

### Offset Manipulation

The attacker crafts a BLF where `ClientContextOffset` or `ContainerContextOffset` points outside the base record boundary into adjacent pool memory. When CLFS dereferences this offset relative to the base record allocation, it reads or writes kernel memory that belongs to a different object.

### Container Count Mismatch

The `cContainers` field is set larger than the actual container descriptor array in the base record. When CLFS iterates over containers, it walks past the array bounds into adjacent memory, causing out-of-bounds reads or writes.

### Symbol Table Corruption

Symbol table entries with invalid offsets cause the BLF parser to dereference pointers that land outside the base record allocation. This provides a flexible primitive since the symbol table is processed during multiple CLFS operations.

### Checksum Bypass

Certain code paths in CLFS skip CRC32 checksum validation under specific conditions (log recovery, certain error paths). This allows tampered metadata blocks to be processed without detection, enabling the corruption patterns described above.

## Exploitation Pattern

A typical CLFS exploitation chain follows a consistent sequence:

1. Create a log file using `CreateLogFile()` with appropriate flags
2. Close the log handle and manipulate the BLF file on disk to corrupt metadata offsets (client context, container context, or symbol table entries)
3. Trigger CLFS to reparse the corrupted BLF by calling `FlushLogBuffers()`, `ReadLogRecord()`, or reopening the log
4. The corrupted offset causes an out-of-bounds read or write relative to the base record's pool allocation
5. Use the OOB write to corrupt an adjacent pool object -- commonly `_WNF_STATE_DATA` (pre-22H2), pipe attributes, or I/O Ring structures
6. Leverage the corrupted object to build a stable arbitrary kernel read/write primitive
7. Perform privilege escalation via token swapping or PTE manipulation to obtain SYSTEM privileges

## CLFS Isolation Mitigation

Microsoft introduced CLFS Isolation in Windows 11 24H2 as a structural hardening effort:

- BLF metadata offsets are now validated against the allocation size before dereferencing
- Container descriptor arrays have explicit bounds checking on iteration count
- Added integrity verification for base record structures during log open and recovery
- Metadata blocks use enhanced validation during reparsing operations

This is not a complete redesign of the CLFS parser. The fundamental architecture -- parsing on-disk offsets for kernel memory access -- remains. Incremental hardening continues with each Patch Tuesday as new bypass vectors are discovered.

## AutoPiff Detection

AutoPiff monitors `clfs.sys` patches with specific attention to BLF parser changes:

- `added_offset_bounds_check` -- New bounds validation on BLF structure offsets, indicating a previously missing range check
- `added_container_count_validation` -- Container array length checks added to iteration loops
- `modified_blf_parser_logic` -- Changes to core parsing routines that alter control flow through BLF metadata processing

## Related Case Studies

- [CVE-2022-37969](CVE-2022-37969.md) -- CLFS EoP, exploited in the wild
- [CVE-2023-28252](CVE-2023-28252.md) -- CLFS EoP, Nokoyawa ransomware campaign
- [CVE-2024-49138](CVE-2024-49138.md) -- CLFS heap overflow, exploited ITW
- [CVE-2025-29824](CVE-2025-29824.md) -- Latest CLFS exploitation, Storm-2460

## References

- [Microsoft CLFS Documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-the-common-log-file-system)
- [Kaspersky Nokoyawa CLFS Analysis](https://securelist.com/nokoyawa-ransomware-attacks-with-windows-zero-day/109483/)
