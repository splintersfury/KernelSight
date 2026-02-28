# NTFS Attack Surface Deep-Dive

Analysis of the NTFS file system driver, a growing kernel attack surface with 7 CVEs in the KernelSight corpus -- including 3 exploited in the wild via crafted VHD images.

## Overview

The NT File System driver (`ntfs.sys`) handles volume mounting, file operations, and metadata parsing for NTFS -- the default Windows file system. It runs entirely in kernel mode, parsing on-disk structures including the Master File Table (MFT), attribute records, index nodes, and security descriptors. Since Windows 10, NTFS volumes can be mounted from VHD/VHDX virtual disk images, so double-clicking a downloaded file triggers kernel-mode NTFS parsing.

## Architecture

### Key Structures

- **Master File Table (MFT)** -- The central metadata structure of an NTFS volume. Each file and directory has an MFT record containing attributes that describe the file's data, name, timestamps, and security. MFT records are fixed-size (typically 1024 bytes) but contain variable-length attributes.
- **Attribute Records** -- Each MFT record contains a sequence of typed attribute records: `$STANDARD_INFORMATION`, `$FILE_NAME`, `$DATA`, `$INDEX_ROOT`, `$INDEX_ALLOCATION`, `$SECURITY_DESCRIPTOR`. Resident attributes store data inline; non-resident attributes store run-list pointers to cluster ranges on disk.
- **Index Nodes (B-trees)** -- Directory listings use B-tree index structures. Index entries contain file references and sort keys. Deep nesting or circular references can cause stack overflow during traversal.
- **Run Lists** -- Non-resident attributes store data location as a compressed list of (offset, length) pairs. Malformed run lists can cause the driver to read from or write to arbitrary volume regions.

### VHD Mount Path

```
User double-clicks .vhd file
  → Explorer calls VirtualDisk API
    → vhdmp.sys creates virtual disk device
      → Volume manager enumerates partitions
        → ntfs.sys mounts and parses MFT
          → Kernel-mode parsing of untrusted on-disk data
```

This path is the key threat model. The user-supplied VHD contains a crafted NTFS volume. Every on-disk structure the kernel parses is attacker-controlled.

## Why NTFS Keeps Showing Up

1. **VHD auto-mount from user context.** Double-clicking a VHD triggers kernel-mode NTFS parsing of attacker-controlled disk structures. No special privileges needed. The VHD file can arrive via email, download, or USB.

2. **Dense on-disk format.** MFT records contain nested, variable-length attribute structures with embedded offsets and lengths. Every offset is a corruption opportunity when validation is missing.

3. **No sandbox.** The kernel parses raw disk structures directly, trusting embedded sizes and offsets. No user-mode pre-validation layer exists for NTFS metadata.

4. **Large parsing surface.** The NTFS driver handles dozens of attribute types, multiple index formats, compression, encryption, sparse files, reparse points, and transaction logging. Each feature widens the attack surface.

5. **Proven ITW exploitation.** Three NTFS CVEs were exploited in the wild via crafted VHD images shared through social engineering. Microsoft classifies [CVE-2025-24993](CVE-2025-24993.md) as RCE because the attacker can embed executable content in the crafted volume.

## CVE Timeline

| CVE | Year | Class | ITW | Notes |
|-----|------|-------|-----|-------|
| CVE-2025-24984 | 2025 | Info Disclosure | Yes | Kernel memory leaked via NTFS parsing |
| CVE-2025-24991 | 2025 | Info Disclosure (OOB Read) | Yes | Out-of-bounds read from crafted attribute |
| CVE-2025-24992 | 2025 | Info Disclosure | No | Unvalidated on-disk offset leaks kernel data |
| CVE-2025-24993 | 2025 | Buffer Overflow (Heap) | Yes | MFT attribute heap overflow via crafted VHD |
| CVE-2025-54916 | 2025 | Buffer Overflow (Stack) | No | Deep nesting causes stack overflow |
| CVE-2026-20840 | 2026 | Buffer Overflow (Heap) | No | Heap overflow in attribute parsing |
| CVE-2026-20922 | 2026 | Buffer Overflow (Heap) | No | Heap overflow in attribute parsing |

## Common Vulnerability Patterns

### Heap Overflow from Crafted MFT Attributes

The most common pattern. An MFT attribute record contains a length field that doesn't match the actual data. The driver allocates a buffer based on one field, then copies data based on another, overflowing the heap buffer. [CVE-2025-24993](CVE-2025-24993.md) is the textbook case -- a crafted VHD with a corrupted MFT record triggers a heap overflow during volume mount, classified as RCE.

[CVE-2026-20840](CVE-2026-20840.md) and [CVE-2026-20922](CVE-2026-20922.md) are variations on the same theme in different attribute parsing code paths.

### Information Disclosure via Unvalidated Offsets

On-disk offset or length fields point past the end of a kernel buffer. The driver reads and returns data from adjacent kernel memory, leaking pool contents to the caller. [CVE-2025-24991](CVE-2025-24991.md) and [CVE-2025-24992](CVE-2025-24992.md) both involve out-of-bounds reads from crafted attribute records. [CVE-2025-24984](CVE-2025-24984.md) leaks sensitive kernel data through a similar offset validation gap.

These info-disclosure bugs serve as KASLR bypass primitives in a multi-bug chain, or as standalone kernel memory leaks.

### Stack Overflow from Deep Nesting

NTFS index structures (B-trees for directory listings) can be deeply nested. If the on-disk structures contain circular references or extreme depth, recursive traversal overflows the kernel stack. [CVE-2025-54916](CVE-2025-54916.md) triggers a stack overflow through crafted directory nesting in a VHD.

## Exploitation Pattern

NTFS exploitation follows the file-format corruption archetype (see [Exploit Chain Patterns](../guides/exploit-chain-patterns.md), archetype A):

1. Craft a VHD/VHDX file containing an NTFS volume with corrupted MFT attribute records
2. Deliver the VHD to the target via email, web download, or removable media
3. User mounts the VHD (double-click or auto-mount), triggering kernel-mode NTFS parsing
4. Corrupted attribute causes heap buffer overflow in ntfs.sys during MFT processing
5. Pool spray places controlled objects adjacent to the overflow allocation
6. The overflow corrupts the adjacent object, building an arbitrary R/W primitive
7. Perform token swap for SYSTEM escalation, or use the overflow for code execution

The three ITW CVEs (CVE-2025-24984, CVE-2025-24991, CVE-2025-24993) were disclosed together in March 2025 and likely used in a combined chain: info disclosure bugs for KASLR defeat, heap overflow for code execution.

## Mitigations

NTFS-specific mitigations are limited:

- **Mark of the Web (MOTW)** -- VHD files downloaded from the internet carry MOTW, which may trigger SmartScreen warnings. However, MOTW does not prevent mounting.
- **Incremental bounds checking** -- Microsoft patches individual offset and length validations as CVEs are reported. No structural sandboxing.
- **Attack Surface Reduction (ASR)** -- ASR rules can block mounting of VHD files from Office macros, but not from Explorer or direct API calls.

The core problem -- kernel-mode parsing of untrusted on-disk structures -- remains open. Microsoft has sandboxed some media codec parsers in user mode, but NTFS metadata parsing still runs unsandboxed in the kernel.

## AutoPiff Detection

AutoPiff monitors `ntfs.sys` patches for these change patterns:

- `added_offset_bounds_check` -- New bounds validation on MFT attribute offsets
- `added_length_check` -- Size validation before buffer copy in attribute parsing
- `added_stack_depth_check` -- Recursion depth limits in index traversal code

## Related Case Studies

- [CVE-2025-24993](CVE-2025-24993.md) -- MFT heap overflow via crafted VHD, exploited ITW
- [CVE-2025-24991](CVE-2025-24991.md) -- OOB read info disclosure, exploited ITW
- [CVE-2025-24984](CVE-2025-24984.md) -- info disclosure, exploited ITW
- [CVE-2025-54916](CVE-2025-54916.md) -- stack overflow from deep nesting

## References

- [Microsoft NTFS Technical Reference](https://learn.microsoft.com/en-us/windows-server/storage/file-server/ntfs-overview)
- [Microsoft Advisory: NTFS VHD Vulnerabilities (March 2025)](https://msrc.microsoft.com/update-guide/)
- [Flatcap NTFS Documentation Project](https://flatcap.github.io/linux-ntfs/ntfs/)
