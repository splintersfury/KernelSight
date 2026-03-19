# NTFS Attack Surface Deep-Dive

The NTFS driver is a growing kernel attack surface with 7 CVEs in the KernelSight corpus, including 3 exploited in the wild via crafted VHD images. This page tells the story of how a file system became a weapon.

## The VHD Problem

A user receives an email with a .vhd attachment. They double-click it. Explorer calls the VirtualDisk API. `vhdmp.sys` creates a virtual disk device. The volume manager enumerates partitions. And then `ntfs.sys`, running in kernel mode with full system privileges, begins parsing the Master File Table of an NTFS volume whose every byte was crafted by an attacker.

```
User double-clicks .vhd file
  --> Explorer calls VirtualDisk API
    --> vhdmp.sys creates virtual disk device
      --> Volume manager enumerates partitions
        --> ntfs.sys mounts and parses MFT
          --> Kernel-mode parsing of untrusted on-disk data
```

This path is the key threat model. No special privileges are needed. No exploit code runs first. The VHD file can arrive via email, web download, or USB drive. One click triggers kernel-mode parsing of attacker-controlled disk structures. Three of the seven NTFS CVEs in this corpus were exploited in the wild through exactly this delivery mechanism.

## Architecture

### Key Structures

**Master File Table (MFT).** The central metadata structure of an NTFS volume. Each file and directory has an MFT record containing attributes that describe the file's data, name, timestamps, and security. MFT records are fixed-size (typically 1024 bytes) but contain variable-length attributes with embedded offsets and lengths. Every one of those offset and length fields is a corruption opportunity when validation is missing.

**Attribute Records.** Each MFT record contains a sequence of typed attribute records: `$STANDARD_INFORMATION`, `$FILE_NAME`, `$DATA`, `$INDEX_ROOT`, `$INDEX_ALLOCATION`, `$SECURITY_DESCRIPTOR`. Resident attributes store data inline; non-resident attributes store run-list pointers to cluster ranges on disk. The variety of attribute types means the driver has dozens of separate parsing code paths, each potentially harboring its own validation gaps.

**Index Nodes (B-trees).** Directory listings use B-tree index structures. Index entries contain file references and sort keys. Deep nesting or circular references can cause stack overflow during traversal, as [CVE-2025-54916](CVE-2025-54916.md) demonstrated.

**Run Lists.** Non-resident attributes store data location as a compressed list of (offset, length) pairs. Malformed run lists can cause the driver to read from or write to arbitrary volume regions.

## Why NTFS Keeps Showing Up

The answer is structural, not incidental.

**VHD auto-mount from user context.** Double-clicking a VHD triggers kernel-mode NTFS parsing of attacker-controlled disk structures. No special privileges needed. No user interaction beyond the click. The VHD file can arrive through any delivery channel.

**Dense on-disk format.** MFT records contain nested, variable-length attribute structures with embedded offsets and lengths. The format was designed for performance and flexibility, not for adversarial resilience. Every embedded offset is a trust boundary the kernel must validate, and the format has dozens of them.

**No sandbox.** The kernel parses raw disk structures directly, trusting embedded sizes and offsets. There is no user-mode pre-validation layer for NTFS metadata. Compare this to media codecs, where Microsoft has moved some parsers to user-mode sandboxes. NTFS metadata parsing still runs unsandboxed in the kernel.

**Large parsing surface.** The NTFS driver handles dozens of attribute types, multiple index formats, compression, encryption, sparse files, reparse points, and transaction logging. Each feature widens the attack surface.

**Proven ITW exploitation.** Three NTFS CVEs were exploited in the wild via crafted VHD images shared through social engineering. Microsoft classifies [CVE-2025-24993](CVE-2025-24993.md) as RCE because the attacker can embed executable content in the crafted volume.

## The Vulnerability History

| CVE | Year | Class | ITW | What Happened |
|-----|------|-------|-----|---------------|
| CVE-2025-24984 | 2025 | Info Disclosure | Yes | Kernel memory leaked via NTFS parsing |
| CVE-2025-24991 | 2025 | Info Disclosure (OOB Read) | Yes | Out-of-bounds read from crafted attribute |
| CVE-2025-24992 | 2025 | Info Disclosure | No | Unvalidated on-disk offset leaks kernel data |
| CVE-2025-24993 | 2025 | Buffer Overflow (Heap) | Yes | MFT attribute heap overflow via crafted VHD |
| CVE-2025-54916 | 2025 | Buffer Overflow (Stack) | No | Deep nesting causes stack overflow |
| CVE-2026-20840 | 2026 | Buffer Overflow (Heap) | No | Heap overflow in attribute parsing |
| CVE-2026-20922 | 2026 | Buffer Overflow (Heap) | No | Heap overflow in attribute parsing |

The three ITW CVEs (CVE-2025-24984, CVE-2025-24991, CVE-2025-24993) were disclosed together in March 2025. They were almost certainly used in a combined chain: the info disclosure bugs defeat KASLR by leaking kernel addresses, and the heap overflow provides the code execution primitive. Together, they form a complete exploit chain triggered by a single VHD file.

## Common Vulnerability Patterns

### Heap Overflow from Crafted MFT Attributes

This is the most common and most dangerous pattern. An MFT attribute record contains a length field that does not match the actual data. The driver allocates a buffer based on one field, then copies data based on another, overflowing the heap buffer.

[CVE-2025-24993](CVE-2025-24993.md) is the textbook case. A crafted VHD with a corrupted MFT record triggers a heap overflow during volume mount. Microsoft classified it as RCE. The attacker delivers the VHD via email or web download, the user clicks it, and the kernel executes attacker-influenced code.

[CVE-2026-20840](CVE-2026-20840.md) and [CVE-2026-20922](CVE-2026-20922.md) are variations in different attribute parsing code paths. The root cause is the same: size field inconsistency leading to buffer overflow.

### Information Disclosure via Unvalidated Offsets

On-disk offset or length fields point past the end of a kernel buffer. The driver reads and returns data from adjacent kernel memory, leaking pool contents to the caller.

[CVE-2025-24991](CVE-2025-24991.md) and [CVE-2025-24992](CVE-2025-24992.md) both involve out-of-bounds reads from crafted attribute records. [CVE-2025-24984](CVE-2025-24984.md) leaks sensitive kernel data through a similar offset validation gap. These info-disclosure bugs serve as KASLR bypass primitives in multi-bug chains, or as standalone kernel memory leaks.

### Stack Overflow from Deep Nesting

NTFS index structures can be deeply nested. If the on-disk structures contain circular references or extreme depth, recursive traversal overflows the kernel stack. [CVE-2025-54916](CVE-2025-54916.md) triggers this through crafted directory nesting in a VHD.

## Exploitation Pattern

NTFS exploitation follows the file-format corruption archetype (see [Exploit Chain Patterns](../guides/exploit-chain-patterns.md), archetype A):

The attacker crafts a VHD/VHDX file containing an NTFS volume with corrupted MFT attribute records. They deliver it to the target through email, web download, or removable media. The user mounts the VHD, triggering kernel-mode NTFS parsing. The corrupted attribute causes a heap buffer overflow in ntfs.sys. Pool spray places controlled objects adjacent to the overflow allocation. The overflow corrupts the adjacent object, building an arbitrary R/W primitive. The attacker performs token swap for SYSTEM escalation, or uses the overflow for direct code execution.

The beauty of this chain, from the attacker's perspective, is its simplicity. One file. One click. Kernel code execution.

## Mitigations

NTFS-specific mitigations are limited, and none address the core problem:

**Mark of the Web (MOTW)** -- VHD files downloaded from the internet carry MOTW, which may trigger SmartScreen warnings. However, MOTW does not prevent mounting.

**Incremental bounds checking** -- Microsoft patches individual offset and length validations as CVEs are reported. No structural sandboxing.

**Attack Surface Reduction (ASR)** -- ASR rules can block mounting of VHD files from Office macros, but not from Explorer or direct API calls.

The core problem, kernel-mode parsing of untrusted on-disk structures, remains open. Microsoft has sandboxed some media codec parsers in user mode, but NTFS metadata parsing still runs unsandboxed in the kernel. Until that changes, the NTFS attack surface will keep producing vulnerabilities.

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
