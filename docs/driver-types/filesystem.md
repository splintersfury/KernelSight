# File System Drivers

<div class="ks-pipeline-pos">
  <span class="ks-active">Driver Type</span> &rarr; Attack Surface &rarr; Vuln Class &rarr; Primitive &rarr; Case Study
</div>

Plug a USB drive into a Windows machine and the kernel immediately begins parsing untrusted data structures at ring 0. The same thing happens when a standard user double-clicks a VHD file. File system drivers sit at the boundary between raw storage and the structured file hierarchy that the rest of the OS depends on, and every field they read from disk is attacker-controlled if the media is crafted. This makes them one of the few kernel attack surfaces reachable without any special privileges, API calls, or network access.

## How File System Drivers Fit Into the Kernel

File system drivers are WDM drivers loaded by the I/O Manager when a volume is mounted. They register IRP dispatch routines for the standard file operation major functions: `IRP_MJ_CREATE`, `IRP_MJ_READ`, `IRP_MJ_WRITE`, `IRP_MJ_SET_INFORMATION`, and `IRP_MJ_QUERY_INFORMATION`, among others. When user-mode code opens a file, the I/O Manager routes the request down through any minifilter stack and into the file system driver, which must translate the logical operation into physical reads against the underlying disk.

The critical detail for security research is that the driver's first interaction with a new volume involves parsing metadata structures whose layout and values are entirely determined by the disk contents. For NTFS, this means Master File Table (MFT) records, attribute lists, index entries, and bitmap allocations. For FAT, this means FAT table entries, cluster bitmaps, and directory entries. None of these values can be trusted.

``` mermaid
graph TD
    A["User Mode<br/>Mount VHD / Insert USB"] -->|CreateFile| B["I/O Manager"]
    B --> C["Minifilter Stack"]
    C --> D["File System Driver<br/>ntfs.sys / fastfat.sys"]
    D -->|"Parse MFT / FAT"| E["On-Disk Metadata<br/>(attacker-controlled)"]
    D -->|"Pool Alloc"| F["Kernel Pool"]

    style A fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    style B fill:#152a4a,stroke:#3b82f6,color:#e2e8f0
    style C fill:#152a4a,stroke:#3b82f6,color:#e2e8f0
    style D fill:#152a4a,stroke:#3b82f6,color:#e2e8f0
    style E fill:#0d1320,stroke:#ef4444,color:#e2e8f0
    style F fill:#0d1320,stroke:#f59e0b,color:#e2e8f0
```

## Where the Bugs Live

The attack surface concentrates in three areas, all related to the same core problem: trusting values read from disk.

**On-disk structure parsing** is the primary vulnerability surface. When ntfs.sys reads an MFT record, it interprets the `FILE_RECORD_SEGMENT_HEADER` to locate attributes, and uses offset and length fields from the record itself to walk the attribute list. If those offsets point outside the record, or if a length field exceeds the allocation, the driver will read or write out of bounds. CVE-2025-24993 is a direct example: a crafted VHD containing malformed MFT metadata triggers a heap buffer overflow in ntfs.sys because the driver copies data using an attacker-controlled length from the MFT record.

**Size calculations** are the second major risk area. File systems perform arithmetic on cluster counts, allocation sizes, and bitmap lengths to determine how much memory to allocate and how much data to copy. These calculations are prime targets for integer overflow. In CVE-2025-24985, fastfat.sys computes a bitmap allocation size from the cluster count stored in the FAT boot sector. A carefully chosen cluster count overflows the 32-bit multiplication, producing a small allocation that the driver then fills with a much larger copy.

**VHD/VHDX mount accessibility** is what elevates these bugs from "requires physical access" to "local privilege escalation." Since Windows 10, standard users can mount VHD and VHDX files without administrator privileges. This means any file system parsing bug is reachable from a regular user account by crafting a virtual disk image and mounting it. Both CVE-2025-24985 and CVE-2025-24993 were exploited in the wild through this vector.

## Vulnerability Patterns and Detection

| Pattern | Description | AutoPiff Rules |
|---------|-------------|----------------|
| Integer overflow in size calc | Cluster count or allocation size overflows a 32-bit value | `alloc_size_overflow_check_added`, `safe_size_math_helper_added` |
| Heap overflow from MFT parse | Untrusted MFT record length used as memcpy size | `added_len_check_before_memcpy`, `added_struct_size_validation` |
| Missing bounds on bitmap | FAT bitmap allocation trusts on-disk cluster count | `added_index_bounds_check` |

These patterns share a common fix strategy: validate every value read from disk against known bounds before using it in memory operations. Microsoft's patches for both CVEs in the corpus add explicit size checks before the memcpy or allocation call, replacing implicit trust in on-disk values with defensive validation.

## CVEs

| CVE | Driver | Description | Class |
|-----|--------|-------------|-------|
| [CVE-2025-24993](../case-studies/CVE-2025-24993.md) | `ntfs.sys` | MFT metadata heap buffer overflow via crafted VHD | Buffer Overflow |
| [CVE-2025-24985](../case-studies/CVE-2025-24985.md) | `fastfat.sys` | Cluster count overflow in FAT bitmap allocation | Integer Overflow |

## Key Drivers

### ntfs.sys

The NTFS file system driver handles the default file system on modern Windows installations. Its attack surface centers on MFT record parsing: every file and directory on an NTFS volume is represented by an MFT record containing a variable-length list of attributes (filename, data, security descriptor, index). The driver must walk this attribute list during mount and on every file open, interpreting offset and length fields that come directly from disk. Key structures include `FILE_RECORD_SEGMENT_HEADER`, `ATTRIBUTE_RECORD_HEADER`, and index entries. The primary attack vector is a crafted VHD or VHDX file containing malformed MFT records, mountable by a standard user.

### fastfat.sys

The FAT12/16/32 file system driver handles the older FAT file systems still used on USB drives, SD cards, and some VHD images. Its attack surface is smaller than NTFS but focused on arithmetic-intensive code: FAT table entry chains, cluster bitmap allocations, and directory entry parsing. The FAT boot sector contains fields like `BPB_TotSec32` and `BPB_SecPerClus` that the driver uses to compute allocation sizes. When these values are chosen to trigger integer overflow in the multiplication, the resulting undersized allocation leads to a heap overflow during the subsequent data copy. Crafted FAT-formatted VHDs or USB drives are the primary attack vector.

## Research Outlook

File system drivers remain a productive research target because the fundamental problem, parsing complex untrusted binary formats at ring 0, is inherently difficult to get right across every code path. Microsoft has hardened the most obvious paths, but the MFT attribute list format is deeply recursive (attributes can contain attribute lists that reference other MFT records), and FAT drivers must handle multiple FAT variants with subtly different field widths. The VHD mount vector ensures these bugs remain reachable from standard user context, making them viable components of local privilege escalation chains.

For the minifilter drivers that sit above these file system drivers in the I/O stack, see [File System Minifilters](minifilter.md). For the attack surface details on how user-mode code reaches file system parsing, see [Attack Surfaces](../attack-surfaces/).
