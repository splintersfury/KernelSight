# Filesystem IRPs

Plug in a USB drive containing a crafted NTFS image. Double-click a VHD file attached to an email. Save a file to a OneDrive-synced folder. Each of these routine actions triggers kernel-mode parsing of complex, variable-length data structures that an attacker can control completely. Filesystem IRP dispatch routines and minifilter callbacks represent one of the broadest kernel attack surfaces in Windows, not because they are conceptually complex (file I/O is well understood), but because the data they parse comes from so many untrusted sources: removable media, network shares, cloud sync providers, and crafted disk images that the operating system mounts eagerly.

What distinguishes filesystem attack surface from other kernel entry points is the depth of parsing involved. An IOCTL handler typically processes a single input structure with known fields. A filesystem driver parses recursive, self-referential on-disk metadata: MFT records containing attribute lists that reference other MFT records, FAT cluster chains with attacker-controlled link values, CLFS log files with circular container references and packed records. The parsing logic is deeply nested, the integer arithmetic is pervasive, and a single miscalculation in a size or offset field can corrupt the kernel heap.

## How filesystem I/O reaches the kernel

``` mermaid
graph TD
    A["User Process\nCreateFile / ReadFile / WriteFile"] --> B["I/O Manager\nBuild IRP"]
    B --> C["Filter Manager\nfltmgr.sys"]
    C --> D["Minifilter Stack\n(altitude-ordered)"]
    D --> E["Pre-Operation Callbacks\ncldflt.sys, wcifs.sys, wof.sys"]
    E --> F["File System Driver\nntfs.sys / fastfat.sys / refs.sys"]
    F --> G["On-Disk Metadata Parsing\nMFT records, FAT chains,\nreparse data, EA buffers"]
    G --> H["Post-Operation Callbacks\n(minifilter post-processing)"]
    style E fill:#152a4a,stroke:#f59e0b,color:#e2e8f0
    style F fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    style G fill:#2d1b1b,stroke:#ef4444,color:#e2e8f0
```

When a user-mode application performs a file operation, the I/O Manager builds an IRP and sends it down the filesystem device stack. The Filter Manager (`fltmgr.sys`) intercepts the IRP and dispatches it through registered minifilter drivers in altitude order. Each minifilter can inspect or modify the request in its pre-operation callback, and examine or alter the result in its post-operation callback. The file system driver itself (`ntfs.sys`, `fastfat.sys`, or `refs.sys`) then processes the request, which may involve reading and parsing on-disk metadata structures.

The IRP major function codes that constitute filesystem attack surface span the full range of file operations. `IRP_MJ_CREATE` handles file open and path resolution, including reparse point processing. `IRP_MJ_READ` and `IRP_MJ_WRITE` transfer data between user buffers and disk. `IRP_MJ_SET_INFORMATION` handles rename, delete, and attribute changes. `IRP_MJ_QUERY_INFORMATION` returns file metadata. `IRP_MJ_FILE_SYSTEM_CONTROL` (FSCTL) handles filesystem-specific control requests with complex input structures. `IRP_MJ_SET_EA` and `IRP_MJ_QUERY_EA` process variable-length extended attribute data. Each of these code paths must handle untrusted data correctly, and each has produced real vulnerabilities.

## The reparse point attack vector

The reparse point mechanism deserves close examination because it is one of the most productive sources of filesystem kernel bugs in recent years. When a file system encounters a reparse point during name resolution in `IRP_MJ_CREATE`, it returns `STATUS_REPARSE` with a reparse data buffer. Minifilter drivers registered to handle specific reparse tags then parse the associated data buffers. These buffers are variable-length structures with embedded offsets and sizes, and the parsing must validate every field before using it.

Cloud Files minifilter (`cldflt.sys`) is the canonical example. It handles the `IO_REPARSE_TAG_CLOUD` reparse tag and processes placeholder data for OneDrive and other cloud sync providers. CVE-2024-30085 demonstrated that a missing size check before a `memcpy` in `cldflt.sys` reparse data handling allowed a heap buffer overflow from a crafted reparse point. CVE-2023-36036 was another heap overflow in the same driver through a different reparse data code path. The pattern repeats because reparse data structures are deeply nested, and each new feature (placeholder hydration, partial file support, cloud-specific metadata) adds new fields that each need their own bounds checks.

Other minifilters face the same challenge. The Windows Container Isolation filter (`wcifs.sys`), the Bind Filter (`bindflt.sys`), and the Windows Overlay Filter (`wof.sys`) all parse reparse data buffers with custom formats. Junction points and symlinks, while simpler in structure, still involve path manipulation that can be exploited for TOCTOU attacks: a symlink target verified in a pre-create callback can be changed by a concurrent thread before the filesystem driver completes the operation.

## Crafted disk images: a low-barrier entry point

Crafted disk images represent an especially accessible attack vector. A VHD or VHDX file containing a malformed NTFS or FAT filesystem can be mounted via `Mount-DiskImage`, through a PowerShell command, or simply by double-clicking it in Explorer. Once mounted, the filesystem driver parses the on-disk structures from the image, and any parsing vulnerability becomes reachable without elevated privileges.

Two vulnerabilities from early 2025 illustrate this clearly. CVE-2025-24993 was a heap buffer overflow in `ntfs.sys` triggered during MFT metadata record parsing from a crafted disk image. The MFT record contained a malformed attribute list with size fields that caused an undersized allocation, and the subsequent copy of attribute data overflowed the heap buffer. CVE-2025-24985 was an integer overflow in `fastfat.sys` where a crafted FAT cluster count bitmap calculation wrapped around 32-bit integer bounds, producing a small allocation for a large copy operation.

These are not exotic attack scenarios. A crafted VHD can be embedded in an email attachment, hosted on a web server, or placed on a network share. The user interaction required is minimal: open the file, and Windows mounts it automatically. The fact that the parsing happens in kernel mode means the overflow corrupts the kernel heap, not a user-mode buffer.

## CLFS: a recurring target

The Common Log File System (`clfs.sys`) occupies a unique position in the filesystem attack surface landscape. It manages BLF (Base Log File) structures with an on-disk format that is both complex and deeply interconnected: metadata blocks with circular references, nested containers, and packed records. CLFS has been a recurring source of kernel exploitation, with CVE-2024-49138, CVE-2023-28252, and CVE-2022-37969 all targeting BLF metadata parsing.

The pattern is consistent. A crafted BLF file triggers parsing through the `CreateLogFile` API, reaching nested parsing logic in `clfs.sys` that processes base record headers, container contexts, and client contexts. The format complexity means that validation must check not only individual field sizes but also cross-references between fields, container indices that reference other containers, and packed record boundaries that depend on values from previous records. Missing any of these checks produces an out-of-bounds write in kernel pool memory.

What makes CLFS particularly attractive to attackers is that BLF files can be created and manipulated by unprivileged users. The `CreateLogFile` API does not require elevation, and the log file can be placed in any writable directory. This means that an attacker who can write a file to disk can trigger kernel code execution through CLFS parsing.

## Extended attributes and FSCTL handlers

Extended attributes (EAs) are variable-length name-value pairs attached to files, processed through `IRP_MJ_SET_EA` and `IRP_MJ_QUERY_EA` handlers. The variable-length nature of EA data, with a `NextEntryOffset` field linking entries in a chain, creates the same integer arithmetic hazards seen in other variable-length parsing. Total-length validation must account for all entries in the chain, and a mismatch between the declared total length and the sum of individual entry sizes produces heap overflows.

FSCTL handlers (`IRP_MJ_FILE_SYSTEM_CONTROL`) are functionally similar to IOCTLs but operate through the filesystem stack. They accept complex input structures for operations like defragmentation, compression, reparse point management, and filesystem-specific features. Each FSCTL code path must independently validate its input buffer, and the same size-check and type-confusion patterns that affect [IOCTL handlers](ioctl-handlers.md) apply here. The `FSCTL_SET_REPARSE_POINT` control code is the entry point for creating reparse points, making it the user-mode API that feeds the reparse parsing attack surface described above.

## Oplock races and TOCTOU

Opportunistic locks (oplocks) introduce a timing dimension to filesystem attack surface. An oplock allows a process to be notified when another process attempts to access a file, creating a window during which the oplock holder can perform operations before the access proceeds. Attackers use oplocks to create precise TOCTOU (time-of-check-to-time-of-use) windows: the minifilter validates a file's content or attributes during a pre-create callback, the attacker's oplock fires and modifies the file, and the filesystem driver processes the modified content that the minifilter already approved.

This technique is a building block for many filesystem exploitation chains. By combining oplock races with symlink swaps or reparse point manipulation, an attacker can redirect file operations to arbitrary targets after validation has already passed. The resulting bugs are difficult to detect through static analysis because the vulnerability is not in any single code path but in the interaction between two concurrent operations mediated by the oplock mechanism.

## Detection approaches

**Reparse data auditing** targets minifilter callbacks that handle reparse data by searching for reparse tag checks and `FltTagDataBuffer` access. The critical verification is that all variable-length field accesses include bounds checks against the actual reparse data length. Missing checks on embedded offset fields are the most common gap.

**Disk image fuzzing** mounts crafted VHD images containing malformed NTFS/FAT structures and monitors for kernel crashes using special pool and Driver Verifier. Systematically corrupting on-disk metadata fields in sector-level hex editing is productive because the parsing code paths are deep and interact with each other. A corruption in an MFT attribute list can trigger failures in index processing, which can trigger failures in security descriptor lookup, each with its own potential for overflow.

**CLFS log fuzzing** creates malformed BLF files by corrupting base record headers, container contexts, and client contexts, then triggers parsing via `CreateLogFile`. The format complexity and the number of cross-referenced fields make CLFS an exceptionally productive fuzzing target. Multiple independent research groups have found distinct vulnerabilities in this same component.

**Minifilter state analysis** uses `!fltkd.filters` in WinDbg to enumerate registered minifilters and their callback registrations. Tracing pre/post-operation callbacks to verify context reference counting on all code paths, including error returns and fast-I/O fallbacks, catches the reference leak bugs that accumulate into denial-of-service conditions or, less commonly, use-after-free through extra decrements.

**Patch diffing** compares driver binaries across Windows updates to find newly added size checks in reparse data parsing, FSCTL handlers, or on-disk metadata parsing routines. Filesystem patches tend to be surgical (a single bounds check added before a `memcpy`) and are straightforward to identify through [AutoPiff](../tooling/autopiff-integration.md) binary comparison.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-30085](../case-studies/CVE-2024-30085.md) | `cldflt.sys` | Missing size check before `memcpy` in Cloud Files reparse handling |
| [CVE-2023-36036](../case-studies/CVE-2023-36036.md) | `cldflt.sys` | Heap overflow via crafted reparse data buffer |
| [CVE-2025-24985](../case-studies/CVE-2025-24985.md) | `fastfat.sys` | Integer overflow in FAT cluster count bitmap calculation |
| [CVE-2025-24993](../case-studies/CVE-2025-24993.md) | `ntfs.sys` | Heap buffer overflow during MFT metadata record parsing |
| [CVE-2024-49138](../case-studies/CVE-2024-49138.md) | `clfs.sys` | Heap overflow in CLFS base log file parsing |
| [CVE-2023-28252](../case-studies/CVE-2023-28252.md) | `clfs.sys` | Out-of-bounds write in CLFS log block processing |
| [CVE-2022-37969](../case-studies/CVE-2022-37969.md) | `clfs.sys` | Elevation of privilege via crafted BLF file metadata |

## AutoPiff Detection

- `added_len_check_before_memcpy` -- Bounds check added before memory copy operation in buffer parsing
- `flt_context_reference_leak_fix` -- Minifilter context reference leak fixed on error or cleanup path
- `flt_create_race_mitigation` -- TOCTOU race condition in `IRP_MJ_CREATE` pre-operation callback mitigated
- `reparse_data_bounds_check_added` -- Validation added for reparse data buffer length fields
- `fsctl_input_validation_added` -- Input buffer size validation added for filesystem control request
- `clfs_metadata_validation_added` -- Bounds or integrity check added to CLFS base log file record parsing

The filesystem attack surface connects naturally to several vulnerability classes. Buffer overflows from metadata parsing feed into [heap overflow](../vuln-classes/buffer-overflow.md) exploitation. Oplock-based races produce [TOCTOU](../vuln-classes/toctou-double-fetch.md) conditions. Minifilter reference counting bugs lead to [use-after-free](../vuln-classes/use-after-free.md). And the primitives that emerge from these bugs, particularly the controlled heap corruptions from CLFS and NTFS parsing, are among the most reliable paths to [pool spray](../primitives/exploitation/pool-spray-feng-shui.md) exploitation.
