# Filesystem IRPs

File system IRP dispatch routines and minifilter callbacks represent a broad attack surface reached through file I/O operations, crafted disk images, and reparse point manipulation.

## Attack Surface Overview

- **Entry points**: `IRP_MJ_CREATE`, `IRP_MJ_READ`, `IRP_MJ_WRITE`, `IRP_MJ_SET_INFORMATION`, `IRP_MJ_QUERY_INFORMATION`, and `IRP_MJ_FILE_SYSTEM_CONTROL` (FSCTL) dispatch routines
- **Minifilter callbacks**: Pre-operation and post-operation callbacks registered via `FltRegisterFilter` with altitude-ordered interception of file I/O
- **Reparse points**: Untrusted reparse data buffers (junction points, symlinks, Cloud Files placeholders) parsed by filesystem drivers and filters
- **On-disk structures**: MFT records (NTFS), FAT/exFAT cluster chains, ReFS metadata trees, and CLFS base log file blocks parsed from potentially crafted media
- **Extended attributes**: Variable-length extended attribute (EA) data processed through `IRP_MJ_SET_EA` and `IRP_MJ_QUERY_EA` handlers
- **User-mode reach**: Standard file APIs (`CreateFile`, `ReadFile`, `WriteFile`, `DeviceIoControl` with FSCTLs), mounting VHD/VHDX images, USB storage insertion, and reparse point creation via `DeviceIoControl(FSCTL_SET_REPARSE_POINT)`
- **Key risk**: Complex parsing of untrusted on-disk metadata structures and variable-length reparse data buffers involving integer arithmetic on attacker-controlled size fields

## Mechanism Deep-Dive

When a user-mode application performs a file operation, the I/O Manager builds an IRP and sends it down the filesystem device stack. Minifilter drivers registered at various altitudes intercept these IRPs through pre-operation and post-operation callbacks. The file system driver itself (such as `ntfs.sys` or `fastfat.sys`) then processes the request, which may involve reading and parsing on-disk metadata structures. For NTFS, this includes MFT records, attribute lists, index entries, and security descriptors. For FAT, this includes FAT table entries, directory entries, and cluster chains.

The reparse point mechanism provides a particularly interesting attack surface. When a file system encounters a reparse point during name resolution in `IRP_MJ_CREATE`, it returns `STATUS_REPARSE` with the reparse data buffer. Minifilter drivers such as `cldflt.sys` (Cloud Files), `wcifs.sys` (Windows Container Isolation), and `wof.sys` (Windows Overlay Filter) register to handle specific reparse tags and parse the associated data buffers. These buffers are variable-length structures with embedded offsets and sizes that must be carefully validated. The CVE-2024-30085 vulnerability in `cldflt.sys` demonstrated that a missing size check before a `memcpy` in reparse data handling allowed a heap buffer overflow, leading to local privilege escalation.

Crafted disk images represent an additional vector with lower barrier to entry. An attacker can create a VHD or VHDX file containing a malformed NTFS or FAT filesystem, then mount it via `Mount-DiskImage` or by double-clicking in Explorer. The filesystem driver parses the on-disk structures from the mounted image, and any parsing vulnerability becomes reachable. This was the attack vector for both CVE-2025-24993 (NTFS MFT metadata heap overflow) and CVE-2025-24985 (FastFAT cluster count integer overflow), where crafted disk images triggered heap buffer overflows during metadata parsing.

The Common Log File System (`clfs.sys`) deserves special mention as a filesystem-adjacent component that manages BLF (Base Log File) structures. CLFS has been an exceptionally prolific source of vulnerabilities because its on-disk log file format contains complex metadata blocks with circular references, nested containers, and packed records. An attacker can craft a malicious BLF file and trigger parsing through the `CreateLogFile` API, reaching deeply nested parsing logic that has historically contained multiple heap overflow and out-of-bounds write vulnerabilities.

## Common Vulnerability Patterns

- **Reparse data buffer overflow**: Missing bounds checks on variable-length fields within reparse data structures, allowing a crafted reparse point to trigger a heap overflow during `memcpy`
- **MFT/FAT metadata parsing overflow**: Integer overflow in cluster count or record size calculations when processing crafted on-disk structures, leading to undersized allocations
- **Minifilter context reference leaks**: `FltReferenceContext` called on a pre-operation path but not released on error or fast-I/O fallback paths, causing pool exhaustion
- **TOCTOU in filename validation**: Filename checked in pre-create callback, but the actual path can change via reparse or symlink before the operation completes
- **Extended attribute handling**: `IRP_MJ_SET_EA` with variable-length extended attribute data and insufficient total-length validation leading to heap overflows
- **Oplock race conditions**: Opportunistic lock break handling creates windows where file state changes between validation and use
- **FSCTL input buffer validation**: File system control requests with complex input structures and missing sub-field size validation
- **CLFS log block corruption**: Crafted BLF files with malformed container context, base record headers, or client context fields causing out-of-bounds writes during log file parsing
- **Minifilter fast-I/O fallback**: Fast I/O paths bypass pre/post-operation callbacks, allowing operations to proceed without the security checks that the minifilter applies to IRP-based paths

## Driver Examples

Core filesystem drivers `ntfs.sys`, `refs.sys`, and `fastfat.sys` parse on-disk structures and are reachable via crafted media. The Common Log File System driver `clfs.sys` manages BLF log files with complex internal metadata and has been a repeat exploitation target (CVE-2024-49138, CVE-2023-28252, CVE-2022-37969). Minifilter drivers `cldflt.sys` (Cloud Files), `wcifs.sys` (Container Isolation), `bindflt.sys` (Bind Filter), and `wof.sys` (Overlay Filter) process reparse data buffers. Third-party minifilters from antivirus products, backup solutions, and encryption software add further filesystem attack surface. `mrxsmb.sys` and `rdbss.sys` handle remote filesystem operations over SMB.

## Detection Approach

- **Reparse data auditing**: Identify minifilter callbacks that handle reparse data by searching for reparse tag checks and `FltTagDataBuffer` access. Verify all variable-length field accesses include bounds checks against the actual reparse data length.
- **Disk image fuzzing**: Mount crafted VHD images containing malformed NTFS/FAT structures and monitor for kernel crashes using special pool and Driver Verifier. Systematically corrupt on-disk metadata fields in sector-level hex editing.
- **CLFS log fuzzing**: Create malformed BLF files by corrupting base record headers, container contexts, and client contexts, then trigger parsing via `CreateLogFile`. CLFS is a high-yield fuzzing target due to its format complexity.
- **Minifilter state analysis**: Use `!fltkd.filters` in WinDbg to enumerate registered minifilters and their callback registrations. Trace pre/post-operation callbacks to verify context reference counting on all code paths including error returns and fast-I/O fallbacks.
- **Patch diffing**: Compare driver binaries across Windows updates to find newly added size checks in reparse data parsing, FSCTL handlers, or on-disk metadata parsing routines.

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
