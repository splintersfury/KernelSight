# Filesystem IRPs

Filesystem filter drivers (minifilters) and file system drivers process IRPs for create, read, write, and control operations. Reparse points and extended attributes provide additional attack surface.

## Attack Surface Overview

- **Entry points**: `IRP_MJ_CREATE`, `IRP_MJ_READ`, `IRP_MJ_WRITE`, `IRP_MJ_SET_INFORMATION`
- **Minifilter callbacks**: Pre/post-operation callbacks registered via `FltRegisterFilter`
- **Reparse data**: Controlled data structures passed through reparse points
- **Key risk**: Complex parsing of untrusted on-disk structures

## Common Vulnerability Patterns

- Missing bounds checks on reparse data buffers
- Minifilter context reference leaks on error paths
- TOCTOU between filename validation and actual I/O
- Integer overflows in MFT record or FAT cluster calculations

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-30085](../case-studies/CVE-2024-30085.md) | `cldflt.sys` | Missing size check before memcpy in Cloud Files |
| [CVE-2023-36036](../case-studies/CVE-2023-36036.md) | `cldflt.sys` | Heap overflow via crafted reparse data |
| [CVE-2025-24985](../case-studies/CVE-2025-24985.md) | `fastfat.sys` | Cluster count overflow in FAT bitmap |
| [CVE-2025-24993](../case-studies/CVE-2025-24993.md) | `ntfs.sys` | MFT metadata heap buffer overflow |

## AutoPiff Detection

- `flt_context_reference_leak_fix` — Minifilter context reference leak fixed
- `flt_create_race_mitigation` — TOCTOU in IRP_MJ_CREATE fixed
- `added_len_check_before_memcpy` — Bounds check added before memory copy
