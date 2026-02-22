# Shared Memory

Kernel-user shared memory regions (sections, MDL mappings) provide high-bandwidth data paths but introduce double-fetch and mapping vulnerabilities.

## Attack Surface Overview

- **Mechanisms**: `ZwMapViewOfSection`, MDL-based mappings, `KUSER_SHARED_DATA`
- **Key risk**: Kernel reading from shared pages that user-mode can modify concurrently
- **MDL abuse**: `MmProbeAndLockPages` with wrong access mode allows arbitrary mapping

## Common Vulnerability Patterns

- `MmProbeAndLockPages` called with `KernelMode` on user-supplied MDL
- `MmMapLockedPages` without prior `MmProbeAndLockPages`
- Double-fetch from shared mapped memory

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2023-29360](../case-studies/CVE-2023-29360.md) | `mskssrv.sys` | MmProbeAndLockPages with KernelMode on user MDL |
| [CVE-2024-38238](../case-studies/CVE-2024-38238.md) | `ksthunk.sys` | MmMapLockedPages without MmProbeAndLockPages |

## AutoPiff Detection

- `mdl_probe_access_mode_fix` — Access mode fixed from KernelMode to UserMode
- `mdl_safe_mapping_replacement` — Unsafe MDL mapping replaced with safe variant
- `mdl_null_check_added` — NULL check on Irp->MdlAddress added
