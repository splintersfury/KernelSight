# MDL Mapping Primitive

Abusing Memory Descriptor List (MDL) lock/map operations to map arbitrary physical memory into user space.

## Description

MDLs describe physical memory regions. If a driver calls `MmProbeAndLockPages` with `KernelMode` access on a user-supplied MDL, or calls `MmMapLockedPages` without first probing, an attacker can map arbitrary physical memory.

## Mechanism

1. Supply a crafted MDL or buffer address
2. Driver locks pages with KernelMode (no address validation)
3. Driver maps locked pages to user-accessible address
4. Attacker now has read/write access to arbitrary physical memory

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2023-29360](../case-studies/CVE-2023-29360.md) | `mskssrv.sys` | MmProbeAndLockPages with KernelMode |
| [CVE-2024-38238](../case-studies/CVE-2024-38238.md) | `ksthunk.sys` | MmMapLockedPages without probe |

## AutoPiff Detection

- `mdl_probe_access_mode_fix`
- `mdl_safe_mapping_replacement`
- `mdl_null_check_added`
