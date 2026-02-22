# Buffer Overflow

Stack and heap buffer overflows from missing or incorrect size validation before memory copy operations.

## Description

Buffer overflows occur when a driver copies data beyond the bounds of an allocated buffer. In kernel context, this typically manifests as pool (heap) overflows that corrupt adjacent allocations, or stack overflows that overwrite return addresses or saved registers.

## Patterns

### Pool/Heap Overflow
- Missing length check before `RtlCopyMemory` / `memcpy`
- Trusting user-supplied size without validation against buffer capacity
- Incorrect calculation of remaining buffer space

### Stack Overflow
- Fixed-size stack buffer with unchecked copy from user input
- Recursive functions without depth limits

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-30085](../case-studies/CVE-2024-30085.md) | `cldflt.sys` | Missing size check before memcpy |
| [CVE-2023-36036](../case-studies/CVE-2023-36036.md) | `cldflt.sys` | Heap overflow via reparse data |
| [CVE-2023-28252](../case-studies/CVE-2023-28252.md) | `clfs.sys` | OOB write via corrupted base log offset |
| [CVE-2024-49138](../case-studies/CVE-2024-49138.md) | `clfs.sys` | Heap overflow in LoadContainerQ |
| [CVE-2022-37969](../case-studies/CVE-2022-37969.md) | `clfs.sys` | SignaturesOffset OOB write |
| [CVE-2025-24993](../case-studies/CVE-2025-24993.md) | `ntfs.sys` | MFT metadata heap buffer overflow |

## AutoPiff Detection

- `added_len_check_before_memcpy` — Length check added before memory copy
- `added_struct_size_validation` — Input structure size validation added
- `added_index_bounds_check` — Index bounds check added
- `safe_string_function_replacement` — Unsafe string function replaced
- `unicode_string_length_validation_added` — UNICODE_STRING length validation

## Exploitation

Pool overflows are typically exploited via [Pool Spray / Feng Shui](../primitives/exploitation/pool-spray-feng-shui.md) to control adjacent allocations, then corrupting object headers or function pointers to gain code execution or a R/W primitive.
