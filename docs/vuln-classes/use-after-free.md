# Use-After-Free

Dangling pointer dereference after an object or pool chunk has been freed.

## Description

Use-after-free occurs when a driver continues to reference memory after it has been freed. If an attacker can reclaim the freed allocation with controlled data, they can hijack control flow or corrupt kernel state.

## Patterns

- Missing NULL-after-free
- Reference count imbalance (missing ObDereferenceObject on error path)
- Concurrent free and access without synchronization
- Callback invocation on freed object

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-38193](../case-studies/CVE-2024-38193.md) | `afd.sys` | UAF race on Registered I/O buffers |
| [CVE-2024-30089](../case-studies/CVE-2024-30089.md) | `mskssrv.sys` | Ref-count logic error causes UAF |
| [CVE-2023-29336](../case-studies/CVE-2023-29336.md) | `win32kfull.sys` | UAF from unlocked nested menu object |

## AutoPiff Detection

- `null_after_free_added` — Pointer set to NULL after free
- `guard_before_free_added` — NULL check before free
- `ob_reference_balance_fix` — ObDereferenceObject added on error path
- `error_path_cleanup_added` — Resource cleanup on error path
