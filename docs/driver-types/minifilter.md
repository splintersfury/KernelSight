# File System Minifilters

Minifilter drivers attach to file system stacks via the Filter Manager (FltMgr) to intercept and modify file I/O operations. They are used for antivirus scanning, cloud sync, encryption, and backup.

## Architecture

- **Driver model**: Minifilter (registered via `FltRegisterFilter`)
- **Callbacks**: Pre-operation and post-operation callbacks for each IRP major function
- **Context management**: Per-stream, per-instance, per-volume contexts tracked by FltMgr
- **Altitude**: Ordering determined by altitude value in the minifilter's INF

## Attack Surface

- **Reparse data handling**: Cloud files minifilters process reparse points with complex data structures
- **Context reference management**: FltGetStreamContext / FltReleaseContext leaks on error paths
- **Pre/post-operation TOCTOU**: State can change between pre-op validation and post-op action
- **Extended attribute parsing**: EA buffers from IRP_MJ_CREATE

## Common Vulnerability Patterns

| Pattern | Description | AutoPiff Rules |
|---------|-------------|----------------|
| Heap overflow via reparse data | Untrusted reparse buffer size used in memcpy | `added_len_check_before_memcpy`, `added_bounds_check_on_offset` |
| Context reference leak | FltReleaseContext not called on error path | `flt_context_reference_leak_fix` |
| TOCTOU in IRP_MJ_CREATE | Buffer validated then re-read from shared mapping | `flt_create_race_mitigation` |

## CVEs

| CVE | Driver | Description | Class | ITW |
|-----|--------|-------------|-------|-----|
| [CVE-2024-30085](../case-studies/CVE-2024-30085.md) | `cldflt.sys` | Missing size check before memcpy in Cloud Files | Buffer Overflow | No |
| [CVE-2023-36036](../case-studies/CVE-2023-36036.md) | `cldflt.sys` | Heap overflow via crafted reparse data | Buffer Overflow | Yes |

## Key Drivers

### cldflt.sys (Cloud Files Mini Filter)
- **Role**: Windows Cloud Files API minifilter for OneDrive and cloud sync providers
- **Attack vector**: Crafted reparse points, cloud file placeholders
- **Recurring pattern**: Both CVEs are heap overflows from missing bounds checks on reparse data — the same driver class, same bug class, patched months apart
