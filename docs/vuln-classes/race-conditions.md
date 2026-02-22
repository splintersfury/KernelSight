# Race Conditions

Concurrency bugs from missing locks, broken synchronization, or IRQ-level races in kernel drivers.

## Description

Race conditions occur when shared kernel state is accessed concurrently without proper synchronization. This can lead to use-after-free, data corruption, or privilege escalation.

## Patterns

- Missing spinlock around shared data access
- Missing mutex/resource lock around multi-step operations
- IRP cancellation races (missing cancel-safe queue)
- PnP removal races (missing remove lock)

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-30088](../case-studies/CVE-2024-30088.md) | `ntoskrnl.exe` | TOCTOU race in security attribute copy |
| [CVE-2024-38106](../case-studies/CVE-2024-38106.md) | `ntoskrnl.exe` | Missing lock around VslpEnterIumSecureMode |
| [CVE-2024-38193](../case-studies/CVE-2024-38193.md) | `afd.sys` | UAF race on Registered I/O buffers |

## AutoPiff Detection

- `spinlock_acquisition_added` — Spinlock acquisition added
- `mutex_or_resource_lock_added` — Mutex or resource lock added
- `cancel_safe_irp_queue_added` — Cancel-safe IRP queue added
- `io_remove_lock_added` — Remove lock added for PnP safety
