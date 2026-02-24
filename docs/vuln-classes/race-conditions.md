# Race Conditions

Concurrent access to shared kernel state without proper synchronization, leading to corrupted data, logic errors, or exploitable memory safety violations.

## Description

Race condition vulnerabilities occur when two or more threads, processors, or interrupt contexts access shared kernel state concurrently without adequate synchronization, and at least one access is a write. The Windows kernel is inherently concurrent -- code runs on multiple processors simultaneously, hardware interrupts can preempt thread context, and DPCs (Deferred Procedure Calls) can execute between any two instructions at PASSIVE_LEVEL. This makes race conditions a persistent vulnerability class in kernel drivers.

Unlike TOCTOU bugs (which are a specific subclass involving user-mode data), general race conditions affect any shared kernel state: global variables, linked lists, reference counts, object state fields, and synchronization flags. The consequences depend on what gets corrupted. A race on a linked list operation can cause list corruption leading to arbitrary write when the list is later traversed. A race on a reference count can cause it to reach zero prematurely, resulting in a use-after-free. A race on a state flag can cause security checks to be bypassed.

Exploitation difficulty varies. Some races have very narrow windows (single-instruction read-modify-write) and require precise timing, while others span multiple function calls. Multi-processor systems with shared caches make races more reproducible. Thread pinning (CPU affinity), priority manipulation, and suspension/resumption timing are commonly used to widen race windows and improve reliability.

Race conditions are prevalent in IRP handling and PnP (Plug and Play) code paths. IRP cancellation is a classic source: the driver must handle the case where `IoCancelIrp` is called concurrently with IRP completion, and incorrect handling leads to double-free or use-after-free. The WDM cancel-safe queue APIs (`IoCsqInsertIrp`, `IoCsqRemoveIrp`) were designed to eliminate this class of race, but many older drivers use manual cancellation logic that remains vulnerable.

## Common Patterns in Drivers

- Missing spinlock acquisition around linked list insert/remove operations (`InsertHeadList`, `RemoveEntryList`), allowing concurrent modifications that corrupt list pointers
- Check-then-act on a shared variable without using interlocked operations: `if (flag == 0) { flag = 1; do_work(); }` can be entered by two threads simultaneously
- IRQL-based "synchronization" (`KeRaiseIrql` to DISPATCH_LEVEL) that only prevents preemption on the current processor, providing no protection on multi-processor systems
- Work item or DPC callback accessing an object that a thread-context code path is concurrently tearing down
- Reference count increment/decrement not using `InterlockedIncrement` / `InterlockedDecrement`, allowing lost updates on multi-processor systems
- IRP cancellation racing with normal IRP completion -- both paths attempt to finalize the same IRP, with the second access corrupting freed memory
- PnP device removal racing with active I/O -- `IRP_MN_REMOVE_DEVICE` handler frees resources while another thread is mid-operation on those resources, without `IoAcquireRemoveLock` protection
- Fast mutex or pushlock acquired at wrong IRQL, allowing reentrant access on the same processor
- Timer/DPC callback accessing state after the parent object has been freed due to missing cancellation before free
- File system filter drivers with reentrancy races: a filter issues an I/O request that re-enters the same filter, accessing shared state without reentrancy protection

## Exploitation Implications

Exploitation depends on what the race corrupts. List corruption races (missing lock on `InsertHeadList` / `RemoveHeadList`) can produce a controlled arbitrary write: when a corrupted forward pointer is used in a subsequent list insertion, the `Flink->Blink = NewEntry` operation writes to an attacker-influenced address. Reference count races produce use-after-free conditions, exploited via pool spray as described in the UAF vulnerability class.

CPU affinity pinning constrains the two racing threads to the same or adjacent cores. Thread priority manipulation ensures the racing thread gets scheduled at the right moment. `NtSuspendThread` / `NtResumeThread` can precisely control when a thread proceeds past a specific point. On systems with Hyper-Threading, logical processors sharing a physical core have tightly coupled cache behavior that makes races highly reproducible.

Some races can be won on the first attempt -- for example, a race between a PnP removal handler and an active IOCTL handler may have a window of hundreds of microseconds if the IOCTL handler performs blocking operations. Others require thousands of attempts and statistical analysis to determine optimal timing parameters for the target hardware.

## Typical Primitives Gained

- [Pool Spray / Feng Shui](../primitives/exploitation/pool-spray-feng-shui.md) -- used to exploit the UAF that results from reference count races
- [Write-What-Where](../primitives/arw/write-what-where.md) -- from list corruption or state corruption races that redirect a kernel write operation
- [Pool Overflow](../primitives/arw/pool-overflow.md) -- when a race on a size or bounds variable leads to an unchecked memory copy
- Privilege escalation via state machine race that bypasses authorization checks

## Mitigations

- **Spinlocks** -- `KeAcquireSpinLock` / `KeReleaseSpinLock` for protecting shared state accessed at DISPATCH_LEVEL or from DPC/ISR contexts
- **ERESOURCE locks** -- `ExAcquireResourceExclusiveLite` / `ExAcquireResourceSharedLite` for reader/writer synchronization on complex data structures
- **Cancel-safe IRP queues** -- `IoCsqInsertIrp` / `IoCsqRemoveIrp` eliminate IRP cancellation races by handling synchronization internally
- **Remove locks** -- `IoAcquireRemoveLock` / `IoReleaseRemoveLock` prevent PnP removal from proceeding while I/O operations are in flight
- **Interlocked operations** -- `InterlockedIncrement`, `InterlockedDecrement`, `InterlockedCompareExchange` for atomic updates to shared counters and flags
- **KMDF synchronization** -- WDF provides automatic synchronization scope (device-level or none) that serializes callbacks as appropriate

## Detection Strategies

- **Patch diffing**: Look for added lock acquisitions (`KeAcquireSpinLock`, `ExAcquireFastMutex`, `KeWaitForMutexObject`), interlocked operations replacing non-atomic read-modify-write sequences, or `IoAcquireRemoveLock` additions. AutoPiff detects these patterns.
- **Static analysis**: Thread safety analyzers (e.g., SAL annotations `_Requires_lock_held_`, `_Guarded_by_`) can identify unprotected accesses to shared state. Flag all global variable accesses in multi-threaded code paths that lack corresponding lock acquisitions.
- **Dynamic analysis**: Enable Driver Verifier's Concurrency Stress and Deadlock Detection options. Run I/O stress tests with multiple threads and PnP removal stress to surface races.
- **Code review**: Focus on teardown/cleanup paths and their interaction with active I/O paths. Verify that every resource freed in a teardown path is protected from concurrent access by a lock or remove lock.
- **Kernel debugging**: Use `!deadlock` extension and Concurrency Visualizer to identify lock ordering issues and unprotected shared state accesses.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-30088](../case-studies/CVE-2024-30088.md) | `ntoskrnl.exe` | TOCTOU race in security attribute copy allowing token manipulation |
| [CVE-2024-38106](../case-studies/CVE-2024-38106.md) | `ntoskrnl.exe` | Missing lock around VslpEnterIumSecureMode allowing concurrent privilege escalation |
| [CVE-2024-38193](../case-studies/CVE-2024-38193.md) | `afd.sys` | UAF race on Registered I/O buffer deregistration during active use |
| [CVE-2024-30089](../case-studies/CVE-2024-30089.md) | `mskssrv.sys` | Race condition in streaming service request reference counting |
| [CVE-2023-21768](../case-studies/CVE-2023-21768.md) | `afd.sys` | Concurrency race in AFD leading to use-after-free and privilege escalation |

## AutoPiff Detection

- `spinlock_acquisition_added` -- Detects patches adding spinlock acquire/release pairs around previously unprotected shared state accesses
- `mutex_or_resource_lock_added` -- Detects addition of fast mutex, ERESOURCE, or pushlock synchronization to protect multi-step operations on shared data
- `cancel_safe_irp_queue_added` -- Detects conversion of IRP queuing to use `IoCsqInsertIrp` / cancel-safe queue pattern, eliminating IRP cancellation races
- `io_remove_lock_added` -- Detects addition of `IoAcquireRemoveLock` / `IoReleaseRemoveLock` to protect against PnP removal races during active I/O
- `added_interlocked_operation` -- Detects replacement of non-atomic read-modify-write sequences with `InterlockedIncrement`, `InterlockedDecrement`, or `InterlockedCompareExchange`
- `added_lock_acquisition` -- Detects general lock acquisition additions for shared state protection
