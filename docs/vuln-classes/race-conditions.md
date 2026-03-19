# Race Conditions

Two threads enter the same IOCTL handler simultaneously. Both read a global counter, both see the value 1, both decrement it to zero, and both free the associated object. The second free corrupts the pool allocator. Neither thread did anything wrong in isolation. The bug exists only in the space between them, in the interleaving that no single-threaded test will ever exercise.

Race conditions are the concurrency failures that produce every other vulnerability class on this site. A race on a reference count becomes a [use-after-free](use-after-free.md). A race on a size field becomes a [buffer overflow](buffer-overflow.md). A race between validation and use becomes a [TOCTOU](toctou-double-fetch.md). Understanding race conditions means understanding the *mechanism* by which these other classes are triggered in concurrent code, and why the fixes always involve adding synchronization rather than adding bounds checks.

## Why the kernel is inherently concurrent

Single-threaded code does not have race conditions. The Windows kernel is never single-threaded. Code runs on multiple processors simultaneously. Hardware interrupts preempt thread context. DPCs (Deferred Procedure Calls) execute between any two instructions at PASSIVE_LEVEL. Work items run on system worker threads. IRP completion routines fire when I/O finishes, potentially long after the requesting thread has moved on.

This means every shared variable, every linked list, every reference count, and every state flag in a kernel driver is a potential race target unless explicitly protected. The protection mechanisms are well-known: spinlocks for DISPATCH_LEVEL code, ERESOURCE locks for reader/writer patterns, interlocked operations for atomic counters, remove locks for PnP lifecycle management. The bugs happen when protection is missing, incomplete, or applied at the wrong granularity.

Raising IRQL to DISPATCH_LEVEL via `KeRaiseIrql` is a common misunderstanding. It prevents preemption on the current processor, which provides synchronization on a single-core system. On a multi-processor system, it does nothing to prevent concurrent execution on another core. Code that relies on IRQL alone for synchronization has a latent race condition that only manifests on multi-core hardware, which is exactly the hardware that every modern Windows system runs.

## Patterns that race

### Reference count races

The most impactful pattern, because it produces [use-after-free](use-after-free.md) bugs. Two threads decrement a reference count concurrently. Both read the count as 2, both decrement to 1, and the count never reaches zero, causing a memory leak. Or worse: both read the count as 1, both decrement to 0, and both attempt to free the object, producing a double-free that corrupts the pool allocator.

When the increment and decrement are not atomic (using `InterlockedIncrement`/`InterlockedDecrement`), the read-modify-write sequence is interruptible. Even on x86 where individual memory operations appear atomic, a non-interlocked `count--` compiles to a load, subtract, store sequence that can be interleaved with another core's identical sequence.

CVE-2024-30089 in `mskssrv.sys` is a reference count race in the kernel streaming server's request handling. Concurrent streaming operations could hit a code path where the reference count was decremented without interlocked semantics, causing premature object destruction while another thread still held a stale pointer.

### Linked list corruption

`InsertHeadList`, `RemoveEntryList`, and the other doubly-linked list macros are not atomic. They perform multiple pointer writes: updating `Flink` and `Blink` fields in three different list entries. If two threads insert or remove entries concurrently without a lock, the pointer writes interleave, and the list becomes corrupt. The corruption manifests as circular links (infinite traversal), dangling pointers (traversal accesses freed memory), or mislinked entries (an element appears in the wrong position or is silently dropped).

Corrupted list pointers can be exploited for arbitrary write. When the kernel later inserts a new entry into a corrupted list, the `Flink->Blink = NewEntry` assignment writes the new entry's address to whatever address the corrupted `Flink` points to. If the attacker can influence the corrupted pointer value (through heap grooming or prior operations), this becomes a [write-what-where](../primitives/arw/write-what-where.md) primitive.

### IRP cancellation races

IRP cancellation is the classic kernel race condition. When `IoCancelIrp` is called on an IRP that is simultaneously being completed by the target driver, both the cancel routine and the completion path attempt to finalize the same IRP. If the driver does not use the cancel-safe queue APIs (`IoCsqInsertIrp`/`IoCsqRemoveIrp`) or equivalent manual synchronization, the IRP may be completed twice (double-free) or accessed after the cancel routine has freed it (use-after-free).

The WDM cancel-safe queue APIs were specifically designed to eliminate this class of race by serializing cancellation and completion through a single lock. Many older drivers predate these APIs and use manual cancellation logic that remains vulnerable. KMDF handles IRP cancellation internally, which is one reason KMDF drivers have far fewer race condition CVEs than WDM drivers.

### PnP removal during active I/O

When a device is removed (via `IRP_MN_REMOVE_DEVICE`), all resources associated with the device must be freed. If active I/O is in progress on another thread, the removal handler and the I/O handler race over the device's resources. The `IoAcquireRemoveLock`/`IoReleaseRemoveLock` API exists precisely for this scenario: the I/O path acquires the remove lock, the removal handler waits for all outstanding locks to be released, and only then proceeds with resource cleanup.

Drivers that skip remove lock acquisition have a latent race between removal and I/O that can be triggered by physically removing a USB device while I/O is in progress, or by programmatically disabling a device through Device Manager.

### Timer and DPC callback races

When a driver cancels a timer or deregisters a DPC callback and then frees the associated context, there is a window where the callback may already be queued for execution on another processor. `KeCancelTimer` returns whether the timer was actually cancelled, but even when it returns TRUE, a DPC may already be running. The driver must use `KeFlushQueuedDpcs` or an event synchronization pattern to ensure the callback is not executing before freeing its context.

## Exploitation: widening the window

Race conditions require two things to exploit: a race window (the period during which the vulnerable interleaving can occur) and a way to hit that window reliably. Attackers have several techniques for both.

**CPU affinity pinning** via `SetThreadAffinityMask` constrains the racing threads to specific logical processors. Placing them on two hyperthreads sharing a physical core provides the tightest possible scheduling interleaving, because cache-to-cache transfer between logical processors on the same core is nearly instantaneous.

**Thread priority manipulation** ensures the racing thread gets scheduled at the critical moment. Elevating one thread to time-critical priority while the other runs at normal priority creates predictable scheduling patterns.

**NtSuspendThread/NtResumeThread** provides precise control over when a thread proceeds past a specific point. The attacker suspends the target thread, sets up the race condition, then resumes it at the exact moment needed.

**Blocking operations** within the race window help enormously. If one side of the race involves a blocking I/O operation, file system access, or registry query, the window may span milliseconds rather than nanoseconds. Some races between PnP removal and active I/O have windows of hundreds of microseconds if the I/O handler performs blocking operations.

Some races can be won on the first attempt with these techniques. Others require thousands of attempts and statistical analysis to determine optimal timing parameters. CVE-2024-38106 in `ntoskrnl.exe` was a race in `VslpEnterIumSecureMode` that required careful thread scheduling but was reliably exploitable in the wild.

## Typical primitives gained

- [Pool Spray / Feng Shui](../primitives/exploitation/pool-spray-feng-shui.md), used to exploit the UAF that results from reference count races
- [Write-What-Where](../primitives/arw/write-what-where.md), from list corruption or state corruption races that redirect a kernel write operation
- [Pool Overflow](../primitives/arw/pool-overflow.md), when a race on a size or bounds variable leads to an unchecked memory copy
- Privilege escalation via state machine race that bypasses authorization checks

## Mitigations

Concurrency bugs are fixed by adding synchronization, and the Windows kernel provides a comprehensive toolkit for this.

**Spinlocks** (`KeAcquireSpinLock`/`KeReleaseSpinLock`) protect shared state accessed at DISPATCH_LEVEL or from DPC/ISR contexts. They are the most common synchronization primitive in kernel drivers and the most commonly missing one in race condition CVEs.

**ERESOURCE locks** (`ExAcquireResourceExclusiveLite`/`ExAcquireResourceSharedLite`) provide reader/writer synchronization for complex data structures where multiple readers should proceed concurrently but writers need exclusive access.

**Cancel-safe IRP queues** (`IoCsqInsertIrp`/`IoCsqRemoveIrp`) handle IRP cancellation synchronization internally, eliminating the entire class of IRP cancellation races.

**Remove locks** (`IoAcquireRemoveLock`/`IoReleaseRemoveLock`) prevent PnP removal from proceeding while I/O operations are in flight, ensuring that device resources are not freed while another thread is using them.

**Interlocked operations** (`InterlockedIncrement`, `InterlockedDecrement`, `InterlockedCompareExchange`) provide atomic updates to shared counters and flags without requiring a lock. They are the correct tool for reference counts and simple state flags.

**KMDF synchronization** provides automatic serialization at device or queue level, ensuring that callbacks are not invoked concurrently unless the driver explicitly opts into concurrent dispatch. This eliminates many race conditions by construction.

## Detection strategies

**Patch diffing** for race condition fixes looks for added lock acquisitions (`KeAcquireSpinLock`, `ExAcquireFastMutex`, `KeWaitForMutexObject`), interlocked operations replacing non-atomic read-modify-write sequences, or `IoAcquireRemoveLock` additions. These patterns are highly visible in binary diffs because they introduce new function calls around previously unprotected code sections. AutoPiff detects all of these patterns.

**Static analysis** through SAL annotations (`_Requires_lock_held_`, `_Guarded_by_`) can identify unprotected accesses to shared state when annotations are present. For unannotated code, flag all global variable accesses in multi-threaded code paths that lack corresponding lock acquisitions.

**Dynamic analysis** through Driver Verifier's Concurrency Stress and Deadlock Detection options is the most effective runtime approach. Running I/O stress tests with multiple threads, PnP removal stress, and IRP cancellation stress surfaces races that do not manifest under normal sequential testing. The Concurrency Stress option randomizes scheduling to expose timing-dependent bugs.

**Code review** should focus on the intersection of teardown/cleanup paths and active I/O paths. Every resource freed in a teardown path must be protected from concurrent access. Verify that every timer cancellation is followed by `KeFlushQueuedDpcs` or equivalent synchronization before freeing the timer context.

**Kernel debugging** with the `!deadlock` extension identifies lock ordering issues, and the Concurrency Visualizer shows thread interleavings that can help diagnose suspected race conditions in crash dumps.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-30088](../case-studies/CVE-2024-30088.md) | `ntoskrnl.exe` | TOCTOU race in security attribute copy allowing token manipulation |
| [CVE-2024-38106](../case-studies/CVE-2024-38106.md) | `ntoskrnl.exe` | Missing lock around VslpEnterIumSecureMode allowing concurrent privilege escalation |
| [CVE-2024-38193](../case-studies/CVE-2024-38193.md) | `afd.sys` | UAF race on Registered I/O buffer deregistration during active use |
| [CVE-2024-30089](../case-studies/CVE-2024-30089.md) | `mskssrv.sys` | Race condition in streaming service request reference counting |
| [CVE-2023-21768](../case-studies/CVE-2023-21768.md) | `afd.sys` | Concurrency race in AFD leading to use-after-free and privilege escalation |

## AutoPiff Detection

- `spinlock_acquisition_added` detects patches adding spinlock acquire/release pairs around previously unprotected shared state accesses
- `mutex_or_resource_lock_added` detects addition of fast mutex, ERESOURCE, or pushlock synchronization to protect multi-step operations on shared data
- `cancel_safe_irp_queue_added` detects conversion of IRP queuing to use `IoCsqInsertIrp`/cancel-safe queue pattern, eliminating IRP cancellation races
- `io_remove_lock_added` detects addition of `IoAcquireRemoveLock`/`IoReleaseRemoveLock` to protect against PnP removal races during active I/O
- `added_interlocked_operation` detects replacement of non-atomic read-modify-write sequences with `InterlockedIncrement`, `InterlockedDecrement`, or `InterlockedCompareExchange`
- `added_lock_acquisition` detects general lock acquisition additions for shared state protection

Race conditions are the most "meta" vulnerability class: they do not produce a specific type of corruption, but rather they *enable* corruption that would be impossible in single-threaded execution. Every [use-after-free](use-after-free.md) that involves concurrent free-and-use, every [TOCTOU](toctou-double-fetch.md) that involves concurrent check-and-modify, and every [buffer overflow](buffer-overflow.md) caused by a concurrently-modified size field is, at its root, a race condition. The distinction matters for detection (you look for missing locks, not missing bounds checks) and for fixing (you add synchronization, not validation).
