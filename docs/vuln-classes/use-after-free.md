# Use-After-Free

If you could pick only one vulnerability class to master for Windows kernel exploitation, use-after-free would be the rational choice. Not because UAF bugs are the most common (integer overflows and missing size checks probably outnumber them), but because they are the most *reliably exploitable*. A pool overflow gives you a write that corrupts whatever happens to be adjacent. A UAF gives you something far more powerful: the ability to replace an entire object with content you control, then let the kernel interpret your data as if it were the original structure. Function pointers, vtable references, size fields, linked list entries: all become attacker-controlled the moment the stale pointer is dereferenced.

This page covers how UAF bugs arise in Windows kernel drivers, why they are so dangerous in practice, and how to detect them through patch diffing and static analysis.

## Why UAF dominates the exploit landscape

The Windows pool allocator is the reason UAF exploitation works so well. When the kernel frees an object of, say, 0x200 bytes, that memory returns to the 0x200-byte bucket. The next allocation of the same size from the same pool type has a high probability of landing in exactly the same address. Compare this to user-mode heap exploitation, where allocator randomization, guard pages, and metadata integrity checks make reclamation far less predictable. In kernel pool land, the allocator's size-class bucketing is essentially a feature that attackers exploit: free the target, spray the bucket, and the stale pointer now points at your data.

The consequence is that kernel UAF exploitation often approaches deterministic reliability. For reference-counting bugs where the free is triggered by a specific syscall sequence (not a race), the attacker can free the object, spray thousands of controlled allocations into the same bucket, and then trigger the stale access at leisure. The spray has already won before the dangling pointer is ever dereferenced.

## How UAF bugs happen in drivers

UAF vulnerabilities in kernel drivers are rarely about a simple "forgot to NULL the pointer" mistake (though that happens too). They emerge from the fundamental difficulty of managing object lifetimes in concurrent, asynchronous kernel code. The root causes cluster into a few recurring patterns, and understanding them means understanding where to look during code review and patch analysis.

### Reference counting errors

The most classic pattern. Every shared kernel object is supposed to be reference-counted: each component holding a pointer calls `ObReferenceObject` to increment the count and `ObDereferenceObject` to release it. The object is freed when the count hits zero. The bug occurs when one code path decrements the count without actually being done with the object, or when another path skips the increment entirely and operates on a raw pointer.

Consider `afd.sys`, the Ancillary Function Driver for WinSock and one of the most frequently patched drivers in Windows. Its Registered I/O (RIO) implementation manages buffers that can be concurrently accessed by the completion path and the deregistration path. CVE-2024-38193 is the textbook case: a race between buffer deregistration and ongoing I/O caused the reference count to drop to zero while another thread still held a pointer. The fix was straightforward (an additional `ObReferenceObject` on the I/O path), but the bug had been shipping for years.

Error paths are where reference count bugs hide. The happy path through a function is usually correct because it gets the most testing. But when an intermediate operation fails and the function bails out, does the cleanup code release only the references it acquired, or does it release one too many? CVE-2024-30089 in `mskssrv.sys` (Microsoft Kernel Streaming Server) demonstrates exactly this: a logic error in reference count management caused premature object destruction while the object was still in active use.

### Asynchronous callbacks outliving their context

Kernel drivers are inherently asynchronous. Timer DPCs fire at DISPATCH_LEVEL. Work items execute on system worker threads. IRP completion routines run when I/O finishes, potentially long after the initiating code has moved on. Every one of these asynchronous mechanisms references some context, and if that context is freed before the callback fires, the callback dereferences freed memory.

The pattern is insidious because the timing dependency may not manifest during normal testing. The timer DPC fires 50 milliseconds later, and in testing, the object is always still alive at that point. But under memory pressure, or on a system with different core counts, or when an attacker deliberately induces the right timing, the object is freed first.

IRP completion routines deserve special attention. When a driver passes an IRP down the stack with a completion routine, the completion routine will eventually execute regardless of whether the originating driver still cares about the result. If the driver's cancel routine or teardown path frees the IRP context while the IRP is still pending in a lower driver, the completion routine will access freed memory. The cancel routine and the completion routine are effectively racing, and both believe they own the cleanup responsibility.

### The win32k reentrancy problem

The `win32k` subsystem (now split across `win32kbase.sys` and `win32kfull.sys`) has been the single largest source of UAF vulnerabilities in Windows for over a decade. The reason is architectural: win32k's USER object model allows user-mode callbacks during kernel operations. When the kernel is manipulating a menu object hierarchy, for example, it may call back to user mode to execute a hook procedure. During that callback, user-mode code can destroy the very objects the kernel was in the middle of processing.

CVE-2023-29336 illustrates this perfectly. A nested menu object was left unlocked during a user-mode callback. The callback destroyed the object, and when execution returned to the kernel, the code continued operating on freed memory. Microsoft has spent years adding callback validation and object locking to win32k, but the attack surface is enormous because the callback mechanism is fundamental to the windowing system's design.

### Linked list and iterator races

A subtler variant occurs when an object is removed from a linked list and freed while an iterator on another thread still holds a pointer to it. The iterator obtained a valid pointer by walking the list, but by the time it dereferences that pointer, the object has been unlinked and freed by a concurrent operation. This pattern is common in drivers that maintain queues of pending requests, connection lists, or resource tracking structures.

The related pattern is the lookaside list race: an entry is returned to a lookaside list (conceptually "freed"), immediately reclaimed by another allocation, and then accessed through a stale pointer from the original lookup. Because lookaside lists are designed for high-performance recycling, the window between return and reclaim can be extremely small, making these bugs hard to reproduce but trivially exploitable once understood.

### Missing teardown synchronization

When a driver is unloading, or a device is being removed, all outstanding references to driver-owned objects must be resolved before the memory is freed. Registry callbacks, process/thread notification routines, and filter manager contexts all hold implicit references to driver state. If the unload routine frees these structures without first unregistering the callbacks that reference them, the next callback invocation accesses freed memory.

## From free to SYSTEM

Understanding how UAF bugs are exploited transforms them from abstract memory safety issues into concrete privilege escalation chains. The exploitation follows a three-act structure: trigger the free, reclaim the memory, and exploit the stale access.

``` mermaid
graph LR
    A["1. Trigger Free\n(refcount bug,\nrace condition)"] --> B["2. Spray Pool\n(pipe attrs, WNF,\nEA buffers)"]
    B --> C["3. Stale Deref\n(kernel reads\nattacker data)"]
    C --> D["4. Primitive\n(W-W-W, token\ncorruption)"]
    D --> E["5. SYSTEM"]
    style A fill:#1e293b,stroke:#ef4444,color:#e2e8f0
    style B fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    style C fill:#1e293b,stroke:#f59e0b,color:#e2e8f0
    style D fill:#1e293b,stroke:#8b5cf6,color:#e2e8f0
    style E fill:#1e293b,stroke:#10b981,color:#e2e8f0
```

**Act 1: Trigger the free.** The attacker exercises the code path that causes the object to be freed prematurely. For reference count bugs, this might be calling a specific sequence of syscalls that hits the error path with the extra decrement. For race conditions, it means running two threads in a tight loop: one performing the operation, the other triggering the concurrent free. The goal is to leave a dangling pointer somewhere in the kernel that will be dereferenced later.

**Act 2: Reclaim the memory.** This is where [pool spray](../primitives/exploitation/pool-spray-feng-shui.md) enters the picture. The attacker floods the pool bucket matching the freed object's size with controlled allocations. Named pipe queue entries, pipe attributes, WNF state data, EA buffers: any kernel allocation of the right size whose content is user-controlled will work. Because the pool allocator recycles memory within size classes, one of these spray objects will land at the exact address of the freed object.

The spray content is crafted to look like a legitimate instance of the freed object, but with key fields replaced. If the original object had a function pointer at offset 0x18, the spray places the address of an attacker-controlled code gadget (or, post-kCFI, a data pointer that redirects a subsequent read or write) at that offset.

**Act 3: Trigger the stale access.** The attacker causes the kernel to dereference the dangling pointer. The kernel reads the spray data as if it were the original object. A virtual call through a fake vtable pointer redirects execution. A write through an attacker-controlled data pointer becomes a write-what-where primitive. A size field inflated beyond the original object's bounds turns a bounded copy into an out-of-bounds read or write.

On modern Windows with kCFI (kernel Control Flow Integrity), direct vtable hijacking to arbitrary code is increasingly difficult. But data-only attacks remain fully viable. Corrupting a token pointer to point at an attacker-controlled fake token, or modifying a size field to enable an out-of-bounds copy, achieves privilege escalation without ever diverting control flow.

## Typical primitives gained

A successful UAF reclaim can yield several exploitation primitives depending on the original object's structure and how the stale pointer is used:

- [Pool Spray / Feng Shui](../primitives/exploitation/pool-spray-feng-shui.md) for controlling the content of the reallocated memory to dictate what the stale pointer dereference encounters
- [Write-What-Where](../primitives/arw/write-what-where.md) when the stale object use involves a write through a pointer field that is now attacker-controlled
- [Token Manipulation](../primitives/arw/token-manipulation.md) when the UAF object contains or references token structures that can be replaced with attacker-controlled values
- Code execution via fake vtable or function pointer in the sprayed replacement object (pre-kCFI or through gadget chaining)

## Mitigations

Preventing UAF bugs requires discipline at the code level and hardening at the allocator level. Neither alone is sufficient.

**Reference counting discipline** is the first line of defense. Every pointer to a shared object must hold its own reference, acquired via `ObReferenceObject` and released via `ObDereferenceObject`. Raw pointers without references are the primary source of UAF bugs. This sounds obvious, but in practice, performance pressure leads developers to skip the increment "because the caller already holds a reference." That assumption breaks when the caller's lifetime changes in a future refactor.

**NULL-after-free** is simple but effective. Setting a pointer to NULL immediately after freeing ensures any subsequent access causes an immediate NULL dereference (a crash, not silent corruption). The crash is recoverable and debuggable; silent use of reallocated memory is neither.

**Pool type isolation** using dedicated lookaside lists or separate pool tags for security-critical objects makes it harder for attackers to reclaim freed memory with controlled data of a matching size. If the freed object came from a private lookaside list that only the driver uses, generic spray objects from pipes or WNF will not land in the same memory.

**The KMDF object model** deserves mention because it solves many of these problems architecturally. WDF's parent-child object hierarchy with automatic reference counting eliminates the manual lifetime management that produces so many WDM UAF bugs. Drivers built on KMDF still have bugs, but they are far less likely to be UAF.

**KPool hardening** on Windows 11 introduces delayed free lists and pool quarantine that make UAF exploitation less reliable by holding freed memory out of circulation for a randomized period. This does not prevent the bug, but it shrinks the attacker's reclamation window.

## Detection strategies

**Patch diffing** is the highest-signal approach for finding UAF fixes. Look for added reference count operations (`ObReferenceObject`, `InterlockedIncrement` on ref count fields), added NULL-after-free patterns, or added synchronization around free/use paths. AutoPiff detects these automatically (see the detection rules below), making it possible to scan hundreds of patched binaries for UAF fixes without manual review.

**Static analysis** tracks object lifetimes through allocation, reference counting, and free operations. The goal is to flag any code path where an object is accessed after a potential free without re-validation. Tools like SDV (Static Driver Verifier) and custom Sema queries can model reference count flow, but false positive rates remain high in complex drivers.

**Driver Verifier with Special Pool** is the most direct dynamic detection. Special Pool places each allocation on its own page with a guard page immediately after (or before), so any access to freed memory causes an immediate bugcheck rather than silent corruption. Pool tracking mode additionally records allocation and free call stacks, making it possible to identify the free site when a stale access is caught.

**Concurrency stress testing** targets the race-condition variant. Stress testing concurrent code paths (simultaneous IOCTL calls, device removal during I/O, IRP cancellation during completion) with multiple threads and varying CPU affinities exposes lifetime races that do not manifest under normal sequential testing.

**Code review** should focus on error paths. Ensure every error path that calls a cleanup or free function also invalidates all pointers to the freed objects. Verify that async callbacks (timers, DPCs, work items, completion routines) hold their own references to every object they access. If a callback's only reference is "the caller was holding one when the callback was registered," the code has a latent UAF.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-38193](../case-studies/CVE-2024-38193.md) | `afd.sys` | UAF race on Registered I/O buffers during concurrent deregistration |
| [CVE-2024-30089](../case-studies/CVE-2024-30089.md) | `mskssrv.sys` | Reference count logic error causes premature free while object still in use |
| [CVE-2023-29336](../case-studies/CVE-2023-29336.md) | `win32kfull.sys` | UAF from unlocked nested menu object during callback |
| [CVE-2023-21768](../case-studies/CVE-2023-21768.md) | `afd.sys` | Use-after-free in AFD socket operations enabling privilege escalation |
| [CVE-2024-38106](../case-studies/CVE-2024-38106.md) | `ntoskrnl.exe` | Race condition causing UAF in secure mode transition |

## AutoPiff Detection

AutoPiff identifies UAF-related patches through several complementary rules, each targeting a different fix pattern:

- `null_after_free_added` detects patches that set a pointer to NULL immediately after freeing the memory it references, preventing subsequent stale pointer use
- `guard_before_free_added` detects NULL check guards added before free operations to prevent double-free conditions
- `ob_reference_balance_fix` detects addition of `ObDereferenceObject` on error paths or `ObReferenceObject` on use paths to fix reference count imbalances
- `error_path_cleanup_added` detects resource cleanup logic added to error paths that previously leaked references or left dangling pointers
- `added_reference_count_fix` detects fixes to reference counting logic that prevent premature object destruction
- `added_synchronization` detects lock or interlocked operation additions that serialize access to objects with concurrent free/use paths

Understanding UAF is necessary but not sufficient for exploitation. The next question is always: how do you control what fills the freed memory? That question leads directly to [pool spray and heap feng shui](../primitives/exploitation/pool-spray-feng-shui.md), the technique that transforms a dangling pointer from a crash into a controlled primitive.
