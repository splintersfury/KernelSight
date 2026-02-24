# Use-After-Free

Accessing kernel memory after it has been freed, leading to operations on a stale or reallocated object that an attacker can control.

## Description

Use-after-free (UAF) vulnerabilities occur when a driver continues to reference memory through a pointer after that memory has been freed back to the pool allocator. In the time between the free and the stale access, the memory may be reallocated for a completely different purpose. If an attacker can control what data fills the reallocated memory, they effectively control the fields that the stale pointer's code path will interpret -- including function pointers, data pointers, and size fields.

UAF bugs in the Windows kernel are reliably exploitable because the pool allocator's behavior is sufficiently deterministic. The allocator groups allocations by size class, so freeing an object of size N and immediately allocating a controlled buffer of the same size N has a high probability of reclaiming the exact same memory. This makes kernel UAF exploitation more reliable than user-mode heap exploits where allocator randomization and metadata integrity checks are more aggressive.

The root causes of UAF bugs fall into several categories: reference counting errors (extra decrement or missing increment), object lifetime mismanagement in asynchronous operations (timer callbacks, DPCs, work items, IRP completion routines), and concurrency races where one thread frees an object while another thread is still using it. Multi-threaded kernel code is particularly susceptible because objects may be shared across processors, and the window between a reference check and actual use can be exploited by a racing thread.

`afd.sys` (Ancillary Function Driver for WinSock) and the `win32k` subsystem are the most common sources of UAF vulnerabilities in Windows. `afd.sys` manages complex asynchronous I/O state for network sockets, and `win32k` manages deeply nested USER/GDI object hierarchies with callback reentrancy. Both have extensive multi-threaded codepaths where object lifetime management is difficult, producing recurring reference count and synchronization bugs.

## Common Patterns in Drivers

- Reference count decremented to zero prematurely due to an extra `ObDereferenceObject` on an error path, while another component still holds a raw pointer without its own reference
- Asynchronous callback (timer DPC, work item, IRP completion routine) fires after the object it references has been freed by the main code path
- IRP completion routine accesses the IRP's context or associated buffer after the IRP has been completed and freed by another layer
- Cancel routine and normal completion routine both attempt to finalize the same IRP or associated object, with the second access hitting freed memory
- Lookaside list entry freed and reclaimed, but a stale pointer from a previous lookup is still in use
- Object removed from a linked list and freed, but an iterator still holds a pointer to the removed node
- Missing synchronization between a "teardown" path that frees resources and an "I/O" path that accesses them concurrently
- Pointer not set to NULL after free, allowing subsequent code paths to use the dangling pointer without detecting the free
- Registry callback or process/thread notification routines that access driver context freed during driver unload
- Double-free variant: the same allocation is freed twice, and between the two frees, the allocator reuses the memory for a new allocation that gets corrupted by the second free

## Exploitation Implications

UAF exploitation follows a three-step pattern: trigger the free of the target object, reclaim the freed memory by spraying allocations of the same size with controlled content (pipe attributes, named pipe queue entries, extended attributes, or other user-controllable kernel allocations), then trigger the stale pointer dereference so the driver interprets the sprayed data as the original object's fields.

The most useful case is when the original object contains function pointers or vtable pointers. Placing a fake vtable pointer in the sprayed data redirects a virtual function call to arbitrary code. With kCFI on modern Windows, vtable hijacking is harder, but data-only attacks remain viable -- corrupting a pointer to redirect a subsequent read/write to an attacker-chosen address.

The pool allocator's size-class bucketing makes reclamation predictable, so UAF exploitation reliability is generally high. The main challenge is timing: the spray must complete between the free and the stale use. For race-based UAFs this window may be narrow, but for reference count bugs where the free is deterministic, the spray can be performed before triggering the stale access.

## Typical Primitives Gained

- [Pool Spray / Feng Shui](../primitives/exploitation/pool-spray-feng-shui.md) -- controlling the content of the reallocated memory to dictate what the stale pointer dereference encounters
- [Write-What-Where](../primitives/arw/write-what-where.md) -- if the stale object use involves a write through a pointer field that is now attacker-controlled
- [Token Manipulation](../primitives/arw/token-manipulation.md) -- if the UAF object contains or references token structures that can be replaced with attacker-controlled values
- Code execution via fake vtable or function pointer in the sprayed replacement object

## Mitigations

- **Reference counting discipline** -- Every pointer to a shared object must hold its own reference, acquired via `ObReferenceObject` and released via `ObDereferenceObject`. Raw pointers without references are a primary source of UAF.
- **NULL-after-free pattern** -- Setting a pointer to NULL immediately after freeing ensures any subsequent access causes an immediate NULL dereference (crash) rather than silent use of reallocated memory
- **Pool type isolation** -- Using dedicated lookaside lists or separate pool tags for security-critical objects makes it harder for attackers to reclaim freed memory with controlled data of the matching size
- **KMDF object model** -- The WDF framework's parent-child object hierarchy with automatic reference counting eliminates many manual lifetime management bugs
- **KPool (Kernel Pool hardening)** -- Windows 11 pool hardening features include delayed free lists and pool quarantine that make UAF exploitation less reliable

## Detection Strategies

- **Patch diffing**: Look for added reference count operations (`ObReferenceObject`, `InterlockedIncrement` on ref count), added NULL-after-free patterns, or added synchronization around free/use paths. AutoPiff detects these as `ob_reference_balance_fix` and `null_after_free_added`.
- **Static analysis**: Track object lifetimes through allocation, reference counting, and free operations. Flag any code path where an object is accessed after a potential free without re-validation.
- **Driver Verifier**: Enable Special Pool with pool tracking to detect accesses to freed pool memory. Also enable Deadlock Detection to find synchronization issues that may lead to UAF.
- **Concurrency testing**: Stress test concurrent code paths (e.g., simultaneous IOCTL calls, device removal during I/O, IRP cancellation during completion) to expose lifetime races.
- **Code review**: Focus on error paths -- ensure every error path that calls a cleanup/free function also invalidates all pointers to the freed objects. Check that async callbacks hold their own references to objects they access.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-38193](../case-studies/CVE-2024-38193.md) | `afd.sys` | UAF race on Registered I/O buffers during concurrent deregistration |
| [CVE-2024-30089](../case-studies/CVE-2024-30089.md) | `mskssrv.sys` | Reference count logic error causes premature free while object still in use |
| [CVE-2023-29336](../case-studies/CVE-2023-29336.md) | `win32kfull.sys` | UAF from unlocked nested menu object during callback |
| [CVE-2023-21768](../case-studies/CVE-2023-21768.md) | `afd.sys` | Use-after-free in AFD socket operations enabling privilege escalation |
| [CVE-2024-38106](../case-studies/CVE-2024-38106.md) | `ntoskrnl.exe` | Race condition causing UAF in secure mode transition |

## AutoPiff Detection

- `null_after_free_added` -- Detects patches that set a pointer to NULL immediately after freeing the memory it references, preventing subsequent stale pointer use
- `guard_before_free_added` -- Detects NULL check guards added before free operations to prevent double-free conditions
- `ob_reference_balance_fix` -- Detects addition of `ObDereferenceObject` on error paths or `ObReferenceObject` on use paths to fix reference count imbalances
- `error_path_cleanup_added` -- Detects resource cleanup logic added to error paths that previously leaked references or left dangling pointers
- `added_reference_count_fix` -- Detects fixes to reference counting logic that prevent premature object destruction
- `added_synchronization` -- Detects lock or interlocked operation additions that serialize access to objects with concurrent free/use paths
