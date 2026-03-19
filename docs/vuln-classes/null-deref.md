# NULL Pointer Dereference

On a modern 64-bit Windows system, dereferencing a NULL pointer in the kernel does one thing: it crashes the entire machine. Not the process, not the thread, the whole system. A blue screen, a reboot, and every user on the box loses their session. This makes NULL dereference the most democratic of kernel vulnerabilities: an unprivileged user can take down a server that serves thousands, with a single IOCTL call.

On older systems, the story was different, and far worse. This page covers both eras: the historical exploitability of NULL dereference for code execution, the modern reality of denial-of-service, and the cases where the boundary between the two is less clear than it appears.

## The zero page, then and now

To understand NULL dereference exploitation, you need to understand what happens at virtual address zero.

On 32-bit Windows 7 and earlier, user-mode processes could map the zero page using `NtAllocateVirtualMemory` with a base address of zero. The call would succeed, and the process would have valid, readable, writable, executable memory at address 0x0. When the kernel then dereferenced a NULL pointer, it would not crash. Instead, it would read (or execute) whatever the attacker had placed at address zero. If the NULL pointer was a function pointer, execution transferred to user-mode code running at ring-0 privilege. If it was a data pointer, the kernel read attacker-controlled fake structures. This was a clean, reliable, often one-shot privilege escalation.

Windows 8 changed the landscape fundamentally. The zero page (virtual addresses 0x0 through 0xFFFF) is now unconditionally reserved by the kernel. No user-mode process can map it. Additionally, SMEP (Supervisor Mode Execution Prevention) on Intel processors prevents the kernel from executing code at user-mode addresses, even if they were somehow mapped. Together, these mitigations reduced NULL dereference from "reliable code execution" to "reliable system crash."

But "reliable system crash" is not nothing. In cloud and multi-tenant server environments, a denial-of-service that requires no privileges and crashes the entire host affects every VM, every container, every user on the system. Repeated triggering can prevent boot if the crash occurs in an early initialization path. Cloud providers treat kernel NULL dereference bugs as security vulnerabilities precisely because of this blast radius.

## How NULL dereferences happen

NULL dereferences are, in a sense, the simplest vulnerability class. A function returns NULL to indicate failure, and the caller does not check. But the patterns through which this simplicity manifests in real driver code are varied enough to warrant examination.

### Missing allocation failure checks

`ExAllocatePoolWithTag` returns NULL when the system cannot satisfy the allocation (low memory, pool exhaustion, or Driver Verifier fault injection). If the driver does not check for NULL and immediately dereferences the returned pointer, the system crashes. This pattern is most common in error paths that are rarely exercised: the allocation always succeeds in testing, so the NULL path is never tested.

The modern `ExAllocatePool2` API also returns NULL on failure (rather than bugchecking, as `ExAllocatePoolWithQuotaTag` does), making proper NULL checking even more important for drivers migrating to the new API.

### Missing MDL mapping checks

`MmGetSystemAddressForMdlSafe` returns NULL if it cannot map the MDL's physical pages into system virtual address space. This can happen under memory pressure or when the MDL describes pages that cannot be locked. The driver receives NULL and, if it proceeds to read or write through the result, crashes the system. The older `MmGetSystemAddressForMdl` (without "Safe") bugchecks on failure rather than returning NULL, which is arguably worse because the driver has no opportunity to handle the error.

### Missing handle lookup checks

`ObReferenceObjectByHandle` can fail for many reasons: invalid handle, wrong object type, insufficient access rights. When it fails, the output object pointer is not set to a valid value. If the driver does not check the return status and proceeds to use the output pointer, it dereferences uninitialized or NULL memory.

### Function pointers in optional structures

Kernel drivers frequently use tables of function pointers for dispatch (completion routines, callback tables, filter dispatch tables). When a table entry is optional, the pointer may be NULL if the corresponding functionality is not registered. Calling through a NULL function pointer (`object->OptionalCallback(args)`) attempts to execute code at address zero, causing an immediate bugcheck on modern systems.

CVE-2024-35250 in `ks.sys` (kernel streaming) involved a NULL pointer dereference that, despite being "just" a NULL deref, was classified as an elevation of privilege vulnerability. The NULL deref occurred in a specific kernel streaming configuration path, and the circumstances around it enabled more than simple denial of service.

### Chained dereferences

A common C pattern, `obj->parent->child->method()`, crashes if any intermediate pointer is NULL. The driver may check that `obj` is non-NULL but assume that `obj->parent` is always valid. Under error conditions or race scenarios, intermediate fields can be NULL even when the top-level object is valid.

## Beyond denial of service

While modern NULL dereference is primarily a DoS vector, several edge cases push it beyond simple crashing.

**Write-at-offset-from-NULL** patterns are the most interesting. When the kernel writes through an expression like `*(NULL + user_controlled_offset) = value`, the offset can reach mapped memory if it is large enough to escape the reserved zero page (past 0xFFFF). In practice, this requires very specific circumstances and careful control over the offset, but it transforms a NULL deref into a limited arbitrary write.

**Logic bypass** is another angle. If a NULL check guards a security-relevant code path, and the NULL dereference occurs *after* the security check but *before* the checked pointer is used, the crash itself may not be the issue. The issue is that the security check's failure path is reachable, and on that path, the driver may perform or skip operations that affect system security state before hitting the NULL deref.

CVE-2023-36802 in `mskssrv.sys` and CVE-2023-29360 in the same driver both involved NULL pointer conditions in kernel streaming code that interacted with type confusion and reference counting issues. The NULL deref was a symptom of a deeper object lifecycle flaw, not the vulnerability in isolation.

## Typical primitives gained

- **Denial of service (BSOD)**, the primary and most common impact on modern x64 Windows
- **Code execution on legacy 32-bit systems** via zero-page mapping and fake object placement (historical, pre-Windows 8)
- **Logic bypass** if the NULL check guards a security-relevant code path and the failure path has security consequences
- **Limited arbitrary write** in write-at-offset-from-NULL patterns where the offset escapes the reserved zero page

## Mitigations

The mitigation story for NULL dereference is one of the most successful in Windows kernel security.

**Zero page reservation** on Windows 8+ unconditionally reserves virtual addresses 0x0 through 0xFFFF, preventing user-mode mapping. This single mitigation eliminated the entire code execution exploitation path for NULL dereferences. It is always on, requires no configuration, and cannot be bypassed from user mode.

**SMEP (Supervisor Mode Execution Prevention)** adds defense-in-depth. Even if the zero page were somehow mapped (through a hypervisor bug, for instance), SMEP prevents kernel-mode execution of user-mode pages. The combination of zero page reservation and SMEP makes code execution through NULL dereference essentially impossible on modern hardware.

**MmGetSystemAddressForMdlSafe** is the "Safe" variant of the MDL mapping function, returning NULL on failure instead of bugchecking. This gives drivers the opportunity to handle the error gracefully, but only if they actually check the return value.

**Low Resources Simulation** in Driver Verifier systematically fails allocations, MDL mappings, and other operations that can return NULL. This exposes missing NULL checks during development by exercising the error paths that normal testing never reaches. Running a driver under Low Resources Simulation for even a few hours typically reveals multiple missing NULL checks.

**ExAllocatePool2** returns NULL on failure rather than raising an exception, making error handling more explicit. Combined with the `/sdl` compiler flag that initializes some locals to zero, the modern development environment makes NULL dereference bugs harder to introduce, though far from impossible.

## Detection strategies

**Patch diffing** for NULL dereference fixes looks for added `if (ptr == NULL) return STATUS_...` checks after function calls that can return NULL. These are among the simplest patches to identify in binary diffs: a new comparison-and-branch inserted before a dereference. AutoPiff detects these through several rules that target specific allocation and mapping functions.

**Static analysis** is the most systematic approach. Track all pointer-returning function calls and verify that every caller checks for NULL before dereference. Focus on `ExAllocatePoolWithTag`, `ExAllocatePool2`, `MmGetSystemAddressForMdlSafe`, `ObReferenceObjectByHandle`, and `IoAllocateIrp`. PREfast (Static Driver Verifier) with SAL annotations detects many of these patterns at compile time.

**Driver Verifier with Low Resources Simulation** is the most effective dynamic approach. It forces allocation failures and exposes missing NULL checks on error paths. This systematically triggers the code paths where NULL dereferences hide, paths that normal functional testing never exercises because allocations almost never fail in practice.

**Code review** should focus specifically on error handling paths. Most NULL dereferences occur because the success path is well-tested but the failure path (allocation failure, handle lookup failure, MDL mapping failure) is never exercised. Ask one question at every function call that can fail: what happens to the output pointer if this call returns an error?

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-35250](../case-studies/CVE-2024-35250.md) | `ks.sys` | NULL pointer dereference leading to EoP in specific kernel streaming configuration |
| [CVE-2023-36802](../case-studies/CVE-2023-36802.md) | `mskssrv.sys` | NULL dereference in streaming proxy handle validation path |
| [CVE-2024-30085](../case-studies/CVE-2024-30085.md) | `cldflt.sys` | Missing NULL check after allocation in error recovery path |
| [CVE-2023-29360](../case-studies/CVE-2023-29360.md) | `mskssrv.sys` | NULL function pointer call in streaming service dispatch |
| [CVE-2022-37969](../case-studies/CVE-2022-37969.md) | `clfs.sys` | NULL pointer dereference in log file container validation |

## AutoPiff Detection

- `pool_allocation_null_check_added` detects patches adding NULL validation after `ExAllocatePoolWithTag` or `ExAllocatePool2` return values before pointer dereference
- `mdl_null_check_added` detects addition of NULL check on `Irp->MdlAddress` or the return value of MDL mapping functions
- `mdl_safe_mapping_replacement` detects replacement of `MmGetSystemAddressForMdl` (which crashes on failure) with the `Safe` variant that returns NULL on mapping failure
- `added_null_check` detects general NULL pointer validation additions before dereference operations in driver code
- `null_pointer_validation_added` detects addition of NULL validation on optional object fields, function pointers, or handle lookup results

NULL dereference is often dismissed as "just a crash," but that framing misses two things. First, a kernel crash is a system-wide event, not a process-local one, and in multi-tenant environments, the blast radius is every user on the machine. Second, the NULL dereference is frequently a symptom of a deeper bug: a missing error check, a lifecycle management flaw, or a race condition that leaves an object in an invalid state. The NULL check that the patch adds is the immediate fix, but the interesting question is always: *why* was the pointer NULL in the first place? That question often leads to a more severe vulnerability hiding behind the crash.
