# TOCTOU / Double-Fetch

Time-of-check to time-of-use race condition where shared data changes between validation and use, bypassing security checks.

## Description

TOCTOU (Time-of-Check to Time-of-Use) vulnerabilities occur when a driver reads a value from user-accessible memory, validates it, and then reads the same value again for actual use. Between the two reads, a concurrent thread in the same process can modify the value, causing the driver to use a malicious value that was never validated. This is also called a "double fetch" because the same memory location is fetched twice from user space.

The canonical scenario involves a size field in a user-mode buffer. The driver first reads the size, validates that it is within acceptable bounds, and then reads the size again (or reads data using the now-stale validation) to perform a copy. A racing thread changes the size between the validation read and the use read, causing the copy to use an unchecked, attacker-controlled value. Because the kernel does not control user-mode page tables, any memory accessible to user mode can change at any time from any thread in the same process.

This vulnerability class extends beyond simple user buffers. Shared memory sections, MDL-mapped buffers backed by user virtual addresses, and memory-mapped files can all be modified by concurrent threads. Even `ProbeForRead` followed by a separate dereference constitutes a double fetch if the probed address can change between the probe and the read. The correct mitigation is to capture user data into a kernel-mode buffer (stack variable or pool allocation) in a single read, then validate and use only the captured copy.

METHOD_BUFFERED IOCTLs are partially protected from double-fetch because the I/O manager copies the input buffer into a kernel allocation before dispatching. However, METHOD_NEITHER and METHOD_IN_DIRECT / METHOD_OUT_DIRECT IOCTLs pass user-mode pointers directly to the driver, making them prime targets for TOCTOU attacks. Additionally, even with METHOD_BUFFERED, if the driver accesses the original user buffer (via `Irp->UserBuffer`) instead of the system buffer (`Irp->AssociatedIrp.SystemBuffer`), it reintroduces the double-fetch risk.

## Common Patterns in Drivers

- Two separate dereferences of the same user-mode pointer: one for validation, one for use (e.g., `if (*userSize <= MAX) { copy(*userSize, ...) }` where `*userSize` is read twice)
- `ProbeForRead(userPtr, ...)` followed by a separate dereference of `userPtr` -- the probe validates accessibility but the value can change before the dereference
- IOCTL handler that validates fields in the user input buffer, then later re-reads those fields for processing instead of using captured local copies
- Shared memory sections (via `ZwCreateSection` / `ZwMapViewOfSection`) read multiple times without capturing to kernel memory
- MDL-mapped user buffers that remain writable from user mode while the driver reads them multiple times
- Validating a handle or pointer value from user memory, then re-reading it for the actual object lookup
- Structure size fields checked on first access but re-read from user memory when computing offsets for nested field access
- File system filter drivers that read file metadata from user-mode mapped pages multiple times during a single IRP processing path
- Callback functions that re-read parameters from user-mode memory instead of using the local copies passed as function arguments

## Exploitation Implications

Exploiting TOCTOU requires racing two threads: one thread invokes the syscall or IOCTL, while a second thread rapidly flips the validated field between a safe value and a malicious value. The race window is typically small (a few instructions between the check and the use), so exploitation requires many attempts. However, modern multi-core systems make this reliable enough for practical exploitation -- success rates of 10-50% per attempt are common, and the attack can be retried indefinitely from user mode.

Attackers use several techniques to widen the race window and improve reliability. Pinning the racing threads to the same CPU core (via `SetThreadAffinityMask`) ensures tight scheduling interleaving. Using `NtSuspendThread` and `NtResumeThread` can precisely stall the victim thread between the check and the use. Some attackers use page-fault-based stalling: placing the user buffer at a page boundary where the second access causes a soft page fault, widening the window to microseconds.

The resulting primitive depends on which field is being raced. Racing a size field leads to buffer overflow. Racing a pointer field leads to arbitrary read/write or type confusion. Racing an index field leads to out-of-bounds access. The TOCTOU itself is just the bypass mechanism; the actual exploitation follows the pattern of whatever vulnerability the bypassed check was protecting against.

## Typical Primitives Gained

- [Pool Overflow](../primitives/arw/pool-overflow.md) -- when the raced field is a size used for memory copy, producing a buffer overflow
- [Write-What-Where](../primitives/arw/write-what-where.md) -- when the raced field is an address or offset used in a write operation
- [Direct IOCTL R/W](../primitives/arw/direct-ioctl-rw.md) -- when TOCTOU bypasses validation on an IOCTL that performs kernel memory operations
- Arbitrary read via raced pointer field used as source for copy-to-user operation

## Mitigations

- **Capture-before-use pattern** -- The primary defense: copy user data into a kernel-mode buffer (local variable or pool allocation) in a single operation, then validate and use only the kernel copy
- **METHOD_BUFFERED IOCTLs** -- Using METHOD_BUFFERED causes the I/O manager to copy input data to a kernel buffer before dispatch, eliminating the double-fetch risk for IOCTL input (but not for mapped sections or direct memory references)
- **ProbeAndCapture helpers** -- Custom helper functions that combine probing and capturing into a single atomic operation, ensuring the validated value is the same one used
- **Volatile pointer marking** -- Marking user-mode pointers as `volatile` does not fix the vulnerability, but it prevents the compiler from caching the value and forces an explicit re-read, making the double-fetch visible in source review
- **Secure buffer APIs** -- Using `WdfRequestRetrieveInputBuffer` in KMDF drivers handles safe buffer capture automatically

## Detection Strategies

- **Patch diffing**: Look for user buffer accesses converted from direct dereference to capture-to-local-variable patterns. AutoPiff detects these as `double_fetch_to_capture_fix`.
- **Static analysis**: Identify all user-mode pointer dereferences in a function and flag any pointer that is dereferenced more than once. Each additional dereference of the same user pointer is a potential double fetch.
- **Binary-level detection**: Tools like DEADLINE and Dr. Checker can identify double-fetch patterns in compiled drivers by tracking memory access patterns to user-mapped addresses.
- **Code review**: Search for functions that access `Irp->UserBuffer`, `IrpSp->Parameters`, or METHOD_NEITHER buffer pointers more than once. Each access should be checked for capture-before-use.
- **Concurrency fuzzing**: Run IOCTL calls while concurrently modifying the input buffer from a second thread. Monitor for crashes or unexpected behavior that indicates the driver read the buffer multiple times.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-30088](../case-studies/CVE-2024-30088.md) | `ntoskrnl.exe` | TOCTOU in AuthzBasepCopyoutInternalSecurityAttributes allows security descriptor manipulation |
| [CVE-2024-30089](../case-studies/CVE-2024-30089.md) | `mskssrv.sys` | Double fetch race in streaming service request handling |
| [CVE-2024-38106](../case-studies/CVE-2024-38106.md) | `ntoskrnl.exe` | Race condition in VslpEnterIumSecureMode allowing privilege escalation |
| [CVE-2023-32019](../case-studies/CVE-2023-32019.md) | `ntoskrnl.exe` | TOCTOU in thread information query leaking kernel memory |
| [CVE-2023-36802](../case-studies/CVE-2023-36802.md) | `mskssrv.sys` | Double fetch enabling type confusion in streaming proxy |

## AutoPiff Detection

- `double_fetch_to_capture_fix` -- Detects patches that replace double reads from user memory with a single capture to a local kernel variable followed by validation and use of the local copy
- `flt_create_race_mitigation` -- Detects TOCTOU fixes in IRP_MJ_CREATE handlers where filter drivers capture user buffer contents before validation
- `added_capture_before_use` -- Detects introduction of local variable capture patterns for user-mode data that was previously read in-place multiple times
- `user_buffer_copied_to_kernel` -- Detects changes that copy user buffer data into a kernel-mode allocation before processing, eliminating concurrent modification
- `double_fetch_eliminated` -- Detects general elimination of double-fetch patterns where a second user-mode memory access was replaced with use of a previously captured value
- `method_buffered_ioctl_change` -- Detects IOCTL method changes from METHOD_NEITHER to METHOD_BUFFERED, which eliminates direct user buffer access and the associated TOCTOU risk
