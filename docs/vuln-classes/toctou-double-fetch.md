# TOCTOU / Double-Fetch

The driver reads a size field from user memory, confirms it is within bounds, and proceeds to copy that many bytes into a kernel buffer. Between the validation read and the copy, a second thread in the same process overwrites the size field with `0xFFFFFFFF`. The copy uses the new value. The check passed; the use did not honor it. This is the essence of TOCTOU: the kernel validates a value it does not own, and the owner changes it before the kernel acts on the validation.

This page covers how time-of-check-to-time-of-use vulnerabilities arise in Windows kernel drivers, why multi-core processors make them reliably exploitable, and how to detect them through patch analysis and static review.

## The fundamental problem: the kernel does not own user memory

Every other vulnerability class on this site involves a flaw in how the kernel handles its *own* data. Buffer overflows corrupt kernel buffers. Use-after-free bugs mismanage kernel object lifetimes. Integer overflows miscalculate kernel allocation sizes. TOCTOU is different. The flaw is that the kernel reads from memory it does not control, and reads it more than once.

User-mode memory is shared among all threads in a process. Any thread can write to any page at any time. The kernel cannot prevent this, because user-mode page tables are managed by the process, not by the driver. When a driver reads a value from a user-mode buffer, validates it, and then reads the same location again, the second read might return a completely different value. The validation was meaningful only for the first read. The second read operates without validation.

This seems like it should be rare. Why would a driver read the same user-mode location twice? In practice, it happens constantly. The compiler may re-read a value from memory instead of keeping it in a register, especially at higher optimization levels or across function calls. The driver may validate an input structure's fields in one function and then pass the user-mode pointer to another function that re-reads those fields. A `ProbeForRead` call validates that an address range is accessible, but the subsequent dereference is a separate read that can see modified data.

METHOD_BUFFERED IOCTLs provide partial protection because the I/O manager copies the input buffer into a kernel allocation before dispatching to the driver. However, METHOD_NEITHER and METHOD_IN_DIRECT/METHOD_OUT_DIRECT IOCTLs pass user-mode pointers directly, making them prime targets. Even with METHOD_BUFFERED, if the driver accesses the original user buffer via `Irp->UserBuffer` instead of the system buffer at `Irp->AssociatedIrp.SystemBuffer`, the double-fetch risk returns.

## Patterns that create double fetches

### Two dereferences of the same pointer

The most direct pattern. The driver reads `*userSize` to validate it, then reads `*userSize` again to use it:

```c
if (*userSize <= MAX_SIZE) {
    RtlCopyMemory(kernelBuf, userSrc, *userSize);  // second read
}
```

Between the `if` and the `RtlCopyMemory`, a racing thread changes `*userSize` to a value larger than `MAX_SIZE`. The check passed with the old value; the copy uses the new one.

### ProbeForRead followed by separate dereference

`ProbeForRead(userPtr, sizeof(ULONG), sizeof(ULONG))` validates that the address range is readable from user mode. It does not capture the value. The subsequent `value = *userPtr` is a separate memory access that can see different data than what was probed. This is a widespread misconception: many drivers treat `ProbeForRead` as if it validates the *content*, but it only validates *accessibility*.

### Shared memory sections and MDL-mapped buffers

Shared sections created via `ZwCreateSection`/`ZwMapViewOfSection` and MDL-mapped user buffers remain writable from user mode even while the kernel is reading them. A driver that reads a field from such a mapping multiple times during a single operation is vulnerable to the same double-fetch attack. The fix is the same: capture to a kernel-local copy on first read.

### Structure size fields re-read for nested access

A common variant in drivers that process complex user-supplied structures. The driver reads the top-level size field to validate the structure, then re-reads it (or a nested offset derived from it) when computing the position of inner fields. The structure can change between the two reads, causing the inner access to use an unvalidated offset.

## Winning the race

Exploiting TOCTOU requires racing two threads: one invokes the syscall or IOCTL, while a second rapidly flips the validated field between a safe value and a malicious value. The race window is typically small, spanning just a few instructions between the check and the use. But modern multi-core systems make this reliable enough for practical exploitation.

**Thread affinity pinning** via `SetThreadAffinityMask` constrains the two threads to the same or adjacent logical cores, ensuring tight scheduling interleaving. **NtSuspendThread/NtResumeThread** can precisely stall the syscall thread between the check and the use, though finding the right suspension point requires experimentation. **Page-fault-based stalling** is the most powerful technique: placing the user buffer at a page boundary where the second access crosses into a page that has been temporarily unmapped widens the race window from nanoseconds to microseconds, dramatically improving success rates.

Success rates of 10-50% per attempt are common for well-tuned TOCTOU exploits, and the attack can be retried indefinitely from user mode without system impact (unlike kernel crashes from failed heap exploitation). On systems with Hyper-Threading, logical processors sharing a physical core have tightly coupled cache behavior that makes the race even more reproducible.

``` mermaid
sequenceDiagram
    participant T1 as Thread 1 (IOCTL)
    participant K as Kernel Driver
    participant T2 as Thread 2 (Flipper)
    T2->>T2: Write safe value (0x100)
    T1->>K: DeviceIoControl()
    K->>K: Read *userSize (gets 0x100)
    K->>K: Validate: 0x100 <= MAX ✓
    T2->>T2: Write malicious value (0xFFFFFFFF)
    K->>K: Read *userSize again (gets 0xFFFFFFFF)
    K->>K: RtlCopyMemory(dst, src, 0xFFFFFFFF)
    K->>K: POOL OVERFLOW
```

The resulting primitive depends on which field is being raced. Racing a size field leads to a [buffer overflow](buffer-overflow.md). Racing a pointer field leads to arbitrary read/write or [type confusion](type-confusion.md). Racing an index field leads to out-of-bounds access. The TOCTOU itself is just the bypass mechanism; the actual exploitation follows the pattern of whatever vulnerability the bypassed check was protecting against.

## Typical primitives gained

- [Pool Overflow](../primitives/arw/pool-overflow.md) when the raced field is a size used for memory copy, producing a buffer overflow
- [Write-What-Where](../primitives/arw/write-what-where.md) when the raced field is an address or offset used in a write operation
- [Direct IOCTL R/W](../primitives/arw/direct-ioctl-rw.md) when TOCTOU bypasses validation on an IOCTL that performs kernel memory operations
- Arbitrary read via raced pointer field used as source for copy-to-user operation

## The one-read fix

The defense against TOCTOU is conceptually simple: read user data exactly once, into a kernel-owned buffer, and then validate and use only the kernel copy. This is the "capture-before-use" pattern, and it eliminates the vulnerability entirely because the kernel copy cannot be modified by user-mode threads.

For IOCTL input, METHOD_BUFFERED handles this automatically; the I/O manager copies the input into `Irp->AssociatedIrp.SystemBuffer` before the driver sees it. For METHOD_NEITHER IOCTLs, the driver must perform the capture manually: `ProbeForRead` followed by `RtlCopyMemory` to a stack or pool buffer, then all subsequent access uses the copy.

**ProbeAndCapture helpers** combine probing and copying into a single operation, making the pattern harder to get wrong. KMDF's `WdfRequestRetrieveInputBuffer` handles safe buffer capture automatically, which is one of the many reasons KMDF drivers have fewer TOCTOU bugs than WDM drivers.

**Volatile pointer marking** deserves mention because it is often misunderstood. Marking a user-mode pointer as `volatile` does not fix the vulnerability; it forces the compiler to re-read from memory on every access, which actually *guarantees* the double-fetch rather than preventing it. The value of `volatile` is in making the double-fetch visible during source review, not in preventing exploitation.

**Method change** from METHOD_NEITHER to METHOD_BUFFERED eliminates the entire class of double-fetch bugs for an IOCTL, at the cost of an extra copy. For IOCTLs that do not handle large buffers, this is the simplest and most robust fix.

## Detection strategies

**Patch diffing** is highly effective because TOCTOU fixes have a distinctive signature. The patch replaces direct user-mode pointer dereferences with a capture to a local variable followed by use of the local. In binary diffs, this manifests as a new `RtlCopyMemory` or assignment from the user buffer early in the function, with subsequent accesses redirected to the local copy. AutoPiff detects this pattern through the `double_fetch_to_capture_fix` rule.

**Static analysis** provides the best systematic coverage. The rule is: identify all user-mode pointer dereferences in a function and flag any pointer that is dereferenced more than once. Each additional dereference of the same user pointer is a potential double fetch. This can be expressed as a dataflow query in CodeQL or similar tools.

**Binary-level detection** tools like DEADLINE and Dr. Checker identify double-fetch patterns in compiled drivers by tracking memory access patterns to user-mapped addresses. These work on binaries directly, without source code.

**Concurrency fuzzing** provides runtime validation. Run IOCTL calls while concurrently modifying the input buffer from a second thread, and monitor for crashes or unexpected behavior that indicates the driver read the buffer multiple times. This is straightforward to implement for METHOD_NEITHER IOCTLs.

**Code review** should search for functions that access `Irp->UserBuffer`, `IrpSp->Parameters`, or METHOD_NEITHER buffer pointers more than once. Each access should be checked for capture-before-use. This is one of the few vulnerability classes where a simple textual search pattern (find all dereferences of `UserBuffer`) provides meaningful coverage.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-30088](../case-studies/CVE-2024-30088.md) | `ntoskrnl.exe` | TOCTOU in AuthzBasepCopyoutInternalSecurityAttributes allows security descriptor manipulation |
| [CVE-2024-30089](../case-studies/CVE-2024-30089.md) | `mskssrv.sys` | Double fetch race in streaming service request handling |
| [CVE-2024-38106](../case-studies/CVE-2024-38106.md) | `ntoskrnl.exe` | Race condition in VslpEnterIumSecureMode allowing privilege escalation |
| [CVE-2023-32019](../case-studies/CVE-2023-32019.md) | `ntoskrnl.exe` | TOCTOU in thread information query leaking kernel memory |
| [CVE-2023-36802](../case-studies/CVE-2023-36802.md) | `mskssrv.sys` | Double fetch enabling type confusion in streaming proxy |

## AutoPiff Detection

- `double_fetch_to_capture_fix` detects patches that replace double reads from user memory with a single capture to a local kernel variable followed by validation and use of the local copy
- `flt_create_race_mitigation` detects TOCTOU fixes in IRP_MJ_CREATE handlers where filter drivers capture user buffer contents before validation
- `added_capture_before_use` detects introduction of local variable capture patterns for user-mode data that was previously read in-place multiple times
- `user_buffer_copied_to_kernel` detects changes that copy user buffer data into a kernel-mode allocation before processing, eliminating concurrent modification
- `double_fetch_eliminated` detects general elimination of double-fetch patterns where a second user-mode memory access was replaced with use of a previously captured value
- `method_buffered_ioctl_change` detects IOCTL method changes from METHOD_NEITHER to METHOD_BUFFERED, which eliminates direct user buffer access and the associated TOCTOU risk

TOCTOU sits at the intersection of memory safety and concurrency, borrowing exploitation techniques from [race conditions](race-conditions.md) while producing corruption patterns that look like [buffer overflows](buffer-overflow.md) or [type confusion](type-confusion.md). The fix is always the same: capture once, use the copy. Every driver function that touches user memory should ask one question, and one question only: am I reading this value from my own copy, or from memory the user controls?
