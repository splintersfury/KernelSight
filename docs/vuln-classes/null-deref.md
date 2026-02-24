# NULL Pointer Dereference

Accessing memory through a pointer that is NULL (zero), reading from or writing to the zero page in kernel context.

## Description

NULL pointer dereference vulnerabilities occur when a kernel driver accesses memory through a pointer that has not been assigned a valid address, defaulting to virtual address zero. In the Windows kernel, dereferencing a NULL pointer causes a bugcheck (BSOD) because the zero page is unmapped. The system crashes with a `KERNEL_DATA_INPAGE_ERROR`, `PAGE_FAULT_IN_NONPAGED_AREA`, or `SYSTEM_SERVICE_EXCEPTION` stop code, resulting in a denial-of-service condition.

On older Windows versions (32-bit Windows 7 and earlier), user-mode processes could map the zero page using `NtAllocateVirtualMemory` with a base address of zero. This allowed controlled data to be placed at address 0x0, so when the kernel dereferenced a NULL pointer, it would read attacker-controlled data instead of crashing. If the NULL pointer was used for a function call, execution could be redirected to user-mode code running at ring-0 privilege. On modern 64-bit Windows (8.0+), the zero page is unconditionally reserved and cannot be mapped from user mode, making NULL pointer dereferences almost exclusively a denial-of-service issue.

NULL dereferences remain relevant beyond simple DoS. They can indicate deeper logic flaws -- the missing NULL check often reveals that an error path is not properly handled, which may have additional security consequences. Certain NULL dereference patterns can still lead to exploitable conditions on modern systems, particularly write-at-offset-from-NULL patterns (e.g., `NULL->field_at_offset_0x40 = attacker_value`) that may overlap with valid mapped memory in edge cases.

## Common Patterns in Drivers

- Missing NULL check after `ObReferenceObjectByHandle` returns `STATUS_INVALID_HANDLE` or other failure -- the output object pointer is not set but the driver proceeds to use it
- Missing NULL check after pool allocation failure (`ExAllocatePoolWithTag` returning NULL on low-memory conditions) -- the driver dereferences the NULL return value
- Missing NULL check on `MmGetSystemAddressForMdlSafe` return -- this function returns NULL if the mapping fails, but the driver uses the result unconditionally
- Function pointer in an optional structure field (e.g., callback table entry, dispatch routine) called without verifying it is non-NULL
- Chained pointer dereference where an intermediate pointer can be NULL: `obj->parent->child->method()` crashes if `parent` is NULL
- Missing NULL check after `IoGetCurrentIrpStackLocation` in unusual IRP handling scenarios
- Optional file object fields (`FsContext`, `FsContext2`) accessed without NULL check when the file was opened in a mode that does not populate these fields
- Return value of `IoGetDeviceObjectPointer` or `IoGetAttachedDeviceReference` used without NULL validation
- Event callback function pointer in an optional extension structure invoked without NULL check when the extension was not initialized
- WDF object context retrieved via `WdfObjectGetTypedContext` used without verifying the context was actually allocated during object creation

## Exploitation Implications

On modern x64 Windows 10 and later, NULL pointer dereferences are primarily a denial-of-service vector. An unprivileged user can trigger a system-wide crash (BSOD) by invoking the vulnerable code path, which is particularly impactful on servers and shared systems. Repeated triggering can prevent system boot if the crash occurs early in the boot process.

On legacy 32-bit systems or in specific configurations, NULL dereferences can be exploited for code execution. The attacker maps the zero page with `NtAllocateVirtualMemory`, places a fake object (with controlled vtable pointers or data fields) at address zero, and triggers the NULL dereference. The kernel reads the fake object and dispatches through the attacker-controlled function pointer, executing arbitrary code at ring-0. While this is largely a historical technique, some hypervisor and embedded Windows configurations may still be vulnerable.

A special case is the NULL dereference of a function pointer. When the kernel calls through a NULL function pointer (e.g., `object->callback(args)` where `callback` is NULL), it attempts to execute code at address zero. On legacy systems with the zero page mapped as executable, this leads directly to code execution. On modern systems it causes an immediate bugcheck.

Write-at-offset-from-NULL patterns (e.g., `*(NULL + user_controlled_offset) = value`) are more interesting on modern systems because the offset could potentially reach mapped memory, though this requires very specific circumstances.

NULL dereferences in kernel code are treated more seriously than their user-mode counterparts because they cause a system-wide crash rather than a single process termination. In cloud and server environments, a reliable NULL dereference trigger from an unprivileged user is a meaningful denial-of-service vulnerability affecting all tenants on a shared host.

## Typical Primitives Gained

- Denial of service (BSOD) -- the primary impact on modern x64 Windows systems
- Code execution on legacy 32-bit systems via zero-page mapping and fake object placement
- Information disclosure if the NULL dereference is a read that returns data to user mode (reading from unmapped page causes bugcheck, so this is rare)
- Logic bypass if the NULL check guards a security-relevant code path -- skipping the NULL path may bypass authorization

## Mitigations

- **Zero page reservation** -- Windows 8+ unconditionally reserves the zero page (VA 0x0-0xFFFF), preventing user-mode mapping and making NULL dereferences non-exploitable for code execution on modern systems
- **SMEP (Supervisor Mode Execution Prevention)** -- Even if the zero page were mapped, SMEP prevents kernel-mode execution of user-mode pages, adding defense-in-depth
- **MmGetSystemAddressForMdlSafe** -- The "Safe" variant of this function returns NULL on failure instead of bugchecking, allowing callers to handle the error gracefully
- **ExAllocatePool2 with error handling** -- The modern pool API returns NULL on failure (rather than bugchecking), making proper NULL checking essential
- **Low Resources Simulation** -- Driver Verifier's fault injection mode systematically fails allocations to test error handling, exposing missing NULL checks during development

## Detection Strategies

- **Patch diffing**: Look for added NULL checks (`if (ptr == NULL) return STATUS_...`) after function calls that can return NULL. AutoPiff detects these as `pool_allocation_null_check_added` and `mdl_null_check_added`.
- **Static analysis**: Track all pointer-returning function calls and verify that every caller checks for NULL before dereference. Focus on `ExAllocatePoolWithTag`, `MmGetSystemAddressForMdlSafe`, `ObReferenceObjectByHandle`, and `IoAllocateIrp`.
- **Compiler analysis**: PREfast (Static Driver Verifier) and the `/analyze` flag in MSVC detect many NULL dereference patterns in Windows drivers through SAL annotation checking.
- **Driver Verifier**: Enable Low Resources Simulation (fault injection) to force allocation failures and expose missing NULL checks on error paths. This systematically triggers the code paths where NULL dereferences hide.
- **Code review**: Focus on error handling paths -- most NULL dereferences occur because the success path is well-tested but the failure path (allocation failure, handle lookup failure) is rarely exercised.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-35250](../case-studies/CVE-2024-35250.md) | `ks.sys` | NULL pointer dereference leading to EoP in specific kernel streaming configuration |
| [CVE-2023-36802](../case-studies/CVE-2023-36802.md) | `mskssrv.sys` | NULL dereference in streaming proxy handle validation path |
| [CVE-2024-30085](../case-studies/CVE-2024-30085.md) | `cldflt.sys` | Missing NULL check after allocation in error recovery path |
| [CVE-2023-29360](../case-studies/CVE-2023-29360.md) | `mskssrv.sys` | NULL function pointer call in streaming service dispatch |
| [CVE-2022-37969](../case-studies/CVE-2022-37969.md) | `clfs.sys` | NULL pointer dereference in log file container validation |

## AutoPiff Detection

- `pool_allocation_null_check_added` -- Detects patches adding NULL validation after `ExAllocatePoolWithTag` or `ExAllocatePool2` return values before pointer dereference
- `mdl_null_check_added` -- Detects addition of NULL check on `Irp->MdlAddress` or the return value of MDL mapping functions
- `mdl_safe_mapping_replacement` -- Detects replacement of `MmGetSystemAddressForMdl` (which crashes on failure) with the `Safe` variant that returns NULL on mapping failure
- `added_null_check` -- Detects general NULL pointer validation additions before dereference operations in driver code
- `null_pointer_validation_added` -- Detects addition of NULL validation on optional object fields, function pointers, or handle lookup results
