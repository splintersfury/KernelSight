# Logic Bugs

Flaws in program logic that violate security assumptions without a traditional memory corruption root cause, enabling privilege escalation or security bypass.

## Description

Logic bugs are vulnerabilities rooted in incorrect security design or implementation rather than memory safety violations. They encompass missing authorization checks, incorrect privilege enforcement, flawed state machine transitions, security policy bypasses, and improper error handling that fails open. Unlike buffer overflows or use-after-free bugs, logic bugs do not corrupt memory -- they allow operations that should be denied by the driver's security model.

These vulnerabilities are often missed by memory-safety tooling. Static analyzers focused on buffer sizes, fuzzers looking for crashes, and runtime sanitizers designed to catch memory corruption will not detect a missing `SeAccessCheck` call or an incorrect `PreviousMode` usage. Logic bugs require understanding the driver's intended security model and verifying that every security-relevant operation is properly gated, making them among the hardest vulnerability classes to detect systematically.

A common subclass involves `PreviousMode` / `RequestorMode` misuse. When a kernel driver processes a request from user mode, it should check `Irp->RequestorMode` or `ExGetPreviousMode()` to determine whether the caller has kernel-mode privileges. If a driver incorrectly hardcodes `KernelMode` or uses the wrong accessor, it bypasses all user/kernel boundary checks, treating an unprivileged user-mode request as if it came from kernel mode. Similarly, drivers that call `ObReferenceObjectByHandle` without `OBJ_FORCE_ACCESS_CHECK` allow user-mode callers to open handles to objects they should not have access to.

Another important subclass is device object security. Every device object created by `IoCreateDevice` or `IoCreateDeviceSecure` has a security descriptor that controls who can open a handle to it. If the security descriptor is overly permissive (e.g., allows `Everyone` full access), any user can open the device and send IOCTLs. When combined with an IOCTL that performs a privileged operation, this becomes a direct privilege escalation path. Many third-party drivers create their device objects with no explicit security descriptor, inheriting default permissions that may be too permissive.

## Common Patterns in Drivers

- Missing `SeSinglePrivilegeCheck` or `SeAccessCheck` before performing a privileged operation (e.g., mapping physical memory, loading a driver, modifying system configuration)
- Using `KernelMode` instead of the actual `Irp->RequestorMode` when validating caller privileges, causing all requests to be treated as kernel-originated
- `ObReferenceObjectByHandle` called without `OBJ_FORCE_ACCESS_CHECK`, allowing user-mode callers to access objects regardless of their DACL
- Incorrect `STATUS_SUCCESS` return on an error path, causing the caller to proceed as if the operation succeeded when it actually failed or was denied
- State machine that allows invalid transitions: an object can be re-initialized while active, or a cleanup operation can be skipped by transitioning directly to a terminal state
- Signature or integrity validation that accepts malformed, truncated, or self-signed data as valid
- Security descriptor not applied to a device object or named pipe, allowing any user to open and send IOCTLs to a privileged driver
- Missing impersonation level check before using a client's token for access decisions
- Version or integrity downgrade: allowing an older, vulnerable component to replace a newer, patched one without proper version enforcement
- Error path that does not clean up partially-completed state, leaving the system in an inconsistent security posture

## Exploitation Implications

Logic bug exploitation is typically straightforward once identified. If the bug is a missing access check, calling the unprotected IOCTL or syscall obtains the privileged operation directly. If the bug is a `PreviousMode` bypass, the user-mode process gains the ability to call kernel APIs as if it were kernel code.

Impact ranges from information disclosure (reading access-controlled objects) to direct privilege escalation (performing operations restricted to SYSTEM or administrators). Some logic bugs create preconditions for memory corruption: a missing access check might allow an unprivileged user to trigger a code path designed for trusted kernel components, where an unsafe operation is "safe" only because of the expected caller privilege level.

Logic bugs tend to persist because memory safety tools do not detect them. The CVE-2024-21338 `appid.sys` vulnerability existed for years in a routinely audited driver, because the flaw was in the security model (allowing arbitrary callback invocation) rather than in memory handling.

## Typical Primitives Gained

- Direct privilege escalation via missing access check -- the attacker performs a privileged operation without authorization
- [Direct IOCTL R/W](../primitives/arw/direct-ioctl-rw.md) -- when a missing access check exposes a memory read/write IOCTL to unprivileged callers
- [Token Manipulation](../primitives/arw/token-manipulation.md) -- when `PreviousMode` bypass allows unprivileged token modification
- Security policy bypass -- circumventing signature validation, integrity checks, or version enforcement
- [Write-What-Where](../primitives/arw/write-what-where.md) -- when a logic bug grants access to a write operation that is normally restricted

## Mitigations

- **Principle of least privilege** -- Device objects should have restrictive security descriptors that limit access to the minimum set of users required
- **OBJ_FORCE_ACCESS_CHECK** -- Always use this flag when calling `ObReferenceObjectByHandle` from IOCTL handlers to enforce DACL checks on user-supplied handles
- **RequestorMode enforcement** -- Always use `Irp->RequestorMode` or `ExGetPreviousMode()` instead of hardcoding `KernelMode` for access decisions
- **Secure device creation** -- Use `IoCreateDeviceSecure` with an explicit SDDL string to define precise access control on the device object at creation time
- **Code review checklists** -- Maintain driver-specific security checklists that enumerate every entry point and the required access checks, validated during code review
- **Threat modeling** -- Formal threat modeling of driver interfaces identifies missing access checks before code is written

## Detection Strategies

- **Patch diffing**: Look for added `SeAccessCheck`, `SeSinglePrivilegeCheck`, `IoIs32bitProcess`, `ExGetPreviousMode`, or `OBJ_FORCE_ACCESS_CHECK` additions. AutoPiff detects these as `privilege_check_added` and `access_mode_enforcement_added`.
- **Manual code review**: This is the most effective technique for logic bugs. Review every IOCTL handler's entry point for proper caller validation. Verify that `RequestorMode` is checked, that required privileges are enforced, and that error paths return appropriate error codes.
- **Security model analysis**: Document the driver's intended security model (who should be able to call what), then systematically verify that each IOCTL and exposed interface enforces that model.
- **Threat modeling**: Enumerate all entry points (IOCTLs, file system callbacks, PnP handlers) and determine what security checks each one should perform. Compare against the actual implementation.
- **Differential testing**: Compare the behavior of the driver when called from an administrative context versus an unprivileged context. Any operation that succeeds from both contexts but should be admin-only indicates a missing access check.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-26229](../case-studies/CVE-2024-26229.md) | `csc.sys` | Missing access check allows unprivileged user to perform privileged IOCTL operations |
| [CVE-2024-21302](../case-studies/CVE-2024-21302.md) | `ntoskrnl.exe` | Secure kernel version downgrade bypass allowing rollback to vulnerable components |
| [CVE-2024-21338](../case-studies/CVE-2024-21338.md) | `appid.sys` | Logic flaw allows arbitrary kernel callback invocation from user mode |
| [CVE-2023-28252](../case-studies/CVE-2023-28252.md) | `clfs.sys` | Logic error in base log record validation enabling controlled memory corruption |
| [CVE-2023-28218](../case-studies/CVE-2023-28218.md) | `win32k.sys` | Missing privilege check in window management operation |
| [Capcom.sys](../case-studies/Capcom-sys.md) | `Capcom.sys` | Intentional ring-0 code execution from user-supplied function pointer — the quintessential logic bug |

## AutoPiff Detection

- `privilege_check_added` -- Detects patches adding `SeSinglePrivilegeCheck`, `SeAccessCheck`, or equivalent privilege verification calls before privileged operations
- `access_mode_enforcement_added` -- Detects replacement of hardcoded `KernelMode` with proper `Irp->RequestorMode` or `ExGetPreviousMode()` for caller validation
- `handle_force_access_check_added` -- Detects addition of `OBJ_FORCE_ACCESS_CHECK` flag to `ObReferenceObjectByHandle` calls, enforcing DACL checks on user-supplied handles
- `interlocked_refcount_added` -- Detects reference count hardening that prevents state manipulation through concurrent operations
- `error_path_corrected` -- Detects fixes to error paths that previously returned `STATUS_SUCCESS` or failed to clean up state properly
- `state_validation_added` -- Detects addition of state machine transition validation to prevent invalid or out-of-order operations
- `authorization_validation_added` -- Detects general authorization check additions to driver entry points
