# Logic Bugs

The driver checks whether the caller has permission to perform the operation. It calls `ObReferenceObjectByHandle` with the handle the user provided. The call succeeds. The driver proceeds. What it did not do is pass `OBJ_FORCE_ACCESS_CHECK`, which means the handle lookup bypassed the object's DACL entirely. The user has no access to the object, but the driver just gave it to them. No memory was corrupted. No buffer was overflowed. The code executed exactly as written. The logic was simply wrong.

Logic bugs are the vulnerability class that memory safety cannot save you from. Every mitigation on this site, stack cookies, pool hardening, kCFI, HVCI, KASLR, exists to make memory corruption harder to exploit. Logic bugs bypass all of them because they do not corrupt memory. They violate the driver's security model through incorrect authorization, flawed state management, or broken trust assumptions. And they persist longer than any other class, because the tools that find memory bugs do not find logic bugs.

## Why logic bugs survive

Consider the typical lifecycle of a kernel vulnerability. A fuzzer crashes the driver, the crash is triaged, the root cause is identified, and a fix is produced. This workflow works for memory corruption because memory corruption *crashes*. A [buffer overflow](buffer-overflow.md) writes past a buffer boundary. A [use-after-free](use-after-free.md) accesses freed memory. Both produce observable symptoms: pool corruption, bugchecks, Driver Verifier violations.

Logic bugs produce none of these symptoms. The driver runs correctly, returns STATUS_SUCCESS, and performs the requested operation. The bug is that the operation should have been denied, not that it was performed incorrectly. Fuzzers do not detect this because fuzzers look for crashes, not for unauthorized success. Static analyzers do not detect this because they track data flow, not security policy. The only reliable detection method is a human reviewer who understands the driver's intended security model and can verify that every entry point enforces it.

CVE-2024-21338 in `appid.sys` is the case that makes this concrete. The AppLocker driver exposed an IOCTL that allowed user-mode callers to invoke arbitrary kernel callback functions. The bug was not in how memory was managed but in the security model: the IOCTL was accessible to any user, and the callback target was not validated. The Lazarus Group exploited this vulnerability in the wild, using it to disable security products. The driver had been audited, shipped in every Windows installation, and updated regularly. The logic bug persisted for years because no automated tool was looking for it.

## Patterns of broken logic

### Missing access checks

The most common and most directly exploitable pattern. A driver performs a privileged operation (mapping physical memory, modifying system configuration, loading code) without verifying that the caller has the required privilege. The operation succeeds for any user, including unprivileged ones.

CVE-2024-26229 in `csc.sys` (Client-Side Caching) is a textbook example. The driver exposed IOCTLs that performed privileged operations without checking the caller's access level. Any user could open a handle to the device and invoke these IOCTLs, effectively gaining capabilities that should be restricted to administrators.

The fix for missing access checks is almost always one of three things: adding `SeSinglePrivilegeCheck` before the operation, adding `SeAccessCheck` for more complex authorization, or adding `OBJ_FORCE_ACCESS_CHECK` to `ObReferenceObjectByHandle` calls. These are single-function additions that are trivially visible in patch diffs, which is why AutoPiff is effective at detecting them even though the underlying bug is a logic issue.

### PreviousMode / RequestorMode misuse

When the kernel processes a request from user mode, `Irp->RequestorMode` (or `ExGetPreviousMode()`) indicates whether the caller is user-mode or kernel-mode. Kernel-mode callers are trusted implicitly; user-mode callers must be validated. If a driver hardcodes `KernelMode` instead of checking the actual mode, every user-mode request is treated as if it came from the kernel. All access checks, buffer probing, and privilege validation are bypassed.

This is particularly dangerous in drivers that implement interfaces used by both user-mode applications and other kernel components. The developer may assume that the IOCTL is only called from kernel mode (because the other kernel component is the primary client) and skip the `RequestorMode` check. When an attacker discovers that the device object is accessible from user mode, the missing check becomes a direct privilege escalation path.

### Device object security

Every device object created by `IoCreateDevice` has a security descriptor that controls who can open a handle to it. If the driver does not explicitly set a security descriptor (using `IoCreateDeviceSecure` with an SDDL string), the device inherits default permissions that may be overly permissive. Many third-party drivers create their device objects with no explicit security descriptor, allowing `Everyone` full access.

By itself, a permissive device object is not a vulnerability. It becomes one when combined with an IOCTL that performs a privileged operation. If any user can open the device *and* the IOCTL does not perform its own access check, the result is direct privilege escalation. The [arbitrary R/W primitives](arbitrary-rw-primitives.md) page covers the extreme version of this: drivers that expose direct memory access through IOCTLs to anyone who can open the device.

### Error paths that fail open

When an operation fails, the error handling code should deny the request and clean up. If the error path returns `STATUS_SUCCESS` instead of an error status, the caller proceeds as if the operation succeeded. This can have cascading security consequences: a failed authorization check that returns success grants unauthorized access. A failed signature verification that returns success accepts unsigned code.

The related pattern is incomplete cleanup on error. If a function partially completes an operation, encounters an error, but does not undo the partial work, the system may be left in a state where security invariants are violated. The caller may then exploit this inconsistent state in a subsequent operation.

### State machine violations

Complex drivers implement state machines for object lifecycle management. An object transitions through states (created, initialized, active, paused, stopped, destroyed) and certain operations are only valid in certain states. If the driver does not validate the current state before performing an operation, an attacker can invoke operations in the wrong order: re-initializing an active object (resetting security state), skipping the cleanup state by transitioning directly from active to destroyed (leaking resources), or performing active-state operations on a destroyed object.

### Version and integrity downgrades

CVE-2024-21302 in `ntoskrnl.exe` demonstrated that even the secure kernel's integrity enforcement could be subverted through a logic bug. The vulnerability allowed rollback to vulnerable components by circumventing the version enforcement that was supposed to prevent exactly that. The downgraded components had known vulnerabilities, effectively allowing the attacker to "un-patch" the system.

## Exploitation: the shortest path to SYSTEM

Logic bug exploitation is typically the most straightforward of any vulnerability class. There is no heap grooming, no race condition to win, no spray to land. If the bug is a missing access check, calling the unprotected IOCTL obtains the privileged operation directly. If the bug is a `PreviousMode` bypass, the user-mode process gains the ability to call kernel APIs as if it were kernel code.

CVE-2024-21338 required a single IOCTL call with controlled parameters to invoke an arbitrary kernel callback. No memory corruption. No exploitation chain. One system call, and the attacker's code runs in kernel context.

This directness makes logic bugs particularly valuable to sophisticated threat actors. Nation-state groups and advanced persistent threats prefer logic bugs because they are reliable (no race conditions to win), stealthy (no unusual memory patterns for EDR to detect), and often survive reboots (the vulnerable driver is loaded on every boot).

## Typical primitives gained

- **Direct privilege escalation** via missing access check, where the attacker performs a privileged operation without authorization
- [Direct IOCTL R/W](../primitives/arw/direct-ioctl-rw.md) when a missing access check exposes a memory read/write IOCTL to unprivileged callers
- [Token Manipulation](../primitives/arw/token-manipulation.md) when `PreviousMode` bypass allows unprivileged token modification
- **Security policy bypass**, circumventing signature validation, integrity checks, or version enforcement
- [Write-What-Where](../primitives/arw/write-what-where.md) when a logic bug grants access to a write operation that is normally restricted

## Mitigations

Logic bugs resist technical mitigations because the mitigation for incorrect logic is correct logic. But several design patterns reduce the attack surface.

**Principle of least privilege** applied to device objects means using `IoCreateDeviceSecure` with an explicit SDDL string that restricts access to the minimum set of users required. If the device should only be accessible to administrators, the SDDL should say so. If it should only be accessible to a specific service account, the SDDL should say that. Default permissions are almost always too broad.

**OBJ_FORCE_ACCESS_CHECK** should be used in every `ObReferenceObjectByHandle` call from an IOCTL handler. Without this flag, the handle lookup bypasses DACL checks, allowing user-mode callers to access objects they should not reach. This is a single flag that prevents an entire category of logic bugs.

**RequestorMode enforcement** means always using `Irp->RequestorMode` or `ExGetPreviousMode()` for access decisions, never hardcoding `KernelMode`. If a kernel component needs to call the same IOCTL with elevated privileges, it should set `Irp->RequestorMode = KernelMode` explicitly, making the trust decision visible and auditable.

**Secure device creation** via `IoCreateDeviceSecure` with explicit SDDL defines access control at the device level, preventing unauthorized users from opening the device handle in the first place.

**Threat modeling** before code is written identifies the security decisions each entry point must make. A driver-specific security checklist that enumerates every IOCTL and the required access checks, validated during code review, catches missing checks before they ship.

## Detection strategies

**Patch diffing** reveals logic bug fixes through added access check functions. Look for added `SeAccessCheck`, `SeSinglePrivilegeCheck`, `ExGetPreviousMode`, `IoIs32bitProcess`, or `OBJ_FORCE_ACCESS_CHECK` additions. These patches are distinctive because they add comparison-and-branch sequences that were entirely absent before. AutoPiff detects these as `privilege_check_added`, `access_mode_enforcement_added`, and `handle_force_access_check_added`.

**Manual code review** is the most effective technique for logic bugs, and there is no shortcut around this. Review every IOCTL handler's entry point for proper caller validation. Verify that `RequestorMode` is checked, that required privileges are enforced, and that error paths return appropriate error codes. This is labor-intensive, but it is the only approach that reliably catches logic bugs.

**Security model analysis** involves documenting the driver's intended security model (who should be able to call what, under what conditions), then systematically verifying that each IOCTL and exposed interface enforces that model. The gap between intended and actual behavior is where logic bugs live.

**Differential testing** compares driver behavior when called from an administrative context versus an unprivileged context. Any operation that succeeds from both contexts but should be admin-only indicates a missing access check. This is straightforward to automate and has historically been productive for finding missing privilege checks.

**Threat modeling** at the entry point level enumerates all IOCTLs, file system callbacks, and PnP handlers, determines what security checks each should perform, and compares against the actual implementation. The difference is the finding.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-26229](../case-studies/CVE-2024-26229.md) | `csc.sys` | Missing access check allows unprivileged user to perform privileged IOCTL operations |
| [CVE-2024-21302](../case-studies/CVE-2024-21302.md) | `ntoskrnl.exe` | Secure kernel version downgrade bypass allowing rollback to vulnerable components |
| [CVE-2024-21338](../case-studies/CVE-2024-21338.md) | `appid.sys` | Logic flaw allows arbitrary kernel callback invocation from user mode |
| [CVE-2023-28252](../case-studies/CVE-2023-28252.md) | `clfs.sys` | Logic error in base log record validation enabling controlled memory corruption |
| [CVE-2023-28218](../case-studies/CVE-2023-28218.md) | `win32k.sys` | Missing privilege check in window management operation |
| [Capcom.sys](../case-studies/Capcom-sys.md) | `Capcom.sys` | Intentional ring-0 code execution from user-supplied function pointer, the quintessential logic bug |

## AutoPiff Detection

- `privilege_check_added` detects patches adding `SeSinglePrivilegeCheck`, `SeAccessCheck`, or equivalent privilege verification calls before privileged operations
- `access_mode_enforcement_added` detects replacement of hardcoded `KernelMode` with proper `Irp->RequestorMode` or `ExGetPreviousMode()` for caller validation
- `handle_force_access_check_added` detects addition of `OBJ_FORCE_ACCESS_CHECK` flag to `ObReferenceObjectByHandle` calls, enforcing DACL checks on user-supplied handles
- `interlocked_refcount_added` detects reference count hardening that prevents state manipulation through concurrent operations
- `error_path_corrected` detects fixes to error paths that previously returned `STATUS_SUCCESS` or failed to clean up state properly
- `state_validation_added` detects addition of state machine transition validation to prevent invalid or out-of-order operations
- `authorization_validation_added` detects general authorization check additions to driver entry points

Logic bugs occupy the uncomfortable space where technology meets design. You cannot fuzz your way to finding them. You cannot add a compiler flag that prevents them. You cannot deploy a runtime mitigation that catches them. The defense is rigorous security modeling, consistent access check patterns, and code review by people who understand not just what the code does, but what it *should* do. When a logic bug ships, it tends to ship for years, because the code works perfectly. It just works for everyone, including the people it should not work for.
