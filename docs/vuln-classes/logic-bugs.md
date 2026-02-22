# Logic Bugs

Design-level logic errors including missing access checks, incorrect state machines, and privilege escalation by design.

## Description

Logic bugs are not memory corruption — they are flaws in the driver's security design. Missing authorization checks, incorrect privilege enforcement, or state machine errors that allow unauthorized operations.

## Patterns

- Missing `SeSinglePrivilegeCheck` / `SeAccessCheck`
- Using `KernelMode` instead of actual `RequestorMode`
- State machine allows skipping required authorization step
- Version/integrity check bypass

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-26229](../case-studies/CVE-2024-26229.md) | `csc.sys` | Missing access check allows EoP |
| [CVE-2024-21302](../case-studies/CVE-2024-21302.md) | `ntoskrnl.exe` | Secure kernel version downgrade bypass |

## AutoPiff Detection

- `privilege_check_added` — Privilege check enforced
- `access_mode_enforcement_added` — RequestorMode used instead of KernelMode
- `handle_force_access_check_added` — OBJ_FORCE_ACCESS_CHECK flag added
- `interlocked_refcount_added` — Refcount hardening for state protection
