# Core Kernel

The NT kernel executive (`ntoskrnl.exe`) implements process/thread management, memory management, security reference monitor, and system call dispatch. Vulnerabilities here affect all Windows systems.

## Architecture

- **Binary**: `ntoskrnl.exe` — the core kernel image
- **Subsystems**: Process Manager (Ps), Memory Manager (Mm), Security Reference Monitor (Se/Authz), I/O Manager (Io), Object Manager (Ob), Virtual Secure Mode (Vsl)
- **Syscall interface**: `Nt*`/`Zw*` system calls — hundreds of entry points
- **Privilege**: Bugs in ntoskrnl typically have the highest impact

## Attack Surface

- **Security subsystem**: AuthzBasep* functions, token management, access check logic
- **Process/thread info queries**: NtQueryInformationThread, NtQueryInformationProcess — output buffers may leak kernel memory
- **VBS/Secure Kernel interface**: VslpEnterIumSecureMode, version validation — VTL transitions
- **Synchronization**: Shared data structures accessed across CPUs and interrupt levels

## Common Vulnerability Patterns

| Pattern | Description | AutoPiff Rules |
|---------|-------------|----------------|
| TOCTOU in security attributes | Security attribute buffer re-read after validation | `added_lock_around_toctou`, `spinlock_acquisition_added`, `mutex_or_resource_lock_added` |
| Race in VBS transition | Missing lock around VTL state change | `spinlock_acquisition_added`, `mutex_or_resource_lock_added` |
| Version validation bypass | Secure kernel version check can be downgraded | `interlocked_refcount_added` |
| Kernel memory disclosure | Thread info query returns uninitialized buffer data | `buffer_zeroing_before_copy_added`, `stack_variable_initialization_added` |

## CVEs

| CVE | Driver | Description | Class | ITW |
|-----|--------|-------------|-------|-----|
| [CVE-2024-30088](../case-studies/CVE-2024-30088.md) | `ntoskrnl.exe` | TOCTOU in AuthzBasepCopyoutInternalSecurityAttributes | Race Condition | Yes |
| [CVE-2024-38106](../case-studies/CVE-2024-38106.md) | `ntoskrnl.exe` | Missing lock around VslpEnterIumSecureMode | Race Condition | Yes |
| [CVE-2024-21302](../case-studies/CVE-2024-21302.md) | `ntoskrnl.exe` | Secure kernel version downgrade bypass | Logic Bug | No |
| [CVE-2023-32019](../case-studies/CVE-2023-32019.md) | `ntoskrnl.exe` | Kernel heap memory leak via thread info query | Info Disclosure | No |

## Research Notes

ntoskrnl.exe bugs have wide impact: every Windows system runs the same kernel. Security subsystem bugs often yield token manipulation directly, and VTL transition bugs can undermine VBS mitigations.

CVE-2024-30088 (Pwn2Own 2024) demonstrates the pattern: a TOCTOU race in the security attribute copy-out path leads to token manipulation and SYSTEM.
