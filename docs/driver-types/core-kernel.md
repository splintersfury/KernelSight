# Core Kernel

<div class="ks-pipeline-pos">
  <span class="ks-active">Driver Type</span> &rarr; Attack Surface &rarr; Vuln Class &rarr; Primitive &rarr; Case Study
</div>

Every Windows system runs the same kernel binary. A vulnerability in ntoskrnl.exe is not scoped to a specific driver, a specific hardware configuration, or a specific feature that might be disabled. It affects every Windows machine, period. This universality makes core kernel bugs the highest-impact category in the KernelSight corpus, and it explains why two of the four CVEs here were used at Pwn2Own or exploited in the wild by nation-state actors.

The NT kernel executive (`ntoskrnl.exe`) is the foundation of the Windows operating system. It implements process and thread management, memory management, the Security Reference Monitor, the I/O Manager, the Object Manager, and the interface to Virtual Secure Mode (VBS/VTL). Unlike the specialized drivers in other categories, ntoskrnl is not focused on a single task. It is the glue that connects every other kernel component, and its attack surface spans hundreds of `Nt*`/`Zw*` system calls.

## Architecture

``` mermaid
graph TD
    A["User Mode Process"] -->|"Nt*/Zw* Syscalls"| B["ntoskrnl.exe"]
    B --> C["Security Reference Monitor<br/>Se/Authz subsystem"]
    B --> D["Process Manager<br/>Ps subsystem"]
    B --> E["Memory Manager<br/>Mm subsystem"]
    B --> F["Object Manager<br/>Ob subsystem"]
    B --> G["VBS / Secure Kernel<br/>VTL transitions"]

    style A fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    style B fill:#152a4a,stroke:#ef4444,color:#e2e8f0
    style C fill:#0d1320,stroke:#ef4444,color:#e2e8f0
    style D fill:#0d1320,stroke:#3b82f6,color:#e2e8f0
    style E fill:#0d1320,stroke:#3b82f6,color:#e2e8f0
    style F fill:#0d1320,stroke:#3b82f6,color:#e2e8f0
    style G fill:#0d1320,stroke:#8b5cf6,color:#e2e8f0
```

The kernel executive is organized into subsystems, each identified by a two-letter prefix: `Ps` for Process Manager, `Mm` for Memory Manager, `Se` and `Authz` for the Security Reference Monitor, `Io` for I/O Manager, `Ob` for Object Manager, and `Vsl` for the Virtual Secure Mode interface. Bugs in each subsystem have different characteristics and impact profiles, but they all share the property of being reachable through system calls from any user-mode process.

## Where the Bugs Live

### Security Subsystem: Token Manipulation and Access Check Races

The Security Reference Monitor implements access control decisions, token management, and security attribute handling. The `AuthzBasep*` functions perform security attribute copy-out operations that move data between kernel and user buffers. CVE-2024-30088, used at Pwn2Own 2024, exploits a TOCTOU race condition in `AuthzBasepCopyoutInternalSecurityAttributes`. The function validates a security attribute buffer, then re-reads it from a shared mapping. Between the validation and the re-read, another thread modifies the buffer, causing the kernel to process data that does not match what was validated.

This pattern, validate then re-read from shared memory, is a classic TOCTOU that appears when kernel code operates on user-accessible buffers without copying them first or holding a lock across the validation and use. The fix for CVE-2024-30088 adds lock acquisition around the critical section. Security subsystem TOCTOU bugs are particularly valuable because the corrupted data often directly involves token structures or security descriptors, giving the attacker a path from race condition to token manipulation to SYSTEM without needing a separate primitive-building step.

### VBS Transition Interface: Undermining Hardware-Backed Security

Virtual Secure Mode (VBS) creates a separate security domain (VTL 1) backed by the hypervisor. The `Vsl*` functions in ntoskrnl manage the transitions between VTL 0 (the normal kernel) and VTL 1 (the secure kernel). These transitions involve state management that must be atomic and correctly ordered.

CVE-2024-38106, exploited in the wild, targets a missing lock around `VslpEnterIumSecureMode`. The race condition allows an attacker to manipulate the VTL transition state, potentially corrupting the context that the secure kernel relies on. This is significant because VBS is positioned as a hardware-backed security boundary; a bug in the transition interface undermines the entire VBS security model, including Credential Guard, HVCI, and other VBS-dependent features.

CVE-2024-21302 is a different class of VBS bug: a logic flaw in secure kernel version validation that allows downgrading the secure kernel version. This is not a memory corruption bug but rather a bypass of the integrity check that prevents rollback to older, vulnerable secure kernel builds. The impact is indirect but serious: downgrading the secure kernel re-exposes previously patched VBS vulnerabilities.

### Information Disclosure: Kernel Memory Leaks

CVE-2023-32019 is a kernel heap memory leak through `NtQueryInformationThread`. When the syscall returns thread information to the caller, the output buffer contains uninitialized fields that leak data from previous kernel allocations. While this is lower severity than the race conditions and VBS bugs, information disclosure from ntoskrnl is particularly useful because it can leak kernel base addresses (defeating KASLR), pool metadata, or other data that serves as a building block for more powerful exploits.

## Vulnerability Patterns and Detection

| Pattern | Description | AutoPiff Rules |
|---------|-------------|----------------|
| TOCTOU in security attributes | Security attribute buffer re-read after validation | `added_lock_around_toctou`, `spinlock_acquisition_added`, `mutex_or_resource_lock_added` |
| Race in VBS transition | Missing lock around VTL state change | `spinlock_acquisition_added`, `mutex_or_resource_lock_added` |
| Version validation bypass | Secure kernel version check can be downgraded | `interlocked_refcount_added` |
| Kernel memory disclosure | Thread info query returns uninitialized buffer data | `buffer_zeroing_before_copy_added`, `stack_variable_initialization_added` |

The race condition bugs (CVE-2024-30088 and CVE-2024-38106) share a common detection pattern in AutoPiff: the patch adds a spinlock acquisition or mutex around a critical section that previously operated without synchronization. This is a strong signal because adding locking to an existing code path is rarely a performance optimization; it is almost always a fix for a race condition.

## CVEs

| CVE | Driver | Description | Class | ITW |
|-----|--------|-------------|-------|-----|
| [CVE-2024-30088](../case-studies/CVE-2024-30088.md) | `ntoskrnl.exe` | TOCTOU in AuthzBasepCopyoutInternalSecurityAttributes | Race Condition | Yes |
| [CVE-2024-38106](../case-studies/CVE-2024-38106.md) | `ntoskrnl.exe` | Missing lock around VslpEnterIumSecureMode | Race Condition | Yes |
| [CVE-2024-21302](../case-studies/CVE-2024-21302.md) | `ntoskrnl.exe` | Secure kernel version downgrade bypass | Logic Bug | No |
| [CVE-2023-32019](../case-studies/CVE-2023-32019.md) | `ntoskrnl.exe` | Kernel heap memory leak via thread info query | Info Disclosure | No |

## Research Outlook

Core kernel research requires a different approach than auditing individual drivers. The codebase is massive, and the attack surface spans hundreds of system calls. Targeted approaches work better than blanket fuzzing: focus on subsystems that handle security-critical operations (token management, access checks, VBS transitions) and look for patterns where the code operates on shared state without adequate synchronization.

The two race condition CVEs in the corpus (both exploited in the wild) suggest that concurrency bugs in the security and VBS subsystems are a high-value research target. These subsystems are particularly vulnerable to races because they manage state that must be consistent across multiple operations, and the transition to VBS added new state management code that interacts with established code paths in subtle ways.

The VBS attack surface is especially interesting because it targets the boundary between VTL 0 and VTL 1. Microsoft positions VBS as a security boundary backed by hardware virtualization, which means VBS bypass bugs are in the same impact tier as hypervisor escapes. CVE-2024-38106 and CVE-2024-21302 demonstrate that this boundary is not as robust as the hardware backing might suggest.

For the security subsystem TOCTOU patterns, see [Vulnerability Classes](../vuln-classes/). For exploitation primitives that convert race conditions into useful read/write capabilities, see [Primitives](../primitives/).
