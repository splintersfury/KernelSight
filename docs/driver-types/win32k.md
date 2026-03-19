# Win32k Subsystem

<div class="ks-pipeline-pos">
  <span class="ks-active">Driver Type</span> &rarr; Attack Surface &rarr; Vuln Class &rarr; Primitive &rarr; Case Study
</div>

For over a decade, Win32k was the single most exploited component in the Windows kernel. Sandbox escape chains for Chrome and Edge reliably ended with a Win32k bug. Nation-state actors stockpiled Win32k zero-days. The sheer volume of bugs led Microsoft to invest in syscall filtering, type isolation, and eventually Win32k lockdown for certain process types. The three CVEs in the KernelSight corpus represent the current state of this arms race: the bugs are harder to find and harder to exploit than they were five years ago, but the attack surface is still enormous, and the structural patterns that produce bugs, complex object hierarchies, re-entrant callbacks, and a massive syscall table, have not fundamentally changed.

## Architecture

The Win32k subsystem is not a single driver but a family of kernel components that implement the Windows graphical interface. On modern Windows, the code is split across three binaries: `win32kbase.sys` handles core window management and class registration, `win32kfull.sys` handles the full desktop experience including menus, cursors, hooks, and message dispatch, and the legacy `win32k.sys` contains GDI operations for fonts, glyphs, bitmaps, and device contexts.

Unlike most kernel drivers, Win32k is loaded into per-session address space and exposes approximately 1,200 `NtUser*` and `NtGdi*` system calls directly callable from user mode. Any GUI process can invoke these syscalls, which means any process with a desktop can reach the Win32k attack surface. This is what made Win32k historically valuable for sandbox escapes: even sandboxed processes typically have access to a subset of Win32k syscalls.

``` mermaid
graph TD
    A["User Mode Process<br/>GUI Application"] -->|"~1200 NtUser*/NtGdi* syscalls"| B["Win32k Subsystem"]
    B --> C["win32kbase.sys<br/>Window mgmt, class reg"]
    B --> D["win32kfull.sys<br/>Menus, hooks, messages"]
    B --> E["win32k.sys (legacy)<br/>GDI: fonts, bitmaps, DCs"]
    C -->|"User-mode callbacks"| A
    D -->|"Object hierarchies"| F["Window/Menu/Cursor<br/>Kernel Objects"]

    style A fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    style B fill:#152a4a,stroke:#ef4444,color:#e2e8f0
    style C fill:#152a4a,stroke:#3b82f6,color:#e2e8f0
    style D fill:#152a4a,stroke:#3b82f6,color:#e2e8f0
    style E fill:#152a4a,stroke:#3b82f6,color:#e2e8f0
    style F fill:#0d1320,stroke:#f59e0b,color:#e2e8f0
```

## The Bug Patterns That Won't Die

Win32k bugs are structurally different from the buffer overflows and integer overflows that dominate file system and network stack drivers. The vulnerability patterns here arise from the complexity of managing thousands of kernel objects (windows, menus, cursors, bitmaps, device contexts) with intricate parent/child/owner relationships, reference counting, and a callback mechanism that hands control back to user mode mid-operation.

**Type confusion via flag manipulation** is the pattern behind CVE-2022-21882. The `ConsoleWindow` flag in win32kbase.sys changes how the kernel interprets the `WndExtra` data associated with a window class. When the flag state is manipulated, the kernel treats a kernel pointer as a user-mode offset (or vice versa), giving the attacker control over where the kernel reads or writes data. The `xxxClientAllocWindowClassExtraBytes` callback path is a classic Win32k exploitation vector because it transitions to user mode and back, allowing the attacker to modify window state while the kernel holds stale assumptions about that state.

**Use-after-free from nested object destruction** drives CVE-2023-29336. Win32k menu objects form hierarchies where a parent menu owns child submenus. When a menu is destroyed, the destruction must walk the hierarchy and release all child objects. If the destruction sequence is interrupted (by a message dispatch, a callback, or a race with another thread), a child object can be freed while a reference to it persists elsewhere. The freed memory is reclaimed by a controlled allocation, and the stale reference now points to attacker-controlled data. Win32k has had dozens of menu UAF bugs over the years; CVE-2023-29336 is the latest in a long series.

**Information disclosure from uninitialized buffers** appears in CVE-2024-38256. GDI operations produce output buffers that may contain more fields than the operation actually populates. If the buffer is allocated from pool memory without being zeroed, the uninitialized fields contain stale data from previous allocations, potentially including kernel pointers. This is lower severity than the type confusion and UAF bugs, but it provides the address leak that makes ASLR bypass possible, which is often a prerequisite for exploiting the more powerful bugs.

## Vulnerability Patterns and Detection

| Pattern | Description | AutoPiff Rules |
|---------|-------------|----------------|
| Type confusion via flags | Window flag misinterpretation treats kernel data as user offset | `object_type_validation_added`, `handle_object_type_check_added` |
| UAF from menu objects | Nested menu destruction frees object still referenced | `ob_reference_balance_fix` |
| Info leak via uninitialized | GDI output buffer contains stale kernel pointers | `stack_variable_initialization_added`, `kernel_pointer_scrubbing_added` |
| Callback re-entrancy | User-mode callback allows modifying objects mid-operation | (complex pattern, not directly rule-matched) |

The callback re-entrancy pattern deserves special attention because it is the enabler for many Win32k bugs rather than a standalone vulnerability class. When the kernel calls back to user mode (via `xxxClientAllocWindowClassExtraBytes`, `xxxSendMessage`, or similar functions), the user-mode code can call back into the kernel, modify the objects that the original kernel function is operating on, and return. The kernel then continues with stale assumptions about object state. This pattern is extremely difficult to detect through patch diffing alone because the fix is often a lock acquisition or a state re-validation deep in a call chain.

## CVEs

| CVE | Driver | Description | Class | ITW |
|-----|--------|-------------|-------|-----|
| [CVE-2022-21882](../case-studies/CVE-2022-21882.md) | `win32kbase.sys` | ConsoleWindow flag type confusion EoP | Type Confusion | Yes |
| [CVE-2023-29336](../case-studies/CVE-2023-29336.md) | `win32kfull.sys` | UAF from unlocked nested menu object | Use-After-Free | Yes |
| [CVE-2024-38256](../case-studies/CVE-2024-38256.md) | `win32k.sys` | Uninitialized resource leaks kernel memory | Info Disclosure | No |

## Microsoft's Mitigation History

Win32k's history of exploitation has driven a significant investment in mitigations, each targeting a specific bug pattern.

**Win32k syscall filtering** restricts which NtUser/NtGdi syscalls are available to specific process types. Microsoft Edge and Chrome use this to prevent sandboxed renderer processes from reaching most of the Win32k attack surface. This dramatically reduced the value of Win32k bugs for browser sandbox escapes, though it does not help for other process types.

**Win32k lockdown** goes further by preventing Win32k from being loaded into certain processes at all. If the subsystem is not loaded, no Win32k syscalls are available, and the entire attack surface is eliminated for that process.

**Type isolation** moves Win32k objects to isolated pool regions, making it harder to groom adjacent allocations for exploitation after a UAF or type confusion. This does not prevent the bug itself but raises the difficulty of converting the bug into a useful primitive.

Despite these mitigations, the sheer size of the syscall surface (approximately 1,200 handlers) means that new bugs continue to be discovered. The mitigations primarily limit *who* can reach the bugs, not whether the bugs exist. For processes that still have Win32k access (desktop applications, services, many system processes), the full attack surface remains available.

## Research Outlook

Win32k research today requires more effort than it did five years ago, but the structural properties that produce bugs have not changed. The object management code still handles complex hierarchies with reference counting and callbacks to user mode. The syscall table still has over a thousand entry points. And the code paths for window management, menu handling, and GDI operations are deeply intertwined, creating interaction bugs that are difficult to find through automated fuzzing alone.

Researchers should note that Win32k syscall filtering means these bugs are most valuable for scenarios where the attacker already has code execution in a process with Win32k access, rather than for browser sandbox escapes (which was the historical use case). Local privilege escalation from a desktop application or a compromised service is the primary exploitation scenario today.

For the broader context of how syscall-based attack surfaces differ from IOCTL-based ones, see [Attack Surfaces](../attack-surfaces/). For the type confusion and UAF vulnerability classes that dominate Win32k, see [Vulnerability Classes](../vuln-classes/).
