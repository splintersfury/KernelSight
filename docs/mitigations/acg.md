# Arbitrary Code Guard (ACG)

Process-level mitigation that enforces a W^X policy on process memory, preventing dynamic code generation and modification in protected processes.

## Overview

Microsoft introduced Arbitrary Code Guard in Windows 10 RS2 (Creators Update, build 15063) as part of the Windows Defender Exploit Guard suite. ACG prevents a process from allocating memory that is simultaneously writable and executable, or from changing existing memory page permissions from writable to executable. ACG is primarily a user-mode mitigation, but it is relevant to kernel exploitation because many kernel exploit chains end by injecting code into a user-mode process (often a privileged or protected one) for post-exploitation. ACG is also part of the Protected Process Light (PPL) and Code Integrity Guard (CIG) security models, which restrict which processes can be injected into and what code they can execute.

The mitigation is identified internally by the process mitigation policy `ProcessDynamicCodePolicy` and can be configured per-process through the `SetProcessMitigationPolicy` API, Image File Execution Options (IFEO) registry keys, or process creation attributes.

## Mechanism

**W^X Enforcement:**

- `VirtualAlloc` calls with `PAGE_EXECUTE_READWRITE` or `PAGE_EXECUTE_WRITECOPY` protection are rejected with `STATUS_DYNAMIC_CODE_BLOCKED`.
- `VirtualProtect` calls that would change page permissions from writable to executable (e.g., `PAGE_READWRITE` to `PAGE_EXECUTE_READ`) are rejected.
- `VirtualProtect` calls that would change executable pages to writable are also rejected, preventing modification of existing code.
- The enforcement is implemented in the kernel memory manager (`MiArbitraryCodeBlocked`), not in user-mode, so it cannot be bypassed by user-mode hooks.

**Section Mapping Restrictions:**

- Memory-mapped sections with executable permissions must be backed by a signed image file.
- Anonymous sections (created via `NtCreateSection` without a file) cannot be mapped as executable.
- This prevents creating a writable section, writing shellcode, then mapping it as executable.

**JIT Restrictions:**

- Just-In-Time compilation, which requires generating executable code at runtime, is incompatible with ACG.
- Browsers like Chromium and Edge work around this by performing JIT compilation in a separate non-ACG process and mapping the resulting code pages read-only+executable into the ACG-protected renderer process.

**Kernel-Level Enforcement:**

- The policy flag is stored in the `_EPROCESS` structure and checked by `MiArbitraryCodeBlocked` during page allocation and protection changes.
- Because the check occurs in the kernel memory manager, user-mode code in the protected process cannot bypass it through direct system calls.

## Primitives Blocked

- **Shellcode injection into ACG-protected processes:** The classic technique of allocating RWX memory, writing shellcode, and transferring execution is impossible because RWX pages cannot be created.
- **Code cave modification in ACG processes:** Existing executable pages cannot be made writable, so attackers cannot patch existing code to insert hooks or redirects.
- **JIT spray attacks in ACG processes:** Since JIT compilation is blocked (or restricted to out-of-process), JIT spray techniques cannot be used to create attacker-controlled executable content.
- **Reflective DLL injection (unsigned):** Loading unsigned DLLs via manual mapping with executable permissions is blocked because the section must be backed by a signed image.
- **Memory spray with executable payload:** Spraying executable shellcode into the process address space for use as a NOP sled or gadget table is impossible.

## Bypass History

- **Out-of-process JIT (by design):** Chromium/Edge use a separate JIT process that generates code and shares it as read-only into the ACG process. This is an architectural accommodation, not a bypass, but it demonstrates that ACG does not prevent all dynamic code execution.
- **Data-only attacks within the process (always viable):** ACG does not prevent corruption of data structures, function pointers (to existing code), or control flow within the existing code of the process. ROP/JOP chains using existing executable code remain viable.
- **Targeting non-ACG processes (always viable):** Not all processes are ACG-protected. An attacker can inject code into an unprotected process and use it to interact with the system. This shifts the attack to a less-protected target.
- **DLL side-loading with valid signatures:** If a validly signed DLL contains useful code (living-off-the-land), it can be loaded into an ACG process since it passes the signature check.
- **Race conditions during process creation:** In some configurations, there is a window during process initialization before ACG is fully enforced. Exploitation of this window is theoretically possible.

## Kernel Relevance

ACG affects kernel exploitation in several ways:

- **PPL bypass motivation:** Protected Process Light processes use ACG (and CIG). Kernel exploits that inject into PPL processes (e.g., `csrss.exe`, `services.exe`, antivirus engines) must contend with ACG restrictions.
- **Post-exploitation limitations:** After achieving kernel code execution or ARW, injecting a user-mode payload into an ACG-protected process requires using existing signed code paths or targeting a non-ACG process.
- **Combined with HVCI:** When both HVCI (kernel W^X) and ACG (user W^X) are active, there is no memory on the system where custom code can be written and then executed.

## Windows Version Availability

| Version | Status | Notes |
|---------|--------|-------|
| Windows 10 RS2 (1703) | Introduced | Per-process opt-in via `SetProcessMitigationPolicy` |
| Windows 10 RS3 (1709) | Enhanced | Expanded IFEO configuration support |
| Windows 10 RS5-21H2 | Available | Adopted by Edge, system processes |
| Windows 11 21H2+ | Available | Mandatory for certain system services |
| Windows 11 24H2 | Available | Broader enforcement across system processes |

ACG is per-process opt-in. System processes like `svchost.exe` instances, PPL processes, and modern browsers enable it. Legacy applications typically do not use ACG.

## Cross-References

- [VBS / HVCI](vbs-hvci.md) -- kernel-level W^X complement to ACG's user-mode W^X
- [kCFG / kCET](kcfg-kcet.md) -- control flow integrity complements ACG's code generation restrictions
- [Token Swapping](../primitives/exploitation/token-swapping.md) -- data-only kernel technique unaffected by ACG
- [Previous Mode Manipulation](../primitives/exploitation/previous-mode-manipulation.md) -- kernel data-only technique for post-exploitation without code injection
- [CVE-2024-38106](../case-studies/CVE-2024-38106.md) -- kernel race condition exploit where post-exploitation must consider ACG
