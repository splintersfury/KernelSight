# Arbitrary Code Guard (ACG)

A kernel exploit that achieves SYSTEM privileges often wants to inject a payload into a user-mode process: a reverse shell, a credential dumper, an in-memory agent. The traditional injection technique (allocate RWX memory, write shellcode, create a remote thread) has worked reliably for decades. Arbitrary Code Guard blocks it by enforcing a W^X policy on process memory, ensuring that no page can ever be simultaneously writable and executable within a protected process.

ACG is primarily a user-mode mitigation, but it matters for kernel exploitation because it constrains the post-exploitation phase. An attacker who achieves kernel read/write cannot simply inject code into a Protected Process Light (PPL) or a browser renderer. They must use existing signed code paths or target an unprotected process. Combined with [HVCI](vbs-hvci.md), which enforces W^X in kernel space, ACG completes a system-wide model where no memory anywhere can be both written to and executed.

Microsoft introduced ACG in Windows 10 RS2 (Creators Update, build 15063) as part of Windows Defender Exploit Guard. The mitigation is identified internally by `ProcessDynamicCodePolicy` and can be configured per-process through `SetProcessMitigationPolicy`, Image File Execution Options (IFEO) registry keys, or process creation attributes.

## How It Works

**W^X Enforcement** is the core mechanism. `VirtualAlloc` calls requesting `PAGE_EXECUTE_READWRITE` or `PAGE_EXECUTE_WRITECOPY` protection are rejected with `STATUS_DYNAMIC_CODE_BLOCKED`. `VirtualProtect` calls that would transition a page from writable to executable (or vice versa) are similarly rejected. The enforcement is implemented in the kernel memory manager function `MiArbitraryCodeBlocked`, not in user-mode, so it cannot be bypassed by hooking user-mode APIs or making direct system calls from within the protected process.

**Section mapping restrictions** extend the W^X policy to memory-mapped files. Executable sections must be backed by a signed image file. Anonymous sections created via `NtCreateSection` without a backing file cannot be mapped as executable. This prevents the technique of creating a writable section, writing shellcode, then remapping it as executable.

**JIT restrictions** create a tension with just-in-time compilation, which fundamentally requires generating executable code at runtime. Browsers like Chromium and Edge resolve this by performing JIT compilation in a separate non-ACG process and mapping the resulting code pages read-only+executable into the ACG-protected renderer process. This architectural split preserves both JIT performance and ACG protection, though it demonstrates that ACG does not prevent all dynamic code execution across the system.

The policy flag is stored in the `_EPROCESS` structure and checked by `MiArbitraryCodeBlocked` during page allocation and protection changes. Because the enforcement occurs in the kernel memory manager, user-mode code within the protected process cannot bypass it regardless of privilege level within that process.

## What ACG Blocks

Within an ACG-protected process, the classic injection workflow is completely broken. **Shellcode injection** fails because RWX pages cannot be created. **Code cave modification** fails because existing executable pages cannot be made writable. **JIT spray attacks** fail because JIT is either disabled or constrained to an out-of-process model. **Reflective DLL injection** with unsigned DLLs fails because the executable section must be backed by a signed image. **Memory spray with executable payload** fails because no attacker-written memory can become executable.

## Working Around ACG

ACG's per-process model creates several avenues for an attacker who has already achieved kernel-level access.

**Targeting non-ACG processes** is the simplest approach. Not all processes enable ACG. An attacker can inject code into an unprotected process and use it as their foothold. Legacy applications, many third-party services, and some system processes do not enable ACG.

**Data-only attacks within the process** are unaffected by ACG. The mitigation prevents new executable code but does not prevent corruption of function pointers (to existing code), data structures, or control flow within the process's existing code base. ROP/JOP chains using existing signed executable code remain viable within the process.

**DLL side-loading with valid signatures** exploits the fact that validly signed DLLs pass ACG's signature check. If a signed DLL contains useful functionality (living-off-the-land), it can be loaded into an ACG-protected process.

**Out-of-process JIT** is an architectural accommodation, not a bypass, but it illustrates that ACG does not prevent all dynamic code execution across the system. The JIT process itself is not ACG-protected.

**Race conditions during process creation** may provide a window during initialization before ACG is fully enforced, though exploiting this window is difficult in practice.

## Why It Matters for Kernel Exploitation

ACG affects kernel exploitation at the post-exploitation boundary. **PPL bypass motivation** drives many kernel exploits: Protected Process Light processes use ACG (and Code Integrity Guard). Kernel exploits that target `csrss.exe`, `services.exe`, or antivirus engines must contend with ACG when attempting to inject payloads into these protected processes.

**Post-exploitation payload delivery** becomes more complex. After achieving kernel ARW, the attacker cannot simply allocate executable memory and write shellcode into a protected target. They must use existing signed code paths, target an unprotected process, or use data-only techniques like token swapping that achieve their goals without code injection.

**System-wide W^X** is achieved when both HVCI (kernel) and ACG (user-mode protected processes) are active. In this configuration, there is no memory on the system where custom code can be written and then executed, forcing the attacker into entirely data-driven post-exploitation strategies.

## Windows Version Availability

| Version | Status | Notes |
|---------|--------|-------|
| Windows 10 RS2 (1703) | Introduced | Per-process opt-in via `SetProcessMitigationPolicy` |
| Windows 10 RS3 (1709) | Enhanced | Expanded IFEO configuration support |
| Windows 10 RS5-21H2 | Available | Adopted by Edge, system processes |
| Windows 11 21H2+ | Available | Mandatory for certain system services |
| Windows 11 24H2 | Available | Broader enforcement across system processes |

ACG is per-process opt-in. System processes like certain `svchost.exe` instances, PPL processes, and modern browsers enable it. Legacy applications typically do not use ACG, and forcing it on incompatible applications would break JIT-dependent functionality.

## Cross-References

- [VBS / HVCI](vbs-hvci.md) -- kernel-level W^X complement to ACG's user-mode W^X
- [kCFG / kCET](kcfg-kcet.md) -- control flow integrity complements ACG's code generation restrictions
- [Token Swapping](../primitives/exploitation/token-swapping.md) -- data-only kernel technique unaffected by ACG
- [Previous Mode Manipulation](../primitives/exploitation/previous-mode-manipulation.md) -- kernel data-only technique for post-exploitation without code injection
- [CVE-2024-38106](../case-studies/CVE-2024-38106.md) -- kernel race condition exploit where post-exploitation must consider ACG
