# Security / Policy Drivers

<div class="ks-pipeline-pos">
  <span class="ks-active">Driver Type</span> &rarr; Attack Surface &rarr; Vuln Class &rarr; Primitive &rarr; Case Study
</div>

In February 2024, Avast disclosed that the Lazarus Group had been exploiting CVE-2024-21338 in appid.sys for months. The bug was not a memory corruption vulnerability. It was a missing access check on an IOCTL that dispatched a caller-controlled function pointer from a kernel pool allocation. An attacker with admin privileges could send a single IOCTL and get direct kernel code execution, no heap spray, no race condition, no exploit chain. This is the defining characteristic of security and policy driver bugs: they often bypass the entire memory corruption exploitation process because the driver's own functionality, when accessed by the wrong caller, *is* the primitive.

## How Security Drivers Fit Into the Kernel

Security and policy enforcement drivers implement the access control, code integrity, and application whitelisting mechanisms that the rest of the OS depends on. They are WDM or minifilter drivers that run with full kernel privileges and are trusted by the security subsystem. The two primary Microsoft security drivers are `appid.sys` (AppLocker application whitelisting) and `ci.sys` (Code Integrity / WDAC enforcement).

These drivers occupy a unique position in the threat model. They are *the enforcement layer*, the code that decides whether a process can run, whether a binary is signed, whether a DLL can be loaded. A bug in these drivers does not just give the attacker elevated privileges; it gives them the ability to disable or subvert the enforcement mechanism itself. This is why security driver bugs are disproportionately targeted by nation-state actors: compromising the enforcement layer provides persistence and stealth that a simple privilege escalation does not.

``` mermaid
graph TD
    A["Admin Process"] -->|"DeviceIoControl"| B["appid.sys<br/>AppLocker"]
    B -->|"IOCTL 0x22A018"| C["Dispatch Function Pointer<br/>from pool allocation"]
    C -->|"Ring 0 Execution"| D["Kernel Code Exec<br/>No corruption needed"]

    E["Policy Load"] --> F["ci.sys<br/>Code Integrity"]
    F -->|"HVCI systems"| G["KDP Protected<br/>Read-only policy"]

    style A fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    style B fill:#152a4a,stroke:#ef4444,color:#e2e8f0
    style C fill:#0d1320,stroke:#ef4444,color:#e2e8f0
    style D fill:#0d1320,stroke:#ef4444,color:#e2e8f0
    style E fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    style F fill:#152a4a,stroke:#3b82f6,color:#e2e8f0
    style G fill:#0d1320,stroke:#10b981,color:#e2e8f0
```

## The AppLocker IOCTL: Design Becomes Vulnerability

CVE-2024-21338 is a case study in how a feature's design can become its vulnerability. The `\Device\AppId` device exposes an IOCTL (0x22A018) that is part of AppLocker's internal hash computation mechanism. The IOCTL handler receives a structure from the caller that contains, among other fields, a function pointer. The handler allocates a pool buffer, copies the structure into it, and then dispatches through the function pointer at ring 0.

The intended caller is the AppLocker service, which uses this IOCTL as part of its policy evaluation pipeline. But the device object's security descriptor allows access from any administrative process, not just the AppLocker service. An attacker with admin privileges can open a handle to `\Device\AppId`, craft an IOCTL input with a function pointer to their shellcode (or a ROP gadget), and the kernel will execute it directly.

What makes this particularly interesting is that it requires no memory corruption at all. The attacker does not need to find an overflow, win a race, or spray the heap. The driver's own legitimate functionality, dispatching a function pointer, is the exploit. The "vulnerability" is that the access check does not restrict the IOCTL to its intended caller. This is a pure logic bug, and Lazarus Group used it for months before it was patched.

The fix was straightforward: add a proper access check to verify the caller's identity before processing the IOCTL. In AutoPiff terms, this shows up as `ioctl_input_size_validation_added` and `ioctl_code_default_case_added` patterns, though the core fix is really about authorization rather than input validation.

## Code Integrity and ci.sys

`ci.sys` implements the Code Integrity subsystem, including Windows Defender Application Control (WDAC) and Hypervisor-protected Code Integrity (HVCI). Unlike appid.sys, ci.sys is protected by Kernel Data Protection (KDP) on HVCI-enabled systems, which makes its policy data read-only to kernel-mode code running at VTL 0. This architectural protection means that even if an attacker achieves kernel code execution, they cannot directly modify ci.sys's policy data on an HVCI system.

The attack surface for ci.sys is therefore less about IOCTL bugs and more about policy manipulation: finding signed binaries or drivers that ci.sys trusts but that can be abused, or finding ways to influence the policy evaluation logic without modifying the policy data itself. This moves the attack from "find a bug in ci.sys" to "find a gap in the policy that ci.sys faithfully enforces."

## Vulnerability Patterns and Detection

| Pattern | Description | AutoPiff Rules |
|---------|-------------|----------------|
| Missing IOCTL access check | Privileged IOCTL accessible without admin check | `ioctl_input_size_validation_added`, `ioctl_code_default_case_added` |
| BYOVD via policy driver | Using legitimate signed policy driver for kernel R/W | `device_acl_hardening` |

## CVEs

| CVE | Driver | Description | Class | ITW |
|-----|--------|-------------|-------|-----|
| [CVE-2024-21338](../case-studies/CVE-2024-21338.md) | `appid.sys` | IOCTL 0x22A018 missing access control allows kernel code exec | Logic Bug | Yes |

## Research Outlook

Security driver bugs occupy a unique niche in kernel exploitation research. They provide the most direct path from "code execution as admin" to "code execution in the kernel" because their functionality is already security-sensitive by design. An IOCTL that terminates processes, manipulates security tokens, or dispatches function pointers is doing *exactly what the driver was designed to do*, just for the wrong caller.

This makes security drivers a priority audit target for researchers focused on admin-to-kernel escalation scenarios. The specific question to ask when auditing a security driver is not "does this code have a buffer overflow?" but "who is allowed to call this, and is that restriction actually enforced?" The Lazarus Group's exploitation of CVE-2024-21338 demonstrates that nation-state actors actively look for these gaps.

For third-party security product drivers (AV, EDR, anti-rootkit, anti-cheat) that share similar vulnerability patterns but are not part of the Windows security subsystem, see [Third-Party Security Drivers](third-party-security.md). For the IOCTL access control patterns that appear across driver types, see [Attack Surfaces](../attack-surfaces/).
