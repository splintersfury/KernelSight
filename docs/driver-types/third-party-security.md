# Third-Party Security Drivers

<div class="ks-pipeline-pos">
  <span class="ks-active">Driver Type</span> &rarr; Attack Surface &rarr; Vuln Class &rarr; Primitive &rarr; Case Study
</div>

Capcom.sys is an anti-cheat driver that intentionally disables SMEP and executes a user-supplied function pointer in ring 0. It does this by design: the anti-cheat protection mechanism requires running user code with kernel privileges to inspect game memory for cheating tools. The "vulnerability" is that any process on the system, not just the Capcom game, can call the IOCTL and get arbitrary code execution in the kernel. This is the paradox at the heart of third-party security drivers: the capabilities that make them effective at their security function (process termination, callback management, kernel object inspection) are exactly the capabilities that attackers want.

!!! note "Distinct from Security / Policy Drivers"
    This category covers **third-party** security product kernel drivers (AV, EDR, anti-cheat). For Microsoft's built-in security enforcement drivers (appid.sys, ci.sys), see [Security / Policy Drivers](security-policy.md).

## Why Security Drivers Are Different

Third-party security drivers, including antivirus, EDR, anti-rootkit, and anti-cheat kernel modules, differ from the other driver categories in a fundamental way. Their vulnerability is not a bug in the traditional sense. There is no buffer overflow to trigger, no integer overflow to exploit, no race condition to win. Instead, the driver's legitimate functionality, when accessed by an unauthorized caller, provides exactly the capabilities an attacker needs.

The five drivers in the KernelSight corpus illustrate the range of capabilities that security drivers intentionally expose:

Capcom.sys disables SMEP and jumps to a user-mode function pointer in ring 0, giving the caller arbitrary kernel code execution. echo_driver.sys enumerates and removes kernel notification callbacks, blinding EDR products that depend on those callbacks for visibility. viragt64.sys terminates arbitrary processes by PID, allowing ransomware to kill antivirus before encrypting files. Truesight.sys duplicates handles to protected processes and terminates them, bypassing PPL (Protected Process Light) protections that are supposed to prevent exactly this. amsdk.sys terminates security product processes with insufficient access control on the termination IOCTL.

Each of these capabilities exists because the security product needs it. An anti-cheat driver needs to inspect process memory. An anti-rootkit needs to examine kernel callbacks. An antivirus driver needs to terminate malicious processes. The problem is not that these capabilities exist, but that the access control on the IOCTLs that expose them is insufficient to prevent abuse by unauthorized callers.

## Architecture and Attack Surface

Third-party security drivers are typically WDM or minifilter drivers that register kernel callbacks through `PsSetCreateProcessNotifyRoutine`, `ObRegisterCallbacks`, and `CmRegisterCallback`. They create device objects with IOCTL interfaces for management, and they interact directly with security-sensitive kernel objects.

``` mermaid
graph TD
    A["Attacker Process"] -->|"DeviceIoControl"| B["Security Driver<br/>Legitimately Signed"]
    B -->|"Process Term"| C["ZwTerminateProcess<br/>Kill AV/EDR"]
    B -->|"Callback Removal"| D["PspNotifyRoutines<br/>Blind EDR"]
    B -->|"Handle Dup"| E["ObOpenObjectByPointer<br/>Bypass PPL"]
    B -->|"Ring-0 Exec"| F["User Function Ptr<br/>Kernel Code Exec"]

    style A fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    style B fill:#152a4a,stroke:#ef4444,color:#e2e8f0
    style C fill:#0d1320,stroke:#ef4444,color:#e2e8f0
    style D fill:#0d1320,stroke:#ef4444,color:#e2e8f0
    style E fill:#0d1320,stroke:#ef4444,color:#e2e8f0
    style F fill:#0d1320,stroke:#ef4444,color:#e2e8f0
```

The attack surfaces cluster into four categories, each representing a different security product capability being repurposed.

**Ring-0 code execution** (Capcom.sys) is the most extreme case. The driver's IOCTL handler takes a user-mode function pointer, disables SMEP (Supervisor Mode Execution Prevention) by clearing the corresponding bit in CR4, and calls the function pointer from ring 0. After the function returns, SMEP is re-enabled. This gives the attacker unrestricted kernel code execution through a single IOCTL call. tandasat and FuzzySecurity documented the exploitation; Capcom.sys became one of the most famous BYOVD examples in the security community.

**Process termination** (viragt64.sys, amsdk.sys) is the most operationally useful capability for ransomware actors. Both drivers expose IOCTLs that accept a process ID and terminate the corresponding process using kernel-level termination functions that bypass user-mode protections. Trend Micro documented Kasseika ransomware using viragt64.sys to terminate AV/EDR processes before beginning encryption. Check Point documented Silver Fox APT using amsdk.sys for the same purpose. The "vulnerability" in both cases is insufficient access control: the IOCTL should verify that the caller is the legitimate security management application, but it does not.

**Callback manipulation** (echo_driver.sys) targets the kernel notification system that EDR products depend on. Windows provides kernel callbacks for process creation, thread creation, image load, and registry operations. EDR products register callbacks through `PsSetCreateProcessNotifyRoutine` and similar APIs to gain visibility into system activity. echo_driver.sys exposes an IOCTL that enumerates the internal callback array (`PspNotifyRoutines`) and allows removing individual entries. kite03's GitHub PoC demonstrates the technique: by removing all process creation callbacks, the attacker blinds every EDR product on the system in a single operation.

**Handle elevation** (Truesight.sys) targets Protected Process Light (PPL), a security mechanism that prevents even administrator-level processes from opening handles to certain protected processes (like antimalware services). Truesight.sys, as an anti-rootkit tool, legitimately needs to examine protected processes. It exposes IOCTLs that duplicate handles to protected processes with full access rights, bypassing the PPL protection. Check Point Research documented attackers repurposing this capability to obtain handles to PPL-protected processes, enabling them to read memory, inject code, or terminate the process. The driver's anti-rootkit capabilities were repurposed against defenders.

## Vulnerability Patterns and Detection

| Pattern | Description | AutoPiff Rules |
|---------|-------------|----------------|
| Ring-0 code execution | Driver executes user-supplied function pointer in kernel mode | `direct_arw_ioctl_detected` |
| Process termination | IOCTL terminates arbitrary processes by PID | `privilege_check_added` |
| Callback manipulation | Enumerates and zeros kernel notification callbacks | `access_mode_enforcement_added` |
| EDR bypass | Removes or disables security product hooks and callbacks | `authorization_validation_added` |
| Handle elevation | Opens handles to protected processes bypassing PPL | `handle_force_access_check_added` |

## CVEs

| CVE | Driver | Description | Class | ITW |
|-----|--------|-------------|-------|-----|
| [Capcom.sys](../case-studies/Capcom-sys.md) | `Capcom.sys` | Capcom anti-cheat, ring-0 code exec, SMEP bypass | Logic Bug | Yes |
| [echo_driver.sys](../case-studies/echo-driver-sys.md) | `echo_driver.sys` | Echo AC, kernel callback manipulation | Logic Bug | No |
| [viragt64.sys](../case-studies/viragt64-sys.md) | `viragt64.sys` | TG Soft VirIT, process termination via IOCTL | Logic Bug | Yes |
| [Truesight.sys](../case-studies/Truesight-sys.md) | `Truesight.sys` | RogueKiller, EDR bypass | Logic Bug | Yes |
| [amsdk.sys](../case-studies/amsdk-sys.md) | `amsdk.sys` | WatchDog, process termination | Logic Bug | Yes |

Four of five are confirmed exploited in the wild. All five are logic bugs, not memory corruption vulnerabilities. This is the signature of the third-party security driver category: the bugs are design-level issues, not implementation errors.

## The BYOVD Threat Model

Third-party security drivers represent a specific evolution of the BYOVD threat. While [vendor utility drivers](vendor-utility.md) provide generic hardware access (physical memory, MSR, I/O ports), security drivers provide *tactical* capabilities: kill AV, blind EDR, bypass PPL, execute kernel code. An attacker who loads a vendor utility driver needs to build their own exploitation logic on top of the primitive. An attacker who loads Truesight.sys or viragt64.sys gets a ready-made tool for the specific operational step they need.

This distinction matters for defense. Microsoft's Vulnerable Driver Blocklist blocks known driver hashes, but the blocklist is reactive: it requires each driver to be identified, analyzed, and added. The LOLDrivers project catalogs known-abusable drivers, but the pipeline from discovery to blocklist entry takes time. And because these drivers are legitimately signed by their developers (Adlice, TG Soft, WatchDog Development, Capcom), the signing certificate is valid, and the driver passes signature verification even when it is loaded by an attacker.

## Research Outlook

The supply of third-party security drivers available for BYOVD abuse continues to grow. Every AV vendor, EDR product, anti-rootkit tool, and anti-cheat system installs a kernel driver, and many of these drivers expose process termination, callback management, or other security-sensitive operations through IOCTLs with inadequate access control.

Researchers should audit security product drivers with a specific question: "What operations does this driver expose, and what happens if the caller is not the intended management application?" The answer frequently reveals capabilities that are directly useful for attackers, protected only by the assumption that the driver will only be loaded in the context of the legitimate security product.

For Microsoft's built-in security enforcement drivers (appid.sys, ci.sys), which share the "logic bug" pattern but operate at a different privilege level, see [Security / Policy Drivers](security-policy.md). For the vendor utility drivers that provide generic hardware access primitives, see [Vendor Utility Drivers](vendor-utility.md).
