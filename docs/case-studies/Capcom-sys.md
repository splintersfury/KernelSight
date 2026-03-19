# Capcom.sys

> Capcom anti-cheat driver, intentional ring-0 code execution with SMEP bypass

## Summary

| Field | Value |
|-------|-------|
| **Driver** | `Capcom.sys` |
| **Vendor** | Capcom |
| **Vulnerability Class** | Logic Bug / Intentional Ring-0 Code Execution |
| **Abused Version** | 1.0.0.4 (shipped with Street Fighter V) |
| **Status** | Withdrawn — Capcom removed the driver; blocklisted |
| **Exploited ITW** | Yes |

## The Story

`Capcom.sys` is arguably the most famous BYOVD driver ever created, and its notoriety is well-earned. It shipped as an anti-cheat component with Capcom's Street Fighter V, and its design raised a question that the security community still references: can you really call it a vulnerability when the driver is doing exactly what it was designed to do?

Here is what happens when you send IOCTL `0xAA013044` to `\\.\Htsysm72FB`. The driver reads a function pointer from the user-supplied buffer. It clears the SMEP bit in CR4, disabling Supervisor Mode Execution Prevention. It calls the user-supplied function pointer from ring 0. When the function returns, it re-enables SMEP. That is the entire IOCTL handler. Capcom built this so their anti-cheat verification code could run in kernel mode. The device object has world-accessible ACLs.

tandasat first documented the behavior. FuzzySecurity wrote the most widely-referenced exploitation guide. The exploit is about 50 lines of code. No heap spray. No race condition. No mitigation bypass needed, because the driver disables the mitigation for you.

## BYOVD Context

- **Driver signing**: Authenticode-signed by Capcom with valid certificate
- **Vulnerable Driver Blocklist**: Included in Microsoft's recommended driver block rules
- **HVCI behavior**: Blocked on HVCI-enabled systems (SMEP disable is incompatible with HVCI)
- **KDU integration**: Not integrated (historical reference)
- **LOLDrivers**: Listed at loldrivers.io — one of the most famous BYOVD examples

## Affected IOCTLs

- `0xAA013044` — Execute user-supplied function pointer in ring 0 with SMEP disabled

## From User-Mode to Ring 0 in Five Steps

The exploitation flow is almost trivially simple. The attacker loads `Capcom.sys` and opens `\\.\Htsysm72FB`. They allocate a user-mode buffer containing their shellcode. They send IOCTL `0xAA013044` with the buffer address as the function pointer. The driver disables SMEP and calls the pointer, executing the shellcode in ring 0. The shellcode performs whatever kernel operation the attacker desires: token swap, rootkit installation, callback registration, or anything else achievable from ring 0.

On systems without HVCI, this gives reliable, deterministic ring-0 code execution. On HVCI-enabled systems, the story changes completely. The hypervisor prevents CR4 modification (so SMEP cannot be disabled) and enforces W^X on code pages (so user-mode pages cannot execute in ring 0). The attack fails outright, which is one of the strongest practical arguments for HVCI deployment.

## Detection

### YARA Rule

```yara
rule Capcom_sys {
    meta:
        description = "Detects Capcom.sys BYOVD driver"
        author = "KernelSight"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $capcom = "Capcom" wide ascii nocase
        $device = "Htsysm72FB" wide ascii
        $cr4_disable = { 0F 20 E0 48 25 FF FF EF FF 0F 22 E0 }
    condition:
        $mz at 0 and ($capcom or $device or $cr4_disable)
}
```

### ETW Indicators

| Provider | Event / Signal | Relevance |
|----------|---------------|-----------|
| Microsoft-Windows-Kernel-File | Driver load event | Detects loading of Capcom.sys |
| Sysmon | Event ID 6 — Driver loaded | Hash and signature capture |
| Microsoft-Windows-Security-Auditing | Event 4697 — Service installed | Service creation for Capcom driver |
| Microsoft-Windows-Kernel-Process | Process token modification | Post-exploitation detection |

### Behavioral Indicators

- Loading of `Capcom.sys` from any path (the driver was withdrawn from legitimate distribution)
- `DeviceIoControl` to `\\.\Htsysm72FB` with IOCTL `0xAA013044`
- CR4 modification (SMEP bit toggling) detectable via hypervisor instrumentation
- Immediate ring-0 code execution from user-supplied pointer
- Any presence of Capcom.sys on a modern system is suspicious

## Broader Significance

`Capcom.sys` is the canonical example of "vulnerable by design." It demonstrates that BYOVD does not require a bug in the traditional sense; a driver that intentionally provides dangerous capabilities with no access control is just as exploitable. The driver also serves as the clearest real-world argument for HVCI: on systems with hypervisor-enforced code integrity, the entire attack class represented by `Capcom.sys` (disable SMEP, execute user-mode shellcode in ring 0) becomes impossible. For defenders, the lesson is that any signed driver that modifies CR4 or executes user-supplied function pointers should be treated as a critical BYOVD risk, regardless of the vendor's stated intent.

## References

- [tandasat — Capcom.sys Analysis](https://github.com/tandasat)
- [FuzzySecurity — Capcom Exploitation](https://www.fuzzysecurity.com/tutorials/28.html)
- [Rapid7 — Capcom.sys Exploitation](https://www.rapid7.com/)
- [LOLDrivers — Capcom.sys](https://www.loldrivers.io/)
