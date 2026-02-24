# Capcom.sys

> Capcom anti-cheat driver — intentional ring-0 code execution with SMEP bypass

## Summary

| Field | Value |
|-------|-------|
| **Driver** | `Capcom.sys` |
| **Vendor** | Capcom |
| **Vulnerability Class** | Logic Bug / Intentional Ring-0 Code Execution |
| **Abused Version** | 1.0.0.4 (shipped with Street Fighter V) |
| **Status** | Withdrawn — Capcom removed the driver; blocklisted |
| **Exploited ITW** | Yes |

## BYOVD Context

- **Driver signing**: Authenticode-signed by Capcom with valid certificate
- **Vulnerable Driver Blocklist**: Included in Microsoft's recommended driver block rules
- **HVCI behavior**: Blocked on HVCI-enabled systems (SMEP disable is incompatible with HVCI)
- **KDU integration**: Not integrated (historical reference)
- **LOLDrivers**: Listed at loldrivers.io — one of the most famous BYOVD examples

## Affected IOCTLs

- `0xAA013044` — Execute user-supplied function pointer in ring 0 with SMEP disabled

## Root Cause

`Capcom.sys` is the most well-known BYOVD driver. It shipped as an anti-cheat component with Capcom's Street Fighter V. The driver's IOCTL handler accepts a user-mode function pointer via `DeviceIoControl`, then:

1. Disables SMEP (Supervisor Mode Execution Prevention) by clearing the relevant bit in CR4
2. Calls the user-supplied function pointer from ring 0
3. Re-enables SMEP after the call returns

This is not a bug but the driver's intended design. Capcom implemented it to run anti-cheat verification code in kernel mode. Any process that can open the device (world-accessible ACLs) can execute arbitrary code in ring 0 by providing a function pointer. No memory corruption, no exploitation chain, just a direct call.

tandasat first documented the vulnerability. FuzzySecurity wrote the most widely-referenced exploitation guide. Rapid7 published additional analysis.

## Exploitation

1. Load `Capcom.sys` and open `\\.\Htsysm72FB`
2. Allocate a user-mode buffer containing shellcode
3. Send IOCTL `0xAA013044` with the buffer address as the function pointer
4. The driver disables SMEP and calls the pointer, executing shellcode in ring 0
5. Shellcode performs token swap, installs rootkit, or runs any kernel operation

The exploit is about 50 lines of code. No heap spray, no race condition, no mitigation bypass needed (the driver disables SMEP itself). On systems without HVCI, this gives reliable ring-0 code execution.

On HVCI-enabled systems, the driver cannot disable SMEP (the hypervisor prevents CR4 modification) and cannot execute user-mode code pages (W^X enforcement), so the attack fails.

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

## References

- [tandasat — Capcom.sys Analysis](https://github.com/tandasat)
- [FuzzySecurity — Capcom Exploitation](https://www.fuzzysecurity.com/tutorials/28.html)
- [Rapid7 — Capcom.sys Exploitation](https://www.rapid7.com/)
- [LOLDrivers — Capcom.sys](https://www.loldrivers.io/)
