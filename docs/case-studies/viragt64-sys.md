# viragt64.sys

> TG Soft VirIT antivirus -- the ransomware industry's favorite process termination driver

## Summary

| Field | Value |
|-------|-------|
| **Driver** | `viragt64.sys` |
| **Vendor** | TG Soft (VirIT) |
| **Vulnerability Class** | Logic Bug / Process Termination |
| **Abused Version** | Multiple versions |
| **Status** | Blocklisted -- added to Microsoft Vulnerable Driver Blocklist |
| **Exploited ITW** | Yes |

## BYOVD Context

- **Driver signing**: Authenticode-signed by TG Soft with valid certificate
- **Vulnerable Driver Blocklist**: Included in Microsoft's recommended driver block rules
- **HVCI behavior**: Blocked on HVCI-enabled systems via the blocklist
- **KDU integration**: Not integrated
- **LOLDrivers**: Listed at loldrivers.io

## Affected IOCTLs

- Process termination by PID via IOCTL
- Process enumeration

## The Kill-Before-Encrypt Pattern

Kasseika ransomware made `viragt64.sys` famous by establishing what has become the dominant BYOVD abuse pattern in ransomware operations: kill security software, then encrypt. Before Kasseika, most BYOVD abuse focused on sophisticated kernel exploitation chains that swapped tokens or corrupted security descriptors. Kasseika showed that a simple process termination IOCTL is enough. If you can kill every EDR process on the machine, you do not need a privilege escalation. You just need a clear path to encrypt files without interference.

This "kill-before-encrypt" pattern has since been adopted by Reynolds ransomware ([CVE-2025-68947](CVE-2025-68947.md)), the EnPortv.sys EDR killer ([EnPortv.sys](EnPortv-sys.md)), and multiple other ransomware operations. viragt64.sys was the driver that proved the pattern works.

## Root Cause

`viragt64.sys` is the kernel-mode component of TG Soft's VirIT antivirus product. As a security product, the driver has a legitimate need to terminate malicious processes that user-mode APIs cannot touch. It exposes an IOCTL that accepts a process ID and terminates the corresponding process using kernel-mode APIs, specifically `ZwTerminateProcess` with a kernel handle that bypasses all user-mode protections and PPL flags.

The vulnerability is the complete absence of access control on this IOCTL. The driver does not verify that the caller is the VirIT application. It does not check the caller's token or signature. It does not restrict which processes can be targeted. Any process that can open the device handle can terminate any other process on the system.

## Exploitation

Trend Micro documented Kasseika's abuse of `viragt64.sys` in detail. The ransomware operators deploy the driver to the target system as part of their initial payload. They create a kernel service to load it, which requires local admin privileges (already obtained at this stage of a ransomware attack). They enumerate running processes and identify security products by name or hash.

For each security product process, they send the termination IOCTL with the target PID. The driver terminates the process from kernel mode, bypassing any self-protection the security product has implemented. Within seconds, all AV and EDR products are dead. The ransomware payload then executes with no interference.

The temporal pattern is distinctive: driver load, followed by rapid sequential termination of multiple security processes, followed by ransomware execution. This pattern is the behavioral signature of the kill-before-encrypt technique.

## Detection

### YARA Rule

```yara
rule viragt64_sys {
    meta:
        description = "Detects TG Soft viragt64.sys vulnerable driver"
        author = "KernelSight"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $viragt = "viragt64" wide ascii nocase
        $tgsoft = "TG Soft" wide ascii
        $virit = "VirIT" wide ascii
    condition:
        $mz at 0 and ($viragt or $tgsoft or $virit)
}
```

### ETW Indicators

| Provider | Event / Signal | Relevance |
|----------|---------------|-----------|
| Microsoft-Windows-Kernel-File | Driver load event | Detects loading of viragt64.sys |
| Sysmon | Event ID 6 -- Driver loaded | Hash and signature capture |
| Microsoft-Windows-Security-Auditing | Event 4697 -- Service installed | Service creation |
| Microsoft-Windows-Kernel-Process | Process termination events | Mass process termination of security products |

### Behavioral Indicators

- Loading of `viragt64.sys` from a path unrelated to TG Soft VirIT installation
- Rapid sequential process termination of multiple security product processes
- Temporal correlation: security process termination followed by ransomware execution
- Service creation for TG Soft driver by a non-TG-Soft process

## Broader Significance

viragt64.sys is the case study that best illustrates the shift in BYOVD from kernel exploitation to operational tooling. Earlier BYOVD drivers like [RTCore64.sys](CVE-2019-16098.md) and [DBUtil_2_3.sys](CVE-2021-21551.md) were valued for their arbitrary read/write primitives, which enabled sophisticated kernel exploits. viragt64.sys has no read/write primitive at all. Its only useful capability is killing processes. But for ransomware operators, that single capability is more valuable than a kernel R/W, because it directly removes the one obstacle between them and their objective: encrypting files for ransom.

## References

- [Trend Micro -- Kasseika Ransomware BYOVD Analysis](https://www.trendmicro.com/en_us/research/24/a/kasseika-ransomware-deploys-byovd-attack-abuses-psexec.html)
- [LOLDrivers -- viragt64](https://www.loldrivers.io/)
