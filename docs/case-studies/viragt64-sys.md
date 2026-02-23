# viragt64.sys

> TG Soft VirIT antivirus — process termination IOCTL abused by Kasseika ransomware

## Summary

| Field | Value |
|-------|-------|
| **Driver** | `viragt64.sys` |
| **Vendor** | TG Soft (VirIT) |
| **Vulnerability Class** | Logic Bug / Process Termination |
| **Abused Version** | Multiple versions |
| **Status** | Blocklisted — added to Microsoft Vulnerable Driver Blocklist |
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

## Root Cause

`viragt64.sys` is the kernel-mode component of TG Soft's VirIT antivirus product. As a security product, the driver has legitimate need to terminate malicious processes. It exposes an IOCTL that accepts a process ID and terminates the corresponding process using kernel-mode APIs (e.g., `ZwTerminateProcess` with a kernel handle).

The vulnerability is insufficient access control on the termination IOCTL. The driver does not verify that the caller has appropriate privileges or that the target process should be terminated. Any process that can open the device handle can terminate any other process on the system, including other security products.

Trend Micro documented the abuse of `viragt64.sys` by the Kasseika ransomware operation. The attackers:
1. Deploy `viragt64.sys` via BYOVD
2. Use the termination IOCTL to kill all AV/EDR processes
3. Deploy the ransomware payload with security software disabled

## Exploitation

The process termination attack pattern:

1. Load `viragt64.sys` on the target system
2. Open the device handle
3. Enumerate running processes to identify security products
4. Send the termination IOCTL for each security process PID
5. All AV/EDR processes are terminated
6. Deploy ransomware or other malware payload

This represents a "kill before encrypt" BYOVD pattern increasingly common in ransomware operations.

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
| Sysmon | Event ID 6 — Driver loaded | Hash and signature capture |
| Microsoft-Windows-Security-Auditing | Event 4697 — Service installed | Service creation |
| Microsoft-Windows-Kernel-Process | Process termination events | Mass process termination of security products |

### Behavioral Indicators

- Loading of `viragt64.sys` from a path unrelated to TG Soft VirIT installation
- Rapid sequential process termination of multiple security product processes
- Temporal correlation: security process termination followed by ransomware execution
- Service creation for TG Soft driver by a non-TG-Soft process

## References

- [Trend Micro — Kasseika Ransomware BYOVD Analysis](https://www.trendmicro.com/en_us/research/24/a/kasseika-ransomware-deploys-byovd-attack-abuses-psexec.html)
- [LOLDrivers — viragt64](https://www.loldrivers.io/)
