# amsdk.sys

> WatchDog Development security driver — process termination abused by Silver Fox APT

## Summary

| Field | Value |
|-------|-------|
| **Driver** | `amsdk.sys` |
| **Vendor** | WatchDog Development |
| **Vulnerability Class** | Logic Bug / Process Termination |
| **Abused Version** | Multiple versions |
| **Status** | Blocklisted — added to Microsoft Vulnerable Driver Blocklist |
| **Exploited ITW** | Yes |

## BYOVD Context

- **Driver signing**: Authenticode-signed by WatchDog Development with valid certificate
- **Vulnerable Driver Blocklist**: Included in Microsoft's recommended driver block rules
- **HVCI behavior**: Blocked on HVCI-enabled systems via the blocklist
- **KDU integration**: Not integrated
- **LOLDrivers**: Listed at loldrivers.io

## Affected IOCTLs

- Process termination by PID
- Process enumeration

## Root Cause

`amsdk.sys` is the kernel driver for a WatchDog Development security product. The driver provides process termination capabilities via IOCTL — a standard feature for security software that needs to kill malicious processes. The IOCTL accepts a process ID and terminates the target process using kernel-mode APIs.

The vulnerability is insufficient access control. The termination IOCTL does not validate the caller's identity, privilege level, or purpose. Any process with access to the device object can terminate any process on the system.

Check Point documented the abuse of `amsdk.sys` by the Silver Fox APT group. The attackers use the driver to terminate security products before executing their primary campaign objectives.

## Exploitation

The process termination attack pattern:

1. Deploy `amsdk.sys` on the target system via BYOVD
2. Open the device handle
3. Enumerate running processes to identify security products
4. Send the termination IOCTL for each AV/EDR process
5. Security products are terminated
6. Execute primary APT payload

## Detection

### YARA Rule

```yara
rule amsdk_sys {
    meta:
        description = "Detects WatchDog amsdk.sys vulnerable driver"
        author = "KernelSight"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $amsdk = "amsdk" wide ascii nocase
        $watchdog = "WatchDog" wide ascii
    condition:
        $mz at 0 and ($amsdk or $watchdog)
}
```

### ETW Indicators

| Provider | Event / Signal | Relevance |
|----------|---------------|-----------|
| Microsoft-Windows-Kernel-File | Driver load event | Detects loading of amsdk.sys |
| Sysmon | Event ID 6 — Driver loaded | Hash and signature capture |
| Microsoft-Windows-Security-Auditing | Event 4697 — Service installed | Service creation |
| Microsoft-Windows-Kernel-Process | Process termination events | Mass AV/EDR termination |

### Behavioral Indicators

- Loading of `amsdk.sys` from outside WatchDog product installation
- Rapid sequential termination of multiple security product processes
- Service creation for WatchDog driver by a non-WatchDog process
- Temporal correlation: security termination followed by APT activity (C2, lateral movement, data exfiltration)

## References

- [Check Point — Silver Fox APT BYOVD](https://research.checkpoint.com/)
- [LOLDrivers — amsdk](https://www.loldrivers.io/)
