# amsdk.sys

> WatchDog Development security driver, process termination abused by Silver Fox APT

## Summary

| Field | Value |
|-------|-------|
| **Driver** | `amsdk.sys` |
| **Vendor** | WatchDog Development |
| **Vulnerability Class** | Logic Bug / Process Termination |
| **Abused Version** | Multiple versions |
| **Status** | Blocklisted — added to Microsoft Vulnerable Driver Blocklist |
| **Exploited ITW** | Yes |

## The Story

There is a certain irony in a security product becoming the weapon. `amsdk.sys` is the kernel driver for a WatchDog Development security product, designed to protect systems by monitoring and terminating malicious processes. The driver ships with a process termination IOCTL that accepts a process ID and calls kernel-mode APIs to kill the target. This is standard functionality for security software that needs to stop malware. The problem is that the IOCTL does not verify who is asking.

Check Point documented the Silver Fox APT group weaponizing this exact capability. The attack is straightforward: bring `amsdk.sys` to the target via BYOVD, open the device, enumerate the running security products, and send the termination IOCTL for each one. With the defenders dead, the APT payload executes unopposed.

The driver does not validate the caller's identity, privilege level, or purpose. Any process with access to the device object can terminate any other process on the system.

## BYOVD Context

- **Driver signing**: Authenticode-signed by WatchDog Development with valid certificate
- **Vulnerable Driver Blocklist**: Included in Microsoft's recommended driver block rules
- **HVCI behavior**: Blocked on HVCI-enabled systems via the blocklist
- **KDU integration**: Not integrated
- **LOLDrivers**: Listed at loldrivers.io

## Affected IOCTLs

- Process termination by PID
- Process enumeration

## How It Gets Used

The attacker does not need any memory corruption, race condition, or sophisticated exploitation technique. The attack chain is purely logical. First, `amsdk.sys` is deployed on the target system through BYOVD, dropped to disk and loaded as a service. The attacker opens a handle to the device object, which accepts connections from any authenticated user. Then the attacker enumerates running processes, identifying AV and EDR products by name or service registration. For each security product, a termination IOCTL is issued. Within seconds, every defensive process on the box is dead. The primary APT payload then executes in an environment with no active monitoring.

This is the process termination variant of BYOVD, a pattern that has become increasingly common as threat actors realize they do not need kernel read/write primitives when they can simply kill the defenders instead.

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

## Broader Significance

`amsdk.sys` represents the process-killer class of BYOVD, where the attacker does not need kernel memory corruption. The driver's own intended functionality becomes the weapon. Defenders should treat any signed driver with a process termination IOCTL as a potential BYOVD target, especially when the IOCTL lacks caller validation. The Silver Fox campaign proved that security products that expose powerful kernel capabilities without access control are not protecting the system; they are arming the adversary.

## References

- [Check Point — Silver Fox APT BYOVD](https://research.checkpoint.com/)
- [LOLDrivers — amsdk](https://www.loldrivers.io/)
