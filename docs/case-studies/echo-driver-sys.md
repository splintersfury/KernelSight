# echo_driver.sys

> Echo anti-cheat driver — kernel callback manipulation via IOCTL

## Summary

| Field | Value |
|-------|-------|
| **Driver** | `echo_driver.sys` |
| **Vendor** | Echo AC |
| **Vulnerability Class** | Logic Bug / Callback Manipulation |
| **Abused Version** | 1.0.0.0 |
| **Status** | Still loadable — signed driver |
| **Exploited ITW** | No |

## BYOVD Context

- **Driver signing**: Authenticode-signed with valid certificate
- **Vulnerable Driver Blocklist**: Not included in Microsoft's recommended driver block rules
- **HVCI behavior**: May load on HVCI-enabled systems
- **KDU integration**: Not integrated
- **LOLDrivers**: Not widely listed

## Affected IOCTLs

- Enumerate kernel notification callbacks (PsSetCreateProcessNotifyRoutine callbacks)
- Remove kernel notification callbacks by index
- Restore callbacks

## Root Cause

`echo_driver.sys` is a kernel driver for the Echo anti-cheat system. The driver provides IOCTLs for managing kernel notification callbacks — functionality intended for anti-cheat integrity verification. However, the IOCTLs allow enumerating and removing process creation notification callbacks registered by other kernel drivers, including security products.

kite03 published a PoC on GitHub demonstrating how the callback manipulation IOCTLs can be used to blind EDR products. Removing the `PsSetCreateProcessNotifyRoutine` callbacks registered by security drivers prevents EDR products from receiving process creation notifications.

## Exploitation

The callback manipulation flow:

1. Load `echo_driver.sys`
2. Use the enumerate IOCTL to list all registered process creation notification callbacks
3. Identify callbacks belonging to EDR/AV products (by the owning driver module)
4. Use the remove IOCTL to zero out those callbacks
5. EDR products no longer receive process creation notifications
6. Proceed with malicious activity undetected

This is a "living off the land" style BYOVD attack — the driver's legitimate anti-cheat functionality is repurposed for EDR evasion.

## Detection

### YARA Rule

```yara
rule echo_driver_sys {
    meta:
        description = "Detects Echo AC echo_driver.sys"
        author = "KernelSight"
        severity = "high"
    strings:
        $mz = { 4D 5A }
        $echo = "echo_driver" wide ascii nocase
        $echo_ac = "EchoAC" wide ascii
    condition:
        $mz at 0 and ($echo or $echo_ac)
}
```

### ETW Indicators

| Provider | Event / Signal | Relevance |
|----------|---------------|-----------|
| Microsoft-Windows-Kernel-File | Driver load event | Detects loading of echo_driver.sys |
| Sysmon | Event ID 6 — Driver loaded | Hash and signature capture |
| Microsoft-Windows-Security-Auditing | Event 4697 — Service installed | Service creation |
| Microsoft-Windows-Threat-Intelligence | Callback modification events | Detects kernel callback tampering |

### Behavioral Indicators

- Loading of `echo_driver.sys` outside of an anti-cheat context
- IOCTL calls to enumerate kernel notification callbacks
- Sudden loss of EDR callback registrations (detectable via kernel callback auditing)
- Security product monitoring gaps following echo_driver.sys interaction

## References

- [kite03 — echoac-poc](https://github.com/kite03/echoac-poc/)
