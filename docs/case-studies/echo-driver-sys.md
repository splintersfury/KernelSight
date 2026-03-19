# echo_driver.sys

> Echo anti-cheat driver -- a legitimate callback management tool repurposed to blind EDR products

## Summary

| Field | Value |
|-------|-------|
| **Driver** | `echo_driver.sys` |
| **Vendor** | Echo AC |
| **Vulnerability Class** | Logic Bug / Callback Manipulation |
| **Abused Version** | 1.0.0.0 |
| **Status** | Still loadable -- signed driver |
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

## The Tool

`echo_driver.sys` is not your typical BYOVD target. Most abused drivers provide raw hardware access (MSR read/write, physical memory mapping) or process termination IOCTLs. Echo's driver provides something more subtle: the ability to enumerate, remove, and restore kernel notification callbacks. This is a "living off the land" attack at the kernel level.

Windows kernel-mode security products register callbacks through APIs like `PsSetCreateProcessNotifyRoutine` to receive notifications when processes are created. These callbacks are how EDR products learn about new processes, inspect their memory, and decide whether to allow or block execution. Remove the callback, and the EDR product becomes deaf to process creation.

kite03 published a proof-of-concept on GitHub demonstrating how echo_driver.sys's callback management IOCTLs can be weaponized. The technique does not crash or kill the EDR product. The security agent continues running, its UI shows green, and its service reports healthy. But it no longer receives the kernel notifications that its detection logic depends on. The EDR is alive but blind.

## Root Cause

The Echo anti-cheat system legitimately needs callback management to verify game integrity. Anti-cheat products inspect kernel callbacks to detect tampering by cheat software. The IOCTLs that enumerate and modify callbacks are designed for this purpose. The security gap is that these IOCTLs do not validate the caller's identity. Any process that can open the device handle, not just the Echo AC client, can enumerate and remove callbacks belonging to any driver on the system.

## Exploitation

The attack flow is elegant in its simplicity. The attacker loads `echo_driver.sys` and opens the device handle. Using the enumerate IOCTL, they list all registered process creation notification callbacks. Each callback entry includes the owning driver module, so the attacker identifies which callbacks belong to EDR/AV products (CrowdStrike, SentinelOne, Defender, etc.). For each EDR callback, they send the remove IOCTL, which zeroes out the callback entry in the kernel's callback array.

The EDR product continues running. Its user-mode components operate normally. But the kernel no longer sends it process creation notifications. Any process the attacker launches after this point is invisible to the EDR's kernel-level detection. The attacker proceeds with their payload undetected.

When the operation is complete, the attacker can optionally restore the callbacks to reduce forensic artifacts.

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
| Sysmon | Event ID 6 -- Driver loaded | Hash and signature capture |
| Microsoft-Windows-Security-Auditing | Event 4697 -- Service installed | Service creation |
| Microsoft-Windows-Threat-Intelligence | Callback modification events | Detects kernel callback tampering |

### Behavioral Indicators

- Loading of `echo_driver.sys` outside of an anti-cheat context
- IOCTL calls to enumerate kernel notification callbacks
- Sudden loss of EDR callback registrations (detectable via kernel callback auditing)
- Security product monitoring gaps following echo_driver.sys interaction

## Broader Significance

echo_driver.sys represents a category of BYOVD that is harder to detect than process termination or memory read/write. The EDR product is not killed, its memory is not modified, and no crash occurs. The attack operates at the callback registration layer, removing the kernel's notifications to the security product. This is stealthier than [viragt64.sys](viragt64-sys.md) or [CVE-2025-68947](CVE-2025-68947.md) because there are no process termination events to alert on. Defenders must monitor kernel callback integrity directly, which few security products currently do.

The driver remains loadable and is not on the Microsoft blocklist, making it available for future abuse.

## References

- [kite03 -- echoac-poc](https://github.com/kite03/echoac-poc/)
