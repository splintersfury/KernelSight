# Truesight.sys

> Adlice RogueKiller anti-rootkit — EDR bypass via handle duplication and process termination

## Summary

| Field | Value |
|-------|-------|
| **Driver** | `Truesight.sys` |
| **Vendor** | Adlice (RogueKiller) |
| **Vulnerability Class** | Logic Bug / EDR Bypass |
| **Abused Version** | Multiple versions prior to 3.4.0 |
| **Status** | Blocklisted — added to Microsoft Vulnerable Driver Blocklist (2025) |
| **Exploited ITW** | Yes |

## BYOVD Context

- **Driver signing**: Authenticode-signed by Adlice Software with valid certificate
- **Vulnerable Driver Blocklist**: Included in Microsoft's recommended driver block rules (added 2025)
- **HVCI behavior**: Blocked on HVCI-enabled systems via the blocklist
- **KDU integration**: Not integrated
- **LOLDrivers**: Listed at loldrivers.io

## Affected IOCTLs

- Process handle duplication (bypassing object callbacks and PPL)
- Process termination by PID
- Process memory read/write

## Root Cause

`Truesight.sys` is the kernel driver for Adlice's RogueKiller anti-rootkit tool. As an anti-rootkit product, the driver needs to interact with protected processes, open handles with elevated access rights, and terminate malicious processes. It provides IOCTLs for:

- Duplicating process handles with full access rights, bypassing `ObRegisterCallbacks` protections
- Terminating processes by PID, including protected processes
- Reading/writing process memory

The IOCTLs perform insufficient validation of the caller's identity and purpose. Any process that can open the device can use these capabilities.

Check Point Research published a detailed analysis in 2025 documenting how threat actors abuse `Truesight.sys` for EDR bypass. The attack leverages the handle duplication IOCTL to obtain full-access handles to EDR processes that are normally protected by object callbacks, then uses those handles to terminate or modify the security processes.

## Exploitation

The EDR bypass attack chain:

1. Deploy `Truesight.sys` via BYOVD
2. Open the device handle
3. Use the handle duplication IOCTL to get a full-access handle to EDR processes (bypasses ObRegisterCallbacks)
4. Use the termination IOCTL to kill EDR processes, or use process memory write to patch EDR hooks
5. Security products are disabled
6. Execute primary payload

## Detection

### YARA Rule

```yara
rule Truesight_sys {
    meta:
        description = "Detects Adlice Truesight.sys vulnerable driver"
        author = "KernelSight"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $truesight = "Truesight" wide ascii nocase
        $adlice = "Adlice" wide ascii
        $roguekiller = "RogueKiller" wide ascii
    condition:
        $mz at 0 and ($truesight or $adlice or $roguekiller)
}
```

### ETW Indicators

| Provider | Event / Signal | Relevance |
|----------|---------------|-----------|
| Microsoft-Windows-Kernel-File | Driver load event | Detects loading of Truesight.sys |
| Sysmon | Event ID 6 — Driver loaded | Hash and signature capture |
| Microsoft-Windows-Security-Auditing | Event 4697 — Service installed | Service creation |
| Microsoft-Windows-Threat-Intelligence | Handle duplication events | Detects handle elevation to protected processes |
| Microsoft-Windows-Kernel-Process | Process termination events | EDR process termination |

### Behavioral Indicators

- Loading of `Truesight.sys` from outside Adlice RogueKiller installation
- Handle duplication IOCTLs targeting EDR/AV processes (especially PPL-protected processes)
- Process termination of security products following Truesight driver loading
- Temporal pattern: driver load → handle elevation → security process termination → malware execution

## References

- [Check Point Research — Truesight.sys EDR Bypass](https://research.checkpoint.com/)
- [LOLDrivers — Truesight](https://www.loldrivers.io/)
