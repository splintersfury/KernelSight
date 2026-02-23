# ATSZIO64.sys

> ASUS system I/O driver — physical memory read/write via unrestricted MmMapIoSpace

## Summary

| Field | Value |
|-------|-------|
| **Driver** | `ATSZIO64.sys` |
| **Vendor** | ASUS |
| **Vulnerability Class** | Arbitrary R/W / Physical Memory Mapping |
| **Abused Version** | Multiple versions shipped with ASUS system utilities |
| **Status** | Blocklisted — included in Microsoft Vulnerable Driver Blocklist |
| **Exploited ITW** | Yes |

## BYOVD Context

- **Driver signing**: Authenticode-signed by ASUSTek Computer with valid certificate
- **Vulnerable Driver Blocklist**: Included in Microsoft's recommended driver block rules
- **HVCI behavior**: Blocked on HVCI-enabled systems via the blocklist
- **KDU integration**: Integrated as a KDU provider
- **LOLDrivers**: Listed at loldrivers.io

## Affected IOCTLs

- Physical memory read via MmMapIoSpace
- Physical memory write via MmMapIoSpace
- I/O port read/write

## Root Cause

`ATSZIO64.sys` is an ASUS system I/O service driver shipped with various ASUS motherboard utilities. The driver provides low-level hardware access for system monitoring and configuration. It exposes IOCTLs for physical memory access via `MmMapIoSpace` with user-controlled physical address and size parameters, and I/O port access. No access control checks are performed on the caller.

LimiQS documented the privilege escalation vulnerability, and DOGSHITD provided additional PoC code on GitHub.

## Exploitation

Standard physical memory R/W BYOVD exploitation:

1. Load the signed `ATSZIO64.sys` driver
2. Open the device handle
3. Map physical memory at controlled addresses via MmMapIoSpace IOCTL
4. Walk page tables, locate kernel structures
5. Modify EPROCESS tokens for SYSTEM escalation

The driver is integrated into KDU (Kernel Driver Utility by hfiref0x) as an exploitation provider.

## Detection

### YARA Rule

```yara
rule ATSZIO64_sys {
    meta:
        description = "Detects ASUS ATSZIO64.sys vulnerable driver"
        author = "KernelSight"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $driver_name = "ATSZIO64" wide ascii nocase
        $asus = "ASUSTek" wide ascii
        $atszio = "ATSZIO" wide ascii
    condition:
        $mz at 0 and ($driver_name or $atszio or $asus)
}
```

### ETW Indicators

| Provider | Event / Signal | Relevance |
|----------|---------------|-----------|
| Microsoft-Windows-Kernel-File | Driver load event | Detects loading of ATSZIO64.sys |
| Sysmon | Event ID 6 — Driver loaded | Hash and signature capture |
| Microsoft-Windows-Security-Auditing | Event 4697 — Service installed | Driver service creation |
| Microsoft-Windows-Kernel-Process | Process token modification | Post-exploitation token swap |

### Behavioral Indicators

- Loading of `ATSZIO64.sys` from outside ASUS utility installation directories
- Physical memory mapping IOCTLs from non-ASUS processes
- Page table walking patterns in physical memory read sequences
- Privilege escalation following ATSZIO64 driver interaction

## References

- [LimiQS — ASUS Drivers Privilege Escalation](https://github.com/LimiQS/AsusDriversPrivEscala)
- [DOGSHITD — SciDetectorApp](https://github.com/DOGSHITD/SciDetectorApp)
- [LOLDrivers — ATSZIO64](https://www.loldrivers.io/)
