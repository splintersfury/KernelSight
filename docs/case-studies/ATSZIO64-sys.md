# ATSZIO64.sys

> ASUS system I/O driver, physical memory read/write via unrestricted MmMapIoSpace

## Summary

| Field | Value |
|-------|-------|
| **Driver** | `ATSZIO64.sys` |
| **Vendor** | ASUS |
| **Vulnerability Class** | Arbitrary R/W / Physical Memory Mapping |
| **Abused Version** | Multiple versions shipped with ASUS system utilities |
| **Status** | Blocklisted — included in Microsoft Vulnerable Driver Blocklist |
| **Exploited ITW** | Yes |

## The Story

ASUS ships `ATSZIO64.sys` with various motherboard utilities for system monitoring and hardware configuration. Like many vendor utility drivers, it needs low-level hardware access, so it exposes IOCTLs for physical memory access via `MmMapIoSpace` and I/O port operations. The problem is familiar: the user-controlled physical address and size parameters have no range restrictions, and the device object has no access control checks on the caller. Any process on the system can map any physical address.

LimiQS documented the privilege escalation vulnerability, and DOGSHITD provided additional PoC code on GitHub. The driver was subsequently integrated into KDU (Kernel Driver Utility by hfiref0x) as an exploitation provider, making automated exploitation available through the KDU framework.

This is one of several ASUS drivers (alongside [AsIO3.sys](AsIO3-sys.md)) that expose unrestricted physical memory access, reflecting a pattern in hardware vendor driver development where the focus on functionality consistently outweighs security considerations.

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

## How It Gets Exploited

The exploitation path follows the standard physical memory R/W BYOVD pattern. An attacker loads the signed driver, opens a handle to the device, and maps physical memory at controlled addresses through the `MmMapIoSpace` IOCTL. From there, walking the page table hierarchy to translate virtual addresses to physical ones is mechanical. Locating the target process's `EPROCESS` structure and overwriting its token pointer with the SYSTEM process token completes the escalation.

The entire chain requires no memory corruption, no race condition, and no heap layout manipulation. The driver provides the primitive directly.

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

## Broader Significance

`ATSZIO64.sys` is a representative example of the vendor utility BYOVD class: a legitimately signed driver that provides unrestricted physical memory access as part of its normal operation. The pattern recurs across hardware vendors because the same business requirement (low-level hardware access for system utilities) produces the same security outcome (unrestricted kernel primitives for any caller). The only reliable mitigation is the Vulnerable Driver Blocklist, which blocks known hashes but cannot prevent new, unsigned variants or builds that have not yet been cataloged.

## References

- [LimiQS — ASUS Drivers Privilege Escalation](https://github.com/LimiQS/AsusDriversPrivEscala)
- [DOGSHITD — SciDetectorApp](https://github.com/DOGSHITD/SciDetectorApp)
- [LOLDrivers — ATSZIO64](https://www.loldrivers.io/)
