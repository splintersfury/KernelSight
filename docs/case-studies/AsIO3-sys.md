# AsIO3.sys

> ASRock/ASUS hardware access driver — physical memory R/W and potential SMM access

## Summary

| Field | Value |
|-------|-------|
| **Driver** | `AsIO3.sys` |
| **Vendor** | ASRock / ASUS |
| **Vulnerability Class** | Arbitrary R/W / Physical Memory Mapping |
| **Abused Version** | Multiple versions shipped with ASRock and ASUS utilities |
| **Status** | Blocklisted — included in Microsoft Vulnerable Driver Blocklist |
| **Exploited ITW** | Yes |

## BYOVD Context

- **Driver signing**: Authenticode-signed by ASRock Incorporation with valid certificate
- **Vulnerable Driver Blocklist**: Included in Microsoft's recommended driver block rules
- **HVCI behavior**: Blocked on HVCI-enabled systems via the blocklist
- **KDU integration**: Integrated as a KDU provider (added in KDU v1.1)
- **LOLDrivers**: Listed at loldrivers.io

## Affected IOCTLs

- Physical memory read via MmMapIoSpace
- Physical memory write via MmMapIoSpace
- I/O port read/write
- MSR read/write

## Root Cause

`AsIO3.sys` is a hardware access driver shipped with ASRock and some ASUS motherboard utilities. The driver provides direct physical memory access, I/O port access, and MSR read/write via IOCTLs. The physical memory mapping has no address range restrictions, meaning any physical address can be mapped, including addresses in the SMRAM (System Management RAM) region. This provides potential access to System Management Mode (SMM) code and data.

The vulnerability was documented by swapcontext in the KDU v1.1 release blog post, which described how AsIO3.sys was added as a new provider for the Kernel Driver Utility. The blog discusses the SMM attack surface implications.

## Exploitation

The driver provides unrestricted physical memory access:

1. Load the signed `AsIO3.sys` driver
2. Open a device handle
3. Map any physical address via the MmMapIoSpace IOCTL
4. For kernel exploitation: walk page tables, locate and modify kernel structures
5. For advanced attacks: map SMRAM to access SMM code and data

The KDU v1.1 release integrated AsIO3.sys as a provider, enabling automated exploitation via the KDU framework.

## Detection

### YARA Rule

```yara
rule AsIO3_sys {
    meta:
        description = "Detects ASRock/ASUS AsIO3.sys vulnerable driver"
        author = "KernelSight"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $driver_name = "AsIO3" wide ascii nocase
        $asrock = "ASRock" wide ascii
        $asio = "AsIO" wide ascii
    condition:
        $mz at 0 and ($driver_name or $asio) and $asrock
}
```

### ETW Indicators

| Provider | Event / Signal | Relevance |
|----------|---------------|-----------|
| Microsoft-Windows-Kernel-File | Driver load event | Detects loading of AsIO3.sys |
| Sysmon | Event ID 6 — Driver loaded | Hash and signature capture |
| Microsoft-Windows-Security-Auditing | Event 4697 — Service installed | Driver service creation |
| Microsoft-Windows-Kernel-Process | Process token modification | Post-exploitation token swap |

### Behavioral Indicators

- Loading of `AsIO3.sys` from outside ASRock utility installation directories
- Physical memory mapping targeting SMRAM address ranges (typically 0xA0000–0xBFFFF or chipset-defined regions)
- MSR read/write IOCTLs from non-utility processes
- Privilege escalation following AsIO3 driver interaction

## References

- [swapcontext — KDU v1.1 Release and bonus: AsIO3.sys](https://swapcontext.blogspot.com/2021/04/kdu-v11-release-and-bonus-asio3sys.html)
- [LOLDrivers — AsIO3](https://www.loldrivers.io/)
