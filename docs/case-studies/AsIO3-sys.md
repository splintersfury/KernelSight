# AsIO3.sys

> ASRock/ASUS hardware access driver — physical memory R/W, MSR access, and ObfDereferenceObject decrement primitive

## Summary

| Field | Value |
|-------|-------|
| **Driver** | `AsIO3.sys` |
| **Vendor** | ASRock / ASUS |
| **Vulnerability Class** | Arbitrary R/W / Physical Memory Mapping / Authorization Bypass |
| **Abused Version** | Multiple versions shipped with ASRock and ASUS utilities |
| **Status** | Blocklisted — included in Microsoft Vulnerable Driver Blocklist |
| **Exploited ITW** | Yes |
| **Related CVEs** | [CVE-2025-1533](CVE-2025-1533.md) (stack overflow), [CVE-2025-3464](CVE-2025-3464.md) (auth bypass) |

## BYOVD Context

- **Driver signing**: Authenticode-signed by ASRock Incorporation with valid certificate
- **Vulnerable Driver Blocklist**: Included in Microsoft's recommended driver block rules
- **HVCI behavior**: Blocked on HVCI-enabled systems via the blocklist
- **KDU integration**: Integrated as a KDU provider (added in KDU v1.1)
- **LOLDrivers**: Listed at loldrivers.io

## Affected IOCTLs

| IOCTL | Capability | Notes |
|-------|-----------|-------|
| `0xA040200C` | Physical memory R/W via MmMapIoSpace | Range-filtered by `checkPhyMemoryRange` / `g_goodRanges` |
| — | I/O port read/write | Direct port access |
| `0xA040A45C` | MSR read/write | Allowlist filtering; excludes IA32_LSTAR and IA32_SYSENTER_EIP |
| `0xa0402450` | `ObfDereferenceObject` on controlled address | Provides decrement-by-one primitive at `(addr - 0x30)` |

## Root Cause

`AsIO3.sys` is a hardware access driver shipped with ASRock and some ASUS motherboard utilities. The driver provides direct physical memory access, I/O port access, MSR read/write, and an `ObfDereferenceObject` call via IOCTLs. While the physical memory and MSR IOCTLs have some filtering (range checks and allowlists respectively), the `ObfDereferenceObject` IOCTL (`0xa0402450`) has no restrictions — it accepts any address and decrements the value at `(address - 0x30)` by 1.

The driver's authorization relies solely on SHA256 hash verification of the calling process's executable path ([CVE-2025-3464](CVE-2025-3464.md)), which can be bypassed via a hardlink attack. The `IRP_MJ_CREATE` handler also contains a stack buffer overflow in its `Win32PathToNtPath` function ([CVE-2025-1533](CVE-2025-1533.md)) due to a `MAX_PATH` length assumption.

The driver was first documented by swapcontext in the KDU v1.1 release and later received full exploitation analysis from Cisco Talos (Marcin Noga), who demonstrated a complete SYSTEM escalation chain using the decrement-by-one primitive.

## Exploitation

### Via KDU (Physical Memory)

1. Load the signed `AsIO3.sys` driver
2. Open a device handle
3. Map physical addresses via the MmMapIoSpace IOCTL
4. Walk page tables, locate and modify kernel structures
5. For advanced attacks: map SMRAM to access SMM code and data

The KDU v1.1 release integrated AsIO3.sys as a provider, enabling automated exploitation via the KDU framework.

### Via Decrement-by-One (Talos Chain)

The full exploitation chain from Cisco Talos bypasses authorization and uses the `ObfDereferenceObject` IOCTL:

1. **Auth bypass** — hardlink attack to pass SHA256 hash check ([CVE-2025-3464](CVE-2025-3464.md))
2. **KTHREAD leak** — `NtQuerySystemInformation` with handle enumeration to find KTHREAD address
3. **PreviousMode flip** — IOCTL `0xa0402450` decrements `KTHREAD.PreviousMode` (offset `0x232`) from 1 to 0
4. **Kernel R/W** — with `PreviousMode = 0`, Nt* syscalls bypass all `ProbeForRead`/`ProbeForWrite` checks
5. **Token theft** — traverse `ActiveProcessLinks` to find SYSTEM token, swap it into current process
6. **SYSTEM shell** — launch `cmd.exe` as NT AUTHORITY\SYSTEM

See [CVE-2025-3464](CVE-2025-3464.md) for the full technical breakdown.

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

## Techniques Used

| Technique | KernelSight Page |
|-----------|-----------------|
| Arbitrary Decrement (ObfDereferenceObject) | [Arb Increment/Decrement](../primitives/arw/arb-increment-decrement.md) |
| PreviousMode Manipulation | [PreviousMode Manipulation](../primitives/exploitation/previous-mode-manipulation.md) |
| Token Swapping | [Token Swapping](../primitives/exploitation/token-swapping.md) |
| Physical Memory Mapping | [Direct IOCTL R/W](../primitives/arw/direct-ioctl-rw.md) |

## References

- [Talos — Decrement by one to rule them all: AsIO3.sys driver exploitation](https://blog.talosintelligence.com/decrement-by-one-to-rule-them-all/)
- [swapcontext — KDU v1.1 Release and bonus: AsIO3.sys](https://swapcontext.blogspot.com/2021/04/kdu-v11-release-and-bonus-asio3sys.html)
- [LOLDrivers — AsIO3](https://www.loldrivers.io/)
- [CVE-2025-1533 — Stack overflow in Win32PathToNtPath](CVE-2025-1533.md)
- [CVE-2025-3464 — Authorization bypass and full exploit chain](CVE-2025-3464.md)
