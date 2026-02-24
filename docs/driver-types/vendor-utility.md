# Vendor Utility Drivers

OEM hardware utility, diagnostic, and management drivers — the canonical BYOVD targets.

## Architecture

- **Driver model**: WDM, typically loaded as a kernel-mode service
- **Key drivers**: `DBUtil_2_3.sys` (Dell), `RTCore64.sys` (MSI), `gdrv.sys` (Gigabyte), `HW.sys` (Marvin Test), `iqvw64e.sys` (Intel), `LenovoDiagnosticsDriver.sys` (Lenovo), `ATSZIO64.sys` (ASUS), `AsIO3.sys` (ASRock/ASUS), `WinRing0x64.sys` (OpenLibSys), `mydrivers64.sys` (DriverGenius), Viper RGB driver (Patriot), LG LSB driver (LG), `iREC.sys` (iREC), `NeacController.sys` (NEAC)
- **IOCTL interface**: Physical memory R/W, MSR access, I/O port access, PCI configuration space access via DeviceIoControl
- **Privilege**: Originally designed for hardware management utilities; most run with full kernel privileges but provide world-accessible device objects

## Attack Surface

- **Physical memory read/write**: IOCTLs expose MmMapIoSpace or direct physical memory access with user-controlled address and size
- **MSR access**: IOCTLs for reading/writing Model-Specific Registers enable CPU configuration changes
- **I/O port access**: Direct IN/OUT port instructions with user-controlled port address and data
- **PCI configuration space**: Reading/writing PCI device configuration without authorization checks
- **Device object ACL**: Most vendor utility drivers create device objects with permissive security descriptors, allowing any user to open a handle

## Common Vulnerability Patterns

| Pattern | Description | AutoPiff Rules |
|---------|-------------|----------------|
| Arbitrary physical memory R/W | IOCTL maps or copies physical memory at user-controlled address | `physical_memory_mapping_exposed`, `mmmapiospace_user_controlled` |
| Arbitrary virtual memory R/W | IOCTL reads/writes kernel virtual addresses from user input | `direct_arw_ioctl_detected` |
| MSR read/write | IOCTL executes RDMSR/WRMSR with user-controlled register index | `direct_arw_ioctl_detected` |
| I/O port access | IOCTL performs IN/OUT with user-controlled port number | `direct_arw_ioctl_detected` |
| Missing device ACL | Device object accessible to all users | `device_acl_hardening` |

## CVEs

| CVE | Driver | Description | Class | ITW |
|-----|--------|-------------|-------|-----|
| [CVE-2021-21551](../case-studies/CVE-2021-21551.md) | `DBUtil_2_3.sys` | Dell BIOS utility — arbitrary R/W via IOCTL | Arbitrary R/W | Yes |
| [CVE-2019-16098](../case-studies/CVE-2019-16098.md) | `RTCore64.sys` | MSI Afterburner — physical mem R/W, MSR, I/O port | Arbitrary R/W | Yes |
| [CVE-2018-19320](../case-studies/CVE-2018-19320.md) | `gdrv.sys` | Gigabyte — arbitrary kernel R/W, MSR access | Arbitrary R/W | Yes |
| [CVE-2015-2291](../case-studies/CVE-2015-2291.md) | `iqvw64e.sys` | Intel Ethernet diagnostics — arbitrary R/W via IOCTL | Arbitrary R/W | Yes |
| [CVE-2020-15368](../case-studies/CVE-2020-15368.md) | `HW.sys` | Marvin Test Solutions — physical memory R/W | Arbitrary R/W | Yes |
| [CVE-2022-3699](../case-studies/CVE-2022-3699.md) | `LenovoDiagnosticsDriver.sys` | Lenovo Diagnostics — arbitrary R/W | Arbitrary R/W | Yes |
| [CVE-2019-18845](../case-studies/CVE-2019-18845.md) | Viper RGB driver | Patriot — physical memory R/W | Arbitrary R/W | No |
| [CVE-2019-8372](../case-studies/CVE-2019-8372.md) | LG LSB driver | LG — arbitrary write | Arbitrary R/W | No |
| [CVE-2023-41444](../case-studies/CVE-2023-41444.md) | `iREC.sys` | iREC — arbitrary R/W | Arbitrary R/W | No |
| [CVE-2025-45737](../case-studies/CVE-2025-45737.md) | `NeacController.sys` | NEAC — arbitrary R/W | Arbitrary R/W | No |
| [ATSZIO64.sys](../case-studies/ATSZIO64-sys.md) | `ATSZIO64.sys` | ASUS — physical memory R/W | Arbitrary R/W | Yes |
| [AsIO3.sys](../case-studies/AsIO3-sys.md) | `AsIO3.sys` | ASRock/ASUS — physical mem R/W, SMM | Arbitrary R/W | Yes |
| [CVE-2023-1048](../case-studies/CVE-2023-1048.md) | `WinRing0x64.sys` | OpenLibSys — MSR write, phys mem R/W, I/O port | Arbitrary R/W | Yes |
| [CVE-2023-1676](../case-studies/CVE-2023-1676.md) | `mydrivers64.sys` | DriverGenius — MSR write, phys mem R/W | Arbitrary R/W | No |

## Key Drivers

### DBUtil_2_3.sys (Dell)
- **Role**: Dell BIOS Utility driver, shipped with Dell firmware update tools
- **Attack vector**: Five IOCTL codes providing arbitrary kernel memory read/write
- **Note**: Connor McGarr's 5-part series details the exploitation chain; abused by multiple ransomware groups

### RTCore64.sys (MSI Afterburner)
- **Role**: Kernel component of MSI Afterburner GPU overclocking utility
- **Attack vector**: IOCTLs for physical memory R/W, MSR access, I/O port access
- **Note**: Used by BlackByte and Cuba ransomware; Barakat PoC and swapcontext blog detail the vulnerability

### gdrv.sys (Gigabyte)
- **Role**: Gigabyte system management driver
- **Attack vector**: Arbitrary kernel memory R/W and MSR read/write IOCTLs
- **Note**: Used by RobbinHood ransomware; integrated into KDU

### iqvw64e.sys (Intel)
- **Role**: Intel Ethernet diagnostics driver
- **Attack vector**: Arbitrary physical and virtual memory R/W IOCTLs
- **Note**: One of the earliest documented BYOVD drivers (2015); exploit-db #36392

### ATSZIO64.sys (ASUS)
- **Role**: ASUS system I/O service driver
- **Attack vector**: Physical memory mapping via MmMapIoSpace with user-controlled parameters
- **Note**: Integrated into KDU; LimiQS and DOGSHITD GitHub PoCs available

### AsIO3.sys (ASRock/ASUS)
- **Role**: ASRock/ASUS hardware access driver
- **Attack vector**: Physical memory R/W, potentially reaching SMM (System Management Mode)
- **Note**: Documented in swapcontext KDU v1.1 blog; demonstrates SMM attack surface

## Research Notes

Vendor utility drivers are the canonical BYOVD targets. They are legitimately signed by major OEMs and intentionally expose physical memory R/W, MSR access, and I/O port access — the "vulnerability" is the design itself, since the driver was never intended to be loaded by unauthorized parties. Microsoft's Vulnerable Driver Blocklist covers many of these, but new variants are continually discovered. KDU (Kernel Driver Utility by hfiref0x) integrates many as exploitation providers, and LOLDrivers catalogs over 100 vendor utility drivers with known BYOVD potential.
