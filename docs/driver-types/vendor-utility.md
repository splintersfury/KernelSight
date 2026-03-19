# Vendor Utility Drivers

<div class="ks-pipeline-pos">
  <span class="ks-active">Driver Type</span> &rarr; Attack Surface &rarr; Vuln Class &rarr; Primitive &rarr; Case Study
</div>

Dell ships a BIOS update utility. It includes a kernel driver called DBUtil_2_3.sys. That driver exposes five IOCTLs that provide arbitrary kernel memory read and write. It is signed by Dell's legitimate code signing certificate. Microsoft's driver signature enforcement trusts it completely. And any user on the system can open a handle to its device object and read or write any byte in kernel memory.

This is the BYOVD (Bring Your Own Vulnerable Driver) problem in its purest form. Vendor utility drivers are not buggy in the traditional sense; their "vulnerability" is their design. They were built to give hardware management utilities direct access to physical memory, Model-Specific Registers (MSRs), I/O ports, and PCI configuration space. The developers never expected an adversary to load the driver independently and use these capabilities for exploitation. But that is exactly what ransomware groups, APT actors, and red teams do, and it has been happening at scale since at least 2018.

## The Scope of the Problem

With 14 CVEs in the KernelSight corpus and 9 confirmed in-the-wild exploitations, vendor utility drivers are the largest and most actively exploited category. The drivers come from major OEMs: Dell, MSI, Gigabyte, Intel, ASUS, ASRock, Lenovo, Marvin Test Solutions, Patriot, LG, and smaller vendors. Each one is legitimately signed, most have been shipped with consumer hardware, and all of them provide some combination of physical memory access, MSR read/write, and I/O port operations through simple IOCTL calls.

The common architecture is remarkably consistent across vendors. The driver creates a device object (usually with a permissive security descriptor), registers an IOCTL dispatch routine, and implements a set of IOCTL codes that map directly to privileged hardware operations. There is no authentication, no capability check, and no access control beyond the device object's ACL, which is often set to allow access from any user.

``` mermaid
graph TD
    A["Attacker Process<br/>Any user"] -->|"DeviceIoControl"| B["Vendor Driver<br/>Legitimately Signed"]
    B -->|"IOCTL: Phys Mem R/W"| C["MmMapIoSpace<br/>Physical Memory"]
    B -->|"IOCTL: MSR R/W"| D["RDMSR / WRMSR<br/>CPU Registers"]
    B -->|"IOCTL: I/O Port"| E["IN / OUT<br/>Port Access"]
    B -->|"IOCTL: PCI Config"| F["PCI Config Space<br/>Bus/Dev/Func"]

    style A fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    style B fill:#152a4a,stroke:#ef4444,color:#e2e8f0
    style C fill:#0d1320,stroke:#ef4444,color:#e2e8f0
    style D fill:#0d1320,stroke:#ef4444,color:#e2e8f0
    style E fill:#0d1320,stroke:#ef4444,color:#e2e8f0
    style F fill:#0d1320,stroke:#ef4444,color:#e2e8f0
```

## How They Are Exploited

The exploitation pattern for vendor utility drivers is fundamentally different from every other category in this knowledge base. There is no memory corruption to trigger, no race to win, no heap to groom. The driver provides the primitive directly through its documented IOCTL interface.

**Physical memory read/write** is the most common capability. Drivers like DBUtil_2_3.sys, RTCore64.sys, gdrv.sys, HW.sys, ATSZIO64.sys, and AsIO3.sys all expose IOCTLs that call `MmMapIoSpace` or equivalent functions with user-controlled physical addresses and sizes. The attacker passes a physical address to the IOCTL, and the driver maps it into virtual address space and returns the mapping. With physical memory read/write, the attacker can locate and modify any kernel data structure, including process tokens, EPROCESS structures, and page tables.

**MSR access** is the second major capability. MSRs control CPU configuration, and several are security-sensitive. Writing to `IA32_LSTAR` (MSR 0xC0000082) redirects the syscall entry point, effectively allowing the attacker to hook every system call. Writing to specific MSRs can disable SMEP, SMAP, or other hardware security features. Drivers like RTCore64.sys, gdrv.sys, WinRing0x64.sys, and mydrivers64.sys expose RDMSR/WRMSR IOCTLs with no restrictions on which MSR is accessed.

**I/O port access** provides direct IN/OUT instructions with user-controlled port addresses and data values. This can be used to interact with hardware controllers, PCI devices, and chipset registers. While the exploitation value depends on the specific hardware, I/O port access can reach SMM (System Management Mode) entry points on some platforms, which represents a ring -2 escalation.

The typical BYOVD attack proceeds as follows: the attacker drops the signed driver binary on disk, loads it as a kernel service (which requires admin privileges or a service creation vulnerability), opens a handle to the device object, and then uses the IOCTLs to read and write kernel memory. The entire chain, from driver load to SYSTEM, can be completed in seconds.

## Vulnerability Patterns and Detection

| Pattern | Description | AutoPiff Rules |
|---------|-------------|----------------|
| Arbitrary physical memory R/W | IOCTL maps or copies physical memory at user-controlled address | `physical_memory_mapping_exposed`, `mmmapiospace_user_controlled` |
| Arbitrary virtual memory R/W | IOCTL reads/writes kernel virtual addresses from user input | `direct_arw_ioctl_detected` |
| MSR read/write | IOCTL executes RDMSR/WRMSR with user-controlled register index | `direct_arw_ioctl_detected` |
| I/O port access | IOCTL performs IN/OUT with user-controlled port number | `direct_arw_ioctl_detected` |
| Missing device ACL | Device object accessible to all users | `device_acl_hardening` |

Unlike memory corruption bugs where the vulnerability is in the implementation, vendor utility driver "vulnerabilities" are in the design. AutoPiff's `direct_arw_ioctl_detected` and `physical_memory_mapping_exposed` rules detect these by identifying IOCTL handlers that pass user-controlled values to `MmMapIoSpace`, `WRMSR`, or memory copy operations without bounds checking or access validation.

## CVEs

| CVE | Driver | Description | Class | ITW |
|-----|--------|-------------|-------|-----|
| [CVE-2021-21551](../case-studies/CVE-2021-21551.md) | `DBUtil_2_3.sys` | Dell BIOS utility, arbitrary R/W via IOCTL | Arbitrary R/W | Yes |
| [CVE-2019-16098](../case-studies/CVE-2019-16098.md) | `RTCore64.sys` | MSI Afterburner, physical mem R/W, MSR, I/O port | Arbitrary R/W | Yes |
| [CVE-2018-19320](../case-studies/CVE-2018-19320.md) | `gdrv.sys` | Gigabyte, arbitrary kernel R/W, MSR access | Arbitrary R/W | Yes |
| [CVE-2015-2291](../case-studies/CVE-2015-2291.md) | `iqvw64e.sys` | Intel Ethernet diagnostics, arbitrary R/W via IOCTL | Arbitrary R/W | Yes |
| [CVE-2020-15368](../case-studies/CVE-2020-15368.md) | `HW.sys` | Marvin Test Solutions, physical memory R/W | Arbitrary R/W | Yes |
| [CVE-2022-3699](../case-studies/CVE-2022-3699.md) | `LenovoDiagnosticsDriver.sys` | Lenovo Diagnostics, arbitrary R/W | Arbitrary R/W | Yes |
| [CVE-2019-18845](../case-studies/CVE-2019-18845.md) | Viper RGB driver | Patriot, physical memory R/W | Arbitrary R/W | No |
| [CVE-2019-8372](../case-studies/CVE-2019-8372.md) | LG LSB driver | LG, arbitrary write | Arbitrary R/W | No |
| [CVE-2023-41444](../case-studies/CVE-2023-41444.md) | `iREC.sys` | iREC, arbitrary R/W | Arbitrary R/W | No |
| [CVE-2025-45737](../case-studies/CVE-2025-45737.md) | `NeacController.sys` | NEAC, arbitrary R/W | Arbitrary R/W | No |
| [ATSZIO64.sys](../case-studies/ATSZIO64-sys.md) | `ATSZIO64.sys` | ASUS, physical memory R/W | Arbitrary R/W | Yes |
| [AsIO3.sys](../case-studies/AsIO3-sys.md) | `AsIO3.sys` | ASRock/ASUS, physical mem R/W, SMM | Arbitrary R/W | Yes |
| [CVE-2023-1048](../case-studies/CVE-2023-1048.md) | `WinRing0x64.sys` | OpenLibSys, MSR write, phys mem R/W, I/O port | Arbitrary R/W | Yes |
| [CVE-2023-1676](../case-studies/CVE-2023-1676.md) | `mydrivers64.sys` | DriverGenius, MSR write, phys mem R/W | Arbitrary R/W | No |

## Key Drivers

### DBUtil_2_3.sys (Dell)

Dell's BIOS Utility driver ships with Dell firmware update tools and provides five IOCTL codes for arbitrary kernel memory read and write. Connor McGarr's detailed five-part exploitation series documents the full chain from IOCTL discovery through buffer identification to SYSTEM token theft. Multiple ransomware groups have adopted this driver for BYOVD operations because it is widely available (shipped on millions of Dell systems) and reliably signed.

### RTCore64.sys (MSI Afterburner)

The kernel component of MSI's Afterburner GPU overclocking utility exposes the full trifecta: physical memory R/W, MSR access, and I/O port access through its IOCTL interface. BlackByte and Cuba ransomware groups have used this driver in production attacks. Barakat's PoC and the swapcontext blog document the vulnerability in detail.

### gdrv.sys (Gigabyte)

Gigabyte's system management driver provides arbitrary kernel memory R/W and MSR read/write through IOCTLs. It was notably used by the RobbinHood ransomware and is integrated into KDU (Kernel Driver Utility by hfiref0x) as an exploitation provider.

### iqvw64e.sys (Intel)

Intel's Ethernet diagnostics driver is one of the earliest documented BYOVD drivers, with exploitation details published in 2015 on Exploit-DB (#36392). It provides arbitrary physical and virtual memory read/write through IOCTLs. Despite being nearly a decade old, it remains relevant because signed copies continue to circulate and the driver is still accepted by Windows driver signature enforcement on many systems.

### ATSZIO64.sys (ASUS) and AsIO3.sys (ASRock/ASUS)

Both ASUS-family drivers expose physical memory mapping via `MmMapIoSpace` with user-controlled parameters. ATSZIO64.sys is integrated into KDU with PoCs available from LimiQS and DOGSHITD on GitHub. AsIO3.sys extends the attack surface to SMM (System Management Mode) access on some platforms, as documented in the swapcontext KDU v1.1 blog, representing a potential ring -2 escalation path.

### WinRing0x64.sys (OpenLibSys)

The OpenLibSys WinRing0 driver is particularly widespread because it is open source and used by dozens of hardware monitoring tools (HWiNFO, LibreHardwareMonitor, OpenHardwareMonitor, and many others). It provides MSR write, physical memory R/W, and I/O port access. Its ubiquity means that copies of this driver are present on a large number of systems, making it a convenient BYOVD target.

## The Defense Landscape

Microsoft's primary defense against BYOVD is the Vulnerable Driver Blocklist, a list of known-vulnerable driver hashes that Windows will refuse to load. This list is updated through Windows Update and covers many of the drivers listed above. However, the blocklist has significant limitations.

New variants are continually discovered. The KernelSight corpus alone contains 14 vendor utility drivers, and the LOLDrivers project catalogs over 100 with known BYOVD potential. Each new driver requires a new blocklist entry, and there is always a window between discovery and blocklist update.

The blocklist is hash-based, so a recompiled version of the same driver with a different hash evades it. Some drivers have multiple versions with different hashes, not all of which are blocked. And on systems that are not receiving regular Windows Update, the blocklist may be months or years out of date.

HVCI (Hypervisor-protected Code Integrity) provides a stronger defense by restricting kernel code execution to signed code, but it does not prevent loading of legitimately signed vulnerable drivers. The driver is signed, so HVCI allows it; the vulnerability is in the design, not in unsigned code execution.

## Research Outlook

Vendor utility drivers remain the easiest path from admin to kernel on most Windows systems. The research opportunity is not in finding new bug classes (the pattern is always the same: IOCTL exposes hardware access) but in discovering new driver instances. Every OEM hardware utility, overclocking tool, RGB controller, fan management application, and diagnostic tool is a potential BYOVD driver. The [LOLDrivers](https://www.loldrivers.io/) project maintains the most comprehensive catalog, and tools like [KDU](https://github.com/hfiref0x/KDU) provide a framework for testing new discoveries.

For the performance and GPU drivers that share some characteristics with this category (MSR access, memory mapping) but target a different hardware class, see [Performance & GPU Drivers](performance-gpu.md). For the broader context of how IOCTL-based attack surfaces work, see [Attack Surfaces](../attack-surfaces/).
