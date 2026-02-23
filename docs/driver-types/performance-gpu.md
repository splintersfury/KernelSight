# Performance & GPU Drivers

CPU tuning, GPU, and chipset drivers — expose MSR writes, GPU memory mapping, and MMIO register access.

## Architecture

- **Driver model**: WDM or WDDM (Windows Display Driver Model for GPU drivers)
- **Key drivers**: `AMDRyzenMasterDriver.sys` (AMD), `ThrottleStop.sys` (ThrottleStop), `nvlddmkm.sys` (NVIDIA), AMD chipset driver
- **IOCTL interface**: MSR read/write for CPU tuning, GPU memory mapping for monitoring/overclocking, MMIO register access
- **Privilege**: Designed for performance tuning applications; require kernel access for hardware register manipulation

## Attack Surface

- **MSR write access**: IOCTLs that execute WRMSR with user-controlled register index and value, enabling CPU configuration changes
- **GPU memory mapping**: Mapping GPU framebuffer or MMIO registers to user space, potentially exposing kernel memory through DMA
- **MMIO register access**: Direct hardware register read/write via mapped I/O regions
- **Chipset register access**: Reading/writing chipset configuration for power management or bus control
- **Device object ACL**: Performance tuning drivers often allow low-privilege access for monitoring tools

## Common Vulnerability Patterns

| Pattern | Description | AutoPiff Rules |
|---------|-------------|----------------|
| Arbitrary MSR write | IOCTL writes to any MSR with user-controlled index/value | `direct_arw_ioctl_detected` |
| GPU memory mapping | Maps GPU MMIO regions accessible from user mode | `mmmapiospace_user_controlled` |
| MMIO register access | Direct hardware register R/W via IOCTL | `mmio_mapping_bounds_validation_added` |
| Chipset info disclosure | Chipset configuration readable via IOCTL | `physical_memory_mapping_exposed` |

## CVEs

| CVE | Driver | Description | Class | ITW |
|-----|--------|-------------|-------|-----|
| [CVE-2020-12928](../case-studies/CVE-2020-12928.md) | `AMDRyzenMasterDriver.sys` | AMD Ryzen Master — arbitrary R/W via IOCTL | Arbitrary R/W | No |
| [CVE-2023-20598](../case-studies/CVE-2023-20598.md) | AMD chipset driver | AMD chipset — info disclosure / MMIO | Info Disclosure | No |
| [CVE-2025-7771](../case-studies/CVE-2025-7771.md) | `ThrottleStop.sys` | ThrottleStop — MSR write / AV killer | Arbitrary R/W | Yes |
| [NVDrv](../case-studies/NVDrv.md) | `nvlddmkm.sys` | NVIDIA — GPU memory R/W | Arbitrary R/W | No |

## Key Drivers

### AMDRyzenMasterDriver.sys (AMD)
- **Role**: AMD Ryzen Master CPU tuning utility kernel driver
- **Attack vector**: IOCTLs provide arbitrary physical memory read/write
- **Note**: h0mbre's detailed writeup demonstrates the full exploitation chain from IOCTL discovery to SYSTEM token theft

### ThrottleStop.sys (ThrottleStop)
- **Role**: CPU throttling management driver for the ThrottleStop utility
- **Attack vector**: MSR write IOCTL allows writing arbitrary MSR values; abused to disable AV/EDR
- **Note**: Kaspersky SecureList 2025 documents ITW abuse as an AV killer

### nvlddmkm.sys (NVIDIA)
- **Role**: NVIDIA GPU kernel-mode display driver
- **Attack vector**: GPU memory mapping exposes physical memory through GPU DMA regions
- **Note**: zer0condition's NVDrv PoC demonstrates kernel R/W via GPU memory mapping

### AMD Chipset Driver
- **Role**: AMD chipset driver for motherboard management
- **Attack vector**: MMIO register access may expose chipset configuration data
- **Note**: AMD-SB-6009 bulletin documents the information disclosure vulnerability

## Research Notes

Performance and GPU drivers are valuable BYOVD targets because:
- They **require MSR access** by design — CPU tuning requires writing to performance-related MSRs
- GPU drivers **map large physical memory regions** for framebuffer and MMIO access
- MSR writes can be weaponized to **disable security features** (e.g., writing to IA32_LSTAR to redirect syscalls)
- GPU memory mapping can provide a **covert channel** for kernel memory access
- These drivers are **widely deployed** on gaming and workstation systems
