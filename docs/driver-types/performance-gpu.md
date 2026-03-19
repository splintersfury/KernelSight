# Performance & GPU Drivers

<div class="ks-pipeline-pos">
  <span class="ks-active">Driver Type</span> &rarr; Attack Surface &rarr; Vuln Class &rarr; Primitive &rarr; Case Study
</div>

In 2025, Kaspersky's SecureList documented an in-the-wild campaign using ThrottleStop.sys, a CPU throttling management driver, to disable antivirus products. The attack did not exploit a buffer overflow or a race condition. It used the driver's legitimate MSR write IOCTL to write arbitrary values to Model-Specific Registers, which can redirect the syscall entry point, disable SMEP, or corrupt critical CPU state. ThrottleStop.sys is designed to do this; it is a CPU tuning tool, and MSR writes are its core functionality. The attacker simply loaded it and called the IOCTL.

Performance and GPU drivers occupy a middle ground between [vendor utility drivers](vendor-utility.md) (which are pure BYOVD targets) and traditional kernel drivers (which have memory corruption bugs). Like vendor utilities, they expose privileged hardware access by design. But unlike generic hardware management tools, they target specific subsystems: CPU performance registers, GPU memory, MMIO regions, and chipset configuration. This specialization gives them a different threat profile: the exposed capabilities are narrower but sometimes deeper, reaching GPU DMA regions or chipset registers that generic utility drivers do not touch.

## Architecture

Performance and GPU drivers use either WDM or WDDM (Windows Display Driver Model, for GPU drivers). They are loaded as kernel-mode services and create device objects with IOCTL interfaces for their management applications. The four drivers in the KernelSight corpus represent three distinct hardware targets.

**CPU tuning drivers** (AMDRyzenMasterDriver.sys, ThrottleStop.sys) expose MSR read/write IOCTLs for adjusting CPU voltage, frequency, and power management settings. MSR access is inherently privileged: Model-Specific Registers control CPU behavior at a fundamental level, and some MSRs (like `IA32_LSTAR` at MSR 0xC0000082) control security-critical functions like the syscall entry point.

**GPU drivers** (nvlddmkm.sys) manage GPU hardware through memory-mapped I/O regions. The NVIDIA display driver maps GPU framebuffer and MMIO registers into kernel virtual address space, and in some configurations, these mappings can be used to access physical memory through GPU DMA channels. zer0condition's NVDrv proof-of-concept demonstrates kernel read/write by exploiting the GPU memory mapping interface.

**Chipset drivers** (AMD chipset driver) provide access to motherboard chipset configuration for power management and bus control. CVE-2023-20598 documents an information disclosure vulnerability where chipset configuration data, potentially including sensitive hardware state, is readable through an IOCTL.

## Attack Surfaces and Exploitation

### MSR Write as a Weapon

The MSR write capability deserves detailed discussion because it is one of the most powerful primitives available to an attacker with kernel access, and performance drivers provide it by design.

Writing to `IA32_LSTAR` (MSR 0xC0000082) changes the kernel's syscall entry point. The attacker can redirect all syscalls to their own code, effectively hooking the entire kernel. Writing to `IA32_STAR` (MSR 0xC0000081) changes the CS/SS segments used during syscall transitions. Clearing the SMEP bit in CR4 through MSR manipulation allows the CPU to execute code from user-mode pages while in ring 0.

ThrottleStop.sys demonstrates this threat concretely. Kaspersky documented its use as an "AV killer" in the wild: the attacker loads the signed driver, uses the MSR write IOCTL to corrupt CPU state in a way that crashes or disables security products, then deploys their payload. The driver is legitimately signed by the ThrottleStop developer, and Windows driver signature enforcement does not distinguish between "loaded by the intended application" and "loaded by malware."

AMDRyzenMasterDriver.sys takes a different approach. Rather than exposing MSR access directly, it provides arbitrary physical memory read/write IOCTLs, which is functionally equivalent to the vendor utility drivers discussed in the [vendor utility](vendor-utility.md) category. h0mbre's detailed writeup documents the full exploitation chain from IOCTL discovery through physical address scanning to SYSTEM token theft.

### GPU Memory as Kernel Memory Access

NVIDIA's nvlddmkm.sys manages the GPU through memory-mapped I/O regions that include the GPU framebuffer and control registers. On systems with discrete GPUs, the GPU has its own DMA engine that can read and write system physical memory independently of the CPU. If the GPU driver's IOCTL interface allows user-mode code to configure GPU DMA operations, the attacker can use the GPU as a proxy to read and write arbitrary physical memory.

zer0condition's NVDrv PoC demonstrates this by using the GPU memory mapping interface to establish kernel read/write. The technique works because the GPU's view of physical memory is not restricted by the CPU's page tables or SMEP/SMAP protections. This makes GPU-based memory access particularly interesting as a bypass for CPU-side mitigations.

## Vulnerability Patterns and Detection

| Pattern | Description | AutoPiff Rules |
|---------|-------------|----------------|
| Arbitrary MSR write | IOCTL writes to any MSR with user-controlled index/value | `direct_arw_ioctl_detected` |
| GPU memory mapping | Maps GPU MMIO regions accessible from user mode | `mmmapiospace_user_controlled` |
| MMIO register access | Direct hardware register R/W via IOCTL | `mmio_mapping_bounds_validation_added` |
| Chipset info disclosure | Chipset configuration readable via IOCTL | `physical_memory_mapping_exposed` |

## CVEs

| CVE | Driver | Description | Class | ITW |
|-----|--------|-------------|-------|-----|
| [CVE-2020-12928](../case-studies/CVE-2020-12928.md) | `AMDRyzenMasterDriver.sys` | AMD Ryzen Master, arbitrary R/W via IOCTL | Arbitrary R/W | No |
| [CVE-2023-20598](../case-studies/CVE-2023-20598.md) | AMD chipset driver | AMD chipset, info disclosure / MMIO | Info Disclosure | No |
| [CVE-2025-7771](../case-studies/CVE-2025-7771.md) | `ThrottleStop.sys` | ThrottleStop, MSR write / AV killer | Arbitrary R/W | Yes |
| [NVDrv](../case-studies/NVDrv.md) | `nvlddmkm.sys` | NVIDIA, GPU memory R/W | Arbitrary R/W | No |

## Research Outlook

Performance and GPU drivers are common on gaming and workstation systems, which means the attack surface is present on a large number of endpoints. CPU tuning utilities like AMD Ryzen Master and ThrottleStop are popular among enthusiasts, and their drivers may remain installed even after the utility itself is uninstalled. GPU drivers from NVIDIA and AMD are present on virtually every system with a discrete graphics card.

The research opportunity in this category goes beyond finding new BYOVD-capable drivers. GPU-based memory access techniques (like NVDrv) represent an emerging class of attack that bypasses CPU-side mitigations entirely. As Microsoft hardens kernel memory protections through HVCI, KDP, and other mechanisms, GPU DMA channels may become one of the few remaining paths to unrestricted physical memory access. Researchers should investigate whether GPU driver IOCTL interfaces on AMD and Intel GPUs offer similar capabilities to what zer0condition demonstrated on NVIDIA.

For the broader category of OEM hardware drivers that share the BYOVD pattern, see [Vendor Utility Drivers](vendor-utility.md). For third-party security drivers that are also used as BYOVD targets but for different capabilities (process termination, callback removal), see [Third-Party Security Drivers](third-party-security.md).
