# NVDrv

> NVIDIA display driver -- the BYOVD target that cannot be blocklisted

## Summary

| Field | Value |
|-------|-------|
| **Driver** | `nvlddmkm.sys` |
| **Vendor** | NVIDIA |
| **Vulnerability Class** | Arbitrary R/W / GPU Memory Mapping |
| **Abused Version** | Multiple versions |
| **Status** | Still loadable -- signed NVIDIA display driver |
| **Exploited ITW** | No |

## BYOVD Context

- **Driver signing**: Authenticode-signed by NVIDIA Corporation with valid certificate; WHQL-certified
- **Vulnerable Driver Blocklist**: Not included -- blocklisting the primary GPU driver would break display functionality
- **HVCI behavior**: Loads normally as a WHQL-signed driver
- **KDU integration**: Not integrated
- **LOLDrivers**: Not listed as a standard BYOVD driver

## Affected Interfaces

- GPU MMIO register mapping to user space
- GPU physical memory mapping via DMA regions
- GPU BAR (Base Address Register) mapping

## The Unblocklable Target

Most BYOVD drivers have a mitigation path: Microsoft adds them to the Vulnerable Driver Blocklist, HVCI prevents their loading, and defenders detect their presence on disk. NVDrv breaks this model entirely. `nvlddmkm.sys` is NVIDIA's primary Windows display driver. Blocking it would disable display output on every NVIDIA GPU in the world. It is WHQL-certified, which means it has passed Microsoft's driver quality testing. It loads on HVCI-enabled systems without issue. There is no practical way to prevent it from being present on systems with NVIDIA hardware.

This makes NVDrv one of the most strategically interesting BYOVD techniques: it abuses a driver that defenders cannot remove, cannot blocklist, and cannot prevent from loading.

## Root Cause

The "vulnerability" in NVDrv is not a traditional bug. It is an inherent consequence of GPU architecture. Modern GPUs have DMA engines that can access all system physical memory. The GPU driver must map GPU-accessible memory to user space for applications to submit rendering commands and read back results. This memory mapping infrastructure, when combined with the GPU's DMA capability, creates a path from user space to arbitrary system physical memory.

zer0condition's NVDrv project on GitHub demonstrates how to exploit this architectural feature. The technique manipulates GPU page tables or DMA mappings to point the GPU's memory access at arbitrary system physical addresses. By reading and writing through the GPU's DMA window, the attacker accesses any physical memory page on the system, including kernel code, page tables, and process tokens.

This differs fundamentally from traditional BYOVD. A traditional BYOVD driver has a specific IOCTL that reads or writes kernel memory. NVDrv exploits the GPU's DMA architecture itself. The "vulnerability" is that GPUs have unrestricted physical memory access by design, and the driver provides the interfaces to direct that access.

## Exploitation

zer0condition's approach proceeds through the GPU's memory management layer rather than through simple IOCTLs.

The attacker interacts with the NVIDIA driver's GPU memory management interfaces to allocate and map GPU memory regions. By manipulating GPU page table entries, the attacker redirects GPU DMA operations to target system physical memory pages that contain kernel data structures. Reading through the GPU's DMA path reveals kernel addresses and structure contents, defeating KASLR. Walking kernel page tables through GPU-mediated physical memory reads locates the `_EPROCESS` structure and its token pointer. Writing through the same DMA path modifies the token, granting SYSTEM privileges.

The technique is more complex than standard IOCTL-based BYOVD but harder to detect because all operations go through legitimate GPU memory management APIs. The driver's behavior appears normal to kernel-level monitoring.

## Detection

### YARA Rule

```yara
rule NVDrv_abuse_tool {
    meta:
        description = "Detects NVDrv exploitation tool"
        author = "KernelSight"
        severity = "high"
    strings:
        $nvdrv = "NVDrv" ascii nocase
        $gpu_map = "NvGpuMap" ascii
        $phys_read = "PhysRead" ascii
        $phys_write = "PhysWrite" ascii
    condition:
        2 of them
}
```

### ETW Indicators

| Provider | Event / Signal | Relevance |
|----------|---------------|-----------|
| Microsoft-Windows-DxgKrnl | GPU memory allocation events | Unusual GPU memory mapping patterns |
| Microsoft-Windows-Kernel-Process | Process token modification | Post-exploitation token swap |
| Microsoft-Windows-Security-Auditing | Event 4672 -- Special privileges | Privilege escalation detection |

### Behavioral Indicators

- Non-graphical processes interacting with NVIDIA GPU memory management interfaces
- GPU memory allocations with physical address mappings to kernel address ranges
- Token swap on a process that has been interacting with GPU driver interfaces
- Unusual DXGK (DirectX Graphics Kernel) subsystem calls from non-rendering processes

## Broader Significance

NVDrv represents the future of the BYOVD problem. As Microsoft's Vulnerable Driver Blocklist grows and HVCI adoption increases, the easy BYOVD targets (small utility drivers with obvious IOCTLs) will be eliminated. What remains are the drivers that cannot be blocked: GPU drivers, network drivers, storage drivers, and other hardware-critical components that provide powerful primitives through their normal operation. DMA-based attacks through GPU drivers are one example; RDMA-capable network drivers are another. The defense industry has not yet developed effective mitigations for this category of threat.

## References

- [zer0condition -- NVDrv](https://github.com/zer0condition/NVDrv)
