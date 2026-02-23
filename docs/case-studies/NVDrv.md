# NVDrv

> NVIDIA display driver — GPU memory mapping exposes kernel read/write primitive

## Summary

| Field | Value |
|-------|-------|
| **Driver** | `nvlddmkm.sys` |
| **Vendor** | NVIDIA |
| **Vulnerability Class** | Arbitrary R/W / GPU Memory Mapping |
| **Abused Version** | Multiple versions |
| **Status** | Still loadable — signed NVIDIA display driver |
| **Exploited ITW** | No |

## BYOVD Context

- **Driver signing**: Authenticode-signed by NVIDIA Corporation with valid certificate; WHQL-certified
- **Vulnerable Driver Blocklist**: Not included — blocklisting the primary GPU driver would break display functionality
- **HVCI behavior**: Loads normally as a WHQL-signed driver
- **KDU integration**: Not integrated
- **LOLDrivers**: Not listed as a standard BYOVD driver

## Affected Interfaces

- GPU MMIO register mapping to user space
- GPU physical memory mapping via DMA regions
- GPU BAR (Base Address Register) mapping

## Root Cause

`nvlddmkm.sys` is NVIDIA's primary Windows display driver. As a WDDM (Windows Display Driver Model) driver, it manages GPU hardware, including mapping GPU memory regions (MMIO registers, framebuffer, command queues) between kernel and user space. The GPU's DMA engine has access to all system physical memory, and the GPU driver manages this access.

zer0condition's NVDrv project on GitHub demonstrates how the GPU driver's memory mapping interfaces can be abused to achieve arbitrary kernel read/write. The technique exploits the fact that GPU hardware has DMA access to system physical memory, and the driver provides interfaces to map GPU-accessible memory to user space. By manipulating GPU page tables or DMA mappings, an attacker can read/write arbitrary system physical memory through the GPU.

This differs from traditional BYOVD drivers because the "vulnerability" is inherent in the GPU's DMA architecture rather than a simple IOCTL-based memory access.

## Exploitation

zer0condition's approach:

1. Interact with the NVIDIA driver's GPU memory management interfaces
2. Manipulate GPU page tables to map system physical memory into GPU-accessible regions
3. Read system physical memory through GPU DMA
4. Walk page tables to locate kernel structures
5. Modify EPROCESS tokens for privilege escalation

The technique is more complex than standard IOCTL-based BYOVD but harder to detect and mitigate since the NVIDIA display driver cannot be blocklisted without breaking display functionality.

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
| Microsoft-Windows-Security-Auditing | Event 4672 — Special privileges | Privilege escalation detection |

### Behavioral Indicators

- Non-graphical processes interacting with NVIDIA GPU memory management interfaces
- GPU memory allocations with physical address mappings to kernel address ranges
- Token swap on a process that has been interacting with GPU driver interfaces
- Unusual DXGK (DirectX Graphics Kernel) subsystem calls from non-rendering processes

## References

- [zer0condition — NVDrv](https://github.com/zer0condition/NVDrv)
