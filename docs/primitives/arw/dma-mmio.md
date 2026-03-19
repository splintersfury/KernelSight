# DMA / MMIO Access

Physical memory is the layer beneath virtual memory, beneath the kernel, beneath every software protection mechanism that Windows provides. If an attacker can read and write physical memory directly, they bypass KASLR (which only randomizes virtual addresses), bypass pool isolation (which only separates virtual mappings), and bypass most kernel-mode protections (which assume physical memory is not directly accessible from user mode). DMA and MMIO access primitives provide exactly this capability: they let user-mode code touch physical memory without going through the kernel's virtual memory management layer.

The distinction between DMA and MMIO is architectural but the exploitation impact is the same. Memory-Mapped I/O (MMIO) uses `MmMapIoSpace` or `MmMapIoSpaceEx` to map a physical address range into kernel virtual address space, making it accessible through normal pointer dereference. Direct Memory Access (DMA) uses bus-mastering hardware to read and write physical memory independently of the CPU, through DMA common buffers or scatter/gather lists. Both techniques ultimately provide access to the same physical address space, and both are dangerous when a driver allows user-mode code to control the target physical address.

## How MMIO access becomes exploitable

The most common vulnerability pattern involves a driver that calls `MmMapIoSpace` with a physical address derived from user input. `MmMapIoSpace` maps a range of physical addresses into kernel virtual space, returning a pointer that can be used for read and write operations. The function is designed for hardware register access and makes no distinction between device memory regions and main system RAM. If the attacker controls the physical address argument, they can map any physical memory, including the pages backing kernel code, page tables, process structures, and security tokens.

Drivers that expose this capability typically do so through IOCTLs intended for hardware diagnostics, firmware updates, or performance monitoring. MSI Afterburner's `RTCore64.sys` ([CVE-2019-16098](../../case-studies/CVE-2019-16098.md)) exposed IOCTLs for reading and writing arbitrary physical addresses through `MmMapIoSpace`, along with MSR and I/O port access. Gigabyte's `gdrv.sys` ([CVE-2018-19320](../../case-studies/CVE-2018-19320.md)) provided similar physical memory mapping capabilities. In both cases, the drivers were legitimately signed and loaded by their respective software packages, making them ideal [BYOVD](direct-ioctl-rw.md) tools.

ASUS `AsIO3.sys` extends the MMIO pattern to include SMRAM (System Management RAM) access. SMRAM is a protected memory region used by System Management Mode (SMM), the most privileged execution mode on x86 platforms. Accessing SMRAM through `MmMapIoSpace` can expose SMM handler code and data, potentially enabling SMM-level persistence that survives operating system reinstallation.

## How DMA access becomes exploitable

DMA-based access is architecturally different from MMIO. Instead of the CPU mapping physical addresses into virtual space, a bus-mastering device (or a device under software control) reads and writes physical memory directly through the memory bus. The CPU is not involved in the actual memory transfer, which means kernel protections like page table permissions do not apply.

GPU drivers are a notable source of DMA-based primitives. Modern GPUs have their own memory controllers and DMA engines that can access system physical memory for texture uploads, command buffer processing, and display surface management. If a GPU driver allows user-mode code to control DMA transfer parameters (source address, destination address, transfer size), the user can direct the GPU to read or write arbitrary physical memory.

The NVDrv (`nvlddmkm.sys`) case demonstrates this pattern. NVIDIA's GPU driver manages DMA transfers between system memory and GPU memory, and certain code paths allow user-mode applications to influence the physical addresses involved in these transfers. While the intended use is legitimate GPU operation, the same mechanism can be redirected to access arbitrary physical memory.

## IOMMU as the hardware defense

The Input/Output Memory Management Unit (IOMMU, also known as Intel VT-d or AMD-Vi) is the hardware-level defense against DMA attacks. An IOMMU sits between the device bus and physical memory, translating device-visible addresses to actual physical addresses through a page table that the operating system controls. With IOMMU enforcement enabled, a device can only access physical memory pages that the OS has explicitly mapped into the device's IOMMU page table.

Windows supports IOMMU through Kernel DMA Protection (introduced in Windows 10 1803), which uses VBS to enforce IOMMU restrictions. When enabled, external devices cannot access physical memory outside their assigned regions. However, IOMMU protection has limitations: it does not protect against drivers that map physical memory through `MmMapIoSpace` (which uses CPU virtual memory, not device DMA), it may not cover all internal bus-mastering devices, and it requires specific hardware support.

Without IOMMU enforcement, any device with bus-mastering capability can access all physical memory. This includes devices connected via Thunderbolt, FireWire, or PCIe, making physical access attacks possible through external port connections. The ATSZIO64.sys driver represents the software variant of this attack, where a legitimately loaded driver provides the same physical memory access that a malicious Thunderbolt device would.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2019-16098](../../case-studies/CVE-2019-16098.md) | `RTCore64.sys` | Physical memory mapping via MmMapIoSpace |
| [CVE-2018-19320](../../case-studies/CVE-2018-19320.md) | `gdrv.sys` | Physical memory mapping via MmMapIoSpace |
| [ATSZIO64.sys](../../case-studies/ATSZIO64-sys.md) | `ATSZIO64.sys` | Physical memory mapping via MmMapIoSpace |
| [AsIO3.sys](../../case-studies/AsIO3-sys.md) | `AsIO3.sys` | Physical memory R/W including SMRAM access |
| [NVDrv](../../case-studies/NVDrv.md) | `nvlddmkm.sys` | GPU DMA-based physical memory access |

## AutoPiff Detection

AutoPiff detects patches related to DMA and MMIO access through three rules. The `mmio_mapping_bounds_validation_added` rule fires when a patch adds range validation on the physical address argument to `MmMapIoSpace` or `MmMapIoSpaceEx`, restricting mappings to specific hardware regions rather than allowing arbitrary physical addresses. The `dma_buffer_bounds_check_added` rule catches patches that add size or address validation on DMA common buffer allocations. The `new_dma_mmio_access` rule identifies cases where a new code path introduces physical memory access, which may indicate a regression or feature addition that warrants security review.

- `mmio_mapping_bounds_validation_added`
- `dma_buffer_bounds_check_added`
- `new_dma_mmio_access`

## From physical access to exploitation

Once an attacker has physical memory read/write, the exploitation path depends on the target. The most straightforward approach is to search physical memory for known structures. The `_EPROCESS` structure for each process contains identifiable fields (process ID, image file name, linked list pointers) that can be found through physical memory scanning. Once the target `_EPROCESS` is located, the attacker reads the SYSTEM token and writes it to the current process's token field, performing a [token swap](../exploitation/token-swapping.md) entirely through physical memory access.

[PTE manipulation](pte-manipulation.md) is another common target for physical memory access. Page table entries are stored in physical memory and control virtual-to-physical address translation. By modifying PTEs through physical memory access, the attacker can create virtual mappings that bypass SMEP, SMAP, and other page-level protections. This provides code execution capability on top of the data-only access that physical memory R/W already provides.

Physical memory access also enables attacks that are impossible through virtual memory alone. Reading the page tables themselves reveals the physical-to-virtual address mapping, defeating KASLR completely. Modifying interrupt descriptor table (IDT) entries redirects hardware interrupts to attacker-controlled code. Accessing firmware regions (UEFI variables, ACPI tables) enables boot-level persistence.

## See Also

- [Direct IOCTL R/W](direct-ioctl-rw.md) -- the broader category of drivers exposing unrestricted memory access
- [MDL Mapping](mdl-mapping.md) -- a related technique that maps physical pages through the MDL API rather than `MmMapIoSpace`
- [PTE Manipulation](pte-manipulation.md) -- modifying page tables, often achieved through physical memory access
- [Token Manipulation](token-manipulation.md) -- a common exploitation target reachable through physical memory scanning
