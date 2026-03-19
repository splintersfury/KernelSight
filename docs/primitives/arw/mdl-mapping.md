# MDL Mapping Primitive

Consider a kernel streaming driver that needs to share a buffer between user mode and kernel mode for high-performance media processing. The efficient approach is to lock the physical pages backing the buffer and map them into both address spaces, avoiding costly copy operations. Windows provides the Memory Descriptor List (MDL) API for exactly this purpose: `MmProbeAndLockPages` locks the physical pages, and `MmMapLockedPages` or `MmMapLockedPagesSpecifyCache` creates a virtual mapping. When used correctly, these APIs are safe. When used incorrectly, they give user-mode code direct read/write access to arbitrary physical memory, including kernel code pages, process tokens, and page tables.

The vulnerability pattern is subtle because the MDL APIs are doing what they were designed to do. The security failure lies in how the driver calls them: which access mode it passes to `MmProbeAndLockPages`, whether it validates the buffer address before locking, and whether it maps the pages with appropriate protection. A single parameter choice, `KernelMode` instead of `UserMode` in the access mode argument, is the difference between a safe operation and an arbitrary physical memory mapping primitive.

## How MDL mapping works

An MDL is a kernel structure that describes a set of physical pages underlying a virtual address range. The normal sequence for sharing a buffer with user mode is:

1. The driver allocates or receives a buffer and builds an MDL for it using `IoAllocateMdl`
2. `MmProbeAndLockPages` validates that the virtual address range is accessible at the requested access mode and locks the physical pages into memory (preventing them from being paged out)
3. `MmMapLockedPages` or `MmMapLockedPagesSpecifyCache` creates a new virtual mapping of those physical pages, potentially in a different address space

The critical security check happens in step 2. When `MmProbeAndLockPages` is called with `UserMode` as the access mode, it verifies that every page in the range belongs to the user-mode address space and that the caller has the requested access (read or write). When called with `KernelMode`, it skips these checks entirely, because kernel-mode callers are assumed to know what they are doing. If a driver passes `KernelMode` but the buffer address came from user-mode input, the user controls which physical pages get locked, and by extension, which physical pages get mapped back to them.

## The vulnerability pattern

The exploitable pattern has two variants, both involving a mismatch between the trust level of the caller and the access mode used for the MDL operation.

In the first variant, the driver receives a buffer address from user mode (through an IOCTL, IRP, or shared memory region), builds an MDL for that address, and calls `MmProbeAndLockPages` with `KernelMode`. Because the access mode is `KernelMode`, no validation is performed on the address. If the user supplies a kernel virtual address, the driver will lock the physical pages backing that kernel address and then map them into user space. The attacker now has a user-mode mapping of kernel memory and can read or write it at will.

In the second variant, the driver calls `MmMapLockedPages` or `MmMapLockedPagesSpecifyCache` without first calling `MmProbeAndLockPages` at all. Some drivers skip the probe step as an optimization, especially when dealing with pre-locked buffers or DMA descriptors. Without the probe, there is no validation of the page range, and the mapping may expose arbitrary physical memory.

CVE-2023-29360 in `mskssrv.sys` (the Kernel Streaming Service Proxy driver) demonstrates the first variant. The driver accepted a user-controlled buffer address and passed it to `MmProbeAndLockPages` with `KernelMode`, allowing an attacker to map arbitrary kernel memory into user space. CVE-2024-38238 in `ksthunk.sys` demonstrates a related pattern where the mapping operation lacked adequate probing.

## From mapping to full R/W

Once the attacker has a user-mode mapping of kernel memory, the exploitation path depends on what physical pages were mapped. If the attacker can determine the physical address of a target structure (such as the current process's `_EPROCESS` or its token), they can map those pages and modify them directly. This provides a direct path to [token manipulation](token-manipulation.md) or [PTE manipulation](pte-manipulation.md) without needing an intermediate information leak or pool spray chain.

The challenge is that the attacker needs to know which physical address to request. KASLR randomizes kernel virtual addresses, but physical addresses can sometimes be derived through other information leaks, `NtQuerySystemInformation` calls, or by leveraging the MDL mapping itself iteratively: map a page, check its contents, unmap it, and try the next page until the target structure is found.

On systems without Virtualization-Based Security (VBS), the entire physical address space is fair game. The attacker can map MMIO regions, kernel code pages, page tables, and hardware device memory. On VBS-enabled systems, the hypervisor restricts which physical pages can be mapped, but the protection is not comprehensive for all page types.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2023-29360](../../case-studies/CVE-2023-29360.md) | `mskssrv.sys` | MmProbeAndLockPages with KernelMode |
| [CVE-2024-38238](../../case-studies/CVE-2024-38238.md) | `ksthunk.sys` | MmMapLockedPages without probe |

## AutoPiff Detection

AutoPiff identifies MDL-related patches through three rules that capture the most common fix patterns. The `mdl_probe_access_mode_fix` rule detects cases where a patch changes the access mode argument from `KernelMode` to `UserMode` in `MmProbeAndLockPages` calls, which is the direct fix for the first vulnerability variant. The `mdl_safe_mapping_replacement` rule fires when a driver replaces `MmMapLockedPages` with `MmMapLockedPagesSpecifyCache` using safer parameters, or adds `MmProtectMdlSystemAddress` calls to restrict the mapping permissions. The `mdl_null_check_added` rule catches cases where the patch adds a NULL check on the MDL pointer before operations, preventing use of an uninitialized or freed MDL.

- `mdl_probe_access_mode_fix`
- `mdl_safe_mapping_replacement`
- `mdl_null_check_added`

## Mitigations

[VBS/HVCI](../../mitigations/vbs-hvci.md) provides the strongest protection against MDL mapping abuse. The hypervisor enforces Second Level Address Translation (SLAT) permissions that prevent mapping kernel code pages as writable, even through a legitimate MDL operation. However, VBS does not protect all kernel data pages, and data-only attacks (such as token modification through a mapped page) may still succeed.

The kernel itself does not perform retroactive validation on MDL mappings. Once `MmProbeAndLockPages` succeeds, the locked pages remain accessible through any subsequent mapping operation. There is no mechanism to detect that a user-mode process has obtained a mapping of kernel memory pages. This makes MDL mapping abuse particularly stealthy compared to other R/W primitives that involve syscall-based reads and writes.

## See Also

- [DMA / MMIO](dma-mmio.md) -- physical memory access through hardware mapping APIs, a related but distinct primitive
- [PTE Manipulation](pte-manipulation.md) -- another technique for creating unauthorized memory mappings
- [Token Manipulation](token-manipulation.md) -- a common exploitation target once kernel memory is mapped into user space
- [Direct IOCTL R/W](direct-ioctl-rw.md) -- a simpler variant where the driver's IOCTL directly exposes memory access without MDL intermediate steps
