# PTE Manipulation

Page Table Entries are the CPU's translation layer between virtual addresses and physical memory. Every memory access on an x86-64 system traverses a four-level page table hierarchy (PML4, PDPT, PD, PT), and the final entry in that hierarchy, the PTE, determines which physical page the virtual address maps to, whether the page is readable, writable, executable, and whether it belongs to user mode or kernel mode. Modifying a PTE changes the fundamental properties of the corresponding memory page. With an arbitrary write primitive targeting a PTE, an attacker can remap virtual addresses to point at arbitrary physical memory, make kernel pages writable, make user pages kernel-executable (bypassing SMEP), or create entirely new virtual-to-physical mappings that expose memory not otherwise accessible.

PTE manipulation is the most powerful primitive in the exploitation arsenal because it operates below the abstraction layer that all other protections depend on. KASLR randomizes virtual addresses, but PTEs contain the physical addresses. Pool isolation separates allocations in virtual space, but PTE manipulation can create new mappings that bypass the separation entirely. SMEP prevents the kernel from executing user-mode pages, but clearing the User/Supervisor bit in a PTE reclassifies the page as kernel-mode. The page table is the ground truth of the memory model, and controlling it means controlling everything above it.

## Resolving a virtual address to its PTE

Before an attacker can modify a PTE, they need to find it. The function `MiGetPteAddress` in `ntoskrnl.exe` computes the kernel virtual address of the PTE for any given virtual address. The computation is a simple linear transformation based on the PTE base address:

```
PTE_address = PTE_base + ((virtual_address >> 12) * 8)
```

The PTE base is the virtual address where the kernel maps the page table entries themselves (a self-referencing page table structure). On Windows 10 pre-RS1, this base was a fixed constant (`0xFFFFF68000000000`), making PTE address calculation trivial. Starting with RS1, Microsoft randomized the PTE base on each boot. The base is now a 25-bit random value shifted into the appropriate position, creating millions of possible locations.

This randomization does not make PTE manipulation impossible. It makes it dependent on an information leak. The PTE base can be obtained through several channels: reading it from `MiGetPteAddress`'s code (if the kernel base is known), leaking it through `NtQuerySystemInformation` information classes (some of which are restricted in newer builds), or computing it from a known PTE address for a controlled page. Once the PTE base is known, any virtual address can be resolved to its PTE address through the formula above.

## What a PTE contains

A 64-bit PTE on x86-64 contains the physical page frame number (bits 12-51), access permissions, and control flags:

```
PTE layout (x86-64)
  Bit  0    Present        // Page is in physical memory
  Bit  1    Read/Write     // 0 = read-only, 1 = read-write
  Bit  2    User/Super     // 0 = kernel-only, 1 = user-accessible
  Bit  3    PWT            // Page Write-Through
  Bit  4    PCD            // Page Cache Disable
  Bit  5    Accessed       // Page has been accessed
  Bit  6    Dirty          // Page has been written
  Bit  7    PAT            // Page Attribute Table
  Bit  63   NX/XD          // No-Execute (0 = executable, 1 = non-executable)
  Bits 12-51               // Physical page frame number
```

Each flag offers a distinct exploitation possibility. Clearing the NX bit makes a non-executable page executable, enabling code execution from data pages. Setting the R/W bit makes a read-only page writable, allowing modification of kernel code or read-only data structures. Clearing the U/S bit reclassifies a user page as kernel, bypassing SMEP (which prevents the kernel from executing user-mode pages). Changing the physical page frame number remaps the virtual address to point at a different physical page entirely, which is the most powerful manipulation: it can overlay any kernel structure with attacker-controlled content.

## Exploitation scenarios

**SMEP bypass** was historically the primary use case for PTE manipulation. Before data-only exploitation techniques matured, kernel exploits relied on redirecting kernel execution to shellcode mapped in user-mode memory. SMEP blocks this by faulting when the CPU attempts to execute a page marked as User. By clearing the U/S bit in the PTE for the shellcode page, the attacker makes the CPU treat it as a kernel page, and SMEP no longer prevents execution. This technique is less relevant on systems with HVCI, where page table modifications are validated by the hypervisor, but remains effective on non-VBS systems.

**Physical memory remapping** uses PTE manipulation to access memory that is not otherwise mapped into the process's address space. The attacker allocates a user-mode page, locates its PTE, and overwrites the physical page frame number with the frame number of a target page (such as the page containing the SYSTEM process's token). The user-mode virtual address now points at the target physical page, and the attacker can read and write it as if it were a normal user-mode allocation. This technique combines the power of [DMA/MMIO access](dma-mmio.md) with the convenience of user-mode addressing.

**Kernel code patching** uses PTE manipulation to make kernel code pages writable. The kernel's `.text` section is mapped as read-only and executable, preventing modification through normal write primitives. By setting the R/W bit in the PTE for a kernel code page, the attacker can patch kernel functions, install inline hooks, or modify jump tables. On HVCI-enabled systems, the hypervisor enforces a W^X policy on kernel pages: pages cannot be both writable and executable simultaneously. PTE manipulation on HVCI systems is therefore limited to data pages.

## Mitigations

[VBS/HVCI](../../mitigations/vbs-hvci.md) provides the strongest protection against PTE manipulation. With HVCI enabled, page table modifications are validated by the hypervisor through Second Level Address Translation (SLAT). The hypervisor enforces W^X: a page table entry cannot simultaneously set the R/W bit and clear the NX bit. Attempts to create a writable-executable page fault through the hypervisor rather than applying the change. This prevents SMEP bypass through PTE manipulation and prevents making kernel code pages writable.

However, HVCI does not prevent all PTE manipulation. The hypervisor does not validate all PTE changes for data pages, and physical page frame number remapping may still succeed for data (non-executable) pages. Additionally, HVCI requires VBS to be enabled, and many Windows systems (especially those running Windows 10 or Server editions) do not have VBS active.

PTE base randomization (Windows 10 RS1+) is a secondary mitigation that complicates PTE address calculation. It does not prevent PTE manipulation but requires the attacker to obtain the PTE base through an information leak before computing PTE addresses. The PTE base is a per-boot constant, so a single leak is sufficient for the entire exploitation session.

## See Also

- [DMA / MMIO](dma-mmio.md) -- physical memory access through hardware mapping, often combined with PTE manipulation
- [Write-What-Where](write-what-where.md) -- the arbitrary write primitive needed to modify PTEs
- [KUSER_SHARED_DATA](../exploitation/kuser-shared-data.md) -- a fixed-address structure whose PTE is sometimes targeted for code staging
- [Token Manipulation](token-manipulation.md) -- can be performed through PTE-based physical memory remapping
