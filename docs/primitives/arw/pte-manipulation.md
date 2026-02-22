# PTE Manipulation

Modifying page table entries to remap pages or change memory protection flags.

## Description

Page Table Entries (PTEs) control virtual-to-physical address translation and page permissions. With an arbitrary write primitive, an attacker can modify PTEs to:

- Map user pages as kernel-executable (bypass SMEP)
- Map arbitrary physical memory into the process address space
- Change page permissions (read-only → read-write)

## Key Addresses

- `MiGetPteAddress` — resolves virtual address to PTE address
- PTE base is randomized since Windows 10 RS1 (but can be leaked)

## Mitigations

- [VBS/HVCI](../mitigations/vbs-hvci.md) protects page tables via hypervisor
- PTE base randomization complicates address calculation
