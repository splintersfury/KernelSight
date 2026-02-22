# DMA / MMIO Access

Using Direct Memory Access or Memory-Mapped I/O to read/write physical memory.

## Description

Drivers that map physical memory via `MmMapIoSpace` or configure DMA transfers without proper bounds validation may allow mapping of arbitrary physical addresses. Without IOMMU enforcement, DMA-capable devices can access all physical memory.

## Mechanism

- `MmMapIoSpace` / `MmMapIoSpaceEx` with controlled physical address
- DMA common buffer allocation with attacker-influenced parameters
- Missing IOMMU (VT-d) enforcement

## AutoPiff Detection

- `mmio_mapping_bounds_validation_added`
- `dma_buffer_bounds_check_added`
- `new_dma_mmio_access`
