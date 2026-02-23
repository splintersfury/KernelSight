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

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2019-16098](../../case-studies/CVE-2019-16098.md) | `RTCore64.sys` | Physical memory mapping via MmMapIoSpace |
| [CVE-2018-19320](../../case-studies/CVE-2018-19320.md) | `gdrv.sys` | Physical memory mapping via MmMapIoSpace |
| [ATSZIO64.sys](../../case-studies/ATSZIO64-sys.md) | `ATSZIO64.sys` | Physical memory mapping via MmMapIoSpace |
| [AsIO3.sys](../../case-studies/AsIO3-sys.md) | `AsIO3.sys` | Physical memory R/W including SMRAM access |
| [NVDrv](../../case-studies/NVDrv.md) | `nvlddmkm.sys` | GPU DMA-based physical memory access |
