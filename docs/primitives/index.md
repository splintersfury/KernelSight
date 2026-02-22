# Primitives

Exploitation primitives used in Windows kernel driver exploitation, organized into arbitrary R/W primitives and exploitation techniques.

## Arbitrary Read/Write Primitives

Vulnerability patterns and driver behaviors that yield controlled kernel memory access.

| Primitive | Description |
|-----------|-------------|
| [Direct IOCTL R/W](arw/direct-ioctl-rw.md) | Drivers exposing direct memory read/write IOCTLs |
| [Pool Overflow](arw/pool-overflow.md) | Heap corruption of adjacent allocations |
| [MDL Mapping](arw/mdl-mapping.md) | Abusing MDL lock/map for arbitrary mapping |
| [Arb Increment/Decrement](arw/arb-increment-decrement.md) | Controlled increment/decrement at arbitrary address |
| [Write-What-Where](arw/write-what-where.md) | Controlled address and value write |
| [Registry-Based](arw/registry-based.md) | Passing controlled data via registry values |
| [DMA / MMIO](arw/dma-mmio.md) | Physical memory access via DMA or MMIO |
| [Pipe Attributes](arw/pipe-attributes.md) | Named pipe EA-based pool read/write |
| [Token Manipulation](arw/token-manipulation.md) | Overwriting token structures |
| [PTE Manipulation](arw/pte-manipulation.md) | Modifying page table entries |

## Exploitation Primitives

Techniques for converting a vulnerability into reliable exploitation.

| Primitive | Description |
|-----------|-------------|
| [Pool Spray / Feng Shui](exploitation/pool-spray-feng-shui.md) | Heap grooming for controlled layout |
| [Named Pipe Objects](exploitation/named-pipe-objects.md) | Pipe objects as spray and R/W gadgets |
| [I/O Ring](exploitation/io-ring.md) | I/O Ring mechanism for kernel R/W |
| [WNF State Data](exploitation/wnf-state-data.md) | WNF objects as pool spray primitives |
| [Palette / Bitmap](exploitation/palette-bitmap.md) | Legacy GDI object exploitation |
| [KUSER_SHARED_DATA](exploitation/kuser-shared-data.md) | Fixed-address data structure abuse |
| [PreviousMode Manipulation](exploitation/previous-mode-manipulation.md) | KTHREAD.PreviousMode overwrite |
| [Token Swapping](exploitation/token-swapping.md) | Process token pointer replacement |
| [ACL / SD Manipulation](exploitation/acl-sd-manipulation.md) | Security descriptor modification |
