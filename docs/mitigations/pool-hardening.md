# Pool Hardening

Kernel pool allocator hardening including segment heap, LFH randomization, pool cookies, and NonPagedPoolNx.

## Description

- **Segment Heap** (Win10 20H1+): Replaced the NT heap with a hardened allocator
- **LFH Randomization**: Low Fragmentation Heap random ordering resists pool spray
- **Pool Cookies**: Integrity checks on pool chunk headers
- **NonPagedPoolNx**: Non-executable non-paged pool (default with `ExAllocatePool2`)
- **ExAllocatePool2**: Zeros memory by default, preventing info leaks

## AutoPiff Detection

- `pool_type_nx_migration` — Migration to NonPagedPoolNx
- `deprecated_pool_api_replacement` — ExAllocatePoolWithTag → ExAllocatePool2
- `pool_allocation_null_check_added` — NULL check after allocation
