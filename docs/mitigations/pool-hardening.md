# Pool Hardening

Incremental protections added to the Windows kernel pool allocator over multiple releases to raise the cost of heap corruption, pool overflow, and deterministic pool layout attacks.

## Overview

Microsoft has progressively hardened the kernel pool (heap) allocator since Windows 10, with each release adding protections against pool-based exploitation. The most significant architectural change came in Windows 10 19H1 (build 18362), which replaced the legacy NT pool allocator with the Segment Heap -- a modern allocator design with randomized metadata placement and improved isolation. Additional changes include NonPagedPoolNx enforcement, pool header cookie validation, safe unlinking, the `ExAllocatePool2` API that zeros memory by default, and allocation size class bucketing that resists deterministic pool spray layouts.

Pool corruption (overflow, use-after-free, type confusion) remains the most common class of kernel vulnerability. Unlike SMEP/SMAP or HVCI, which block specific exploitation primitives, pool hardening targets the initial corruption step directly.

## Mechanism

**Pool Header Cookies and Checksums:**

- Each pool allocation has a header containing metadata (size, pool type, tag). A cookie value derived from the header address and a global secret is stored in the header.
- On free, the pool manager validates the cookie. Corrupted headers (e.g., from an overflow) cause a bugcheck (`BAD_POOL_HEADER`).
- This prevents classic attacks that overwrite pool headers to control free-list operations.

**Safe Unlinking:**

- When removing a pool chunk from a free list, the allocator validates that the forward and backward pointers are consistent (i.e., `entry->Flink->Blink == entry && entry->Blink->Flink == entry`).
- Corrupted list pointers are detected before the unlink operation, preventing arbitrary write via linked list manipulation.

**Segment Heap (Windows 10 19H1+):**

- Replaces the legacy NT heap with a segment-based allocator that uses Variable Size (VS) segments, Low Fragmentation Heap (LFH) buckets, and large block segments.
- Metadata is placed at randomized offsets rather than inline with allocations, making it harder to corrupt via linear overflow.
- LFH buckets introduce randomized allocation order within a subsegment, defeating deterministic pool spray.
- VS segment subsegments have randomized base addresses.

**NonPagedPoolNx and ExAllocatePool2:**

- `NonPagedPoolNx` replaces `NonPagedPool` as the default non-paged pool type, ensuring all pool allocations are non-executable.
- `ExAllocatePool2` (introduced in 20H1) replaces the deprecated `ExAllocatePoolWithTag`. It zeros memory by default, preventing information disclosure from uninitialized pool data, and mandates `NonPagedPoolNx`.

**Allocation Size Class Separation:**

- Allocations are grouped into size classes. Same-size allocations tend to land in the same LFH bucket subsegment.
- However, different size classes are separated, making it harder to get a target object adjacent to a controlled overflow object of a different size.

## Primitives Blocked

- **Pool header corruption leading to arbitrary free (cookies):** Overwriting pool headers to control the next-free-pointer or trigger a controlled free is detected by cookie validation.
- **Free list unlink exploitation (safe unlinking):** Corrupting linked list pointers to achieve a write-what-where during unlink is caught by pointer validation.
- **Deterministic pool spray layout (Segment Heap):** The randomized allocation order in LFH and VS segments means pool spray is probabilistic rather than deterministic, reducing exploit reliability.
- **Information disclosure from uninitialized pool (ExAllocatePool2):** Memory zeroing eliminates leaks of kernel pointers from recycled pool chunks.
- **Code execution from pool memory (NonPagedPoolNx):** Pool allocations are non-executable, blocking shellcode placed in pool chunks.

## Bypass History

- **Pool header cookie leakage and forging (ongoing):** If an attacker has an information disclosure primitive to read the pool header cookie and global secret, they can forge valid headers. This downgrades the cookie protection to an information disclosure requirement.
- **Probabilistic pool spray (ongoing):** While the Segment Heap randomizes allocation order, spraying a sufficient number of allocations (typically thousands) still achieves high probability of adjacent placement. The attack becomes probabilistic rather than deterministic but remains practical.
- **Incomplete type isolation (ongoing):** Many different kernel object types share the same size class buckets. One object type can be sprayed and overflowed into a different type in the same bucket. Microsoft has been adding type-based isolation for specific objects but coverage is incomplete.
- **Large allocations bypass LFH (ongoing):** Allocations above the LFH threshold (approximately 16KB) go through the VS segment allocator, which has different randomization properties. Very large allocations (above 1 page) use page-aligned allocations that can be more predictable.
- **Cross-page overflow into adjacent allocation (ongoing):** Pool overflow attacks that cross page boundaries can still reach adjacent objects, especially in VS segments where subsegment layout is less randomized than LFH.

## AutoPiff Detection

- `pool_type_nx_migration` -- Migration to NonPagedPoolNx
- `deprecated_pool_api_replacement` -- `ExAllocatePoolWithTag` to `ExAllocatePool2`
- `pool_allocation_null_check_added` -- NULL check after allocation

## Windows Version Availability

| Version | Status | Notes |
|---------|--------|-------|
| Windows 10 RS1 (1607) | Pool cookies, safe unlinking | Initial pool header hardening |
| Windows 10 RS5 (1809) | NonPagedPoolNx default | Non-executable pool enforcement |
| Windows 10 19H1 (1903) | Segment Heap | Major allocator replacement |
| Windows 10 20H1 (2004) | `ExAllocatePool2` | Zeroing by default, deprecates `ExAllocatePoolWithTag` |
| Windows 11 21H2 | Enhanced Segment Heap | Additional randomization improvements |
| Windows 11 22H2-24H2 | Incremental hardening | Type isolation for selected object types |

## Cross-References

- [Secure Pool](secure-pool.md) -- VBS-backed pool providing stronger guarantees for critical allocations
- [Pool Overflow](../primitives/arw/pool-overflow.md) -- the primary attack primitive that pool hardening targets
- [Pool Spray / Feng Shui](../primitives/exploitation/pool-spray-feng-shui.md) -- heap grooming techniques affected by Segment Heap randomization
- [Write-What-Where](../primitives/arw/write-what-where.md) -- pool header unlink exploitation converts to WWW
- [CVE-2024-30085](../case-studies/CVE-2024-30085.md) -- pool overflow in `clfs.sys` that must contend with pool hardening
- [CVE-2023-28252](../case-studies/CVE-2023-28252.md) -- CLFS pool corruption exploit
- [CVE-2024-49138](../case-studies/CVE-2024-49138.md) -- heap-based buffer overflow in CLFS
