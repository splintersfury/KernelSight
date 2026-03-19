# Pool Hardening

Pool corruption remains the most common entry point for Windows kernel exploitation. Buffer overflows, use-after-free, and type confusion in pool allocations account for the majority of CVEs in the KernelSight corpus. Pool hardening targets this initial corruption step directly, adding layers of protection to the kernel heap allocator that make pool-based exploitation harder without eliminating it entirely.

Microsoft has progressively hardened the kernel pool since Windows 10, with each release adding protections against specific exploitation techniques. The most significant architectural change came in Windows 10 19H1 (build 18362), which replaced the legacy NT pool allocator with the Segment Heap. Additional changes include NonPagedPoolNx enforcement, pool header cookie validation, safe unlinking, the `ExAllocatePool2` API that zeros memory by default, and allocation size class bucketing that resists deterministic pool spray.

## How It Works

**Pool header cookies and checksums** protect the metadata that the allocator stores alongside each allocation. Each pool allocation has a header containing size, pool type, and tag information, along with a cookie value derived from the header address and a global secret. On free, the pool manager validates the cookie. If an overflow has corrupted the header, the cookie check fails and the system bugchecks with `BAD_POOL_HEADER`. This prevents the classic attack where an overflow corrupts pool headers to control free-list operations and achieve an arbitrary write during the unlink.

**Safe unlinking** adds pointer validation to the free-list removal operation. When removing a pool chunk from a free list, the allocator verifies that `entry->Flink->Blink == entry && entry->Blink->Flink == entry`. Corrupted list pointers are detected before the unlink happens, preventing the write-what-where primitive that linked list manipulation historically provided.

**Segment Heap (Windows 10 19H1 onward)** replaced the legacy NT heap with a fundamentally different architecture. The new allocator uses Variable Size (VS) segments for irregular allocations, Low Fragmentation Heap (LFH) buckets for common sizes, and large block segments for allocations above one page. Crucially, metadata is placed at randomized offsets rather than inline with allocations, making it much harder to corrupt via linear overflow. LFH buckets introduce randomized allocation order within a subsegment, breaking the deterministic pool spray patterns that made pre-19H1 exploitation reliable. VS segment subsegments have randomized base addresses.

**NonPagedPoolNx and ExAllocatePool2** address two separate problems. `NonPagedPoolNx` replaces `NonPagedPool` as the default non-paged pool type, ensuring all pool allocations are non-executable. This blocks shellcode placement in pool memory. `ExAllocatePool2`, introduced in Windows 10 20H1, replaces the deprecated `ExAllocatePoolWithTag` with an API that zeros memory by default, preventing information disclosure from uninitialized pool data, and mandates `NonPagedPoolNx`.

**Allocation size class separation** groups allocations into size classes. Same-size allocations tend to land in the same LFH bucket subsegment, but different size classes are separated. This makes it harder to place a target object adjacent to a controlled overflow object when the two objects have different sizes. The attacker must find a spray object that matches the target's size class.

## What Pool Hardening Blocks

The cumulative effect is significant. Pool header corruption leading to arbitrary free is caught by cookie validation. Free list unlink exploitation is caught by pointer validation. Deterministic pool spray layout is disrupted by Segment Heap randomization. Information disclosure from recycled pool chunks is prevented by `ExAllocatePool2`'s zeroing. Shellcode placed in pool memory cannot execute because of NonPagedPoolNx.

## What Still Works

Pool hardening raises the cost of pool exploitation without eliminating it. Each protection has known limitations that keep pool-based attacks viable.

**Pool header cookie leakage and forging** is possible with an information disclosure primitive. If the attacker can read a pool header and the global cookie secret, they can forge valid headers. This downgrades the cookie protection to an information disclosure requirement.

**Probabilistic pool spray** accounts for the Segment Heap's randomization. While allocation order within an LFH bucket is randomized, spraying a sufficient number of allocations (typically thousands) still achieves high probability of adjacent placement. The attack becomes probabilistic rather than deterministic, but with enough spray iterations, success rates above 90% are achievable. Every CLFS exploit in the corpus ([CVE-2025-29824](../case-studies/CVE-2025-29824.md), [CVE-2023-28252](../case-studies/CVE-2023-28252.md), [CVE-2024-49138](../case-studies/CVE-2024-49138.md)) uses probabilistic spray against the Segment Heap.

**Incomplete type isolation** means many different kernel object types share the same size class buckets. An overflow from one object type can corrupt a different type in the same bucket. Microsoft has been adding type-based isolation for specific high-value objects, but coverage remains incomplete.

**Large allocations bypass LFH** because allocations above the LFH threshold (approximately 16KB) go through the VS segment allocator, which has different randomization properties. Very large allocations (above 1 page) use page-aligned allocations that can be more predictable.

**Cross-page overflow into adjacent allocations** remains effective, especially in VS segments where subsegment layout is less randomized than LFH. Pool overflow attacks that cross page boundaries can still reach adjacent objects.

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

## The Reliability Tax

Pool hardening's real contribution is not prevention but reliability degradation. A pre-Segment Heap exploit could achieve near-100% reliability with a carefully sized spray. Post-Segment Heap, the same technique might succeed 70-90% of the time, with failed attempts risking a bugcheck that alerts defenders. For a ransomware operator deploying across thousands of machines, that reliability drop is acceptable. For a targeted APT that needs silent, single-attempt exploitation, it is a meaningful obstacle. The hardening does not stop exploitation, but it makes it noisier and less predictable, shifting the advantage toward defenders who can detect the spray patterns and failed attempts.

For VBS-backed pool protections that go beyond software-level hardening, see [Secure Pool](secure-pool.md). For how pool spray and heap grooming techniques have adapted to these changes, see [Pool Spray / Feng Shui](../primitives/exploitation/pool-spray-feng-shui.md).

## Cross-References

- [Secure Pool](secure-pool.md) -- VBS-backed pool providing stronger guarantees for critical allocations
- [Pool Overflow](../primitives/arw/pool-overflow.md) -- the primary attack primitive that pool hardening targets
- [Pool Spray / Feng Shui](../primitives/exploitation/pool-spray-feng-shui.md) -- heap grooming techniques affected by Segment Heap randomization
- [Write-What-Where](../primitives/arw/write-what-where.md) -- pool header unlink exploitation converts to WWW
- [CVE-2024-30085](../case-studies/CVE-2024-30085.md) -- pool overflow in `clfs.sys` that must contend with pool hardening
- [CVE-2023-28252](../case-studies/CVE-2023-28252.md) -- CLFS pool corruption exploit
- [CVE-2024-49138](../case-studies/CVE-2024-49138.md) -- heap-based buffer overflow in CLFS
