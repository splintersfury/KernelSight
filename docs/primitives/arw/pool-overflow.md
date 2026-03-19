# Pool Overflow to R/W

A buffer overflow in user-mode code usually corrupts a stack frame or a heap chunk. In the kernel, the stakes are different. The pool allocator packs kernel objects shoulder to shoulder within fixed-size buckets, and a write past the end of one allocation lands directly in the header or data fields of the adjacent object. If that adjacent object happens to be a pipe attribute entry, a WNF state data structure, or an I/O completion packet, the attacker does not just crash the system. They gain a controlled read or write primitive that turns a simple size-check omission into full privilege escalation.

Pool overflows have been the single most productive vulnerability class for Windows kernel exploitation over the past five years. The `cldflt.sys` mini-filter driver alone has produced multiple exploitable pool overflows ([CVE-2024-30085](../../case-studies/CVE-2024-30085.md), [CVE-2023-36036](../../case-studies/CVE-2023-36036.md)), and the `clfs.sys` Common Log File System driver has been a recurring source of heap corruption bugs that threat actors have exploited in the wild ([CVE-2024-49138](../../case-studies/CVE-2024-49138.md), [CVE-2023-36424](../../case-studies/CVE-2023-36424.md)). What makes these vulnerabilities reliably exploitable, rather than just denial-of-service crashes, is the combination of pool spray techniques and carefully chosen corruption targets.

## From overflow to primitive

The raw vulnerability is straightforward: a kernel function allocates a buffer of size N and copies more than N bytes into it. The excess bytes overwrite whatever sits in the adjacent pool chunk. Without intervention, this adjacent chunk is some random kernel allocation, the overwritten data is meaningless, and the result is a bluescreen at some indeterminate future point. This is the default outcome for a pool overflow, and it is useless for exploitation.

The attacker's job is to replace that randomness with predictability. Through [pool spray](../exploitation/pool-spray-feng-shui.md), the attacker fills the target size bucket with controlled objects, then selectively frees some of them to create holes. When the vulnerable allocation lands in one of these holes, the overflow writes into a known object type with known field offsets. The corruption is no longer random; it modifies specific fields in a specific structure to produce a specific capability.

The most common corruption targets are length fields and data pointers. Extending the `ValueLength` field of a [pipe attribute](pipe-attributes.md) entry from 0x100 to 0x1000 causes the kernel to read 0xF00 extra bytes from adjacent pool memory when the attribute is queried, leaking kernel pointers and defeating KASLR. Overwriting a data pointer redirects subsequent reads or writes to an arbitrary kernel address. Corrupting a `DataSize` field in a [named pipe data queue entry](../exploitation/named-pipe-objects.md) achieves the same relative-read effect in NonPagedPoolNx.

## The exploitation sequence

A pool overflow exploit follows a predictable structure, though each step requires careful calibration to the specific vulnerability and target object.

First, the attacker determines the vulnerable allocation's size class, pool type, and pool tag. This information comes from reverse engineering the allocation site in the driver. The size class determines which pool bucket the allocation lands in, and only objects in the same bucket can be adjacent to it. The pool type (PagedPool vs. NonPagedPoolNx) constrains which spray objects are available. On Windows 11 with Segment Heap, the pool tag matters too, since allocations with different tags are isolated onto separate pages.

Second, the attacker selects a spray object that matches these constraints. For PagedPool targets, [pipe attributes](pipe-attributes.md) and [WNF state data](../exploitation/wnf-state-data.md) are the standard choices. For NonPagedPoolNx targets, [named pipe data queue entries](../exploitation/named-pipe-objects.md) are the workhorse. The spray object must have user-controlled content, a useful field to corrupt (length, pointer, or callback), and a way to read the corrupted data back from user mode.

Third, the attacker grooms the pool layout by spraying thousands of objects, poking holes at regular intervals, and triggering the vulnerable allocation to fill one of those holes. The [pool spray](../exploitation/pool-spray-feng-shui.md) page covers this process in detail.

Fourth, the attacker triggers the overflow. The excess bytes land in the adjacent spray object, modifying the target field. The attacker then reads back from the corrupted object through its normal API (e.g., `FSCTL_PIPE_GET_ATTRIBUTE` for pipe attributes, `ReadFile` for pipe data queue entries, `NtQueryWnfStateData` for WNF objects) to extract leaked kernel pointers or confirm the corruption.

From this point, the exploit transitions to a different primitive. The information leak feeds into [I/O Ring](../exploitation/io-ring.md) buffer table corruption for full kernel R/W, which then enables [token swapping](../exploitation/token-swapping.md) for privilege escalation. The pool overflow was the entry point, but the actual privilege escalation happens through the downstream chain.

## Common vulnerability patterns

The driver bugs that produce pool overflows fall into a few recurring patterns. Missing length validation before `memcpy` or `RtlCopyMemory` is the most common: the driver copies user-supplied data into a fixed-size or calculated-size buffer without verifying that the data length fits. Integer overflow in size calculations is another frequent source, where adding a header size to a user-controlled length wraps around to a small value, causing an undersized allocation followed by a copy of the full (large) data.

Reparse data handling has been a particularly rich source of pool overflows. Both `cldflt.sys` CVEs in the table below involve reparse point processing where the driver trusts length fields embedded in the reparse data without validating them against the actual buffer size. The CLFS driver (`clfs.sys`) overflows arise from corrupted base log file structures where offset fields point outside the allocated container, and the driver follows them without bounds checking.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-30085](../../case-studies/CVE-2024-30085.md) | `cldflt.sys` | Heap overflow from missing size check |
| [CVE-2023-36036](../../case-studies/CVE-2023-36036.md) | `cldflt.sys` | Heap overflow via reparse data |
| [CVE-2024-49138](../../case-studies/CVE-2024-49138.md) | `clfs.sys` | Heap overflow in LoadContainerQ |
| [CVE-2023-36424](../../case-studies/CVE-2023-36424.md) | `clfs.sys` | Pool overflow from unvalidated reparse data |

## AutoPiff Detection

AutoPiff identifies pool overflow patches through several complementary rules. The `added_len_check_before_memcpy` rule fires when a patch introduces a size comparison before a memory copy operation that previously lacked one. The `pool_allocation_null_check_added` rule catches cases where the patch adds a NULL check after pool allocation, preventing use of a failed allocation that could lead to corruption. The `deprecated_pool_api_replacement` rule detects migrations from older pool APIs (like `ExAllocatePoolWithTag`) to safer variants (`ExAllocatePool2`) that include additional validation and zeroing.

- `added_len_check_before_memcpy`
- `pool_allocation_null_check_added`
- `deprecated_pool_api_replacement`

## Mitigations and the Segment Heap shift

Pool overflows remain exploitable on all current Windows versions, but the difficulty has increased substantially since Windows 10 19H1 introduced Segment Heap for the kernel pool. The most impactful change is pool tag isolation: allocations with different pool tags no longer share pages, meaning the spray object must either share the vulnerable allocation's pool tag or the attacker must find a cross-page overflow path. LFH randomization within buckets makes exact adjacency probabilistic rather than deterministic, requiring larger spray volumes.

Pool header cookies provide a secondary defense: an overflow that corrupts the pool chunk header (the 0x10 bytes preceding each allocation) triggers an immediate bugcheck, converting the exploit into a crash. Successful exploitation must skip the header and target the adjacent object's data fields directly, which requires the overflow to be large enough to span the header gap.

Despite these mitigations, every major pool overflow CVE since 2020 has been successfully exploited on Segment Heap systems. The mitigations raise the cost of exploitation but do not prevent it. The [pool spray](../exploitation/pool-spray-feng-shui.md) page discusses the specific adaptations required for Segment Heap in detail.

## See Also

- [Pool Spray / Heap Feng Shui](../exploitation/pool-spray-feng-shui.md) -- the pool grooming techniques that make overflow exploitation reliable
- [Pipe Attributes](pipe-attributes.md) -- the most common corruption target for PagedPool overflows
- [Named Pipe Objects](../exploitation/named-pipe-objects.md) -- the standard corruption target for NonPagedPoolNx overflows
- [I/O Ring](../exploitation/io-ring.md) -- the downstream R/W primitive typically chained after a pool overflow info leak
