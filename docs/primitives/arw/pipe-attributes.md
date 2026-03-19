# Pipe Attribute Primitives

When a kernel exploit needs to spray PagedPool, read arbitrary kernel memory, or write controlled data past an allocation boundary, named pipe attributes are the tool of choice. They are to PagedPool exploitation what `DATA_QUEUE_ENTRY` objects are to NonPagedPoolNx: a flexible, well-understood primitive that provides both size-controlled allocations for spray and data-controlled content for corruption.

The reason pipe attributes are so widely used comes down to three properties. First, the allocation size is precisely controllable through the attribute value length, allowing the attacker to target any pool bucket. Second, the attribute data is fully attacker-controlled, so spray objects can contain marker bytes, fake pointers, or fake structure fields. Third, corrupted attributes can be read back through a normal API call (`FSCTL_PIPE_GET_ATTRIBUTE`), which means any modification to the attribute's length or pointer fields translates directly into an information leak or an arbitrary read. These properties have made pipe attributes a standard component in exploit chains for vulnerabilities in `cldflt.sys`, `clfs.sys`, `csc.sys`, and `afd.sys`.

## How pipe attributes work in the kernel

Named pipe attributes are key-value pairs managed by the Named Pipe File System driver (`npfs.sys`) through the `NtFsControlFile` API. When an attribute is set with `FSCTL_PIPE_SET_ATTRIBUTE` (control code `0x110038`), the kernel allocates a PagedPool buffer to store the attribute name and value data in an `NP_ATTRIBUTE_ENTRY` structure. When read with `FSCTL_PIPE_GET_ATTRIBUTE` (control code `0x11003C`), the kernel locates the matching entry by name and copies `ValueLength` bytes to the user-mode output buffer. Deleting an attribute with `FSCTL_PIPE_DELETE_ATTRIBUTE` frees the pool allocation, which is useful for hole-poking during pool grooming.

The total allocation size is approximately `sizeof(header) + name_length + value_length`, giving the attacker fine-grained control over which pool bucket the allocation lands in. Exploits typically use short, fixed-length names (like `"A"`) and vary the value size to target specific buckets. Multiple attributes can be set on a single pipe handle, each producing a separate pool allocation, and individual attributes can be deleted independently to create precise holes in the pool layout.

## Key Structures

```
NP_ATTRIBUTE_ENTRY (approximate layout from npfs.sys)
  +0x000  Flink / Blink        // LIST_ENTRY linking to next/previous attribute
  +0x010  AttributeNameLength  // length of attribute name in bytes
  +0x018  AttributeName        // inline UNICODE_STRING or pointer to name
  +0x020  AttributeValue       // pointer to value data (or inline)
  +0x028  ValueLength          // length of attribute value in bytes
  ... (inline name and value data follow the header)
```

The exact internal layout varies between Windows versions, but the fields that matter for exploitation remain consistent across builds.

**`ValueLength`** controls how many bytes the kernel copies on `FSCTL_PIPE_GET_ATTRIBUTE`. Corrupting this field to a larger value produces an out-of-bounds read: the kernel reads past the attribute's allocation boundary into adjacent pool memory, and the excess bytes are returned to user mode. This is the foundation of the pipe attribute information leak.

**`AttributeValue`** is either an inline pointer or the start of inline data, depending on the implementation. If it is a pointer and the attacker can corrupt it to a kernel address, `FSCTL_PIPE_GET_ATTRIBUTE` reads from that arbitrary address and returns the data to user mode. This provides a direct arbitrary read primitive rather than a relative one.

**`LIST_ENTRY` (Flink/Blink)** links attributes together for cleanup. Corrupting these pointers is fatal: the kernel follows them during pipe handle closure, and an invalid pointer causes an immediate BSOD. Exploits must either avoid modifying the list entry fields or restore them before the pipe is closed.

## Using pipe attributes for pool spray

The spray sequence is straightforward. The attacker creates a large number of named pipes (typically thousands), each with a server and client end. On each pipe, they set one or more attributes with value buffers sized to target a specific pool bucket. This saturates the target bucket with controlled allocations. The attacker then selectively deletes attributes on specific pipes to create holes at regular intervals. When the vulnerable allocation lands in one of these holes, it sits adjacent to surviving pipe attribute entries.

The content of each attribute's value data is fully controlled. For pool spray, exploits fill the value with marker bytes (unique patterns for each pipe, so the attacker can identify which attribute was corrupted), fake pointers (for cases where the corrupted object's pointer field should point to a known value), or fake structure fields (for type confusion scenarios). After triggering the vulnerability, the attacker reads back each pipe's attribute to check for modifications. Changed marker bytes indicate which attribute was adjacent to the vulnerable allocation.

## Using pipe attributes as an arbitrary read

After a [pool overflow](pool-overflow.md) or use-after-free corrupts an adjacent pipe attribute entry, the read primitive works through two mechanisms.

In the relative read variant, the overflow extends the `ValueLength` field to a value larger than the actual attribute data. When the attacker calls `FSCTL_PIPE_GET_ATTRIBUTE`, the kernel copies the extended number of bytes starting from the attribute value data, reading past the allocation boundary into adjacent pool memory. The excess bytes may contain kernel pointers from neighboring allocations (useful for KASLR bypass), pool metadata, object headers, or the content of adjacent kernel structures. The kernel performs a normal `memcpy` for this operation, so it does not crash the system.

In the direct read variant, the corruption overwrites the `AttributeValue` pointer itself. The attacker sets it to an arbitrary kernel address, and `FSCTL_PIPE_GET_ATTRIBUTE` reads `ValueLength` bytes from that address. This provides a fully arbitrary read primitive, limited only by the attacker's knowledge of the target address.

## Using pipe attributes as an arbitrary write

The same corruption pattern enables writing beyond allocation boundaries. After corrupting a pipe attribute's `ValueLength` or `AttributeValue` pointer, the attacker calls `FSCTL_PIPE_SET_ATTRIBUTE` with updated value data. The kernel writes the attacker-controlled data to the (corrupted) buffer region, potentially overwriting fields in neighboring kernel objects or writing to an arbitrary kernel address.

This write variant is less commonly used than the read variant, because by the time an attacker has corrupted a pipe attribute entry, they often have other write paths available (such as the pool overflow itself). However, the pipe attribute write is useful for precision: it writes attacker-controlled data of a known length to a known position, which is cleaner than relying on an overflow's spillover.

## Practical Considerations

**Pool type matters.** Pipe attribute allocations are made from PagedPool. They cannot groom NonPagedPoolNx targets. For NonPagedPoolNx, use [named pipe data queue entries](../exploitation/named-pipe-objects.md) instead. Many exploits use both: pipe attributes for PagedPool targets and data queue entries for NonPagedPoolNx targets in the same exploit chain.

**The attribute name contributes to allocation size.** The name string is stored inline in the allocation. Exploits typically use short, fixed-length names and vary the value size for precise bucket targeting. Using long attribute names adds unnecessary size uncertainty.

**Multiple attributes per pipe** allow creating allocations of different sizes from a single pipe handle. This can be useful for complex spray patterns but adds complexity to cleanup.

**LIST_ENTRY corruption is fatal.** The attribute linked list pointers are walked during pipe cleanup. If `Flink` or `Blink` is corrupted, the kernel follows an invalid pointer and causes a BSOD. Exploits must either avoid corrupting the list entry fields (by ensuring the overflow does not reach them) or restore them before closing the pipe. Some exploits intentionally leak pipe handles rather than closing them, avoiding the cleanup code path entirely.

**Segment Heap isolation** on Windows 11 may separate pipe attribute allocations (pool tag `NpAt`) from other allocation types, limiting cross-object spray effectiveness. When pool tag isolation applies, the attacker needs tag-matched spray: finding objects that share the same pool tag as the target allocation, or exploiting code paths that allocate with the same tag.

**Cleanup order matters.** Close pipe handles in a controlled order to avoid triggering linked list traversal on corrupted entries. When in doubt, leak the handles and let the OS clean them up at process exit, which uses a different (and more robust) cleanup path.

## Mitigations and Limitations

Pool header cookies detect overflows that damage pool chunk headers, causing a BSOD before the corruption can be leveraged. The corruption must target the attribute entry's data fields, not the pool header. Segment Heap pool tag isolation (Windows 11) reduces cross-object spray effectiveness by separating allocations with different tags onto different pages. Despite these mitigations, the kernel does not perform any integrity check on attribute fields (`ValueLength`, `AttributeValue`) before using them in `FSCTL_PIPE_GET_ATTRIBUTE`, which is the fundamental weakness that enables the read primitive. No mitigation currently validates that these fields have not been tampered with.

## Related CVEs

| CVE | Driver | Role |
|-----|--------|------|
| [CVE-2024-30085](../../case-studies/CVE-2024-30085.md) | `cldflt.sys` | Pipe attribute spray and read primitive for pool overflow exploitation |
| [CVE-2023-28252](../../case-studies/CVE-2023-28252.md) | `clfs.sys` | Pipe attribute spray for CLFS pool grooming |
| [CVE-2024-26229](../../case-studies/CVE-2024-26229.md) | `csc.sys` | Pipe attribute R/W primitive in exploit chain |
| [CVE-2023-36036](../../case-studies/CVE-2023-36036.md) | `cldflt.sys` | Pipe attribute spray for pool overflow |
| [CVE-2024-38193](../../case-studies/CVE-2024-38193.md) | `afd.sys` | Combined pipe attribute and data queue spray |

## See Also

- [Named Pipe Objects](../exploitation/named-pipe-objects.md) -- `DATA_QUEUE_ENTRY` spray for NonPagedPoolNx targets
- [Pool Spray / Heap Feng Shui](../exploitation/pool-spray-feng-shui.md) -- general pool spray theory and object selection criteria
- [Pool Overflow](pool-overflow.md) -- the vulnerability class that pipe attribute spray most commonly grooms
- [I/O Ring](../exploitation/io-ring.md) -- commonly chained after pipe attribute info leak for full kernel R/W
- [Token Manipulation](token-manipulation.md) -- downstream privilege escalation after achieving R/W via pipe attributes
