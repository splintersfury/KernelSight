# Pipe Attribute Primitives

Named pipe extended attributes used as arbitrary read/write primitives through controlled kernel pool allocations with attacker-specified size and content.

## Description

Named pipe extended attributes are key-value pairs managed by the Named Pipe File System driver (`npfs.sys`) through the `NtFsControlFile` API. When an attribute is set with `FSCTL_PIPE_SET_ATTRIBUTE`, the kernel allocates a pool buffer to store the attribute name and value data. When an attribute is read with `FSCTL_PIPE_GET_ATTRIBUTE`, the kernel copies the stored data back to user mode. By corrupting an attribute entry's value pointer or length field, an attacker gains controlled read-back from arbitrary kernel addresses.

Pipe attributes are allocated in PagedPool with a total size of approximately `sizeof(header) + name_length + value_length`, giving fine-grained control over which pool bucket the allocation lands in. The attribute value content is fully attacker-controlled, making pipe attributes an effective spray primitive. Multiple attributes can be set on a single pipe handle, each producing a separate pool allocation, and individual attributes can be deleted to create precise holes in the pool layout.

The pipe attribute technique is widely used in modern Windows kernel exploits as both a spray primitive for pool grooming and as a read-back primitive for information leaks. It complements the [named pipe data queue entry](../exploitation/named-pipe-objects.md) technique, which operates in NonPagedPoolNx, by providing similar capabilities for PagedPool targets. Together, pipe data queue entries and pipe attributes give an attacker spray coverage across both major pool types.

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

The exact internal layout varies between Windows versions. The important fields for exploitation are:

- **`ValueLength`** -- controls how many bytes the kernel copies on `FSCTL_PIPE_GET_ATTRIBUTE`. Corrupting this field to a larger value produces an out-of-bounds read.
- **`AttributeValue`** -- if this is a pointer (rather than inline data), corrupting it to a kernel address makes `FSCTL_PIPE_GET_ATTRIBUTE` read from that arbitrary address.
- **`LIST_ENTRY`** -- the linked list pointers connecting attributes. Corrupting these causes a BSOD during pipe cleanup, so exploits must avoid modifying them.

## Mechanism

### Setting and Reading Attributes

1. **Create named pipe pair** -- call `CreateNamedPipe` for the server end and `CreateFile` for the client end
2. **Set attribute** -- call `NtFsControlFile` with `FSCTL_PIPE_SET_ATTRIBUTE` (control code `0x110038`), providing an attribute name string and a value buffer of the desired size
3. **Kernel allocates attribute entry** -- `npfs.sys` allocates a PagedPool buffer containing the header, name, and value data
4. **Get attribute** -- call `NtFsControlFile` with `FSCTL_PIPE_GET_ATTRIBUTE` (control code `0x11003C`), providing the attribute name; the kernel locates the matching entry and copies `ValueLength` bytes to the user-mode output buffer
5. **Delete attribute** -- call `NtFsControlFile` with `FSCTL_PIPE_DELETE_ATTRIBUTE` to free the pool allocation (useful for hole-poking)

### As an Arbitrary Read Primitive

1. **Spray pipe attributes** of target size to fill the target pool bucket, creating a dense layout adjacent to the vulnerable allocation
2. **Trigger vulnerability** -- a pool overflow or UAF corrupts an adjacent attribute entry
3. **Corrupt `ValueLength`** -- the overflow extends the `ValueLength` field to a value larger than the actual allocation (e.g., change 0x100 to 0x1000)
4. **Call `FSCTL_PIPE_GET_ATTRIBUTE`** -- the kernel reads `ValueLength` bytes starting from the attribute value data, extending past the allocation boundary
5. **Receive leaked data** -- the excess bytes come from adjacent pool memory and may contain kernel pointers, pool metadata, or object headers useful for KASLR bypass

Alternatively, if the corruption can overwrite the `AttributeValue` pointer directly:

1. **Set `AttributeValue`** to an arbitrary kernel address
2. **Call `FSCTL_PIPE_GET_ATTRIBUTE`** -- the kernel reads `ValueLength` bytes from the specified kernel address
3. **Receive data** from the target kernel address in the user-mode output buffer

### As an Arbitrary Write Primitive

1. **Corrupt attribute entry** -- extend the `ValueLength` or modify the `AttributeValue` pointer
2. **Call `FSCTL_PIPE_SET_ATTRIBUTE`** with updated value data -- the kernel writes the attacker-controlled data to the (corrupted) buffer region
3. **Targeted overwrite** -- the written data extends past the original allocation or targets an arbitrary kernel address, overwriting adjacent object fields

### As a Spray Primitive

1. Create a large number of named pipes (e.g., 10,000)
2. Set attributes on each pipe with value buffers sized to target a specific pool bucket
3. Attribute data is fully controlled -- plant marker bytes, fake pointers, or fake structure fields
4. Selectively delete attributes on specific pipes to create holes at known positions
5. Trigger the vulnerable allocation to land in a prepared hole

## Practical Considerations

- **Pool type**: Pipe attribute allocations are made from PagedPool. This makes them suitable for grooming vulnerabilities in PagedPool but not for NonPagedPoolNx targets (use [named pipe data queue entries](../exploitation/named-pipe-objects.md) for NonPagedPoolNx).
- **Attribute name contributes to allocation size**: The name string is stored inline in the allocation. Exploits typically use short, fixed-length names (e.g., `"A"`) and vary the value size for precise bucket targeting.
- **Multiple attributes per pipe**: A single pipe can hold multiple attributes, each in a separate pool allocation. This allows creating allocations of different sizes from a single pipe handle.
- **LIST_ENTRY corruption is fatal**: The attribute linked list pointers are walked during pipe cleanup. If `Flink` or `Blink` is corrupted, the kernel follows an invalid pointer and causes a BSOD. Robust exploits either avoid corrupting the list entry fields or restore them before closing the pipe.
- **Segment heap considerations**: On Windows 11 with segment heap, pipe attribute allocations may be isolated by pool tag from other allocation types, limiting cross-object spray effectiveness. Tag-matched spray (finding objects with the same pool tag as the target) can bypass this.
- **Combined with DATA_QUEUE_ENTRY**: Many exploits use pipe attributes for PagedPool spray and `DATA_QUEUE_ENTRY` for NonPagedPoolNx spray in the same exploit chain, covering both pool types.
- **Cleanup order matters**: Close pipe handles in a controlled order to avoid triggering linked list traversal on corrupted entries. Some exploits intentionally leak handles rather than closing them.

## Mitigations and Limitations

- **Pool header cookies**: Overflows that damage pool chunk headers are detected and cause BSOD. The corruption must target the attribute entry's data fields, not the pool header.
- **Segment Heap pool tag isolation** (Windows 11): Pipe attribute allocations may be isolated from other pool tag types, reducing cross-object spray effectiveness.
- **No integrity check on attribute fields**: The kernel does not validate that `ValueLength` or `AttributeValue` have not been tampered with before performing the read-back. This is the fundamental weakness that enables the read primitive.
- **PagedPool only**: Pipe attributes cannot be used to groom NonPagedPoolNx targets. Exploits targeting NonPagedPoolNx drivers must use alternative spray objects.
- **KASLR**: Leaked pointers must be interpreted relative to the randomized kernel base. The pipe attribute read primitive is often used specifically to defeat KASLR by disclosing kernel pointers from adjacent allocations.

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
