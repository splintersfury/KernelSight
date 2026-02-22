# Pipe Attribute Primitives

Abusing named pipe extended attributes for controlled kernel pool reads and writes.

## Description

Named pipe objects maintain attribute lists (extended attributes) in kernel pool. By carefully sizing pipe attribute allocations, attackers can place controlled data adjacent to vulnerable objects for pool overflow exploitation, or use pipe attributes for relative read/write operations.

## Mechanism

Named pipe attributes are key-value pairs stored internally by the named pipe file system driver (`npfs.sys`). They are managed through the `NtFsControlFile` API with specific file system control codes:

- **FSCTL_PIPE_SET_ATTRIBUTE** (`0x110038`): Sets a named attribute on a pipe. The kernel allocates a pool buffer to store the attribute name and value data.
- **FSCTL_PIPE_GET_ATTRIBUTE** (`0x11003C`): Reads a named attribute from a pipe. The kernel copies the attribute data back to a user-mode buffer.
- **FSCTL_PIPE_DELETE_ATTRIBUTE**: Removes a named attribute, freeing the associated pool allocation.

Internally, pipe attributes are stored as a linked list of pool allocations associated with the pipe's `FILE_OBJECT`. Each attribute entry contains:

- The attribute name (a string key, e.g., `"PipeAttribute"`)
- The attribute value (arbitrary binary data, fully controlled by the attacker)
- A `LIST_ENTRY` linking to the next attribute

The total allocation size is approximately `sizeof(header) + name_length + value_length`, giving the attacker fine-grained control over which pool bucket the allocation lands in.

## As a Pool Grooming Primitive

Pipe attributes are a powerful pool grooming tool due to their precise size control:

1. **Create many pipes**: Use `CreateNamedPipe` to create a large number of pipe instances.
2. **Set attributes of a target size**: For each pipe, call `NtFsControlFile` with `FSCTL_PIPE_SET_ATTRIBUTE`, passing a value buffer sized to produce allocations in the desired pool bucket. For example, to target the 0x200 bucket, choose a value size that results in a total allocation of 0x181-0x200 bytes.
3. **Attribute data is fully controlled**: The attacker can fill the attribute value with arbitrary bytes, including fake structure fields, pointers, or marker patterns for later identification.
4. **Controlled hole-punching**: Closing a pipe handle releases all associated attribute allocations. By closing specific pipes, the attacker creates holes of the exact target size in the pool layout.
5. **Pool type**: Pipe attribute allocations are made from PagedPool, making them suitable for grooming vulnerabilities in PagedPool allocations.

## As a Relative Read Primitive

After an adjacent pool overflow or UAF corrupts a pipe attribute entry:

1. The overflow modifies the length field of the attribute entry, extending it beyond the actual allocation size.
2. The attacker calls `NtFsControlFile` with `FSCTL_PIPE_GET_ATTRIBUTE` to read the attribute data.
3. The kernel copies `length` bytes starting from the attribute data buffer. Because the length was corrupted to a larger value, the read extends past the allocation boundary.
4. The excess bytes come from the adjacent pool allocation, which may contain:
   - Pool headers and metadata (useful for pool base address calculation)
   - Object headers (for determining object types and security descriptors)
   - Kernel pointers (for KASLR bypass)
   - Other sensitive kernel data

This provides a reliable information leak without crashing the system, as the kernel performs a normal `memcpy` from the (corrupted) attribute buffer.

## As a Relative Write Primitive

The same corruption can be leveraged for writing:

1. After corrupting the attribute entry's length field to be larger than the actual allocation, the attacker calls `NtFsControlFile` with `FSCTL_PIPE_SET_ATTRIBUTE` to update the attribute value.
2. The kernel writes the new attribute data starting from the buffer, but because the length field indicates a larger buffer, the write extends past the allocation boundary.
3. The attacker controls the written data, enabling targeted overwrite of adjacent pool objects.
4. This can be used to modify specific fields in neighboring kernel structures, such as:
   - Corrupting a `_TOKEN` object's `Privileges` field for privilege escalation
   - Modifying an `_OBJECT_HEADER` to change object type or security
   - Overwriting function pointers in adjacent driver-specific structures

## Practical Considerations

- **Attribute name matters**: The attribute name is also stored in the allocation and contributes to the total size. Exploits typically use short, fixed-length names and vary the value size for bucket targeting.
- **Multiple attributes per pipe**: A single pipe can hold multiple attributes, each in a separate pool allocation. This can be used to create multiple allocations of different sizes from a single pipe handle.
- **Cleanup safety**: When closing a pipe, the kernel frees all associated attribute allocations and walks the linked list. If the `LIST_ENTRY` pointers have been corrupted, this can cause a BSOD. Robust exploits either restore the linked list before cleanup or avoid corrupting the list pointers entirely.
- **Segment heap considerations**: On Windows 11 with segment heap, pipe attribute allocations are tagged and may be isolated from other pool tag allocations, limiting cross-object grooming effectiveness.

## Exploitation

1. Create named pipes with specific EA sizes to fill pool holes
2. Use `NtFsControlFile` to read/write pipe attribute data
3. Leverage for relative read after pool corruption
