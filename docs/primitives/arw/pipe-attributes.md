# Pipe Attribute Primitives

Abusing named pipe extended attributes for controlled kernel pool reads and writes.

## Description

Named pipe objects maintain attribute lists (extended attributes) in kernel pool. By carefully sizing pipe attribute allocations, attackers can place controlled data adjacent to vulnerable objects for pool overflow exploitation, or use pipe attributes for relative read/write operations.

## Exploitation

1. Create named pipes with specific EA sizes to fill pool holes
2. Use `NtFsControlFile` to read/write pipe attribute data
3. Leverage for relative read after pool corruption
