# Pool Overflow to R/W

Heap/pool overflow corrupting adjacent allocations to build an arbitrary R/W primitive.

## Description

A pool overflow allows writing past the end of a kernel pool allocation, corrupting the header or data of the adjacent chunk. By controlling the pool layout through spraying, the attacker can target specific object types (e.g., named pipe data queue entries, WNF state data) to gain a R/W primitive.

## Exploitation Flow

1. Trigger pool spray to control adjacent allocation type
2. Overflow into adjacent object's header/data
3. Corrupt size field, pointer, or vtable
4. Use corrupted object to read/write arbitrary memory

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-30085](../../case-studies/CVE-2024-30085.md) | `cldflt.sys` | Heap overflow from missing size check |
| [CVE-2023-36036](../../case-studies/CVE-2023-36036.md) | `cldflt.sys` | Heap overflow via reparse data |
| [CVE-2024-49138](../../case-studies/CVE-2024-49138.md) | `clfs.sys` | Heap overflow in LoadContainerQ |
| [CVE-2023-36424](../../case-studies/CVE-2023-36424.md) | `clfs.sys` | Pool overflow from unvalidated reparse data |

## AutoPiff Detection

- `added_len_check_before_memcpy`
- `pool_allocation_null_check_added`
- `deprecated_pool_api_replacement`
