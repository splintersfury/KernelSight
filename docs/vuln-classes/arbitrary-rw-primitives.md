# Arbitrary R/W Primitives

Overview of vulnerability patterns that yield arbitrary kernel read/write capabilities.

## Description

Many kernel vulnerabilities are not directly exploitable but can be converted into an arbitrary read/write primitive — the ability to read from or write to any kernel virtual address. This primitive is the key stepping stone to full exploitation.

## Primitive Families

See the [Primitives](../primitives/index.md) section for detailed entries:

- [Direct IOCTL R/W](../primitives/arw/direct-ioctl-rw.md) — Drivers exposing direct memory access IOCTLs
- [Pool Overflow](../primitives/arw/pool-overflow.md) — Heap corruption of adjacent objects
- [MDL Mapping](../primitives/arw/mdl-mapping.md) — Abusing MDL lock/map for arbitrary mapping
- [Write-What-Where](../primitives/arw/write-what-where.md) — Controlled address and value write
- [Token Manipulation](../primitives/arw/token-manipulation.md) — Overwriting token structures

## Related CVEs

| CVE | Driver | Primitive Type |
|-----|--------|---------------|
| [CVE-2024-21338](../case-studies/CVE-2024-21338.md) | `appid.sys` | Direct IOCTL |
| [CVE-2023-21768](../case-studies/CVE-2023-21768.md) | `afd.sys` | Write-what-where |
| [CVE-2024-26229](../case-studies/CVE-2024-26229.md) | `csc.sys` | Missing access check |
