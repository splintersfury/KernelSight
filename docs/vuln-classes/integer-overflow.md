# Integer Overflow

Integer overflow and underflow vulnerabilities in size calculations, leading to undersized allocations or incorrect bounds checks.

## Description

Integer overflow occurs when arithmetic on sizes or lengths wraps around, producing a smaller-than-expected value. This commonly leads to undersized pool allocations followed by buffer overflows, or bypassed bounds checks.

## Patterns

- Size multiplication overflow: `count * element_size` wraps to small value
- Addition overflow: `header_size + data_size` wraps
- Subtraction underflow: `total - consumed` underflows to large value
- Truncation: 64-bit size truncated to 32-bit

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-38063](../case-studies/CVE-2024-38063.md) | `tcpip.sys` | Integer underflow in IPv6 reassembly |
| [CVE-2024-38054](../case-studies/CVE-2024-38054.md) | `ksthunk.sys` | Integer overflow in KSSTREAM_HEADER thunking |
| [CVE-2023-28218](../case-studies/CVE-2023-28218.md) | `afd.sys` | Integer overflow in AfdCopyCMSGBuffer |
| [CVE-2025-24985](../case-studies/CVE-2025-24985.md) | `fastfat.sys` | Cluster count overflow in FAT bitmap |

## AutoPiff Detection

- `safe_size_math_helper_added` — Raw arithmetic replaced with safe math helpers
- `alloc_size_overflow_check_added` — Overflow check before allocation
