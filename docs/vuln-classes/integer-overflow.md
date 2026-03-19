# Integer Overflow

A kernel driver asks the user how many items to process, multiplies by the element size, and allocates a buffer for the result. The math looks correct. The allocation succeeds. The subsequent copy writes four gigabytes past the end of a 16-byte buffer, because nobody checked whether `count * element_size` wrapped a 32-bit integer back to zero. Integer overflows are the invisible first domino: the arithmetic produces a wrong answer silently, and every operation downstream inherits that wrongness.

This page covers how integer overflow and underflow bugs arise in Windows kernel drivers, why they are uniquely dangerous as a precursor to other vulnerability classes, and how to detect them in patches and source code.

## Why silent arithmetic is the real problem

Most vulnerability classes announce themselves through visible symptoms. A buffer overflow corrupts adjacent memory. A use-after-free accesses freed memory. A NULL dereference crashes the system. Integer overflows do none of these things at the point of failure. The arithmetic instruction itself executes perfectly; it simply produces a result that does not match the developer's mathematical intent. A 32-bit unsigned multiplication of 0x10000001 by 0x100 yields 0x100, not 0x1000000100. The CPU is not wrong. The type is too narrow.

This silence is what makes integer overflows so persistent. Code review catches a missing NULL check because the reviewer can see the missing `if`. But `total_size = header_size + (count * element_size)` looks correct at a glance, and it *is* correct for every value of `count` that a tester would reasonably try. The bug only manifests at boundary values, and boundary values are exactly what attackers supply.

The consequence is almost always a [buffer overflow](buffer-overflow.md). The integer overflow produces an undersized allocation, and the subsequent copy uses either the original (pre-wrap) size or a separately calculated size, overflowing the tiny buffer into adjacent pool memory. This means integer overflow exploitation follows the buffer overflow playbook: [pool spray](../primitives/exploitation/pool-spray-feng-shui.md) to control adjacency, then corruption of a target object for a [write-what-where](../primitives/arw/write-what-where.md) or [token manipulation](../primitives/arw/token-manipulation.md) primitive.

## The arithmetic that breaks

Integer overflow bugs in drivers cluster around a small number of recurring arithmetic patterns. Recognizing them is the first step toward both finding and fixing these issues.

### Multiplication overflow

The most dangerous pattern. A user-controlled count is multiplied by a fixed element size to compute an allocation size. If `count` is large enough that the product exceeds `ULONG_MAX` (0xFFFFFFFF for 32-bit) or `SIZE_T_MAX` (for 64-bit), the result wraps. The allocation receives the wrapped (small) value while the copy loop iterates `count` times, writing far beyond the buffer.

CVE-2024-38054 in `ksthunk.sys` demonstrates this precisely. The kernel streaming thunking layer multiplied a user-supplied stream header count by the header structure size without overflow checking. The product wrapped to a small value, the pool allocation succeeded with the undersized buffer, and the subsequent copy of headers overflowed into adjacent pool memory.

### Addition overflow

Slightly less common but equally dangerous. A header size is added to a data size, and the sum wraps. The typical pattern is `total = FIELD_OFFSET(STRUCT, variable_array) + count * sizeof(element)`, where the addition of the fixed offset to the multiplication result overflows even if the multiplication itself did not. CVE-2022-21907 in `http.sys` involved exactly this pattern in HTTP header size computation.

### Subtraction underflow

When a consumed offset is subtracted from a total length to compute remaining bytes, and `consumed > total_length`, the result wraps to a massive unsigned value. A subsequent `RtlCopyMemory(dst, src, remaining)` attempts a multi-gigabyte copy. This is less controllable than multiplication overflow because the copy will fault on an unmapped page before the attacker can precisely target adjacent objects. But if the target object sits within the first few pages after the buffer, the corruption lands before the fault.

CVE-2024-38063 in `tcpip.sys` is the canonical example. An integer underflow in IPv6 packet reassembly produced a huge remaining-length value, causing a buffer overflow during fragment recombination. The bug was remotely triggerable without authentication, earning it a CVSS 9.8.

### Truncation

A 64-bit size value is narrowed to 32 bits for a pool allocation, but the full 64-bit value is used for the subsequent copy. `ULONG alloc_size = (ULONG)large_size_64` silently discards the upper 32 bits. If the original value was 0x100000010, the allocation gets 0x10 bytes while the copy processes 0x100000010. This pattern is especially treacherous because it passes every test where the size fits in 32 bits, which is every realistic test case.

### Signed/unsigned mismatch

A signed integer holding a negative value is compared against an unsigned maximum. Depending on the comparison semantics (the C standard promotes both sides to the same type, but the direction of promotion depends on the types involved), the negative value may pass the bounds check. When the same value is later used as an unsigned size for `RtlCopyMemory`, it becomes an enormous positive number. The code looks like it has proper validation. It does not.

### Chained arithmetic

Each individual operation is safe, but the combination overflows. `a + b` fits in 32 bits. `c + d` fits in 32 bits. But `(a + b) + (c + d)` does not. This pattern defeats simple overflow checking at each step and requires whole-expression analysis.

## Exploitation: the buffer overflow it creates

Integer overflow vulnerabilities almost always convert into [buffer overflow](buffer-overflow.md) exploitation. The overflow itself is just the mechanism that produces the wrong allocation size. Once the undersized buffer exists, exploitation proceeds identically to a direct buffer overflow.

The key subtlety is that integer overflows can bypass explicit bounds checks. A developer may correctly write `if (size > MAX_BUFFER_SIZE) return STATUS_INVALID_PARAMETER;`, but if `size` has already overflowed to a small value before this check, the validation passes and the real damage occurs in the subsequent copy. The code may appear to have proper validation at first glance. This is why integer overflow bugs survive code review at rates that would be surprising for other vulnerability classes.

``` mermaid
graph LR
    A["User input:\ncount = 0x40000001"] --> B["Multiply:\ncount * 0x40\n= 0x40 (wrapped)"]
    B --> C["Allocate:\n64-byte pool buffer"]
    C --> D["Copy:\ncount * 0x40 bytes\n(original value)"]
    D --> E["Pool overflow:\n~4GB write past\n64-byte buffer"]
    style A fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    style B fill:#1e293b,stroke:#ef4444,color:#e2e8f0
    style C fill:#1e293b,stroke:#f59e0b,color:#e2e8f0
    style D fill:#1e293b,stroke:#ef4444,color:#e2e8f0
    style E fill:#1e293b,stroke:#8b5cf6,color:#e2e8f0
```

Integer underflow variants, where subtraction wraps an unsigned value to near `ULONG_MAX`, can produce even larger overflows. A `remaining = total - consumed` underflow can cause `RtlCopyMemory` to attempt a multi-gigabyte copy, corrupting everything following the destination buffer until the copy faults on an unmapped page. This is less controllable than a precise multiplication overflow, but can still be exploited if the fault occurs after corrupting a target object.

## Typical primitives gained

Because integer overflows produce buffer overflows, the resulting primitives are the same:

- [Pool Overflow](../primitives/arw/pool-overflow.md), the undersized allocation followed by oversized write, producing a pool overflow identical to a direct buffer overflow
- [Pool Spray / Feng Shui](../primitives/exploitation/pool-spray-feng-shui.md), required to control what object is adjacent to the undersized buffer
- [Write-What-Where](../primitives/arw/write-what-where.md), if the overflow corrupts an object containing a pointer-and-size pair
- [Token Manipulation](../primitives/arw/token-manipulation.md), if pool spray places token-related objects adjacent to the overflowed buffer

## Mitigations that exist (and why adoption lags)

Windows provides a comprehensive safe arithmetic library, and it has been available since the Windows Vista SDK. The `Intsafe.h` header defines functions like `RtlULongMult`, `RtlULongAdd`, and `RtlSizeTAdd` that return `STATUS_INTEGER_OVERFLOW` on wrap-around instead of silently producing incorrect results. Using them is straightforward: replace `total = count * element_size` with `if (FAILED(RtlULongMult(count, element_size, &total))) return STATUS_INTEGER_OVERFLOW;`. The safe variant adds one branch and zero performance overhead in the non-overflow case.

Despite this, adoption remains incomplete. Many legacy drivers predate `Intsafe.h` and have never been updated. Even some recently-written code paths use raw arithmetic for size calculations, either because the developer was unaware of the safe variants or because the performance-conscious culture of kernel development leads to shortcuts. Every Patch Tuesday produces a few CVEs where the fix is literally adding a call to `RtlULongMult`.

Other mitigations include:

- **Compiler intrinsics** such as `__builtin_mul_overflow` that provide overflow detection at the instruction level
- **ExAllocatePool2**, the modern pool allocation API that accepts a `SIZE_T` parameter, reducing 64-to-32-bit truncation compared to the legacy `ExAllocatePoolWithTag`
- **SAL annotations** like `_In_range_` and `_Pre_satisfies_` that enable compile-time verification of size parameter constraints
- **Code review policy** mandating safe math helpers for any size calculation involving user-controlled values

## Detection strategies

**Patch diffing** is highly effective for integer overflow fixes because the patches are distinctive. A raw `count * element_size` replaced by `RtlULongMult(count, element_size, &total)` is immediately visible in a binary diff. Similarly, newly added overflow guards like `if (count > MAX_ULONG / element_size)` before multiplication are unmistakable. AutoPiff detects both patterns automatically, making it possible to scan an entire Patch Tuesday release for integer overflow fixes in minutes.

**Static analysis** should track user-controlled integers through arithmetic operations to allocation sizes. The rule is simple: any multiplication or addition on user input that feeds into `ExAllocatePoolWithTag` or `ExAllocatePool2` without an overflow check is a finding. Tools like CodeQL and Sema can express this as a taint-flow query from IOCTL input to pool allocation size parameter.

**Fuzzing** with boundary values is particularly effective for this class. Supplying 0, 1, `0x7FFFFFFF`, `0x80000000`, and `0xFFFFFFFF` as size and count fields in IOCTL input triggers wrap-around conditions that normal testing never exercises. Combining these values with Driver Verifier's Special Pool mode catches the resulting out-of-bounds writes immediately.

**Compiler warnings** catch some variants at build time. `/W4` in MSVC and SAL annotations can flag truncation and signed/unsigned mismatches, though they do not detect runtime overflow of correctly-typed arithmetic.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-38063](../case-studies/CVE-2024-38063.md) | `tcpip.sys` | Integer underflow in IPv6 reassembly leading to buffer overflow |
| [CVE-2024-38054](../case-studies/CVE-2024-38054.md) | `ksthunk.sys` | Integer overflow in KSSTREAM_HEADER thunking size calculation |
| [CVE-2023-28218](../case-studies/CVE-2023-28218.md) | `afd.sys` | Integer overflow in AfdCopyCMSGBuffer length computation |
| [CVE-2025-24985](../case-studies/CVE-2025-24985.md) | `fastfat.sys` | Cluster count overflow in FAT bitmap allocation |
| [CVE-2022-21907](../case-studies/CVE-2022-21907.md) | `http.sys` | Size calculation overflow in HTTP header parsing |
| [CVE-2023-29360](../case-studies/CVE-2023-29360.md) | `mskssrv.sys` | Integer overflow in streaming service buffer management |

## AutoPiff Detection

- `safe_size_math_helper_added` detects patches replacing raw arithmetic (`a * b`, `a + b`) with safe math helpers (`RtlULongMult`, `RtlULongAdd`) that fail on overflow
- `alloc_size_overflow_check_added` detects explicit overflow guard checks added before pool allocation size calculations
- `added_integer_overflow_check` detects general integer overflow validation added before arithmetic used in security-relevant operations
- `added_safe_math_call` detects introduction of Intsafe.h functions for safe integer arithmetic
- `size_calculation_modified` detects modifications to size calculation logic that may indicate overflow hardening
- `truncation_check_added` detects addition of explicit checks for 64-to-32-bit truncation before narrowing casts on size values
- `signed_unsigned_mismatch_fixed` detects fixes for signed/unsigned comparison or assignment mismatches that could lead to incorrect size interpretation

The treacherous thing about integer overflow is that it makes other vulnerability classes invisible. A [buffer overflow](buffer-overflow.md) is obvious when the copy size is directly user-controlled. When the copy size is the *result* of an arithmetic operation that wraps, the overflow is hidden behind a layer of indirection. This is why AutoPiff tracks safe math adoption separately from bounds checking: the fix pattern is different, and catching it requires looking at the arithmetic, not just the copy.
