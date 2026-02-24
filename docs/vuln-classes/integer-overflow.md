# Integer Overflow

Arithmetic operations on integer values that wrap around, leading to incorrect buffer sizes or offsets in kernel memory operations.

## Description

Integer overflow vulnerabilities occur when arithmetic on size or length values produces a result that wraps around due to the finite width of integer types. On a 32-bit unsigned integer, the maximum value is 0xFFFFFFFF (4,294,967,295); adding 1 wraps to 0. When this wrapped value is used as an allocation size, the kernel allocates a buffer far smaller than intended, while subsequent copy operations use the original (pre-wrap) or separately-calculated large size, resulting in a massive buffer overflow.

These bugs are prevalent in size calculations for pool allocations and in bounds-checking arithmetic. A common pattern is `total_size = header_size + (count * element_size)`, where attacker-controlled `count` causes the multiplication to overflow, producing a small `total_size`. The kernel then allocates a tiny buffer and copies `count` elements into it, overflowing into adjacent pool memory. Integer underflow is the related case where subtraction produces a negative value that, interpreted as unsigned, becomes extremely large -- causing oversized reads, writes, or allocations.

Signed/unsigned mismatches are another variant. When a signed integer holding a negative value is compared against an unsigned maximum, the negative value may pass the check (since the compiler treats both sides as signed, and the negative is less than the max). When the same value is later used as an unsigned size for a copy operation, it becomes an enormous positive number. Similarly, 64-to-32-bit truncation bugs occur when a large 64-bit size is silently narrowed to 32 bits for an allocation, while the full 64-bit value is used for the subsequent data copy.

Windows provides the `Intsafe.h` header with safe arithmetic functions (`RtlULongMult`, `RtlULongAdd`, `RtlSizeTAdd`, etc.) that return `STATUS_INTEGER_OVERFLOW` on wrap-around instead of silently producing incorrect results. Adoption of these functions is the primary mitigation, but many legacy drivers and even some recently-written code paths still use raw arithmetic for size calculations.

## Common Patterns in Drivers

- `size = count * element_size` where `count` is user-controlled and the multiplication wraps a 32-bit integer, producing a small allocation followed by a large copy
- `total = header_size + data_size` where the addition overflows, allocating a tiny buffer for a large combined payload
- `remaining = total_length - consumed` where `consumed > total_length`, producing a large unsigned value used as a copy size
- Signed/unsigned comparison mismatch: a negative signed value passes a `value < MAX_SIZE` check, then is cast to unsigned for `RtlCopyMemory`
- 64-bit to 32-bit truncation: `ULONG alloc_size = (ULONG)large_size_64` silently truncates the size for `ExAllocatePoolWithTag`, but the full 64-bit value is used later
- Missing overflow check on `FIELD_OFFSET(STRUCT, variable_array) + count * sizeof(element)` patterns used to compute allocation sizes for variable-length structures
- Loop counter overflow causing infinite loops or excessive iterations that write beyond buffer bounds
- Shift operation overflow: `1 << user_controlled_shift_amount` where the shift amount exceeds the bit width of the integer type
- Chained arithmetic where each individual operation is safe but the combination overflows: `a + b` is safe, `c + d` is safe, but `(a + b) + (c + d)` overflows

## Exploitation Implications

Integer overflow vulnerabilities almost always convert into buffer overflow exploitation. Once the undersized buffer is allocated, the subsequent copy creates a pool overflow. Exploitation follows the same path as a direct buffer overflow: pool spray to control adjacent allocations, then corruption of a target object's fields through the overflow.

The key problem is that integer overflows can bypass explicit bounds checks. A developer may correctly check `if (size > MAX_BUFFER_SIZE) return STATUS_INVALID_PARAMETER;` but if `size` has already overflowed to a small value before this check, the validation passes and the real damage occurs in the subsequent copy. The code may appear to have proper validation at first glance.

Integer underflow variants, where subtraction wraps an unsigned value to near `ULONG_MAX`, can produce even larger overflows. A `remaining = total - consumed` underflow can cause `RtlCopyMemory` to attempt a multi-gigabyte copy, corrupting everything following the destination buffer until the copy faults on an unmapped page. This is less controllable than a precise overflow, but can still be exploited if the fault occurs after corrupting a target object.

## Typical Primitives Gained

- [Pool Overflow](../primitives/arw/pool-overflow.md) -- the undersized allocation followed by oversized write produces a pool overflow identical to a direct buffer overflow
- [Pool Spray / Feng Shui](../primitives/exploitation/pool-spray-feng-shui.md) -- required to control what object is adjacent to the undersized buffer
- [Write-What-Where](../primitives/arw/write-what-where.md) -- if the overflow corrupts an object containing a pointer-and-size pair
- [Token Manipulation](../primitives/arw/token-manipulation.md) -- if pool spray places token-related objects adjacent to the overflowed buffer

## Mitigations

- **Intsafe.h** -- Windows SDK provides safe arithmetic functions (`RtlULongMult`, `RtlULongAdd`, `RtlSizeTAdd`) that return `STATUS_INTEGER_OVERFLOW` on wrap-around instead of silently producing incorrect results
- **Compiler intrinsics** -- `__builtin_mul_overflow` and similar compiler builtins provide overflow detection at the instruction level
- **ExAllocatePool2** -- The modern pool allocation API accepts a `SIZE_T` parameter, reducing 64-to-32-bit truncation issues compared to the legacy `ExAllocatePoolWithTag`
- **SAL annotations** -- `_In_range_` and `_Pre_satisfies_` annotations enable compile-time verification of size parameter constraints
- **Code review policy** -- Any size calculation involving user-controlled values should use safe math helpers as a mandatory coding standard

## Detection Strategies

- **Safe integer arithmetic APIs**: Check patches for introduction of `RtlULongMult`, `RtlULongAdd`, `RtlSizeTMult`, or the `SAFE_INT` / `Intsafe.h` family of functions. These return an error on overflow rather than silently wrapping.
- **Patch diffing**: Look for newly added overflow checks before arithmetic operations, such as `if (count > MAX_ULONG / element_size)` guards added before multiplication.
- **Static analysis**: Track user-controlled integers through arithmetic operations to allocation sizes. Flag any multiplication or addition on user input that feeds into `ExAllocatePoolWithTag` or `ExAllocatePool2` without an overflow check.
- **Compiler warnings**: `/W4` and SAL annotations can catch some truncation and signed/unsigned mismatches at compile time.
- **Fuzzing**: Supply boundary values (0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF) as size/count fields in IOCTL input to trigger wrap-around conditions.

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

- `safe_size_math_helper_added` -- Detects patches replacing raw arithmetic (`a * b`, `a + b`) with safe math helpers (`RtlULongMult`, `RtlULongAdd`) that fail on overflow
- `alloc_size_overflow_check_added` -- Detects explicit overflow guard checks added before pool allocation size calculations
- `added_integer_overflow_check` -- Detects general integer overflow validation added before arithmetic used in security-relevant operations
- `added_safe_math_call` -- Detects introduction of Intsafe.h functions for safe integer arithmetic
- `size_calculation_modified` -- Detects modifications to size calculation logic that may indicate overflow hardening
- `truncation_check_added` -- Detects addition of explicit checks for 64-to-32-bit truncation before narrowing casts on size values
- `signed_unsigned_mismatch_fixed` -- Detects fixes for signed/unsigned comparison or assignment mismatches that could lead to incorrect size interpretation
