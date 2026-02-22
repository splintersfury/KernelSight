# Uninitialized Memory

Kernel stack or pool memory leaked to user mode without proper initialization, enabling KASLR bypass or data disclosure.

## Description

When kernel code returns data to user mode without fully initializing the output buffer, stale kernel memory (including pointers) may be disclosed. This can defeat KASLR or leak sensitive data.

## Patterns

- Output buffer not zeroed before populating fields
- Stack variables used without initialization
- IoStatus.Information reports more bytes than actually initialized
- Kernel pointer left in user-accessible output

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2023-32019](../case-studies/CVE-2023-32019.md) | `ntoskrnl.exe` | Kernel heap memory leak via thread info query |
| [CVE-2024-38256](../case-studies/CVE-2024-38256.md) | `win32k.sys` | Uninitialized resource leaks kernel memory |

## AutoPiff Detection

- `buffer_zeroing_before_copy_added` — RtlZeroMemory before output buffer population
- `stack_variable_initialization_added` — Stack variable zero-initialized
- `output_length_truncation_added` — IoStatus.Information corrected
- `kernel_pointer_scrubbing_added` — Kernel pointer removed from output
