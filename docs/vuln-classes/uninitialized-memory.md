# Uninitialized Memory

Use of kernel stack or pool memory that was not properly initialized, potentially leaking sensitive data or causing incorrect control flow decisions.

## Description

Uninitialized memory vulnerabilities occur when kernel code allocates memory -- either on the stack or from the pool -- and uses it before writing valid data to all bytes. Stack memory retains whatever values were left by previous function calls, and pool memory retains data from previous allocations (unless explicitly zeroed). When this stale data is used as a pointer, size, flag, or is copied back to user mode, the consequences range from information disclosure to arbitrary code execution.

The information disclosure variant is the most common manifestation. When a driver allocates an output buffer, partially fills it with response data, and copies the entire buffer back to user mode, the unfilled portions contain stale kernel memory. This stale data frequently includes kernel pointers (from previous stack frames or pool allocations), which defeats Kernel Address Space Layout Randomization (KASLR). Leaking a single kernel pointer gives the attacker the base address of `ntoskrnl.exe` or a driver, enabling subsequent exploitation stages that require knowledge of kernel addresses.

Structure padding is a subtle variant of this issue. The C compiler inserts padding bytes between structure members for alignment purposes. If a driver writes individual fields of an output structure but does not zero the entire structure first, the padding bytes between fields contain stale data. On the kernel stack, these padding bytes frequently contain return addresses, saved frame pointers, and other kernel code pointers that are valuable for KASLR bypass.

The control flow variant is less common but more dangerous. If an uninitialized stack variable is used as a function pointer, loop bound, or branch condition, an attacker who can influence the residual stack contents (through prior system calls that leave specific values on the kernel stack) may be able to control the uninitialized value. This technique, known as "stack variable spraying," involves making specific system calls before the vulnerable call to deposit controlled values at the right stack offsets. Pool variants use heap grooming to influence what data remains in a freshly allocated (but unzeroed) pool block.

## Common Patterns in Drivers

- Stack variable declared but not initialized on all code paths: `NTSTATUS status; if (condition) { status = DoWork(); } return status;` -- on the else path, `status` contains stale stack data
- Pool allocation using `ExAllocatePoolWithTag` (or `ExAllocatePool2` without `POOL_FLAG_UNINITIALIZED`) without a subsequent `RtlZeroMemory` call before populating fields
- Output buffer for IOCTL response partially filled: header fields written but trailing bytes or padding not zeroed, leaking kernel data to user mode
- Structure with padding bytes (inserted by compiler for alignment) not zeroed before copy to user mode -- the padding contains stale kernel stack or pool data
- Error paths that skip initialization but still use the variable: `if (success) { init(ptr); } use(ptr);` where the else path falls through with an uninitialized `ptr`
- `IoStatus.Information` set to a value larger than the amount of data actually initialized in the output buffer, causing extra uninitialized bytes to be copied to user mode
- Union types where one variant is written but a different (larger) variant's bytes are copied to user mode, exposing uninitialized portions
- Compiler-optimized code paths where the optimizer removes an initialization that it determines is "dead" but that actually serves a security purpose on an error path
- Output structures returned via shared memory sections where the driver writes fields incrementally without zeroing the entire structure first

## Exploitation Implications

Information disclosure via uninitialized memory is typically a KASLR bypass primitive. The attacker sends an IOCTL that triggers the partial output buffer fill, reads back the kernel pointers from the uninitialized portion, and computes the kernel base address. This is used as a precursor for a second vulnerability that requires kernel address knowledge (e.g., for ROP chains or specific object address targeting).

Control flow exploitation through uninitialized memory is significantly harder but has been demonstrated in practice. The attacker must determine which prior kernel operations leave specific values at the stack offset where the uninitialized variable resides. This requires understanding the kernel's call stack layout and finding a "stack spraying" primitive that writes a controlled value to the right offset. Pool variants use heap grooming: the attacker frees a specifically-crafted allocation, then triggers the vulnerable path to allocate from the same pool with the same size, inheriting the attacker's stale data.

Modern Windows mitigations have reduced the impact of some uninitialized memory variants. The `ExAllocatePool2` API (introduced in Windows 10 2004) zeroes allocations by default unless the caller explicitly opts out with `POOL_FLAG_UNINITIALIZED`. Similarly, `InitializePool` flags in newer pool implementations reduce the prevalence of pool-based uninitialized memory bugs. However, stack-based variants remain common because stack memory is never automatically zeroed for performance reasons.

## Typical Primitives Gained

- KASLR bypass via leaked kernel pointers -- the most common and immediately useful primitive
- [Write-What-Where](../primitives/arw/write-what-where.md) -- if the uninitialized value is used as a destination pointer for a write operation
- [Pool Spray / Feng Shui](../primitives/exploitation/pool-spray-feng-shui.md) -- used to influence pool-based uninitialized memory contents via heap grooming
- Controlled code execution if an uninitialized function pointer is used for an indirect call (rare)

## Mitigations

- **ExAllocatePool2** -- The modern pool API zeroes allocations by default (unless `POOL_FLAG_UNINITIALIZED` is specified), eliminating pool-based uninitialized memory bugs for drivers that adopt it
- **RtlZeroMemory on output buffers** -- Always zero the entire output buffer before populating individual fields, ensuring padding bytes and unfilled regions contain no stale data
- **Stack initialization** -- Initialize all local variables at declaration (`NTSTATUS status = STATUS_UNSUCCESSFUL;`) to prevent stale stack data from being used on error paths
- **Compiler flags** -- `/sdl` (Security Development Lifecycle) flag in MSVC automatically initializes some local variables to zero
- **KASLR hardening** -- While not preventing the bug, High-Entropy ASLR and KASLR randomization reduce the value of leaked pointers by widening the address space

## Detection Strategies

- **Patch diffing**: Look for added `RtlZeroMemory` calls on output buffers or stack variables, or `= 0` initializations added to variable declarations. AutoPiff detects these as `buffer_zeroing_before_copy_added` and `stack_variable_initialization_added`.
- **Compiler warnings**: `/W4` with MSVC and `/Wuninitialized` with Clang flag many uninitialized variable uses. SAL annotation `_Out_writes_bytes_all_(n)` can enforce that all output bytes are written.
- **Static analysis**: Track all paths from variable declaration to use and verify that every path includes an initialization. Pay special attention to error/early-return paths.
- **Dynamic analysis**: Enable Driver Verifier Pool Tracking and use kernel debugger conditional breakpoints to monitor output buffers for non-zero padding bytes before copy to user mode.
- **Code review**: Search for `IoStatus.Information` assignments and verify that the reported byte count matches the actually-initialized portion of the output buffer. Search for `ExAllocatePoolWithTag` calls not followed by `RtlZeroMemory`.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2023-32019](../case-studies/CVE-2023-32019.md) | `ntoskrnl.exe` | Kernel heap memory leak via thread info query returning uninitialized pool data |
| [CVE-2024-38256](../case-studies/CVE-2024-38256.md) | `win32k.sys` | Uninitialized resource leaks kernel memory to user mode |
| [CVE-2024-30085](../case-studies/CVE-2024-30085.md) | `cldflt.sys` | Partial buffer initialization leaks kernel pointers in error path |
| [CVE-2023-28218](../case-studies/CVE-2023-28218.md) | `afd.sys` | Uninitialized stack variable in CMSG buffer copy |
| [CVE-2024-26229](../case-studies/CVE-2024-26229.md) | `csc.sys` | Output buffer contains uninitialized kernel heap data |

## AutoPiff Detection

- `buffer_zeroing_before_copy_added` -- Detects patches adding `RtlZeroMemory` or `memset(0)` before output buffer population to eliminate stale data in unfilled regions
- `stack_variable_initialization_added` -- Detects addition of zero-initialization (`= 0`, `= {0}`, `= NULL`) to stack variable declarations that were previously uninitialized
- `output_length_truncation_added` -- Detects corrections to `IoStatus.Information` to report only the number of actually-initialized bytes, preventing over-read of stale data
- `kernel_pointer_scrubbing_added` -- Detects explicit removal or zeroing of kernel pointer values from output structures before copy to user mode
- `added_buffer_zeroing` -- Detects general buffer zeroing additions to eliminate uninitialized memory before use
- `uninitialized_path_fixed` -- Detects fixes to code paths that previously skipped initialization of variables used later in the function
