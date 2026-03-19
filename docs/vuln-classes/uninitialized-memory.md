# Uninitialized Memory

The driver allocates a 128-byte output buffer on the stack, writes 96 bytes of response data into it, and copies all 128 bytes back to user mode. The last 32 bytes contain whatever was on the kernel stack before the function was called: a return address from `ntoskrnl.exe`, a saved frame pointer, a stale pointer to an EPROCESS structure. The user-mode caller now knows the base address of the kernel. KASLR is defeated, and the next stage of the exploit can begin.

Uninitialized memory vulnerabilities are the quiet enablers of the Windows kernel exploitation ecosystem. They rarely make headlines on their own, but they provide the KASLR bypass that every other exploit chain needs. This page covers how they arise, why structure padding makes them surprisingly difficult to eliminate, and how to detect them in patches and source code.

## The KASLR bypass factory

Modern Windows randomizes the base address of the kernel and all loaded drivers at boot time. Without knowing these addresses, an attacker cannot construct ROP chains, target specific kernel structures, or calculate offsets for reliable exploitation. KASLR is not a strong mitigation on its own (the entropy is limited, typically 8-9 bits for `ntoskrnl.exe`), but it forces every exploit chain to include an information disclosure step. That step is almost always an uninitialized memory leak.

The reason is structural. The kernel stack and pool are recycled memory. Every stack frame reuses memory from previous function calls. Every pool allocation reuses memory from previous allocations. This memory is full of kernel pointers: return addresses, object pointers, vtable references, driver base addresses. If a driver returns any of this stale data to user mode, the attacker gets a window into kernel address space.

A single leaked pointer is often enough. If the leak reveals an address within `ntoskrnl.exe`, subtracting the known offset of that function (from the public PDB) yields the kernel base. If it reveals an EPROCESS pointer, the attacker can compute offsets to the token field for a subsequent [token manipulation](../primitives/arw/token-manipulation.md) exploit. The information disclosure itself does not provide code execution, but it provides the *addressing* that every code execution exploit requires.

## How uninitialized memory reaches user mode

### Partial buffer fills

The most common pattern. A driver allocates an output buffer (on the stack or from the pool), populates some fields with response data, and copies the entire buffer back to user mode. The fields that were not explicitly written contain stale kernel data.

This happens because drivers often initialize structures field-by-field rather than zeroing the entire structure first. If the structure has 20 fields and the driver writes 18 of them, the remaining 2 fields contain whatever was in that memory before. On the stack, this is residual data from previous function calls. In pool memory, it is residual data from the previous allocation that occupied the same address.

CVE-2023-32019 in `ntoskrnl.exe` demonstrated this pattern: a thread information query returned uninitialized pool data to user mode, leaking kernel heap content that included kernel pointers useful for KASLR bypass.

### Structure padding

This is the most insidious variant because it is invisible in source code. The C compiler inserts padding bytes between structure members for alignment. A structure like:

```c
struct {
    UCHAR  Flags;      // offset 0, 1 byte
    // 7 bytes padding
    PVOID  Pointer;    // offset 8, 8 bytes
    USHORT Length;     // offset 16, 2 bytes
    // 6 bytes padding
};                     // total: 24 bytes
```

has 13 bytes of padding that are never written by field-by-field assignment. If the driver writes `output.Flags = 1; output.Pointer = ptr; output.Length = len;` and copies 24 bytes to user mode, the 13 padding bytes contain stale kernel data. The developer wrote every visible field. The padding is invisible in the source but present in the binary.

This is why `RtlZeroMemory` on the entire structure before populating individual fields is the correct pattern. It zeroes the padding along with everything else.

### IoStatus.Information over-reporting

The I/O manager copies `IoStatus.Information` bytes from the system buffer back to the user-mode output buffer. If the driver sets `IoStatus.Information` to a value larger than the number of bytes it actually initialized, the extra bytes contain stale kernel data. This is effectively a partial-fill bug caused by an incorrect length rather than incomplete initialization.

CVE-2024-38256 in `win32k.sys` involved exactly this pattern: the reported output length exceeded the initialized region, causing kernel memory to leak to user mode through the uninitialized tail of the output buffer.

### Error paths that skip initialization

A function initializes a variable on the success path but not on the error path. If the error path still uses the variable (or returns it to the caller), the uninitialized value propagates:

```c
NTSTATUS status;
PVOID result;
if (condition) {
    status = LookupObject(&result);
}
// On the else path, both status and result are uninitialized
return status;
```

The developer intended the `if` to cover all cases. A new code path or a changed condition later makes the else path reachable, and the uninitialized `result` (containing a stale kernel pointer from a previous stack frame) propagates to the caller.

### Union type over-reads

When a C union is used to hold different typed data, and the driver writes the smaller variant but copies the size of the larger variant, the extra bytes (which belong to the larger variant's layout) contain stale data. This is structurally identical to partial buffer fill, but the union makes the size mismatch less obvious during code review because both variants share the same starting address.

## Beyond information disclosure

While KASLR bypass is the primary impact, uninitialized memory bugs can be more dangerous in specific circumstances.

**Control flow via uninitialized variables** occurs when a stack variable used as a function pointer, loop bound, or branch condition is not initialized on all paths. An attacker who can influence residual stack contents (through prior system calls that leave specific values at the right stack offsets) may control the uninitialized value. This technique, called "stack variable spraying," involves making specific system calls before the vulnerable call to deposit controlled values at the right stack offsets. The kernel stack is deterministic enough that this works in practice, though it requires careful analysis of the target function's stack layout and the stack layouts of functions called immediately before it.

**Pool-based control flow exploitation** uses heap grooming to influence what data remains in a freshly allocated pool block. If the driver allocates pool memory without zeroing and uses a field from the uninitialized block as a pointer or size, the attacker can groom the pool to ensure specific values are present. This converts an uninitialized memory bug from an information disclosure into a limited write or read primitive, depending on how the uninitialized field is used.

`ExAllocatePool2` (introduced in Windows 10 2004) mitigates pool-based variants by zeroing allocations by default unless the caller opts out with `POOL_FLAG_UNINITIALIZED`. Stack-based variants remain common because stack memory is never automatically zeroed for performance reasons.

## Typical primitives gained

- **KASLR bypass via leaked kernel pointers**, the most common and immediately useful primitive, enabling all subsequent exploit stages that require kernel address knowledge
- [Pool Spray / Feng Shui](../primitives/exploitation/pool-spray-feng-shui.md), used to influence pool-based uninitialized memory contents via heap grooming
- [Write-What-Where](../primitives/arw/write-what-where.md), if the uninitialized value is used as a destination pointer for a write operation (rare but high impact)
- Controlled code execution if an uninitialized function pointer is used for an indirect call (rare, requires stack spraying)

## Mitigations

**ExAllocatePool2** is the most impactful mitigation for pool-based variants. It zeroes allocations by default, eliminating stale data from previous allocations. Drivers that still use the legacy `ExAllocatePoolWithTag` must manually zero their allocations with `RtlZeroMemory` to achieve the same protection.

**RtlZeroMemory on output buffers** is the correct pattern for all IOCTL output: zero the entire buffer before populating individual fields. This handles structure padding, partial fills, and union over-reads in a single operation. The performance cost is negligible (zeroing a few hundred bytes is a few nanoseconds), and the security benefit is comprehensive.

**Stack initialization at declaration** eliminates uninitialized variable bugs on error paths. Writing `NTSTATUS status = STATUS_UNSUCCESSFUL;` instead of `NTSTATUS status;` ensures that even if the variable is never assigned on an error path, it contains a safe value rather than stale stack data.

**The /sdl compiler flag** in MSVC automatically initializes some local variables to zero, providing a safety net for developers who forget manual initialization. This does not cover all cases (it targets specific variable types and patterns), but it catches the most common ones.

**KASLR hardening** through High-Entropy ASLR does not prevent the leak but reduces its value by widening the address space. On x64 Windows, KASLR provides limited entropy, so even with hardening, a single leaked pointer typically reveals the base address.

## Detection strategies

**Patch diffing** for uninitialized memory fixes is straightforward. Look for added `RtlZeroMemory` calls on output buffers or stack variables, `= 0` or `= {0}` initializations added to variable declarations, or corrections to `IoStatus.Information` that reduce the reported output length. These patches are easy to spot in binary diffs because they add initialization code at the start of functions or before copy-to-user operations. AutoPiff detects these through several complementary rules.

**Compiler warnings** catch many cases at build time. MSVC's `/W4` and Clang's `-Wuninitialized` flag uninitialized variable uses. SAL annotations like `_Out_writes_bytes_all_(n)` can enforce that all output bytes are written, catching partial-fill bugs at compile time.

**Static analysis** should track all paths from variable declaration to use and verify that every path includes an initialization. Error paths and early-return paths deserve particular attention because they are the most common locations for missing initialization.

**Dynamic analysis** with Driver Verifier's Pool Tracking mode can detect uninitialized pool data being copied to user mode. Kernel debugger conditional breakpoints on output buffer copy operations (intercepting `RtlCopyMemory` calls that target user buffers) can check for non-zero padding bytes before the copy executes.

**Code review** should search for two patterns. First, `IoStatus.Information` assignments should be compared against the actually-initialized portion of the output buffer. Second, `ExAllocatePoolWithTag` calls not followed by `RtlZeroMemory` should be flagged unless the caller provably writes every byte before any is read.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2023-32019](../case-studies/CVE-2023-32019.md) | `ntoskrnl.exe` | Kernel heap memory leak via thread info query returning uninitialized pool data |
| [CVE-2024-38256](../case-studies/CVE-2024-38256.md) | `win32k.sys` | Uninitialized resource leaks kernel memory to user mode |
| [CVE-2024-30085](../case-studies/CVE-2024-30085.md) | `cldflt.sys` | Partial buffer initialization leaks kernel pointers in error path |
| [CVE-2023-28218](../case-studies/CVE-2023-28218.md) | `afd.sys` | Uninitialized stack variable in CMSG buffer copy |
| [CVE-2024-26229](../case-studies/CVE-2024-26229.md) | `csc.sys` | Output buffer contains uninitialized kernel heap data |

## AutoPiff Detection

- `buffer_zeroing_before_copy_added` detects patches adding `RtlZeroMemory` or `memset(0)` before output buffer population to eliminate stale data in unfilled regions
- `stack_variable_initialization_added` detects addition of zero-initialization (`= 0`, `= {0}`, `= NULL`) to stack variable declarations that were previously uninitialized
- `output_length_truncation_added` detects corrections to `IoStatus.Information` to report only the number of actually-initialized bytes, preventing over-read of stale data
- `kernel_pointer_scrubbing_added` detects explicit removal or zeroing of kernel pointer values from output structures before copy to user mode
- `added_buffer_zeroing` detects general buffer zeroing additions to eliminate uninitialized memory before use
- `uninitialized_path_fixed` detects fixes to code paths that previously skipped initialization of variables used later in the function

Uninitialized memory is the vulnerability class that other vulnerability classes depend on. A [buffer overflow](buffer-overflow.md) exploit needs to know where the kernel is loaded. A [use-after-free](use-after-free.md) exploit needs to know where to spray. A [type confusion](type-confusion.md) exploit needs to calculate offsets for the confused structure. The uninitialized memory leak that provides KASLR bypass is rarely the most interesting part of an exploit chain, but it is almost always a necessary one. Eliminating these leaks does not prevent exploitation, but it forces every exploit chain to find one more step, and each additional step is another opportunity for detection.
