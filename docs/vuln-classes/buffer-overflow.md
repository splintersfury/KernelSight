# Buffer Overflow

Writing data beyond the bounds of an allocated buffer in kernel memory, corrupting adjacent data structures or control flow metadata.

## Description

Buffer overflows occur when a driver copies data beyond the bounds of an allocated buffer, writing into adjacent memory regions. In the Windows kernel, this manifests primarily in two forms: pool (heap) overflows that corrupt adjacent pool allocations, and stack overflows that overwrite saved registers, return addresses, or stack cookies.

The most common trigger is IOCTL dispatch handlers that accept user-supplied data and copy it into a fixed-size or dynamically-sized kernel buffer without properly validating the input length against the destination capacity. Because IOCTL input buffers are often METHOD_BUFFERED or METHOD_NEITHER, drivers must explicitly validate the `InputBufferLength` and `OutputBufferLength` fields from the IO_STACK_LOCATION before performing any copy operation. Failure to do so allows an attacker to supply a buffer larger than the destination, overwriting whatever follows in memory.

Pool overflows are a common exploitation target in the Windows kernel because the pool allocator's behavior is deterministic enough to predict and control what object occupies adjacent memory. By spraying the pool with objects of a chosen size and type before triggering the overflow, a specific object's fields (function pointers, linked list entries, security tokens) can be reliably corrupted to gain code execution or arbitrary read/write.

File system filter drivers (minifilters) and network drivers are frequent sources of buffer overflows. These drivers process untrusted data from disk or network packets at high frequency, and their parsing routines are complex enough that size validation errors are common. `cldflt.sys` (Cloud Files Mini Filter) and `tcpip.sys` (TCP/IP stack) have both had multiple buffer overflow CVEs in recent years.

## Common Patterns in Drivers

- `RtlCopyMemory(dst, src, user_controlled_size)` or `memcpy` without validating that `user_controlled_size` does not exceed the destination buffer size
- Fixed-size stack buffers (e.g., `WCHAR name[256]`) populated with variable-length input from IOCTL input buffers or user-mode strings
- `ProbeForRead` / `ProbeForWrite` called with an incorrect or unchecked length parameter, allowing the subsequent copy to exceed bounds
- Off-by-one errors in loop bounds when processing arrays or records from user input, writing one element past the end of the buffer
- Unsafe string operations (`wcscpy`, `strcpy`, `RtlCopyUnicodeString`) on user-supplied strings that may not be null-terminated or may exceed the destination length
- Incorrect calculation of remaining buffer space in multi-field parsing (e.g., `remaining = total - offset` where offset can exceed total)
- Trusting embedded length fields in user-supplied structures (e.g., reparse data buffers, extended attributes) without cross-checking against the actual IOCTL buffer length

## Exploitation Implications

Pool buffer overflows are the most commonly exploited variant in modern Windows kernels. The attacker's goal is to corrupt a specific adjacent object in a predictable way. This typically involves three phases: first, filling a pool page with identically-sized allocations of a useful object type (pool spray); second, creating a hole by freeing one of those allocations; third, triggering the vulnerable allocation so it lands in the hole, and overflowing into the adjacent controlled object.

The choice of spray object depends on the pool type (paged vs. nonpaged) and the size of the vulnerable allocation. Common spray objects include named pipe attributes, extended attributes (EA), WNF state data, and palette objects. The corrupted object's fields are then abused -- for example, overwriting a `_POOL_HEADER` to fake an allocation size, or corrupting a `_TOKEN` structure's privileges field.

Stack overflows are harder to exploit on modern Windows due to stack cookies (/GS) and Kernel Control-flow Enforcement Technology (kCET / Intel CET Shadow Stack). However, they can still be relevant when the overflow can corrupt local variables used in security decisions before the function returns and the cookie is checked. Additionally, if the overflow is large enough, it can overwrite the Thread Environment Block (TEB) or adjacent stack pages, potentially leading to more nuanced exploitation paths.

## Typical Primitives Gained

- [Pool Overflow](../primitives/arw/pool-overflow.md) -- corrupting adjacent pool chunk metadata or object fields
- [Pool Spray / Feng Shui](../primitives/exploitation/pool-spray-feng-shui.md) -- controlling the pool layout to position target objects adjacent to the overflowed buffer
- [Write-What-Where](../primitives/arw/write-what-where.md) -- if the overflow corrupts a pointer and size pair in an adjacent object, subsequent use of that object can yield arbitrary write
- [Token Manipulation](../primitives/arw/token-manipulation.md) -- if the adjacent object is a TOKEN or contains a token pointer

## Mitigations

Modern Windows includes several mitigations that reduce buffer overflow exploitability:

- **Stack cookies (/GS)** -- compiler-inserted canary values detect stack buffer overflows before function return
- **Kernel CET (kCET)** -- Intel Control-flow Enforcement Technology Shadow Stack prevents return address overwrite exploitation
- **Pool hardening** -- Windows 10 19H1+ includes pool header encoding and improved pool metadata integrity checks
- **HVCI** -- Hypervisor-protected Code Integrity prevents execution of attacker-injected code in kernel pool
- **Special Pool** -- Driver Verifier option that places each allocation on a separate page with guard pages, detecting overflows immediately

Despite these mitigations, data-only attacks (corrupting non-code-pointer fields in adjacent objects) remain viable on fully patched systems.

## Detection Strategies

- **Patch diffing**: Look for newly added length checks (`if (size > buffer_capacity)`) before `RtlCopyMemory`, `memcpy`, or `memmove` calls. AutoPiff excels at detecting these additions across driver patches.
- **Static analysis**: Track data flow from IOCTL `InputBufferLength` / `OutputBufferLength` to copy operation size parameters. Flag cases where the size is not bounded by the destination allocation size.
- **Fuzzing**: IOCTL fuzzers (e.g., kAFL, IOCTLpus) that mutate buffer sizes and lengths are effective at triggering pool and stack overflows. Enable Driver Verifier Special Pool to detect out-of-bounds accesses immediately.
- **Code review patterns**: Search for `RtlCopyMemory` calls where the third argument originates from user input without an intervening comparison against the destination size. Search for stack-allocated arrays used as copy destinations with user-controlled sizes.
- **Driver Verifier**: Enable Special Pool and Pool Tracking to detect out-of-bounds pool writes at runtime.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-30085](../case-studies/CVE-2024-30085.md) | `cldflt.sys` | Missing size check before memcpy in reparse point handling |
| [CVE-2023-36036](../case-studies/CVE-2023-36036.md) | `cldflt.sys` | Heap overflow via reparse data |
| [CVE-2023-28252](../case-studies/CVE-2023-28252.md) | `clfs.sys` | OOB write via corrupted base log offset |
| [CVE-2024-49138](../case-studies/CVE-2024-49138.md) | `clfs.sys` | Heap overflow in LoadContainerQ |
| [CVE-2022-37969](../case-studies/CVE-2022-37969.md) | `clfs.sys` | SignaturesOffset OOB write |
| [CVE-2025-24993](../case-studies/CVE-2025-24993.md) | `ntfs.sys` | MFT metadata heap buffer overflow |
| [CVE-2024-38054](../case-studies/CVE-2024-38054.md) | `ks.sys` | Kernel streaming buffer overflow via unchecked property size |
| [CVE-2024-38063](../case-studies/CVE-2024-38063.md) | `tcpip.sys` | IPv6 packet reassembly buffer overflow |
| [CVE-2022-21907](../case-studies/CVE-2022-21907.md) | `http.sys` | HTTP protocol stack heap overflow via crafted headers |

## AutoPiff Detection

- `added_len_check_before_memcpy` -- Detects patches that add a length comparison before a memory copy operation, the most direct fix for buffer overflows
- `added_struct_size_validation` -- Detects addition of input structure size validation against expected size at IOCTL entry
- `added_index_bounds_check` -- Detects bounds checking added for array index operations that could lead to OOB access
- `safe_string_function_replacement` -- Detects replacement of unsafe string functions (`wcscpy`, `strcpy`) with bounded variants (`wcsncpy`, `RtlStringCbCopy`)
- `unicode_string_length_validation_added` -- Detects validation of UNICODE_STRING Length/MaximumLength fields before use
- `added_buffer_size_validation` -- Detects general buffer size validation added before operations on user-supplied data
- `fixed_stack_buffer_overflow` -- Detects fixes for stack-based buffer overflow patterns, such as adding size limits before copying into stack arrays
