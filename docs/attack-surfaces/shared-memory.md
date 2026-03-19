# Shared Memory

When the kernel maps a page of memory that a user-mode thread can also write to, every read from that page is a gamble. The kernel reads a value, checks it, and proceeds to use it. But between the check and the use, the user-mode thread overwrites the value with something the kernel never validated. This is the fundamental problem with shared memory as a kernel attack surface: the data is not copied into a safe kernel buffer; it lives on pages that both the kernel and the attacker can access simultaneously. The result is a class of vulnerabilities that cannot be found by checking buffer sizes or validating input at the entry point, because the input changes after validation.

Shared memory vulnerabilities are not limited to double-fetch races. Incorrect MDL (Memory Descriptor List) handling can give the kernel a mapping to arbitrary physical pages, including kernel code and data pages that should never be accessible from user mode. Missing probe calls on MDLs can leave the kernel accessing pages that the memory manager has freed and repurposed. Each of these patterns produces a different primitive, from information disclosure to arbitrary kernel read/write, and each requires a different detection approach.

## Two forms of kernel-user shared memory

``` mermaid
graph TD
    subgraph "Section Objects"
        A["NtCreateSection\n(backed by pagefile)"] --> B["ZwMapViewOfSection\n(kernel mapping)"]
        A --> C["NtMapViewOfSection\n(user mapping)"]
        B --> D["Shared Pages\n⚠ Both can read/write"]
        C --> D
    end
    subgraph "MDL Mappings"
        E["IoAllocateMdl\n(describe pages)"] --> F["MmProbeAndLockPages\n(validate + lock)"]
        F --> G["MmMapLockedPagesSpecifyCache\n(kernel virtual mapping)"]
        G --> H["Kernel accesses\nuser's physical pages"]
    end
    style D fill:#2d1b1b,stroke:#ef4444,color:#e2e8f0
    style F fill:#152a4a,stroke:#f59e0b,color:#e2e8f0
    style H fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
```

Shared memory in Windows takes two primary forms, each with distinct vulnerability profiles.

### Section objects: the double-fetch surface

Section objects (`SECTION_OBJECT`) are kernel objects backed by the pagefile or a named file. They can be mapped into multiple process address spaces simultaneously, and when a driver maps a section into both kernel space and user space, the kernel and user-mode code share the same physical pages. Any data the kernel reads from these shared pages can be modified by user-mode threads between reads.

This is the double-fetch problem in its purest form. The kernel validates a length field, then reads it again to use as a copy size. Between the two reads, a user-mode thread racing on another CPU overwrites the length with a much larger value. The kernel validated length 100 but copies length 10,000, overflowing a kernel buffer. The window for this race can be as short as a few CPU cycles, but on a multicore system, a dedicated racing thread can hit it reliably with enough attempts.

The correct pattern is to read the value once into a local variable and use only the local copy for both validation and subsequent operations. But in practice, compiler optimizations can re-read from the shared page even when the source code appears to use a local variable, unless the variable is declared `volatile` or the read is performed through a function that the compiler cannot optimize away. This subtlety makes double-fetch bugs difficult to eliminate even when developers are aware of the pattern.

### MDL mappings: the probe-and-lock surface

Memory Descriptor Lists provide a different mechanism where the kernel describes a set of physical pages, optionally probes and locks them into memory, and then maps them into kernel virtual address space. The critical function is `MmProbeAndLockPages(mdl, AccessMode, Operation)`, where the `AccessMode` parameter determines the level of validation performed.

When `AccessMode` is `UserMode`, the function verifies that the pages described by the MDL actually belong to user-mode address space and are accessible at the requested access level. When `AccessMode` is `KernelMode`, the function trusts the pages completely, performing no validation. This is safe when the MDL describes pages allocated by the kernel itself, but catastrophic when the MDL describes pages supplied by a user-mode caller.

CVE-2023-29360 in `mskssrv.sys` was exactly this pattern. The driver called `MmProbeAndLockPages` with `KernelMode` on an MDL containing user-controlled page addresses. Because the probe was skipped, the MDL could describe arbitrary physical pages, including kernel code pages, kernel data pages, or pages belonging to other processes. The resulting mapping gave the attacker a direct read/write primitive on arbitrary physical memory with no additional exploitation needed.

The second MDL pitfall is calling `MmMapLockedPagesSpecifyCache` (or its deprecated predecessor `MmMapLockedPages`) without first calling `MmProbeAndLockPages` at all. Without the probe-and-lock step, the pages described by the MDL are not locked in physical memory. The memory manager can page them out, reallocate them, or free them while the kernel mapping persists. When the kernel subsequently reads or writes through this stale mapping, it accesses whatever physical page now occupies that frame, producing a use-after-free condition with unpredictable content. CVE-2024-38238 in `ksthunk.sys` demonstrated this pattern.

## The double-fetch problem in depth

Double-fetch vulnerabilities deserve extended discussion because they are subtle, prevalent, and difficult to detect.

The simplest case involves a length field. A driver maps a shared section containing a header with a `DataLength` field followed by data. The driver reads `DataLength`, verifies it is within bounds, allocates a kernel buffer of that size, and then copies `DataLength` bytes from the shared section into the kernel buffer. If the copy reads `DataLength` again from the shared page (rather than using the value already validated), a race condition exists.

A more subtle case involves structure pointers. A driver reads a pointer or offset from the shared page, validates that it points within the mapped region, and then dereferences it. If the pointer is re-read from the shared page at the dereference point, the user-mode thread can swap it to an out-of-bounds address between validation and use.

Copy-on-write (CoW) semantics introduce a third variant. When a section is mapped with copy-on-write protection, a write to a shared page triggers the memory manager to create a private copy for the writing process. If the kernel holds a pointer into the original shared page and the user process triggers CoW, the kernel pointer still refers to the original shared page, which may now belong to a different process or context. The kernel sees the old data, not the process's modified copy, leading to state inconsistencies.

Google Project Zero's Bochspwn tool detects double-fetches at the hardware level by instrumenting the Bochs x86 emulator to track all physical memory accesses from kernel code. When the kernel reads the same user-mode physical address twice within a short window, with a potential modification between the reads, Bochspwn flags the access as a potential double-fetch. This approach finds bugs that source-level analysis misses because it operates on the actual compiled code, where compiler optimizations may have reintroduced reads that the source code eliminated.

## Section object size and access control issues

Beyond double-fetch races, section objects have two additional vulnerability surfaces.

**Integer overflow in size calculations.** When a driver creates a section object with a user-supplied maximum size, the arithmetic to compute the mapping size can overflow 32-bit or 64-bit integer bounds. An overflow that wraps to a small value produces an undersized mapping. If the kernel then writes to the section assuming the originally requested (pre-overflow) size, it writes beyond the mapped region into adjacent kernel memory.

**Overly permissive security descriptors.** Section objects carry security descriptors that control which processes can map them. A shared section created with a security descriptor granting access to `Everyone` or `Authenticated Users` allows any process on the system to map and modify data that higher-privilege kernel components trust. If a driver creates a section for communication with a specific privileged service but does not restrict the security descriptor, a low-privilege attacker can map the section and manipulate the data that the driver reads from it.

## Drivers that use shared memory

The `win32k.sys` and `win32kbase.sys` subsystem drivers extensively use GDI shared sections for accelerated graphics operations. Shared memory between user-mode GDI clients and kernel-mode GDI processing is the foundation of Windows graphics performance, and it has been a recurring vulnerability source. CVE-2023-29336 was a use-after-free involving shared GDI object memory, and CVE-2022-21882 was a type confusion via shared window object manipulation.

The kernel streaming drivers `mskssrv.sys` and `ksthunk.sys` use MDL-based mappings for media buffer sharing between processes and for 32-bit to 64-bit thunking. Both have had critical MDL handling vulnerabilities (CVE-2023-29360 and CVE-2024-38238 respectively).

Display drivers, both Microsoft's WDDM drivers and third-party GPU drivers like NVIDIA's `nvlddmkm.sys`, map frame buffers and command buffers between user mode and kernel. These mappings handle large data volumes at high frequency, creating both performance pressure (which discourages defensive copying) and security exposure (large shared regions with complex access patterns).

Virtualization components (`vmbus.sys`, `storvsc.sys`) use shared memory rings for host-guest communication. While the trust boundary is different (guest vs. host rather than user vs. kernel), the double-fetch and MDL handling patterns are the same, and the primitives from bugs in this code are guest-to-host escapes rather than privilege escalations.

## Detection approaches

**MDL API auditing** searches for all calls to `MmProbeAndLockPages` in a driver binary and verifies the `AccessMode` parameter is `UserMode` when the MDL describes user-supplied buffers. The audit must also search for `MmMapLockedPagesSpecifyCache` and `MmMapLockedPages` and verify that a preceding `MmProbeAndLockPages` call exists on every code path reaching the mapping call. A mapping without a preceding probe-and-lock is a critical finding.

**Double-fetch detection** identifies patterns where the same shared memory address is read more than once in a function, with a validation check between the reads. Static analysis tools can flag these patterns in source or decompiled code, but dynamic analysis through Bochspwn-style instrumentation is more reliable because it catches reads that the compiler re-introduced during optimization.

**Section object security** enumeration uses the `!handle` command in WinDbg to inspect section object security descriptors. Shared sections accessible to low-privilege processes that are also mapped into kernel space are the highest-priority audit targets.

**Static pattern matching** traces the MDL lifecycle from `IoAllocateMdl` through `MmBuildMdlForNonPagedPool` or `MmProbeAndLockPages` to the eventual mapping and unmapping calls. The analysis must verify that all error paths properly call `MmUnlockPages` and `IoFreeMdl` to prevent MDL leaks and dangling mappings. A dangling MDL mapping after the underlying pages are freed is a use-after-free waiting to happen.

**Patch diffing** reveals shared memory fixes as changes to the `AccessMode` parameter (from `KernelMode` to `UserMode`), additions of `MmProbeAndLockPages` before mapping calls, or replacements of double-reads with single-read-and-capture patterns. These changes are small and surgical, making them ideal targets for [AutoPiff](../tooling/autopiff-integration.md) detection.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2023-29360](../case-studies/CVE-2023-29360.md) | `mskssrv.sys` | `MmProbeAndLockPages` called with `KernelMode` on user-controlled MDL |
| [CVE-2024-38238](../case-studies/CVE-2024-38238.md) | `ksthunk.sys` | `MmMapLockedPages` called without prior `MmProbeAndLockPages` validation |
| [CVE-2023-29336](../case-studies/CVE-2023-29336.md) | `win32k.sys` | Use-after-free involving shared GDI object memory |
| [CVE-2022-21882](../case-studies/CVE-2022-21882.md) | `win32k.sys` | Type confusion via shared window object manipulation |
| [CVE-2024-30085](../case-studies/CVE-2024-30085.md) | `cldflt.sys` | Missing bounds check on buffer copy from user-accessible region |

## AutoPiff Detection

- `mdl_probe_access_mode_fix` -- `MmProbeAndLockPages` access mode changed from `KernelMode` to `UserMode` for user-originated MDLs
- `mdl_safe_mapping_replacement` -- Unsafe `MmMapLockedPages` replaced with safe `MmMapLockedPagesSpecifyCache` with appropriate cache type and access mode
- `mdl_null_check_added` -- NULL check on `Irp->MdlAddress` added before MDL access to handle zero-length transfer cases
- `double_fetch_capture_fix` -- Shared memory value captured to local variable instead of being re-read from shared page, eliminating TOCTOU window
- `section_acl_hardened` -- Section object security descriptor tightened to restrict low-privilege access to shared kernel data

The shared memory attack surface intersects with nearly every other attack surface in the KernelSight knowledge base. [IOCTL handlers](ioctl-handlers.md) that use `METHOD_IN_DIRECT` or `METHOD_OUT_DIRECT` receive user data through MDLs. [Filesystem drivers](filesystem-irps.md) use MDLs for Direct I/O transfers. [WDF drivers](wdf.md) that forward requests to lower drivers pass MDL-described buffers down the stack. Understanding MDL lifecycle and shared memory semantics is not optional for kernel security research; it is prerequisite knowledge that applies across every driver category.
