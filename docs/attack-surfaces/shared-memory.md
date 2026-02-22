# Shared Memory

Kernel-managed shared memory sections and MDL mappings provide high-bandwidth data paths between user mode and kernel mode, but introduce double-fetch, mapping, and access control vulnerabilities.

## Attack Surface Overview

- **Section objects**: Created via `NtCreateSection` / `ZwCreateSection`, mapped with `NtMapViewOfSection` / `ZwMapViewOfSection` for shared memory between processes or between user mode and kernel
- **MDL mappings**: Memory Descriptor Lists built with `IoAllocateMdl`, probed with `MmProbeAndLockPages`, and mapped with `MmMapLockedPagesSpecifyCache` to give kernel code direct access to user-mode pages
- **Shared data pages**: System-wide shared pages like `KUSER_SHARED_DATA` and per-process shared memory regions used by `win32k.sys` for GDI acceleration
- **Direct I/O**: Drivers using `DO_DIRECT_IO` receive user buffers described by MDLs in `Irp->MdlAddress`, and must correctly probe and map these MDLs before accessing the data
- **User-mode reach**: Any process can create sections and map views; drivers that accept user MDLs via `METHOD_IN_DIRECT` / `METHOD_OUT_DIRECT` IOCTLs or that build MDLs from user-supplied addresses are exposed
- **Key risk**: The kernel reads from memory pages that user-mode threads can concurrently modify, creating time-of-check-to-time-of-use (TOCTOU) vulnerabilities, and incorrect MDL access mode parameters bypass page-level protections allowing arbitrary physical memory access

## Mechanism Deep-Dive

Shared memory in Windows takes two primary forms: section objects and MDL-based mappings. Section objects (`SECTION_OBJECT`) are kernel objects backed by the pagefile or a named file, and can be mapped into multiple process address spaces simultaneously. When a driver maps a section into both kernel space and user space, any data the kernel reads from the shared pages can be modified by user-mode threads between reads. This is the fundamental double-fetch problem: the kernel validates a field (e.g., a length value), then reads it again to use it, but the value may have changed between the two reads due to a concurrent user-mode write.

MDL-based mappings provide a different mechanism where the kernel describes a set of physical pages using a Memory Descriptor List, optionally probes and locks those pages into memory, and then maps them into kernel virtual address space. The critical function is `MmProbeAndLockPages(mdl, AccessMode, Operation)`, where `AccessMode` determines whether the pages are validated as belonging to user-mode (`UserMode`) or trusted as kernel pages (`KernelMode`). If a driver calls this function with `KernelMode` on an MDL describing user-supplied pages, the probe is effectively skipped -- the function assumes the pages are trusted kernel memory. An attacker can then supply an MDL pointing to arbitrary physical pages, including kernel code or data pages, achieving arbitrary kernel memory read/write. The CVE-2023-29360 vulnerability in `mskssrv.sys` was exactly this pattern.

The `MmMapLockedPagesSpecifyCache` function (and its deprecated predecessor `MmMapLockedPages`) maps the locked pages into virtual address space. If a driver calls this without first calling `MmProbeAndLockPages`, the pages described by the MDL are not locked and may be paged out, reallocated, or freed by the memory manager while the kernel mapping persists. This leads to use-after-free conditions when the kernel reads or writes through the stale mapping. The CVE-2024-38238 vulnerability in `ksthunk.sys` demonstrated this exact issue.

A subtler aspect of shared memory security involves copy-on-write (CoW) semantics. When a section is mapped with copy-on-write protection, a write to a shared page triggers the memory manager to create a private copy for the writing process. However, if the kernel holds a pointer into the original shared page and the user process triggers CoW, the kernel pointer still refers to the original shared page, which may now belong to a different process or context. Similarly, section object size calculations using user-supplied values can overflow integer bounds, leading to undersized mappings that the kernel writes beyond.

## Common Vulnerability Patterns

- **`MmProbeAndLockPages` with `KernelMode` on user MDL**: The driver probes an MDL containing user-supplied page addresses with `KernelMode` access mode, skipping the validation that the pages actually belong to user space, allowing arbitrary physical page mapping
- **`MmMapLockedPages` without prior `MmProbeAndLockPages`**: The driver maps an MDL directly without locking the pages, meaning the physical pages can be freed or repurposed while the kernel mapping persists
- **Double-fetch from shared mapped memory**: The kernel reads a value from a user-accessible shared page, validates it, then re-reads it for use -- a user-mode thread modifies the value between the two reads to bypass the validation
- **Section object size integer overflow**: User-supplied maximum section size or view size undergoes arithmetic that overflows, resulting in an undersized mapping that the kernel writes beyond
- **Copy-on-write stale pointer**: A driver maps a CoW section and stores a kernel pointer to the shared page; after a user-mode write triggers CoW, the kernel pointer refers to the now-stale original page
- **Missing MDL null check**: The driver accesses `Irp->MdlAddress` without checking for NULL, which can occur for zero-length transfers or when the I/O Manager could not allocate an MDL
- **Shared memory access control**: Section objects created with overly permissive security descriptors allow low-privilege processes to map and modify data that higher-privilege kernel components trust
- **MDL partial mapping**: The driver maps only a portion of an MDL but calculates offsets based on the full MDL length, causing out-of-bounds access relative to the mapped region

## Driver Examples

The `win32k.sys` and `win32kbase.sys` subsystem drivers extensively use GDI shared sections for accelerated graphics operations, with shared memory between user-mode GDI clients and kernel-mode GDI processing. The kernel streaming driver `mskssrv.sys` uses MDL-based mappings for media buffer sharing between processes and was the target of CVE-2023-29360. The `ksthunk.sys` driver maps user buffers for 32-bit to 64-bit kernel streaming thunking and was affected by CVE-2024-38238. Display drivers (both Microsoft's WDDM drivers and third-party GPU drivers like NVIDIA's `nvlddmkm.sys`) map frame buffers and command buffers between user mode and kernel. `ntoskrnl.exe` manages the core section object and MDL infrastructure. Virtualization components (`vmbus.sys`, `storvsc.sys`) use shared memory rings for host-guest communication.

## Detection Approach

- **MDL API auditing**: Search for all calls to `MmProbeAndLockPages` in a driver binary and verify the `AccessMode` parameter is `UserMode` when the MDL describes user-supplied buffers. Search for `MmMapLockedPagesSpecifyCache` and `MmMapLockedPages` and verify a preceding `MmProbeAndLockPages` call exists on every code path.
- **Double-fetch detection**: Identify patterns where the same shared memory address is read more than once in a function, with a validation check between the reads. Tools like `Bochspwn` (from Google Project Zero) can detect kernel double-fetches at the hardware level by intercepting physical memory accesses and flagging repeated reads to user-mode pages.
- **Section object security**: Enumerate section objects using the `!handle` command in WinDbg and check their security descriptors. Shared sections accessible to low-privilege processes that are also mapped into kernel space represent high-risk attack surface.
- **Static pattern matching**: Look for `IoAllocateMdl` followed by `MmBuildMdlForNonPagedPool` or `MmProbeAndLockPages` to trace MDL lifecycle. Verify that all error paths properly call `MmUnlockPages` and `IoFreeMdl` to prevent MDL leaks and dangling mappings.
- **Patch diffing**: MDL security fixes typically change the access mode parameter from `KernelMode` to `UserMode`, add `MmProbeAndLockPages` before mapping calls, or replace double-reads with single-read-and-capture patterns where a value is read once into a local variable.

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
