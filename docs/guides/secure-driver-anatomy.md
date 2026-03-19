# Anatomy of a Secure Driver

> Six anti-patterns behind most Windows kernel driver vulnerabilities -- and how to avoid them.

Most kernel driver vulnerabilities are not exotic. They are not novel exploitation techniques or deep architectural flaws. They are missing checks. A length that was not validated. A lock that was not held. An offset from a file that was trusted without verification. Across 134 CVEs in the KernelSight corpus, the same small set of root causes appears again and again, accounting for the vast majority of the bugs that reach production, get patched on Patch Tuesday, and sometimes get exploited in the wild before the patch ships.

This page distills those root causes into six anti-patterns. Each one describes a specific coding mistake, shows real CVE examples, and provides the fix. If you are writing a kernel driver, these six checks will prevent the majority of exploitable bugs. If you are auditing one, these are the patterns to search for first.

## Root Cause Distribution

<div class="ks-figure" markdown>
  <span class="ks-figure-label">FIG -- Root Cause Distribution (134 CVEs)</span>
  <svg viewBox="0 0 700 240" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Horizontal bar chart showing root cause distribution across 134 CVEs">
    <!-- Unvalidated Input -->
    <text class="ks-label" x="215" y="35" text-anchor="end">Unvalidated Input</text>
    <rect class="ks-box" x="220" y="22" width="380" height="20" rx="0"/>
    <text class="ks-annotation" x="608" y="36">~60%</text>
    <!-- Improper Synchronization -->
    <text class="ks-label" x="215" y="67" text-anchor="end">Improper Sync</text>
    <rect class="ks-box" x="220" y="54" width="89" height="20" rx="0"/>
    <text class="ks-annotation" x="317" y="68">~14%</text>
    <!-- Other -->
    <text class="ks-label" x="215" y="99" text-anchor="end">Other</text>
    <rect class="ks-box" x="220" y="86" width="63" height="20" rx="0"/>
    <text class="ks-annotation" x="291" y="100">~10%</text>
    <!-- Type / Lifetime Confusion -->
    <text class="ks-label" x="215" y="131" text-anchor="end">Type / Lifetime</text>
    <rect class="ks-box" x="220" y="118" width="38" height="20" rx="0"/>
    <text class="ks-annotation" x="266" y="132">~6%</text>
    <!-- Authorization Gaps -->
    <text class="ks-label" x="215" y="163" text-anchor="end">Authorization Gaps</text>
    <rect class="ks-box" x="220" y="150" width="25" height="20" rx="0"/>
    <text class="ks-annotation" x="253" y="164">~4%</text>
    <!-- Error-Path Bypass -->
    <text class="ks-label" x="215" y="195" text-anchor="end">Error-Path Bypass</text>
    <rect class="ks-box" x="220" y="182" width="25" height="20" rx="0"/>
    <text class="ks-annotation" x="253" y="196">~4%</text>
    <!-- Double-Fetch / TOCTOU -->
    <text class="ks-label" x="215" y="227" text-anchor="end">Double-Fetch</text>
    <rect class="ks-box" x="220" y="214" width="13" height="20" rx="0"/>
    <text class="ks-annotation" x="241" y="228">~2%</text>
  </svg>
  <p class="ks-figure-caption">Categories mapped from 134 CVEs in the KernelSight corpus. "Unvalidated Input" includes missing length checks, unchecked offsets, and unbounded copies.</p>
</div>

The distribution tells a clear story. Sixty percent of kernel driver CVEs stem from a single root cause category: unvalidated input. The driver reads a value from userland, from an on-disk structure, or from a network packet, and uses it without checking whether it makes sense. The remaining categories occur less frequently but share a common theme: the driver trusts something it should not.

## The Six Anti-Patterns

### 1. Trusting User-Supplied Lengths

**What goes wrong:** The driver reads a length or size from userland and passes it straight to a copy or allocation without checking it against the actual buffer size. This is the most common vulnerability in the corpus. [CVE-2025-5942](../case-studies/CVE-2025-5942.md) (epdlpdrv.sys heap overflow), [CVE-2024-38054](../case-studies/CVE-2024-38054.md) (ks.sys property request overflow), [CVE-2025-24993](../case-studies/CVE-2025-24993.md) (ntfs.sys heap overflow from crafted VHD), and [CVE-2025-24985](../case-studies/CVE-2025-24985.md) (FAT integer overflow in fastfat.sys) all stem from this pattern.

**The fix:** Validate `InputBufferLength` before touching the buffer. Cap copy sizes against the allocation. Check for integer overflow in size arithmetic.

```c
if (InputBufferLength < sizeof(MY_HEADER))
    return STATUS_BUFFER_TOO_SMALL;

if (header->DataSize > InputBufferLength - sizeof(MY_HEADER))
    return STATUS_INVALID_PARAMETER;

RtlCopyMemory(dst, src, header->DataSize);
```

### 2. Missing Synchronization on Shared State

**What goes wrong:** Concurrent threads access shared driver state -- a reference count, a linked list, a pointer field -- without adequate locking. The race window is usually narrow, sometimes just a few instructions wide, but sufficient for exploitation when the attacker can run millions of iterations. [CVE-2026-21241](../case-studies/CVE-2026-21241.md) (afd.sys notification UAF) hits a race between registration and teardown. [CVE-2024-38106](../case-studies/CVE-2024-38106.md) (ntoskrnl token race), [CVE-2025-32701](../case-studies/CVE-2025-32701.md) (clfs.sys UAF), and [CVE-2023-36802](../case-studies/CVE-2023-36802.md) (mskssrv.sys pipe UAF) follow the same pattern.

**The fix:** Use reference counting for objects accessed from multiple contexts. Protect mutable state with spin locks or push locks. Establish a lock ordering convention and enforce it.

```c
// Reference-counted teardown
if (InterlockedDecrement(&Object->RefCount) == 0) {
    ExFreePoolWithTag(Object, TAG);
}
```

### 3. Trusting On-Disk / File-Embedded Offsets

**What goes wrong:** File system and log drivers read offset/index fields from on-disk structures and use them as memory indices without bounds checking. A crafted disk image triggers out-of-bounds access in kernel context. CLFS has been the worst offender, with [CVE-2025-29824](../case-studies/CVE-2025-29824.md), [CVE-2022-37969](../case-studies/CVE-2022-37969.md), and [CVE-2023-28252](../case-studies/CVE-2023-28252.md) all exploited in the wild by ransomware groups. [CVE-2025-24992](../case-studies/CVE-2025-24992.md) (ntfs.sys) demonstrates that the pattern extends beyond CLFS to any driver that parses complex on-disk formats.

**The fix:** Treat on-disk data with exactly the same suspicion as user input. Bounds-check every offset and index against the container or record size before use.

```c
if (record->FieldOffset + record->FieldLength > ContainerSize)
    return STATUS_LOG_CORRUPTION;
```

### 4. Exposing Physical Memory or Arbitrary MSR Access

**What goes wrong:** The driver maps physical memory to userland or exposes model-specific register (MSR) read/write via IOCTLs, giving any caller full kernel read/write by design. These are not bugs; they are architectural decisions that happen to be exploitable. [CVE-2021-21551](../case-studies/CVE-2021-21551.md) (Dell DBUtil), [CVE-2019-16098](../case-studies/CVE-2019-16098.md) (MSI RTCore64), [CVE-2020-12928](../case-studies/CVE-2020-12928.md) (AMD Ryzen Master), and [Capcom.sys](../case-studies/Capcom-sys.md) are well-known examples, all used in BYOVD campaigns by ransomware groups and APTs.

**The fix:** Do not ship physical memory mapping or MSR access in production drivers. If hardware diagnostics require this functionality, gate it behind a restrictive DACL, limit to specific physical ranges, and never expose it in a signed driver intended for end-user systems. Better yet, use a debug-only build that is never signed for production.

### 5. No IOCTL Authentication / Open Device ACLs

**What goes wrong:** The driver creates its device object with a permissive ACL (or the default ACL), allowing any user to open the device handle and send IOCTLs. Some drivers do not check caller identity at all. [CVE-2025-3464](../case-studies/CVE-2025-3464.md) (AsIO3.sys auth bypass), [CVE-2023-1048](../case-studies/CVE-2023-1048.md) (KProcessHacker unrestricted IOCTLs), [CVE-2025-0289](../case-studies/CVE-2025-0289.md) (Paragon BioNTdrv.sys), and [CVE-2025-68947](../case-studies/CVE-2025-68947.md) (NSecKrnl) all allow unprivileged callers to reach dangerous code paths.

**The fix:** Set a restrictive DACL at device creation time using `IoCreateDeviceSecure` with an SDDL string. Then enforce per-IOCTL access checks for sensitive operations.

```c
// Restrictive SDDL: SYSTEM + Administrators only
DECLARE_CONST_UNICODE_STRING(sddl,
    L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
IoCreateDeviceSecure(..., &sddl, ...);
```

### 6. Double-Fetch / TOCTOU on User Buffers

**What goes wrong:** The driver reads a value from a user-mode buffer, validates it, then reads the same location again for use. An attacker running on another CPU core flips the value between the two reads. [CVE-2024-11616](../case-studies/CVE-2024-11616.md) (epdlpdrv.sys double-fetch of length field), [CVE-2024-30088](../case-studies/CVE-2024-30088.md) (ntoskrnl handle-to-pointer race), and [CVE-2024-38106](../case-studies/CVE-2024-38106.md) (ntoskrnl token assignment race) all exploit this gap.

**The fix:** Capture user data into a kernel buffer in a single copy. Validate the kernel-side copy. Never re-read from userland.

```c
// Capture once, validate the copy
MY_REQUEST req;
__try {
    ProbeForRead(UserBuffer, sizeof(req), __alignof(MY_REQUEST));
    req = *UserBuffer;  // single capture
} __except (EXCEPTION_EXECUTE_HANDLER) {
    return GetExceptionCode();
}
// All validation uses 'req', never *UserBuffer
```

## A Note on BYOVD

Even a vulnerability-free driver becomes a weapon if it exposes raw kernel read/write by design. Drivers that map physical memory, disable code integrity, or provide arbitrary MSR access are routinely dropped by ransomware groups and APTs, with no exploit development needed beyond a client that sends the right IOCTLs. Anti-patterns 4 and 5 are the root causes. See [BYOVD](../reference/byovd.md) for the full attack pattern and [LOLDrivers Deep Analysis](../reference/loldrivers-analysis.md) for the ecosystem-wide assessment.

## Secure Driver Checklist

| # | Check | Anti-Pattern Blocked | Example CVE |
|---|-------|---------------------|-------------|
| 1 | Validate `InputBufferLength` before any buffer access | Trusting user-supplied lengths | [CVE-2025-5942](../case-studies/CVE-2025-5942.md) |
| 2 | Cap copy size against allocation size | Trusting user-supplied lengths | [CVE-2024-38054](../case-studies/CVE-2024-38054.md) |
| 3 | Check for integer overflow in size arithmetic | Trusting user-supplied lengths | [CVE-2025-24985](../case-studies/CVE-2025-24985.md) |
| 4 | Reference-count shared objects | Missing synchronization | [CVE-2026-21241](../case-studies/CVE-2026-21241.md) |
| 5 | Hold locks across check-and-use sequences | Missing synchronization | [CVE-2024-38106](../case-studies/CVE-2024-38106.md) |
| 6 | Bounds-check all on-disk offsets against container size | Trusting on-disk offsets | [CVE-2025-29824](../case-studies/CVE-2025-29824.md) |
| 7 | Validate on-disk index values before array access | Trusting on-disk offsets | [CVE-2022-37969](../case-studies/CVE-2022-37969.md) |
| 8 | Never map physical memory to userland | Exposing physical memory | [CVE-2021-21551](../case-studies/CVE-2021-21551.md) |
| 9 | Never expose MSR read/write via IOCTL | Exposing physical memory | [CVE-2019-16098](../case-studies/CVE-2019-16098.md) |
| 10 | Set restrictive DACL on device object | Open device ACLs | [CVE-2025-3464](../case-studies/CVE-2025-3464.md) |
| 11 | Enforce per-IOCTL access checks | Open device ACLs | [CVE-2023-1048](../case-studies/CVE-2023-1048.md) |
| 12 | Capture user buffers into kernel memory once | Double-fetch / TOCTOU | [CVE-2024-11616](../case-studies/CVE-2024-11616.md) |
| 13 | Validate the kernel-side copy, never re-read userland | Double-fetch / TOCTOU | [CVE-2024-30088](../case-studies/CVE-2024-30088.md) |
| 14 | Use `METHOD_BUFFERED` or probe-and-capture for direct I/O | Double-fetch / TOCTOU | [CVE-2024-38106](../case-studies/CVE-2024-38106.md) |

## Detection and Audit Pointers

Static analysis catches most input validation and double-fetch bugs at scale. [Static Analysis](../tooling/static-analysis.md) tools like CodeQL and Joern can systematically trace data flow from IOCTL input buffers to dangerous sinks across every code path. [Fuzzing](../tooling/fuzzing.md) covers the synchronization and error-path categories where static tools struggle, because race conditions require runtime thread scheduling to manifest. [AutoPiff](../tooling/autopiff-integration.md) automates diff-based detection across Patch Tuesday drops, matching the [patch patterns](patch-patterns.md) that correspond to each anti-pattern.

## Cross-References

- [Vulnerability Classes](../vuln-classes/index.md) -- taxonomy of the underlying bug types
- [Exploitation Primitives](../primitives/index.md) -- what attackers gain from each bug class
- [Mitigations](../mitigations/index.md) -- kernel hardening that blocks or limits exploitation
- [Case Studies](../case-studies/index.md) -- full walkthroughs of individual CVEs
- [BYOVD](../reference/byovd.md) -- when the driver is the weapon
