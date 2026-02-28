# Anatomy of a Secure Driver

> Six anti-patterns behind most Windows kernel driver vulnerabilities -- and how to avoid them.

## Root Cause Distribution

Across 134 CVEs in the KernelSight corpus, the vast majority trace to a small set of root causes. Unvalidated input dominates -- missing length checks, unchecked file offsets, unbounded copies. The remaining categories surface less often individually but share a common theme: the driver trusts something it shouldn't.

<div class="ks-figure" markdown>
  <span class="ks-figure-label">FIG — Root Cause Distribution (134 CVEs)</span>
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

## The Six Anti-Patterns

### 1. Trusting User-Supplied Lengths

**What goes wrong** -- The driver reads a length or size from userland and passes it straight to a copy or allocation without checking it against the actual buffer size. [CVE-2025-5942](../case-studies/CVE-2025-5942.md) (epdlpdrv.sys heap overflow), [CVE-2024-38054](../case-studies/CVE-2024-38054.md) (ks.sys property request overflow), [CVE-2025-24993](../case-studies/CVE-2025-24993.md) (ntfs.sys heap overflow from crafted VHD), and [CVE-2025-24985](../case-studies/CVE-2025-24985.md) (FAT integer overflow in fastfat.sys) all stem from this.

**The fix** -- Validate `InputBufferLength` before touching the buffer. Cap copy sizes against the allocation.

```c
if (InputBufferLength < sizeof(MY_HEADER))
    return STATUS_BUFFER_TOO_SMALL;

if (header->DataSize > InputBufferLength - sizeof(MY_HEADER))
    return STATUS_INVALID_PARAMETER;

RtlCopyMemory(dst, src, header->DataSize);
```

### 2. Missing Synchronization on Shared State

**What goes wrong** -- Concurrent threads access shared driver state -- a reference count, a linked list, a pointer field -- without adequate locking. The window is usually narrow but sufficient for exploitation. [CVE-2026-21241](../case-studies/CVE-2026-21241.md) (afd.sys notification UAF) hits a race between registration and teardown. [CVE-2024-38106](../case-studies/CVE-2024-38106.md) (ntoskrnl token race), [CVE-2025-32701](../case-studies/CVE-2025-32701.md) (clfs.sys UAF), and [CVE-2023-36802](../case-studies/CVE-2023-36802.md) (mskssrv.sys pipe UAF) follow the same pattern.

**The fix** -- Use reference counting for objects accessed from multiple contexts. Protect mutable state with spin locks or push locks. Establish a lock ordering convention and stick to it.

```c
// Reference-counted teardown
if (InterlockedDecrement(&Object->RefCount) == 0) {
    ExFreePoolWithTag(Object, TAG);
}
```

### 3. Trusting On-Disk / File-Embedded Offsets

**What goes wrong** -- File system and log drivers read offset/index fields from on-disk structures and use them as memory indices without bounds checking. A crafted image triggers out-of-bounds access. CLFS alone accounts for three CVEs here: [CVE-2025-29824](../case-studies/CVE-2025-29824.md), [CVE-2022-37969](../case-studies/CVE-2022-37969.md), and [CVE-2023-28252](../case-studies/CVE-2023-28252.md) -- all exploited in the wild. [CVE-2025-24992](../case-studies/CVE-2025-24992.md) (ntfs.sys) rounds out the set.

**The fix** -- Treat on-disk data with the same suspicion as user input. Bounds-check every offset and index against the container or record size before use.

```c
if (record->FieldOffset + record->FieldLength > ContainerSize)
    return STATUS_LOG_CORRUPTION;
```

### 4. Exposing Physical Memory or Arbitrary MSR Access

**What goes wrong** -- The driver maps physical memory to userland or exposes model-specific register (MSR) read/write via IOCTLs. This gives any caller full kernel read/write by design. [CVE-2021-21551](../case-studies/CVE-2021-21551.md) (Dell DBUtil), [CVE-2019-16098](../case-studies/CVE-2019-16098.md) (MSI RTCore64), [CVE-2020-12928](../case-studies/CVE-2020-12928.md) (AMD Ryzen Master), and [Capcom.sys](../case-studies/Capcom-sys.md) are textbook examples. All are used in BYOVD campaigns.

**The fix** -- Don't ship physical memory mapping or MSR access in production drivers. If hardware diagnostics require it, gate behind a restrictive DACL, limit to specific physical ranges, and never expose it in a signed driver intended for end-user systems.

### 5. No IOCTL Authentication / Open Device ACLs

**What goes wrong** -- The driver creates its device object with a permissive ACL, allowing any user to open the device and send IOCTLs. Some drivers don't check caller identity at all. [CVE-2025-3464](../case-studies/CVE-2025-3464.md) (AsIO3.sys auth bypass), [CVE-2023-1048](../case-studies/CVE-2023-1048.md) (KProcessHacker unrestricted IOCTLs), [CVE-2025-0289](../case-studies/CVE-2025-0289.md) (Paragon BioNTdrv.sys), and [CVE-2025-68947](../case-studies/CVE-2025-68947.md) (NSecKrnl) all let unprivileged callers reach dangerous code paths.

**The fix** -- Set a restrictive DACL at `IoCreateDeviceSecure` or via an INF security descriptor. Enforce per-IOCTL access checks for sensitive operations.

```c
// Restrictive SDDL: SYSTEM + Administrators only
DECLARE_CONST_UNICODE_STRING(sddl,
    L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
IoCreateDeviceSecure(..., &sddl, ...);
```

### 6. Double-Fetch / TOCTOU on User Buffers

**What goes wrong** -- The driver reads a value from a user-mode buffer, validates it, then reads the same location again. An attacker flips the value between the two reads. [CVE-2024-11616](../case-studies/CVE-2024-11616.md) (epdlpdrv.sys double-fetch of length field), [CVE-2024-30088](../case-studies/CVE-2024-30088.md) (ntoskrnl handle-to-pointer race), and [CVE-2024-38106](../case-studies/CVE-2024-38106.md) (ntoskrnl token assignment race) all exploit this gap.

**The fix** -- Capture user data into a kernel buffer in a single copy. Validate the kernel-side copy. Never re-read from userland.

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

Even a vulnerability-free driver becomes a weapon if it exposes raw kernel read/write by design. Drivers that map physical memory, disable code integrity, or provide arbitrary MSR access are routinely dropped by ransomware groups and APTs -- no exploit needed. See [BYOVD](../reference/byovd.md) for the full pattern.

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

## Detection & Audit Pointers

Static analysis catches most input validation and double-fetch bugs at scale -- see [Static Analysis](../tooling/static-analysis.md). [Fuzzing](../tooling/fuzzing.md) covers the synchronization and error-path categories where static tools struggle. [AutoPiff](../tooling/autopiff-integration.md) automates diff-based detection across Patch Tuesday drops.

## Cross-References

- [Vulnerability Classes](../vuln-classes/index.md) -- taxonomy of the underlying bug types
- [Exploitation Primitives](../primitives/index.md) -- what attackers gain from each bug class
- [Mitigations](../mitigations/index.md) -- kernel hardening that blocks or limits exploitation
- [Case Studies](../case-studies/index.md) -- full walkthroughs of individual CVEs
- [BYOVD](../reference/byovd.md) -- when the driver is the weapon
