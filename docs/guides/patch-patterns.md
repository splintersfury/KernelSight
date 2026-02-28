# Patch Patterns

> What Microsoft's kernel fixes look like for each bug class -- with before/after pseudocode and AutoPiff rule mapping.

## Overview

Kernel patches tend to be surgical. A typical Patch Tuesday fix adds 5--20 lines of validation code without restructuring the surrounding function. Recognizing the pattern lets you diff a binary update and classify the vulnerability it fixes -- even before the CVE details are public.

This page catalogs the 7 most common patch shapes across the KernelSight corpus. Each pattern maps to AutoPiff detection rules for automated patch analysis.

## Patch Categories

### 1. Added Bounds Check

**Pattern:** A new `if (len > max) return STATUS_...` guard appears before a copy, allocation, or pointer arithmetic operation.

**Where it appears:** Buffer overflow and out-of-bounds access fixes. The most common patch type in the corpus.

**Before:**
```c
// No validation -- copies whatever length the caller provides
RtlCopyMemory(dst, src, header->DataSize);
```

**After:**
```c
if (header->DataSize > AllocationSize - FIELD_OFFSET(MY_STRUCT, Data))
    return STATUS_INVALID_PARAMETER;
RtlCopyMemory(dst, src, header->DataSize);
```

**CVE examples:**

- [CVE-2022-37969](../case-studies/CVE-2022-37969.md) -- CLFS cbSymbolZone bounds check added
- [CVE-2024-49138](../case-studies/CVE-2024-49138.md) -- CLFS LoadContainerQ length validation
- [CVE-2025-24993](../case-studies/CVE-2025-24993.md) -- ntfs.sys MFT attribute size check
- [CVE-2025-21418](../case-studies/CVE-2025-21418.md) -- afd.sys buffer length validation

### 2. Added Lock / Synchronization

**Pattern:** A spin lock, push lock, or `InterlockedCompareExchange` guard wraps a previously unprotected read-modify-write sequence on shared state.

**Where it appears:** Race condition and some UAF fixes. The second most common patch type.

**Before:**
```c
// No lock -- another thread can free Object between check and use
if (Object->State == ACTIVE) {
    ProcessObject(Object);
}
```

**After:**
```c
KeAcquireSpinLock(&Object->Lock, &OldIrql);
if (Object->State == ACTIVE) {
    ProcessObject(Object);
}
KeReleaseSpinLock(&Object->Lock, OldIrql);
```

**CVE examples:**

- [CVE-2024-38106](../case-studies/CVE-2024-38106.md) -- ntoskrnl lock added around VslpEnterIumSecureMode
- [CVE-2026-21241](../case-studies/CVE-2026-21241.md) -- afd.sys spinlock scope extended to cover notification teardown
- [CVE-2025-62215](../case-studies/CVE-2025-62215.md) -- ntoskrnl synchronization for double-free prevention

### 3. Added Probe / Capture

**Pattern:** `ProbeForRead`/`ProbeForWrite` followed by a single-copy capture replaces direct dereference of a user-mode pointer. The kernel validates and captures user data once instead of reading it multiple times.

**Where it appears:** Double-fetch and TOCTOU fixes.

**Before:**
```c
// Reads user buffer twice -- attacker can change value between reads
if (UserBuffer->Length <= MAX_LEN) {
    RtlCopyMemory(dst, UserBuffer->Data, UserBuffer->Length);  // re-read
}
```

**After:**
```c
__try {
    ProbeForRead(UserBuffer, sizeof(MY_REQUEST), __alignof(MY_REQUEST));
    CapturedLength = UserBuffer->Length;  // single capture
} __except (EXCEPTION_EXECUTE_HANDLER) {
    return GetExceptionCode();
}
if (CapturedLength <= MAX_LEN) {
    RtlCopyMemory(dst, src, CapturedLength);  // uses captured value
}
```

**CVE examples:**

- [CVE-2024-30088](../case-studies/CVE-2024-30088.md) -- ntoskrnl probe-and-capture for security attributes
- [CVE-2024-11616](../case-studies/CVE-2024-11616.md) -- epdlpdrv.sys single-copy capture replacing double-fetch

### 4. Added IOCTL Access Control

**Pattern:** The patch adds caller identity checks to an IOCTL dispatcher -- `SeSinglePrivilegeCheck`, `PsGetCurrentProcessSessionId`, or replaces `IoCreateDevice` with `IoCreateDeviceSecure` and a restrictive SDDL string.

**Where it appears:** Authorization bypass fixes. Common in inbox drivers and dominant in BYOVD driver patches.

**Before:**
```c
// Any process can open the device and send this IOCTL
case IOCTL_DANGEROUS_OPERATION:
    DoTheDangerousThing(Irp);
    break;
```

**After:**
```c
case IOCTL_DANGEROUS_OPERATION:
    if (!SeSinglePrivilegeCheck(SeLoadDriverPrivilege,
                                Irp->RequestorMode)) {
        status = STATUS_ACCESS_DENIED;
        break;
    }
    DoTheDangerousThing(Irp);
    break;
```

**CVE examples:**

- [CVE-2024-21338](../case-studies/CVE-2024-21338.md) -- appid.sys IOCTL 0x22A018 access check added
- [CVE-2024-26229](../case-studies/CVE-2024-26229.md) -- csc.sys missing access check patched
- [CVE-2025-3464](../case-studies/CVE-2025-3464.md) -- AsIO3.sys hardlink auth bypass fix

### 5. Added Reference Counting

**Pattern:** `InterlockedIncrement`/`InterlockedDecrement` pairs appear around object acquisition and release paths. The object is only freed when the reference count reaches zero.

**Where it appears:** UAF fixes where the root cause is premature object deallocation while references are still active.

**Before:**
```c
// Free without checking if anyone still holds a reference
RemoveFromList(Object);
ExFreePoolWithTag(Object, TAG);
```

**After:**
```c
RemoveFromList(Object);
if (InterlockedDecrement(&Object->RefCount) == 0) {
    ExFreePoolWithTag(Object, TAG);
}
```

**CVE examples:**

- [CVE-2024-30089](../case-studies/CVE-2024-30089.md) -- mskssrv.sys ref-count logic error fix
- [CVE-2024-38193](../case-studies/CVE-2024-38193.md) -- afd.sys Registered I/O buffer lifetime management
- [CVE-2025-32709](../case-studies/CVE-2025-32709.md) -- afd.sys socket closure ref-count fix

### 6. Removed Dangerous Functionality

**Pattern:** An entire IOCTL handler, code path, or exported function is deleted. The patch doesn't fix the vulnerability -- it removes the attack surface.

**Where it appears:** BYOVD drivers after disclosure. Microsoft's Vulnerable Driver Blocklist entries also fall into this category -- they prevent the driver from loading at all.

**CVE examples:**

- AsIO3.sys -- blocklisted after [CVE-2025-3464](../case-studies/CVE-2025-3464.md) / [CVE-2025-1533](../case-studies/CVE-2025-1533.md)
- ThrottleStop.sys -- [CVE-2025-7771](../case-studies/CVE-2025-7771.md), MSR write removed, driver blocklisted
- BioNTdrv.sys -- [CVE-2025-0289](../case-studies/CVE-2025-0289.md), five CVEs led to driver blocklist entry

This is the bluntest patch pattern -- and the only correct response when the functionality is dangerous by design. There is no safe way to expose physical memory mapping to userland.

### 7. Added Type / Object Validation

**Pattern:** A type check, object signature validation, or runtime tag comparison appears before a pointer cast or object dereference. The patch rejects objects that don't match the expected type.

**Where it appears:** Type confusion fixes, primarily in win32k and Kernel Streaming drivers.

**Before:**
```c
// Cast without checking -- wrong object type causes corruption
PWINDOW_OBJECT Window = (PWINDOW_OBJECT)Object;
Window->ExtraData = NewValue;
```

**After:**
```c
if (Object->Type != OBJECT_TYPE_WINDOW) {
    return STATUS_OBJECT_TYPE_MISMATCH;
}
PWINDOW_OBJECT Window = (PWINDOW_OBJECT)Object;
Window->ExtraData = NewValue;
```

**CVE examples:**

- [CVE-2022-21882](../case-studies/CVE-2022-21882.md) -- win32kbase.sys ConsoleWindow flag type check
- [CVE-2023-36802](../case-studies/CVE-2023-36802.md) -- mskssrv.sys FsContextReg/FsStreamReg validation

## AutoPiff Rule Mapping

AutoPiff detects these patch patterns automatically during binary diff analysis. Each pattern maps to one or more detection rules:

| Patch Pattern | AutoPiff Rule(s) | Example CVE |
|---------------|-------------------|-------------|
| Added Bounds Check | `added_length_check`, `added_offset_bounds_check` | [CVE-2024-49138](../case-studies/CVE-2024-49138.md) |
| Added Lock / Sync | `added_spinlock_acquire`, `added_interlocked_op` | [CVE-2024-38106](../case-studies/CVE-2024-38106.md) |
| Added Probe / Capture | `added_probe_for_read`, `added_user_capture` | [CVE-2024-30088](../case-studies/CVE-2024-30088.md) |
| Added IOCTL Access Control | `added_access_check`, `modified_device_create` | [CVE-2024-21338](../case-studies/CVE-2024-21338.md) |
| Added Reference Counting | `added_ref_count`, `modified_object_free` | [CVE-2024-30089](../case-studies/CVE-2024-30089.md) |
| Removed Functionality | `removed_ioctl_handler`, `deleted_code_path` | [CVE-2025-3464](../case-studies/CVE-2025-3464.md) |
| Added Type Validation | `added_type_check`, `added_object_tag_check` | [CVE-2022-21882](../case-studies/CVE-2022-21882.md) |

See [AutoPiff Integration](../tooling/autopiff-integration.md) for setup and rule configuration.

## Cross-References

- [Corpus Analytics](corpus-analytics.md) -- data distribution behind these patterns
- [Exploit Chain Patterns](exploit-chain-patterns.md) -- the chains these patches break
- [Anatomy of a Secure Driver](secure-driver-anatomy.md) -- the anti-patterns these patches fix
- [Patch Diffing](../tooling/patch-diffing.md) -- tools for identifying these patterns in binaries
- [AutoPiff Integration](../tooling/autopiff-integration.md) -- automated detection at scale
