# Type Confusion

When the kernel dereferences a pointer, it does not ask what the object actually is. It trusts the cast. If a driver interprets a PALETTE object as a BITMAP, or reads a 32-bit structure as 64-bit, the kernel faithfully reads fields at the wrong offsets, dispatches through the wrong vtable, and writes to whatever address happens to sit where a pointer field should be. Type confusion is not about corrupting memory; it is about *reinterpreting* it, and the kernel cooperates fully with the attacker's reinterpretation.

This page covers how type confusion vulnerabilities arise in Windows kernel drivers, why they produce unusually clean exploitation primitives, and how to detect them through patch diffing and static analysis.

## Why type confusion produces surgical exploits

Most memory corruption bugs are inherently messy. A buffer overflow writes a linear swath of bytes past the end of a buffer, corrupting whatever happens to be adjacent. A use-after-free depends on winning a race between free and spray. Both require heap grooming, and both risk collateral damage that triggers a bugcheck before the exploit payload executes.

Type confusion is different. The attacker does not corrupt memory at all. Instead, the attacker provides an object of type A where the driver expects type B, and the driver's own code reads fields at offsets that are correct for type B but land on entirely different data in the type A layout. If byte 0x18 in type B is a function pointer, and byte 0x18 in type A is a user-controlled data field, the driver calls through the attacker's data as if it were a legitimate function pointer. The exploit is surgical: one field, one offset, one controlled value. No spray, no heap grooming, no adjacent object corruption.

This precision makes type confusion bugs among the most reliable to exploit. They also tend to survive mitigation improvements that target heap corruption, because the exploit path never involves corrupting metadata, overflowing a buffer, or reclaiming freed memory. The driver's own logic performs the dangerous operation.

## How type confusion arises

### Handle-based object confusion

The Windows kernel manages many object types through a unified handle infrastructure. When a driver receives a handle from user mode and calls `ObReferenceObjectByHandle`, it should specify the expected `ObjectType` parameter to ensure the handle refers to the correct type. If the driver passes `NULL` for this parameter, the call succeeds for *any* object type, and the returned pointer is cast to whatever structure the driver expects.

CVE-2023-36802 in `mskssrv.sys` illustrates this pattern with particular clarity. The kernel streaming server driver accepted a handle that could reference either an `FsContextReg` or `FsStreamReg` structure. These structures have different layouts but share common handle infrastructure. An attacker could pass a handle to the wrong type, and the driver would interpret one structure's data fields as the other's vtable pointers, enabling controlled dispatch through attacker-influenced values.

### WOW64 structure layout mismatch

When a 32-bit application calls into a 64-bit kernel driver, any structure containing pointers has a different layout. Pointers are 4 bytes in the 32-bit view and 8 bytes in the 64-bit view. If the driver does not call `IoIs32bitProcess(Irp)` and apply the correct thunking, it reads 32-bit fields as if they were 64-bit, or vice versa. A 32-bit pointer value of 0x41414141 followed by another field value gets read as a single 64-bit pointer, pointing to an address the attacker might control.

CVE-2024-38054 in `ksthunk.sys` exists specifically because the kernel streaming thunking layer (whose entire purpose is WOW64 structure translation) got the translation wrong for `KSSTREAM_HEADER` structures. The thunking code is the defense against this class of bug, and the defense itself was vulnerable.

### Polymorphic object dispatch

The `win32k` subsystem is the most prolific source of type confusion in Windows. GDI and USER objects (palettes, bitmaps, windows, menus, brushes) share handle table infrastructure but have entirely different internal layouts. The handle table maps a handle to an object, and the object's type determines which fields exist at which offsets. If a code path fails to validate the object type after lookup, it may process a PALETTE as a BITMAP, reading palette entries as pixel data dimensions or vice versa.

CVE-2022-21882 in `win32kbase.sys` exploited a `ConsoleWindow` flag that caused the driver to treat a window object with one layout as if it had another, enabling privilege escalation. The bug was not in how memory was managed but in how the driver decided what the memory *meant*.

### Union variant confusion

Many kernel structures use C unions where the same memory holds different typed data depending on a discriminator field. If the discriminator is not checked (or is checked but the wrong branch executes), the union is read with the wrong variant, and fields that were written as one type are interpreted as another. This is structurally identical to type confusion at the object level, just at the field level within a single structure.

### Callback context mismatches

Kernel drivers frequently pass context pointers to asynchronous callbacks (timer DPCs, work items, completion routines). The callback casts the context to the expected structure type. If two different callback registrations share the same context pointer but expect different structure types, or if a context is reused for a different purpose after re-registration, the callback interprets the context with the wrong layout.

## From confusion to primitive

The exploitation path depends entirely on which fields overlap between the two confused types. The attacker identifies two object types where controllable fields in one type correspond to security-critical fields (function pointers, sizes, addresses) in the other.

``` mermaid
graph TD
    A["Attacker creates\nObject A with\ncontrolled fields"] --> B["Driver receives\nhandle/pointer\nto Object A"]
    B --> C["Driver casts to\nObject B layout\n(no type check)"]
    C --> D{"Which field\noverlaps?"}
    D -->|"Function ptr\nat offset 0x18"| E["Controlled\ncall target"]
    D -->|"Size field\nat offset 0x10"| F["OOB read/write\nvia inflated size"]
    D -->|"Address field\nat offset 0x20"| G["Write-what-where\nvia redirected ptr"]
    style A fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    style B fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    style C fill:#1e293b,stroke:#ef4444,color:#e2e8f0
    style D fill:#152a4a,stroke:#f59e0b,color:#e2e8f0
    style E fill:#1e293b,stroke:#8b5cf6,color:#e2e8f0
    style F fill:#1e293b,stroke:#8b5cf6,color:#e2e8f0
    style G fill:#1e293b,stroke:#8b5cf6,color:#e2e8f0
```

CVE-2024-21338 in `appid.sys` demonstrates the function-pointer variant. A type confusion in the IOCTL handler allowed an attacker to invoke an arbitrary kernel callback function with controlled arguments. The Lazarus Group exploited this bug in the wild, using it to disable security products by calling into kernel routines that unload drivers. The bug persisted for years in a routinely audited driver because the flaw was in the type logic, not in memory handling.

On modern Windows with kCFI (kernel Control Flow Integrity), direct function pointer hijacking through type confusion is increasingly constrained. But data-only exploitation remains fully viable: corrupting a size field to enable an out-of-bounds copy, or redirecting a destination pointer to overwrite token privileges, achieves the same privilege escalation without diverting control flow.

## Typical primitives gained

- [Write-What-Where](../primitives/arw/write-what-where.md) when confused fields give attacker control over a destination address and value for a write operation
- [Direct IOCTL R/W](../primitives/arw/direct-ioctl-rw.md) when type confusion in an IOCTL handler redirects read/write operations to attacker-chosen addresses
- [Token Manipulation](../primitives/arw/token-manipulation.md) if the confused object allows overwriting token pointers or privilege fields
- Code execution via corrupted function pointer or vtable dispatch (pre-kCFI or through gadget chains)

## Mitigations

Type confusion mitigations center on enforcing type identity at every point where an object is accessed.

**Type tag validation** is the most direct defense. Storing a magic value or type tag at a known offset in every object, and checking it before any type-specific field access, catches confusion at the point of use. This is cheap (one comparison) and reliable, but it must be applied consistently. A single code path that skips the check reintroduces the vulnerability.

**ObReferenceObjectByHandle with ObjectType** enforces type safety at the handle level. When the driver specifies the expected `ObjectType`, the object manager refuses to return an object of a different type, preventing handle-based confusion entirely. Passing `NULL` for this parameter is the root cause of many type confusion CVEs.

**IoIs32bitProcess checks** in IOCTL handlers prevent WOW64 layout confusion. All handlers that process user-mode structures containing pointers must check for 32-bit callers and use the appropriate thunked structure definitions. Missing this check is a separate finding class that AutoPiff tracks.

**kCFI (kernel Control Flow Integrity)** reduces the impact of vtable confusion by validating indirect call targets against expected type signatures. This does not prevent the confusion itself, but it limits the attacker's ability to redirect control flow through a confused function pointer.

**Object type isolation**, using separate handle tables or file object contexts for different object types, prevents cross-type confusion architecturally rather than through runtime checks.

## Detection strategies

**Patch diffing** reveals type confusion fixes clearly. Look for newly added type tag or magic field checks before object field access, addition of the `ObjectType` parameter to `ObReferenceObjectByHandle` calls that previously passed `NULL`, or `IoIs32bitProcess` checks added to IOCTL handlers. These patterns are distinctive in binary diffs because they add comparison-and-branch sequences at the start of type-specific code paths.

**Static analysis** should enumerate all `ObReferenceObjectByHandle` calls and flag any where the `ObjectType` parameter is `NULL`. Each one is a potential type confusion vector. Similarly, all casts of `FsContext` or `FsContext2` fields should be preceded by a type discriminator check.

**Code review** should focus on polymorphic dispatch paths: code that handles multiple object types through a common entry point. Verify that every type-specific operation is preceded by a type check. In `win32k` code, this means verifying that every GDI/USER object access validates the object type after handle table lookup.

**WOW64 auditing** searches for IOCTL handlers that access user-mode structures without calling `IoIs32bitProcess`. Any such handler is a candidate for struct layout confusion when called from a 32-bit process on a 64-bit system.

**Handle type confusion fuzzing** provides good coverage: pass handles of unexpected object types to each IOCTL code and monitor for crashes indicating misinterpreted fields. This is straightforward to automate and has historically been productive.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2023-36802](../case-studies/CVE-2023-36802.md) | `mskssrv.sys` | FsContextReg/FsStreamReg type confusion allowing controlled vtable dispatch |
| [CVE-2022-21882](../case-studies/CVE-2022-21882.md) | `win32kbase.sys` | ConsoleWindow flag type confusion leading to privilege escalation |
| [CVE-2024-21338](../case-studies/CVE-2024-21338.md) | `appid.sys` | Type confusion in IOCTL handler allowing arbitrary kernel callback invocation |
| [CVE-2024-30088](../case-studies/CVE-2024-30088.md) | `ntoskrnl.exe` | Object type confusion in security attribute handling |
| [CVE-2023-29360](../case-studies/CVE-2023-29360.md) | `mskssrv.sys` | Streaming service object type confusion |

## AutoPiff Detection

- `object_type_validation_added` detects patches adding type tag or magic field validation before object field access
- `handle_object_type_check_added` detects addition of the `ObjectType` parameter to `ObReferenceObjectByHandle` calls that previously passed NULL
- `wow64_thunk_validation_added` detects `IoIs32bitProcess` checks added to IOCTL handlers for correct 32/64-bit structure interpretation
- `added_type_validation` detects general type discriminator field checks added before type-specific operations
- `added_object_type_check` detects validation of object type fields in polymorphic dispatch paths
- `type_field_verification_added` detects addition of type/magic field comparison before casting a generic pointer to a specific structure type

Type confusion occupies a unique position among vulnerability classes because it does not require any memory corruption to achieve exploitation. The bug is purely logical: the driver believes it is looking at one thing when it is looking at another. This makes it invisible to memory safety tooling and resistant to allocator hardening. The defense is type discipline, enforced at every boundary where an object changes hands. When that discipline lapses, even once, the kernel's own code becomes the exploit.
