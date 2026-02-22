# Type Confusion

Using a kernel object or structure as a different type than intended, leading to field misinterpretation and potential control-flow hijacking.

## Description

Type confusion vulnerabilities arise when a kernel driver interprets an object pointer as a different type than what it actually points to, causing fields to be read at incorrect offsets or function pointers to be dispatched through the wrong vtable. In the Windows kernel, objects are frequently polymorphic -- different subtypes share common headers but have distinct body layouts. If a driver fails to validate which subtype it is actually handling, it may access type-B-specific fields on a type-A object, interpreting arbitrary data as pointers, sizes, or flags.

This vulnerability class is particularly dangerous in drivers that handle multiple object types through a common dispatch path. For example, kernel streaming drivers (`ks.sys`, `mskssrv.sys`) manage multiple object types (filters, pins, nodes) that share common handle infrastructure. If an IOCTL handler accepts a handle and dereferences it without verifying the object type via `ObReferenceObjectByHandle` with the correct `ObjectType` parameter, an attacker can pass a handle to the wrong object type and cause the driver to misinterpret its fields.

WOW64 (Windows-on-Windows 64-bit) struct layout mismatches represent another common variant. When a 32-bit application calls a 64-bit kernel driver, pointer-containing structures have different layouts due to pointer size differences. If the driver does not check `IoIs32bitProcess(Irp)` and apply the correct thunking, it may read 32-bit fields as 64-bit pointers or vice versa, leading to type confusion on individual structure members.

A related pattern occurs in the `win32k` subsystem, where GDI and USER objects share handle table infrastructure but have different internal layouts. Confusing a PALETTE handle for a BITMAP handle, or a WINDOW handle for a MENU handle, can produce type confusion conditions where the driver interprets the object's body with the wrong field layout. The `win32k` subsystem has historically been a rich source of type confusion vulnerabilities due to its large number of polymorphic object types.

## Common Patterns in Drivers

- `ObReferenceObjectByHandle` called without specifying the expected `ObjectType` parameter, allowing any object type to satisfy the handle lookup
- IOCTL handler casts the file object's `FsContext` or `FsContext2` to a specific structure type without validating a type tag or magic field stored in the structure
- Union fields in a structure interpreted with the wrong variant, typically when a discriminator field is not checked
- Callback context parameters cast to the wrong type in different code paths (e.g., work item callback receives context intended for a different callback)
- Pool allocation reuse where freed memory of type A is reclaimed as type B, and a stale pointer to the original allocation still treats it as type A
- Missing `IoIs32bitProcess` check before interpreting user-mode structures, causing 32-bit and 64-bit layout confusion
- Polymorphic object dispatch where a base-class handler is invoked on a derived object without checking the derived type
- Registry value type confusion: reading a REG_SZ value as REG_DWORD or vice versa, interpreting string data as numeric or pointer data
- IRP system buffer interpreted as different structure types depending on the IOCTL code, but incorrect IOCTL code dispatching causes the wrong structure interpretation

## Exploitation Implications

Type confusion gives the attacker control over how the kernel interprets memory. If a field that is a data value in type A overlaps with a function pointer in type B, the attacker can control what code gets executed. If a size field in type A overlaps with a pointer field in type B, the attacker can control the target of a memory operation. The specific exploitation path depends entirely on which fields overlap between the confused types.

In practice, attackers identify two object types where one has attacker-controllable fields at offsets that correspond to security-critical fields (function pointers, sizes, addresses) in the other type. They then create an object of the controllable type and trick the driver into treating it as the security-critical type. This is often achieved by passing the wrong handle type to an IOCTL or by manipulating object state to cause a code path to use the wrong cast.

Type confusion bugs are particularly valuable to attackers because they often provide very clean primitives. Unlike buffer overflows that require heap grooming and produce messy corruption, a well-exploited type confusion can give precise control over specific fields -- making the exploit more reliable and less likely to cause collateral corruption that triggers a bugcheck before the attacker achieves their goal.

## Typical Primitives Gained

- [Write-What-Where](../primitives/arw/write-what-where.md) -- when confused fields give attacker control over a destination address and value for a write operation
- [Direct IOCTL R/W](../primitives/arw/direct-ioctl-rw.md) -- when type confusion in an IOCTL handler allows redirecting read/write operations to attacker-chosen addresses
- [Token Manipulation](../primitives/arw/token-manipulation.md) -- if the confused object allows overwriting token pointers or privilege fields
- Code execution via corrupted function pointer or vtable dispatch

## Mitigations

- **Type tag validation** -- Drivers should store a magic/type tag in each object and validate it before type-specific field access
- **ObReferenceObjectByHandle with ObjectType** -- Always pass the expected `ObjectType` parameter to enforce type safety at the handle level
- **IoIs32bitProcess checks** -- All IOCTL handlers that process user-mode structures containing pointers must check for WOW64 callers and use appropriate thunked structure definitions
- **kCFI (kernel Control Flow Integrity)** -- Hardware-enforced CFI reduces the impact of vtable confusion by validating indirect call targets
- **Object type isolation** -- Using separate handle tables or file object contexts for different object types prevents cross-type handle confusion

## Detection Strategies

- **Patch diffing**: Look for newly added type tag/magic field checks before object field access. AutoPiff detects these as `object_type_validation_added`.
- **Static analysis**: Identify all `ObReferenceObjectByHandle` calls and verify that the `ObjectType` parameter is not NULL. Flag any NULL `ObjectType` as a potential type confusion vector.
- **Code review**: Examine all casts of `FsContext` / `FsContext2` fields and verify that each cast is preceded by a type discriminator check on the object.
- **WOW64 auditing**: Search for IOCTL handlers that access user-mode structures without checking `IoIs32bitProcess`. These are candidates for struct layout confusion.
- **Fuzzing**: Use handle type confusion fuzzing -- pass handles of unexpected object types to each IOCTL code and monitor for crashes indicating misinterpreted fields.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2023-36802](../case-studies/CVE-2023-36802.md) | `mskssrv.sys` | FsContextReg/FsStreamReg type confusion allowing controlled vtable dispatch |
| [CVE-2022-21882](../case-studies/CVE-2022-21882.md) | `win32kbase.sys` | ConsoleWindow flag type confusion leading to privilege escalation |
| [CVE-2024-21338](../case-studies/CVE-2024-21338.md) | `appid.sys` | Type confusion in IOCTL handler allowing arbitrary kernel callback invocation |
| [CVE-2024-30088](../case-studies/CVE-2024-30088.md) | `ntoskrnl.exe` | Object type confusion in security attribute handling |
| [CVE-2023-29360](../case-studies/CVE-2023-29360.md) | `mskssrv.sys` | Streaming service object type confusion |

## AutoPiff Detection

- `object_type_validation_added` -- Detects patches adding type tag or magic field validation before object field access
- `handle_object_type_check_added` -- Detects addition of the `ObjectType` parameter to `ObReferenceObjectByHandle` calls that previously passed NULL
- `wow64_thunk_validation_added` -- Detects `IoIs32bitProcess` checks added to IOCTL handlers for correct 32/64-bit structure interpretation
- `added_type_validation` -- Detects general type discriminator field checks added before type-specific operations
- `added_object_type_check` -- Detects validation of object type fields in polymorphic dispatch paths
- `type_field_verification_added` -- Detects addition of type/magic field comparison before casting a generic pointer to a specific structure type
