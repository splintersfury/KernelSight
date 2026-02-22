# Type Confusion

Object type confusion from missing type validation on kernel objects, handles, or WOW64 struct layouts.

## Description

Type confusion occurs when a driver interprets an object as the wrong type — accessing fields at wrong offsets, dispatching through wrong vtables, or misinterpreting handle object types.

## Patterns

- Missing `ObjectType` parameter in `ObReferenceObjectByHandle`
- Treating different object subtypes uniformly without tag/type validation
- WOW64 struct layout mismatch (32-bit vs 64-bit)

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2023-36802](../case-studies/CVE-2023-36802.md) | `mskssrv.sys` | FsContextReg/FsStreamReg type confusion |
| [CVE-2022-21882](../case-studies/CVE-2022-21882.md) | `win32kbase.sys` | ConsoleWindow flag type confusion |

## AutoPiff Detection

- `object_type_validation_added` — Object type tag validation added
- `handle_object_type_check_added` — ObjectType parameter added to ObReferenceObjectByHandle
- `wow64_thunk_validation_added` — IoIs32bitProcess check added
