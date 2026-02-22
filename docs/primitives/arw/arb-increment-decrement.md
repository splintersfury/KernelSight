# Arbitrary Increment / Decrement

Primitives that increment or decrement a value at an arbitrary kernel address.

## Description

An arbitrary increment/decrement primitive allows modifying a value at a controlled kernel address by +1 or -1 (or a small controlled amount). While weaker than a full write-what-where, these can be chained to modify token privileges, reference counts, or other small values.

## Exploitation

- Increment token privilege bits to enable `SeDebugPrivilege`
- Decrement reference count to trigger premature free (UAF)
- Modify single bytes in security descriptors

## AutoPiff Detection

- `added_index_bounds_check`
- `interlocked_refcount_added`
