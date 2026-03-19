# Write-What-Where

The write-what-where primitive is the most direct form of kernel memory corruption: the attacker controls both the destination address and the value written to it. Unlike a pool overflow, which corrupts whatever happens to be adjacent, or an increment/decrement, which can only nudge a value by one, a write-what-where gives the attacker a single shot to place an arbitrary value at an arbitrary kernel address. One operation. Full control over both the "what" and the "where."

This directness makes write-what-where one of the most dangerous primitives to achieve, and one of the easiest to exploit once achieved. There is no need for pool spray to arrange adjacent objects. No need for information leaks to determine relative positions. If the attacker knows the address of the current process's `_EPROCESS.Token` field and the address of the SYSTEM process's token, a single write completes the privilege escalation. The entire exploitation chain collapses into: find the addresses, write the value, spawn a SYSTEM shell.

## How write-what-where vulnerabilities arise

The most common source is a missing `ProbeForWrite` call. When a kernel-mode function receives a pointer from user mode and writes to it without first calling `ProbeForWrite` to verify the pointer falls within user-mode address space, the user can supply a kernel address instead. The kernel writes to that address with ring-0 privileges, and the attacker controls the value through another input parameter or a related structure field.

CVE-2023-21768 in `afd.sys` is the textbook example. The Ancillary Function Driver for WinSock accepted a user-controlled pointer through a specific code path and wrote to it without probing. An attacker could pass the address of any kernel structure, and the driver would write a controlled value to it. The fix was a single `ProbeForWrite` call, one of the simplest patches in the KernelSight database, for one of the most powerful primitives.

Buffer overflows with controlled offset calculations also produce write-what-where conditions. If a driver computes a write target as `base + user_controlled_offset`, and the offset is not bounds-checked, the attacker can direct the write anywhere in the kernel's virtual address space. The write value comes from whatever data the driver is copying, which may also be user-controlled.

CLFS (Common Log File System) base log file corruption represents a third pattern. In CVE-2023-28252, a corrupted offset field within a CLFS base log file caused the driver to write outside the allocated container buffer. Because the offset and the data were both derived from the log file (which the attacker controls), this produced a write-what-where condition. The `clfs.sys` driver has been a repeated source of this pattern, with the write targets and values coming from different fields within the same corrupted data structure.

## Exploitation paths

The exploitation path after achieving a write-what-where depends on how many writes the attacker gets and how much control they have over the value.

**Single-write exploitation** is the cleanest path. If the attacker gets exactly one write with full value control, the optimal target is `_EPROCESS.Token`. Overwriting the current process's token `EX_FAST_REF` pointer with the SYSTEM process's token pointer immediately elevates the process to SYSTEM privileges. This requires knowing both addresses, which typically means the attacker needs an information leak before the write, or uses `NtQuerySystemInformation(SystemHandleInformation)` to obtain kernel object addresses. See [token swapping](../exploitation/token-swapping.md) for the full technique.

**Multi-write exploitation** applies when the vulnerability can be triggered multiple times or when the attacker can write multiple values in a single operation. With two writes, the attacker can modify both `_SEP_TOKEN_PRIVILEGES.Present` and `_SEP_TOKEN_PRIVILEGES.Enabled` in the current process's token to grant all privileges. With a write and a read, the attacker can set up an [I/O Ring](../exploitation/io-ring.md) buffer table corruption for stable repeated R/W.

**Partial-value writes** occur when the attacker controls the address but only partially controls the value. For example, the written value might be a counter, a pointer to a known structure, or a fixed constant. Even with constrained values, useful exploitation is possible: writing zero to a security descriptor's DACL pointer produces a NULL DACL (granting everyone full access, see [ACL/SD manipulation](../exploitation/acl-sd-manipulation.md)), and writing zero to `KTHREAD.PreviousMode` achieves the [PreviousMode flip](../exploitation/previous-mode-manipulation.md).

## The `ProbeForWrite` defense

The kernel's primary defense against write-what-where is the `ProbeForWrite` function, which validates that a pointer falls within user-mode address space before allowing a write. When called on a kernel address, `ProbeForWrite` raises an `STATUS_ACCESS_VIOLATION` exception, preventing the write. Drivers that handle `METHOD_NEITHER` IOCTLs are required to call `ProbeForWrite` (and `ProbeForRead`) on all user-supplied pointers before using them, but not all drivers comply.

The fix for most write-what-where vulnerabilities is straightforward: add the missing probe call. AutoPiff detects these patches reliably because the before/after diff shows a new `ProbeForWrite` or `ProbeForRead` call on a path that previously lacked one. This is one of the simplest and most distinctive patch patterns in Windows kernel security.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2023-21768](../../case-studies/CVE-2023-21768.md) | `afd.sys` | Missing ProbeForWrite allows kernel write |
| [CVE-2023-28252](../../case-studies/CVE-2023-28252.md) | `clfs.sys` | OOB write via corrupted base log offset |

## AutoPiff Detection

- `probe_for_read_or_write_added`
- `added_bounds_check_on_offset`
- `method_neither_probe_added`

## Relationship to other primitives

Write-what-where sits at the top of the primitive power hierarchy. An [arbitrary increment/decrement](arb-increment-decrement.md) can emulate a write-what-where by performing many increments, but slowly and noisily. A [pool overflow](pool-overflow.md) can achieve a similar result, but requires pool grooming to control the write target. A write-what-where skips all of that, providing the end result directly.

However, write-what-where alone may not be sufficient. Most exploitation scenarios require at least one read operation (to find addresses for KASLR bypass) before the write can be targeted effectively. The write primitive is often paired with an information leak from a different source: a [named pipe](../exploitation/named-pipe-objects.md) relative read, a handle table query, or an earlier pool overflow. The write-what-where provides the power; the information leak provides the precision.

On systems with HVCI enabled, write-what-where still provides full exploitation capability through data-only attacks. Since the write targets data structures (tokens, security descriptors, PreviousMode) rather than code, HVCI's code integrity enforcement does not interfere. This makes write-what-where one of the primitives least affected by modern kernel mitigations, a property it shares with [I/O Ring](../exploitation/io-ring.md) exploitation.

## See Also

- [Token Swapping](../exploitation/token-swapping.md) -- the most common exploitation target for a write-what-where
- [PreviousMode Manipulation](../exploitation/previous-mode-manipulation.md) -- single-write exploitation when the value is constrained to zero
- [Arbitrary Increment/Decrement](arb-increment-decrement.md) -- the weaker variant with single-unit value control
- [I/O Ring](../exploitation/io-ring.md) -- commonly set up through a write-what-where for stable repeated R/W
- [Pool Overflow](pool-overflow.md) -- the alternative path to controlled writes when a direct write-what-where is not available
