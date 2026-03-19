# Arbitrary Increment / Decrement

Most kernel exploitation research focuses on primitives that write arbitrary values to arbitrary addresses. But some of the most elegant exploit chains start with something far more constrained: the ability to add or subtract 1 from a value at a controlled kernel address. An arbitrary increment or decrement primitive seems weak at first glance. You cannot write a pointer. You cannot overwrite a structure. All you can do is nudge a single byte up or down by one. Yet this is enough to escalate privileges, because many of the kernel's most security-critical fields are small integers, single-byte flags, or bitmask positions where a single-unit change crosses a trust boundary.

The canonical example is `KTHREAD.PreviousMode`. This single byte at a known offset in the current thread's kernel structure determines whether the kernel treats system calls as originating from user mode (value 1) or kernel mode (value 0). Decrementing it from 1 to 0 converts a user-mode thread into one that the kernel trusts as a kernel-mode caller. Every subsequent `ProbeForRead` and `ProbeForWrite` check becomes a no-op. The thread can pass kernel addresses directly to system calls like `NtReadVirtualMemory` and `NtWriteVirtualMemory`, achieving full arbitrary kernel R/W through the kernel's own APIs. One byte. One decrement. Full kernel access.

## Sources of the primitive

Arbitrary increment and decrement primitives arise from several vulnerability patterns. The most common source is an exposed kernel API call where the driver passes an attacker-controlled address as a pointer argument to a function that performs an increment or decrement on the value at that pointer. In CVE-2025-3464, the ASUS `AsIO3.sys` driver exposed an IOCTL that called `ObfDereferenceObject` on a user-supplied pointer. `ObfDereferenceObject` decrements the reference count at offset -0x30 from the supplied address, which means the attacker controls the effective target address by adjusting the input pointer. By pointing this at `KTHREAD.PreviousMode + 0x30`, the decrement lands on the PreviousMode field.

Other sources include integer underflow in array index calculations (where a negative index causes a decrement at an address before the array), reference counting bugs where the driver decrements a refcount through a user-controlled pointer, and race conditions in interlocked operations where the attacker can redirect the target address between the compare and the exchange.

## Exploitation strategies

The exploitation path depends on which kernel field the attacker targets with the increment or decrement. Several strategies have proven effective in practice.

**PreviousMode flip** is the most powerful single-decrement exploitation path. The attacker locates the `KTHREAD` structure for the current thread (via `NtQuerySystemInformation` or by reading `gs:[0x188]` to get the KPCR thread pointer), calculates the offset to `PreviousMode`, and decrements it from `UserMode` (1) to `KernelMode` (0). From this point, the thread has full kernel R/W through standard NT system calls, and the attacker proceeds directly to [token swapping](../exploitation/token-swapping.md). This approach is detailed in the [PreviousMode Manipulation](../exploitation/previous-mode-manipulation.md) page.

**Token privilege bit enabling** uses multiple increments to set specific bits in the `_SEP_TOKEN_PRIVILEGES.Enabled` bitmask within the current process's `_TOKEN` structure. Each privilege corresponds to a bit position, and incrementing the byte containing that bit can enable the privilege if the bit was previously 0. `SeDebugPrivilege` (bit 20) is the most valuable target, as it grants the ability to open handles to any process with `PROCESS_ALL_ACCESS`, including SYSTEM processes. However, this approach requires multiple operations and precise bit-level targeting, making it less reliable than the PreviousMode flip.

**Reference count manipulation** uses decrements to drive a kernel object's reference count to zero prematurely, triggering a free while other references still exist. This converts the increment/decrement primitive into a use-after-free, which can then be exploited through [pool spray](../exploitation/pool-spray-feng-shui.md) reclamation techniques. The attacker issues enough decrements to underflow the refcount, waits for the object to be freed, sprays a replacement object into the freed slot, and then uses the dangling pointer to interact with the controlled content.

**Security descriptor bit modification** uses increments or decrements to alter individual bytes within ACL structures. Zeroing the `AceCount` field of a DACL changes the interpretation from "check these ACEs" to "deny all" (empty DACL), while zeroing the DACL pointer produces a NULL DACL that grants everyone full access. These techniques connect to the broader [ACL/SD manipulation](../exploitation/acl-sd-manipulation.md) primitive.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2025-3464](../../case-studies/CVE-2025-3464.md) | `AsIO3.sys` | `ObfDereferenceObject` IOCTL provides decrement at `(addr - 0x30)`; used to flip PreviousMode for full kernel R/W |

## AutoPiff Detection

AutoPiff detects patches for increment/decrement vulnerabilities through two primary rules. The `added_index_bounds_check` rule fires when a patch adds validation on an array index or offset before it is used in a memory operation, preventing out-of-bounds increments. The `interlocked_refcount_added` rule detects cases where a patch replaces a non-atomic increment/decrement with an interlocked operation that includes range checking, closing race conditions that could be exploited for controlled increments.

- `added_index_bounds_check`
- `interlocked_refcount_added`

## Relationship to other primitives

The arbitrary increment/decrement primitive occupies an interesting position in the exploitation landscape. It is strictly weaker than a [write-what-where](write-what-where.md) primitive, which can write any value to any address in a single operation. But it is sufficient for many exploitation goals because the kernel's security model depends on small numeric values: a 1-byte PreviousMode field, a 1-bit privilege flag, a 4-byte reference count. The increment/decrement primitive's constraints are a poor match for overwriting 8-byte pointers (like token pointers in [token swapping](../exploitation/token-swapping.md)), but a perfect match for flipping the flags that control access boundaries.

When the target requires more than a single-unit change, the attacker can chain multiple increment or decrement operations. This is slower and noisier than a direct write, but it works. Ten decrements on a refcount achieve the same result as writing zero, just less efficiently. The tradeoff is between the exploit's complexity and the strength of the initial primitive.

## See Also

- [PreviousMode Manipulation](../exploitation/previous-mode-manipulation.md) -- the most common downstream technique after a decrement primitive
- [Write-What-Where](write-what-where.md) -- the strictly more powerful variant that provides full value control
- [Token Manipulation](token-manipulation.md) -- privilege bit enabling through targeted increments
- [ACL / SD Manipulation](../exploitation/acl-sd-manipulation.md) -- security descriptor modification through byte-level changes
