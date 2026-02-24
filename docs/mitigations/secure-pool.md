# Secure Pool

VBS-backed kernel pool that provides hypervisor-enforced integrity for selected allocations, isolating them from corruption by VTL 0 kernel exploits.

## Overview

Microsoft introduced the Secure Pool in Windows 10 21H2 (build 19044) as a specialized memory allocator that uses VBS to provide stronger guarantees than the standard kernel pool. Standard pool hardening relies on software checks (cookies, safe unlinking) that can be bypassed with sufficient primitives. Secure Pool protections are enforced at the hypervisor level through VTL 1 and SLAT. Allocations in the Secure Pool are isolated from adjacent memory corruption and have their metadata stored in the Secure Kernel's address space, making them immune to pool overflow and use-after-free techniques that remain effective against the standard pool.

The Secure Pool is the strongest form of heap protection available in Windows, but its effectiveness is limited by adoption: only a small fraction of kernel objects are allocated from it.

## Mechanism

**Allocation API:**

- Kernel components allocate from the Secure Pool using `ExAllocatePool3` with the `POOL_FLAG_USE_SECURE_POOL` flag or through `ExSecurePoolAlloc`.
- The allocation request is forwarded to the Secure Kernel (VTL 1), which manages the Secure Pool independently of the standard VTL 0 pool allocator.
- The caller receives a pointer to memory that is accessible from VTL 0 for normal read/write operations, but the surrounding metadata and guard regions are invisible to VTL 0.

**Hypervisor-Enforced Isolation:**

- Secure Pool memory pages are controlled by VTL 1 EPT/NPT entries. The Secure Kernel configures SLAT permissions so that VTL 0 can read/write the allocation (as needed by the kernel) but cannot access adjacent metadata or guard regions.
- Guard pages are placed between individual Secure Pool allocations. These guard pages have no VTL 0 read/write permission in the EPT, so any overflow or underflow from one allocation triggers a hypervisor-level page fault before reaching adjacent allocations.
- The isolation is spatial: each allocation is surrounded by inaccessible memory, preventing linear corruption from reaching neighboring objects.

**Metadata Protection:**

- Pool metadata (chunk headers, free lists, allocation tracking) is stored entirely in VTL 1 address space.
- VTL 0 code, even with a full arbitrary read/write primitive, cannot access or modify Secure Pool metadata because it resides in a different Virtual Trust Level.
- This eliminates the entire class of pool header corruption attacks that have historically been the backbone of pool exploitation.

**Free Operation Protection:**

- When a Secure Pool allocation is freed, the Secure Kernel validates the request through VTL 1.
- Protections against double-free and use-after-free are enforced at the hypervisor level, with the Secure Kernel tracking allocation state independently of VTL 0 data structures.
- Freed pages can be immediately unmapped from VTL 0, causing any use-after-free access to fault rather than succeed silently.
- The free validation prevents type confusion attacks where an attacker frees an object and reclaims the memory with a different object type.

## Primitives Blocked

- **Pool overflow into adjacent Secure Pool allocation:** Guard pages enforced by the hypervisor between allocations prevent linear overflow from reaching adjacent objects, regardless of how the overflow occurs or its size.
- **Pool header manipulation:** Since all metadata resides in VTL 1, there are no pool headers in VTL 0 memory for the attacker to corrupt. Cookie leakage and forging attacks are irrelevant.
- **Pool spray targeting Secure Pool objects:** The Secure Kernel controls allocation placement independently of the standard VTL 0 allocator. Standard pool spray techniques do not influence Secure Pool layout.
- **Use-after-free on Secure Pool objects:** The Secure Kernel can immediately revoke VTL 0 access to freed allocations via EPT, converting a use-after-free into an immediate fault.
- **Type confusion via pool reuse:** The Secure Kernel can enforce type-safe allocation by tracking the intended object type and preventing reuse with a different type during reallocation.

## Bypass History

- **Limited adoption (primary bypass, ongoing):** Very few kernel objects currently use Secure Pool. The vast majority of kernel allocations -- including `_TOKEN`, `_EPROCESS`, `_OBJECT_HEADER`, and driver-specific objects -- remain in the standard kernel pool. Exploits simply target unprotected objects. Until adoption reaches critical mass, this mitigation covers only a narrow subset of the kernel attack surface.
- **VTL 0 access still permitted for reads/writes (by design):** The kernel needs to read and write Secure Pool allocations during normal operation. This means an attacker with an arbitrary read/write primitive can still read and modify the contents of a Secure Pool allocation if they know its address. The protection is against adjacent corruption and metadata manipulation, not against direct content modification of a known allocation.
- **VBS dependency:** On systems where VBS is not enabled (or has been disabled), Secure Pool APIs may still succeed but without hypervisor-backed enforcement, reducing to standard pool semantics with no additional security benefit.
- **Interaction with standard pool objects:** Secure Pool objects often contain pointers to standard pool objects and vice versa. An attacker can corrupt the standard pool object that a Secure Pool object references, achieving an indirect attack.

## Windows Version Availability

| Version | Status | Notes |
|---------|--------|-------|
| Windows 10 21H2 | Introduced | Initial Secure Pool implementation |
| Windows 11 21H2 | Available | Expanded API support, additional opt-in components |
| Windows 11 22H2 | Available | Additional kernel components opted in |
| Windows 11 23H2 | Available | Incremental adoption growth |
| Windows 11 24H2 | Available | Continued expansion of protected object types |

Requires VBS to be enabled and active. Without VBS, Secure Pool provides no additional protection over the standard pool. The feature has no performance impact on non-Secure-Pool allocations.

## Impact on Exploit Development

Secure Pool's real-world impact depends on adoption rate. Currently, exploits can simply choose targets that are not in the Secure Pool. As Microsoft moves more objects into Secure Pool (tokens, security descriptors, process objects), pool overflow and use-after-free exploitation will become harder. The long-term goal is for all security-sensitive kernel allocations to reside in Secure Pool, reducing pool corruption vulnerabilities to denial-of-service rather than privilege escalation.

In practice, certain newer kernel objects may be unexpectedly resistant to pool-based techniques. Verify whether a target object type uses Secure Pool before pursuing a pool corruption strategy against it.

## Cross-References

- [VBS / HVCI](vbs-hvci.md) -- Secure Pool requires the VBS infrastructure for hypervisor enforcement
- [Kernel Data Protection (KDP)](kdp.md) -- complementary VBS-backed protection for static/global data
- [Pool Hardening](pool-hardening.md) -- software-level pool protections for the standard pool
- [Pool Overflow](../primitives/arw/pool-overflow.md) -- the attack primitive that Secure Pool is designed to defeat
- [Pool Spray / Feng Shui](../primitives/exploitation/pool-spray-feng-shui.md) -- heap grooming that is ineffective against Secure Pool
- [Token Manipulation](../primitives/arw/token-manipulation.md) -- tokens remain in standard pool, bypassing Secure Pool
- [CVE-2024-30085](../case-studies/CVE-2024-30085.md) -- CLFS pool overflow targeting standard pool objects
