# Secure Pool

Standard pool hardening raises the cost of heap exploitation through software checks: cookies, safe unlinking, randomized layout. Every one of these checks can be bypassed with a sufficient information disclosure primitive or enough spray iterations. Secure Pool takes a different approach entirely. By placing critical allocations in VBS-protected memory with hypervisor-enforced guard pages and metadata stored in VTL 1, it creates a pool region where the fundamental exploitation techniques (overflow into adjacent objects, header corruption, use-after-free reclamation) are blocked at the hardware level rather than detected by software.

Microsoft introduced the Secure Pool in Windows 10 21H2 (build 19044) as a specialized allocator that uses VBS infrastructure to provide guarantees that no software-level hardening can match. It represents the strongest form of heap protection available in Windows, but its effectiveness is constrained by the same factor that limits [KDP](kdp.md): adoption. Only a small fraction of kernel objects currently reside in Secure Pool.

## How It Works

**Allocation API.** Kernel components allocate from the Secure Pool using `ExAllocatePool3` with the `POOL_FLAG_USE_SECURE_POOL` flag or through `ExSecurePoolAlloc`. The allocation request is forwarded to the Secure Kernel (VTL 1), which manages the Secure Pool independently of the standard VTL 0 pool allocator. The caller receives a pointer to memory that is accessible from VTL 0 for normal read/write operations, but the surrounding metadata and guard regions are invisible to VTL 0.

**Hypervisor-enforced isolation** is the core property. Secure Pool memory pages are controlled by VTL 1 EPT/NPT entries. The Secure Kernel configures SLAT permissions so that VTL 0 can read and write the allocation contents (as needed by the kernel during normal operation), but cannot access adjacent metadata or guard regions. Guard pages with no VTL 0 read/write permission are placed between individual Secure Pool allocations. Any overflow or underflow from one allocation triggers a hypervisor-level page fault before reaching adjacent allocations, regardless of the overflow size or direction.

**Metadata protection** eliminates the entire class of pool header attacks. Pool metadata (chunk headers, free lists, allocation tracking) is stored entirely in VTL 1 address space. VTL 0 code, even with a full arbitrary read/write primitive, cannot access or modify Secure Pool metadata because it resides in a different Virtual Trust Level. Cookie leakage, header forging, and free-list corruption are all impossible because the data they target does not exist in VTL 0 memory.

**Free operation protection** addresses use-after-free and type confusion. When a Secure Pool allocation is freed, the Secure Kernel validates the request through VTL 1 and can immediately unmap the freed pages from VTL 0. Any use-after-free access triggers a fault rather than succeeding silently. Double-free is detected at the hypervisor level. Type confusion attacks where an attacker frees an object and reclaims the memory with a different object type are prevented because the Secure Kernel tracks allocation state independently of VTL 0 data structures and can enforce type-safe reallocation.

## What Secure Pool Blocks

The protections are comprehensive for objects that reside in Secure Pool. **Pool overflow into adjacent allocations** is blocked by hypervisor-enforced guard pages. **Pool header manipulation** is impossible because headers do not exist in VTL 0 memory. **Pool spray targeting Secure Pool objects** is ineffective because the Secure Kernel controls allocation placement independently of the standard VTL 0 allocator. **Use-after-free** is converted into an immediate fault by revoking VTL 0 access to freed pages via EPT. **Type confusion via pool reuse** is prevented by Secure Kernel tracking of allocation types.

## The Adoption Gap

Secure Pool shares the same fundamental limitation as KDP: it only protects objects that explicitly opt in.

**Very few kernel objects currently use Secure Pool.** The vast majority of kernel allocations, including `_TOKEN`, `_EPROCESS`, `_OBJECT_HEADER`, and driver-specific objects, remain in the standard kernel pool. Every data-only exploit in the corpus targets these unprotected objects. Until Secure Pool adoption reaches the structures that attackers actually target, the mitigation covers only a narrow subset of the kernel attack surface.

**VTL 0 access is still permitted for allocation contents.** The kernel needs to read and write Secure Pool allocations during normal operation. An attacker with an arbitrary read/write primitive who knows a Secure Pool allocation's address can still read and modify its contents. The protection prevents adjacent corruption and metadata manipulation, but if the attacker can directly target a specific Secure Pool object's data, Secure Pool does not prevent that modification. The isolation is spatial (preventing overflow from neighboring objects) rather than access-control-based (preventing all unauthorized writes to the object itself).

**VBS dependency** means that on systems where VBS is not enabled or has been disabled, Secure Pool APIs may succeed but without hypervisor-backed enforcement. The allocations fall back to standard pool semantics with no additional security benefit.

**Interaction with standard pool objects** creates indirect attack paths. Secure Pool objects often contain pointers to standard pool objects and vice versa. An attacker can corrupt the standard pool object that a Secure Pool object references, achieving an indirect attack that bypasses the Secure Pool's spatial isolation.

## Windows Version Availability

| Version | Status | Notes |
|---------|--------|-------|
| Windows 10 21H2 | Introduced | Initial Secure Pool implementation |
| Windows 11 21H2 | Available | Expanded API support, additional opt-in components |
| Windows 11 22H2 | Available | Additional kernel components opted in |
| Windows 11 23H2 | Available | Incremental adoption growth |
| Windows 11 24H2 | Available | Continued expansion of protected object types |

Requires VBS to be enabled and active. Without VBS, Secure Pool provides no additional protection over the standard pool. The feature has no performance impact on non-Secure-Pool allocations.

## Where Secure Pool Matters Most

Secure Pool's real-world impact depends entirely on which objects move into it. Currently, exploits can simply choose targets that are not in the Secure Pool. As Microsoft migrates more objects (tokens, security descriptors, process objects), pool overflow and use-after-free exploitation will become harder. The long-term vision is that all security-sensitive kernel allocations reside in Secure Pool, reducing pool corruption from a privilege escalation vector to a denial-of-service outcome.

For researchers, this creates a practical concern: newer kernel objects may be unexpectedly resistant to pool-based techniques. Before pursuing a pool corruption strategy against a specific object type, verify whether that type uses Secure Pool on the target build. The shift can happen silently between Windows versions as Microsoft moves objects into the protected allocator.

The combination of Secure Pool for heap objects and [KDP](kdp.md) for static/global data represents Microsoft's long-term strategy for hardening the data plane against data-only attacks. Neither is complete yet, but both are expanding with each release, and the trajectory suggests that the most critical kernel structures will eventually be protected from the write primitives that current exploits depend on.

## Cross-References

- [VBS / HVCI](vbs-hvci.md) -- Secure Pool requires the VBS infrastructure for hypervisor enforcement
- [Kernel Data Protection (KDP)](kdp.md) -- complementary VBS-backed protection for static/global data
- [Pool Hardening](pool-hardening.md) -- software-level pool protections for the standard pool
- [Pool Overflow](../primitives/arw/pool-overflow.md) -- the attack primitive that Secure Pool is designed to defeat
- [Pool Spray / Feng Shui](../primitives/exploitation/pool-spray-feng-shui.md) -- heap grooming that is ineffective against Secure Pool
- [Token Manipulation](../primitives/arw/token-manipulation.md) -- tokens remain in standard pool, bypassing Secure Pool
- [CVE-2024-30085](../case-studies/CVE-2024-30085.md) -- CLFS pool overflow targeting standard pool objects
