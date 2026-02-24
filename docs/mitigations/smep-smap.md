# SMEP / SMAP

Supervisor Mode Execution Prevention (SMEP) and Supervisor Mode Access Prevention (SMAP) are CPU-enforced mitigations that prevent the kernel from executing code in or directly accessing user-mode memory pages.

## Overview

SMEP and SMAP are hardware mitigations implemented at the CPU level to enforce strict separation between supervisor (ring-0) and user (ring-3) memory access. Intel introduced SMEP with the Ivy Bridge microarchitecture in 2012 and SMAP with Broadwell in 2014. AMD added support for both in their Zen architecture. On the Windows side, Microsoft enabled SMEP enforcement starting with Windows 8.1 and SMAP enforcement starting with Windows 10 RS1 (Anniversary Update, build 14393). Both features are controlled via bits in the CR4 control register and are enforced by the CPU's page fault logic in conjunction with page table entry flags.

Before these mitigations, a common kernel exploitation technique was "ret2user" -- corrupting a kernel function pointer to redirect execution to attacker-controlled shellcode mapped in user-mode memory. SMEP and SMAP blocked this by introducing hardware-level enforcement of the user/kernel boundary.

SMEP and SMAP eliminated an entire class of trivially reliable exploitation techniques. Before SMEP, kernel exploits could allocate executable memory in user space, write shellcode, and redirect a kernel function pointer to it. The exploit was deterministic and required no heap manipulation, no ROP chain, and no information disclosure. SMAP extended this to data references, closing the follow-up technique of placing fake kernel structures in user-mode memory.

## Mechanism

**SMEP (CR4 bit 20):** When enabled, the processor generates a page fault (#PF) if code running at CPL 0 (kernel mode) attempts to fetch and execute instructions from a page whose User/Supervisor (U/S) bit in the page table entry is set to User. This means the kernel cannot execute code that resides in user-mode address space, regardless of the page's execute permissions. The SMEP check occurs during the instruction fetch stage and is evaluated against the U/S bit in the final page table entry (PTE) used by the page walk.

**SMAP (CR4 bit 21):** When enabled, the processor generates a page fault if code running at CPL 0 attempts to read from or write to a page marked as User in the page table entries, unless the EFLAGS.AC (Alignment Check) flag is explicitly set. The kernel uses the `STAC` (Set AC Flag) and `CLAC` (Clear AC Flag) instructions to temporarily enable and disable user-mode access in controlled code paths such as `copy_from_user` equivalents (e.g., `ProbeForRead`/`ProbeForWrite` and the `Mm` copy routines). The AC flag window is kept as narrow as possible to minimize the attack surface during legitimate user-mode access.

The enforcement depends on the U/S bit in the page table hierarchy. A page is considered "user-mode" if any level of the page table walk has the U/S bit set to User. This means the protection is based on page table metadata, not on virtual address ranges.

**CR4 Register Protection:**

- The SMEP and SMAP bits in CR4 are themselves a target for attackers. Clearing CR4 bit 20 or 21 disables the respective protection entirely.
- On systems without VBS, CR4 can be modified by any code running in ring 0, which is why early SMEP bypasses simply used ROP to execute `mov cr4, <value>`.
- On systems with VBS enabled, the hypervisor intercepts CR4 writes via VM-exit traps. The hypervisor validates the new CR4 value and rejects attempts to clear the SMEP or SMAP bits, adding a second layer of enforcement.
- On kCET-enabled systems (Win 11 24H2), ROP chains that would reach a `mov cr4` gadget are detected by shadow stack validation before they can execute.

## Primitives Blocked

- **Direct shellcode execution in user memory (SMEP):** The classic ret2user attack, where the attacker maps shellcode at a user-mode address and redirects a kernel function pointer to it, is blocked because execution from user pages triggers a page fault.
- **User-mode fake structure access (SMAP):** Attacks that overwrite a kernel pointer to reference a fake object in user-mode memory (e.g., a forged `_TOKEN` structure) are blocked because the kernel cannot read from user pages without explicit `STAC`.
- **User-mode data staging for kernel callbacks (SMAP):** Kernel callbacks that dereference attacker-controlled pointers into user memory will fault if SMAP is active.
- **Ret2user with mapped shellcode (SMEP):** Even if the attacker can control RIP, execution will fault when the CPU attempts to fetch instructions from the user-mode page.
- **User-mode trampoline code (SMEP):** Techniques that place a short JMP or CALL trampoline in user space to redirect to kernel shellcode are blocked at the initial execution attempt.

## Bypass History

- **CR4 bit-flip via ROP (2012-2016):** Early bypasses used ROP chains to overwrite CR4, clearing the SMEP bit. The gadget `mov cr4, <reg>` or `pop <reg>; mov cr4, <reg>` was sufficient. This technique is now blocked on systems with kCFG/kCET and HVCI, which prevent arbitrary ROP and protect CR4 writes.
- **STAC instruction via ROP (ongoing without kCET):** On systems without hardware shadow stacks, an attacker with stack control can ROP to a `STAC` gadget, enabling user-mode access under SMAP. With kCET (Win 11 24H2+), return address tampering is detected.
- **PTE remapping (ongoing):** With an arbitrary read/write primitive, the attacker can locate the PTE for a user-mode page and clear its U/S bit, making the CPU treat it as a supervisor page. This bypasses both SMEP and SMAP entirely because the page is no longer classified as user-mode. This remains viable as long as the attacker has an ARW primitive and can locate the PTE base.
- **Data-only attacks (always viable):** Attacks that modify kernel data structures (e.g., token privilege manipulation, `PreviousMode` modification) without redirecting code execution are unaffected by SMEP and SMAP. These mitigations are irrelevant when the exploit does not cross the user/kernel memory boundary for code or data access.
- **MDL remapping (historical):** Creating an MDL (Memory Descriptor List) for a user-mode buffer and mapping it into kernel address space with `MmMapLockedPagesSpecifyCache` created a kernel-mode alias for user pages. This alias had the U/S bit set to Supervisor, bypassing SMEP/SMAP. Modern Windows versions have restricted this technique.
- **KUSER_SHARED_DATA abuse (limited, ongoing):** The `KUSER_SHARED_DATA` page at a fixed kernel address (`0xFFFFF78000000000`) is mapped as supervisor-mode readable/writable. Although this page cannot contain executable code (it is NX), its fixed address and writable nature make it useful as a data staging area in some data-only attacks, sidestepping SMAP entirely since the page is already in kernel space.

## Windows Version Availability

| Version | Status | Notes |
|---------|--------|-------|
| Windows 8.1 | SMEP enabled | First Windows release to enforce SMEP |
| Windows 10 RS1 (1607) | SMEP + SMAP enabled | SMAP enforcement added |
| Windows 10 RS2-21H2 | SMEP + SMAP enabled | No significant changes to enforcement |
| Windows 11 21H2+ | SMEP + SMAP enabled | Combined with kCFG to protect CR4 |
| Windows 11 24H2 | SMEP + SMAP + kCET | Hardware shadow stacks block ROP-based CR4 flip |

All versions require a CPU that supports the respective feature (CPUID check). SMEP requires Ivy Bridge or newer (Intel) / Zen or newer (AMD). SMAP requires Broadwell or newer (Intel) / Zen or newer (AMD). On VBS-enabled systems, the hypervisor provides additional CR4 protection regardless of CPU generation.

Feature detection is performed via CPUID: SMEP support is indicated by CPUID.(EAX=07H, ECX=0):EBX[bit 7], and SMAP support by CPUID.(EAX=07H, ECX=0):EBX[bit 20]. The Windows kernel checks these bits during boot and enables the CR4 bits accordingly. If the CPU does not support SMEP or SMAP, the kernel continues without these protections.

## Impact on Exploit Development

SMEP and SMAP changed the landscape of Windows kernel exploitation. Before these mitigations, kernel exploits were often trivially reliable one-shot attacks. After their introduction, exploits must either:

1. Construct ROP/JOP chains within kernel code to achieve code execution (blocked by kCFG/kCET on modern systems)
2. Use PTE remapping to create supervisor-mode aliases for user pages (requires ARW + PTE base leak)
3. Adopt entirely data-only strategies that manipulate kernel structures without executing attacker code

The third approach has become dominant in modern exploitation, driving the industry toward token manipulation, `PreviousMode` modification, and I/O Ring-based primitives.

## Cross-References

- [PTE Manipulation](../primitives/arw/pte-manipulation.md) -- the primary technique to bypass SMEP/SMAP by remarking user pages as supervisor
- [Token Manipulation](../primitives/arw/token-manipulation.md) -- data-only attack that renders SMEP/SMAP irrelevant
- [MDL Mapping](../primitives/arw/mdl-mapping.md) -- historical SMEP/SMAP bypass via kernel-mode memory aliasing
- [kCFG / kCET](kcfg-kcet.md) -- prevents ROP-based CR4 modification
- [VBS / HVCI](vbs-hvci.md) -- hypervisor-level CR4 protection
- [CVE-2024-30088](../case-studies/CVE-2024-30088.md) -- race condition exploit where SMEP/SMAP forces data-only approach
- [CVE-2024-21338](../case-studies/CVE-2024-21338.md) -- appid.sys exploit using data-only strategy due to SMEP/SMAP
- [Previous Mode Manipulation](../primitives/exploitation/previous-mode-manipulation.md) -- data-only technique unaffected by SMEP/SMAP
