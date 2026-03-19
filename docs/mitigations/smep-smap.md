# SMEP / SMAP

Before 2013, the simplest kernel exploit in the world worked like this: find a function pointer you can overwrite, point it at user-mode memory, put your shellcode there, and wait for the kernel to call it. The shellcode ran at Ring 0 with full kernel privileges. No heap manipulation, no ROP chain, no information leak. Just a single write and a return to user space with SYSTEM.

Supervisor Mode Execution Prevention (SMEP) and Supervisor Mode Access Prevention (SMAP) ended that era. These CPU-enforced mitigations prevent the kernel from executing code in or directly accessing user-mode memory pages, turning the trivial ret2user attack into a hardware fault. Their introduction in Windows 8.1 (SMEP) and Windows 10 RS1 (SMAP) is the single most consequential change in the history of Windows kernel exploitation, forcing a permanent shift from code execution to data-only attack strategies.

## How They Work

Both mitigations are controlled via bits in the CR4 control register and enforced by the CPU's page fault logic in conjunction with page table entry flags.

**SMEP (CR4 bit 20)** triggers a page fault (#PF) if code running at CPL 0 (kernel mode) attempts to fetch and execute instructions from a page whose User/Supervisor (U/S) bit in the page table entry is set to User. This check occurs during the instruction fetch stage and is evaluated against the U/S bit in the final PTE used by the page walk. The result is straightforward: the kernel cannot execute code that resides in user-mode address space, regardless of the page's execute permissions. Intel introduced SMEP with Ivy Bridge in 2012, and AMD added support with Zen. Windows first enforced it in Windows 8.1.

**SMAP (CR4 bit 21)** extends the protection to data access. When enabled, the processor faults if kernel-mode code attempts to read from or write to a User-marked page, unless the EFLAGS.AC (Alignment Check) flag is explicitly set. The kernel uses `STAC` (Set AC Flag) and `CLAC` (Clear AC Flag) instructions to create narrow windows where user-mode access is permitted, such as the `ProbeForRead`/`ProbeForWrite` and `Mm` copy routines that implement controlled user-to-kernel data transfer. The AC flag window is kept as short as possible to minimize the attack surface during legitimate user-mode access. Intel introduced SMAP with Broadwell in 2014, and Windows enabled enforcement starting with Windows 10 RS1 (build 14393).

The enforcement mechanism is based on the U/S bit in the page table hierarchy, not on virtual address ranges. A page is considered "user-mode" if any level of the page table walk has the U/S bit set to User. This distinction matters for bypass analysis: the protection can be circumvented by changing the page table metadata rather than the virtual address.

**CR4 Register Protection** is itself a security concern because clearing CR4 bit 20 or 21 disables the respective protection entirely. On systems without VBS, any Ring 0 code can modify CR4, which is why early SMEP bypasses simply used ROP to execute `mov cr4, <value>`. On VBS-enabled systems, the hypervisor intercepts CR4 writes via VM-exit traps and rejects attempts to clear the SMEP or SMAP bits, adding a second enforcement layer. On kCET-enabled systems (Windows 11 24H2), the ROP chains needed to reach a `mov cr4` gadget are detected by shadow stack validation before they can execute.

Feature detection occurs via CPUID: SMEP support is indicated by CPUID.(EAX=07H, ECX=0):EBX[bit 7], and SMAP by CPUID.(EAX=07H, ECX=0):EBX[bit 20]. The kernel checks these bits during boot and enables CR4 bits accordingly. If the CPU lacks support, the kernel runs without these protections.

## What They Block

SMEP and SMAP together eliminate the entire class of attacks that cross the user/kernel memory boundary for code or data access.

The classic **ret2user attack** is the primary casualty. An attacker who maps shellcode at a user-mode address and redirects a kernel function pointer to it will trigger a page fault the instant the CPU attempts to fetch the first instruction, because SMEP detects the user-mode U/S bit. Even if the attacker can control RIP, execution faults before a single instruction of shellcode runs.

**User-mode fake structure access** is blocked by SMAP. Before SMAP, attackers could overwrite a kernel pointer to reference a forged object (a fake `_TOKEN`, a fake vtable) in user-mode memory. The kernel would dereference the corrupted pointer and operate on attacker-controlled data. With SMAP active, any kernel read from a user-mode page without explicit `STAC` triggers a fault.

**User-mode data staging for kernel callbacks** fails for the same reason. Kernel callbacks that dereference attacker-controlled pointers into user memory will fault under SMAP. This blocks a class of attacks where the attacker sets up a carefully crafted data structure in user space and tricks the kernel into reading it through a corrupted pointer chain.

**Trampoline code in user space** is blocked by SMEP. Techniques that place a short JMP or CALL trampoline in user memory to redirect into kernel shellcode elsewhere are caught at the initial fetch from the user page.

## How Attackers Adapted

The history of SMEP/SMAP bypasses traces the evolution from code execution to data-only exploitation.

**CR4 bit-flip via ROP (2012-2016)** was the first and simplest bypass. Attackers constructed ROP chains using kernel gadgets to overwrite CR4, clearing the SMEP bit. A `mov cr4, <reg>` or `pop <reg>; mov cr4, <reg>` sequence was sufficient. This technique is now blocked on systems with kCFG/kCET (which prevent arbitrary ROP) and VBS/HVCI (which trap CR4 writes at the hypervisor level). It remains viable only on legacy systems without these protections.

**STAC instruction via ROP** targets SMAP specifically. On systems without hardware shadow stacks, an attacker with stack control can ROP to a `STAC` gadget, setting the AC flag and enabling user-mode access. With kCET active on Windows 11 24H2, return address tampering is detected before the `STAC` gadget can execute.

**PTE remapping** is the most durable bypass and remains viable on current systems. With an arbitrary read/write primitive, the attacker locates the PTE for a user-mode page and clears its U/S bit, making the CPU treat it as a supervisor page. This bypasses both SMEP and SMAP entirely because the page is no longer classified as user-mode. The technique requires an ARW primitive and the ability to locate the PTE base address. See [PTE Manipulation](../primitives/arw/pte-manipulation.md).

**Data-only attacks** sidestep SMEP and SMAP completely by never crossing the user/kernel memory boundary. Attacks that modify kernel data structures (token privileges, `PreviousMode`, security descriptors) do not execute attacker code and do not access user-mode pages from kernel context. These mitigations are irrelevant when the exploit operates entirely within kernel address space through an existing read/write primitive. This approach has become dominant in modern exploitation.

**MDL remapping** was a historical bypass where creating a Memory Descriptor List for a user-mode buffer and mapping it into kernel address space with `MmMapLockedPagesSpecifyCache` produced a kernel-mode alias with the U/S bit set to Supervisor. Modern Windows versions have restricted this technique.

**KUSER_SHARED_DATA abuse** provides a limited data staging area. The `KUSER_SHARED_DATA` page at a fixed kernel address (`0xFFFFF78000000000`) is mapped as supervisor-mode readable/writable. Although NX prevents code execution from this page, its fixed address and writable nature make it useful for data-only attacks that need a known writable kernel location.

## The Lasting Impact

SMEP and SMAP fundamentally changed the economics of Windows kernel exploitation. Before these mitigations, kernel exploits were often trivially reliable one-shot attacks where a single corruption led directly to code execution. After their introduction, exploits must take one of three paths, each significantly more complex than the pre-SMEP world.

The first path, constructing ROP/JOP chains within kernel code, is now blocked by kCFG/kCET on modern systems. The second, PTE remapping to create supervisor-mode aliases for user pages, requires an ARW primitive and the ability to locate the PTE base. The third, and now dominant, approach is entirely data-only: manipulating kernel structures without executing attacker code. This is why token manipulation, `PreviousMode` modification, and I/O Ring-based primitives have become the standard endgame for modern kernel exploits. SMEP and SMAP did not make exploitation impossible, but they permanently ended the era of trivial kernel code execution.

## Windows Version Availability

| Version | Status | Notes |
|---------|--------|-------|
| Windows 8.1 | SMEP enabled | First Windows release to enforce SMEP |
| Windows 10 RS1 (1607) | SMEP + SMAP enabled | SMAP enforcement added |
| Windows 10 RS2-21H2 | SMEP + SMAP enabled | No significant changes to enforcement |
| Windows 11 21H2+ | SMEP + SMAP enabled | Combined with kCFG to protect CR4 |
| Windows 11 24H2 | SMEP + SMAP + kCET | Hardware shadow stacks block ROP-based CR4 flip |

All versions require a CPU that supports the respective feature. SMEP requires Ivy Bridge or newer (Intel) / Zen or newer (AMD). SMAP requires Broadwell or newer (Intel) / Zen or newer (AMD). On VBS-enabled systems, the hypervisor provides additional CR4 protection regardless of CPU generation.

## Cross-References

- [PTE Manipulation](../primitives/arw/pte-manipulation.md) -- the primary technique to bypass SMEP/SMAP by remarking user pages as supervisor
- [Token Manipulation](../primitives/arw/token-manipulation.md) -- data-only attack that renders SMEP/SMAP irrelevant
- [MDL Mapping](../primitives/arw/mdl-mapping.md) -- historical SMEP/SMAP bypass via kernel-mode memory aliasing
- [kCFG / kCET](kcfg-kcet.md) -- prevents ROP-based CR4 modification
- [VBS / HVCI](vbs-hvci.md) -- hypervisor-level CR4 protection
- [CVE-2024-30088](../case-studies/CVE-2024-30088.md) -- race condition exploit where SMEP/SMAP forces data-only approach
- [CVE-2024-21338](../case-studies/CVE-2024-21338.md) -- appid.sys exploit using data-only strategy due to SMEP/SMAP
- [Previous Mode Manipulation](../primitives/exploitation/previous-mode-manipulation.md) -- data-only technique unaffected by SMEP/SMAP
