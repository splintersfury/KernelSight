# kCFG / kCET

Overwriting a function pointer used to be the most reliable step in a kernel exploit chain. Find a vtable, a callback registration, or a dispatch table entry, replace the target address with one you control, and wait for the kernel to call it. Kernel Control Flow Guard (kCFG) made this harder by validating indirect call targets against a compiler-generated bitmap. Kernel Control-flow Enforcement Technology (kCET) made it harder still by using hardware shadow stacks to detect return address corruption. Together, they cover both directions of control flow: kCFG protects forward edges (indirect calls and jumps) while kCET protects backward edges (return instructions).

The practical effect on exploitation has been decisive. Before kCFG, a single function pointer overwrite was often enough to hijack kernel execution. After kCFG, exploits must find a useful CFG-valid target or avoid control flow hijacking entirely. With kCET added in Windows 11 24H2, the ROP/JOP fallback is eliminated too. The result is that modern kernel exploits on fully updated systems have abandoned control flow hijacking altogether, converging on data-only techniques like token swapping and `PreviousMode` manipulation.

## How They Work

**kCFG (Kernel Control Flow Guard)** is a software-based forward-edge control flow integrity mechanism introduced in Windows 10 RS1 (build 14393). At compile time, the MSVC compiler generates a bitmap of all valid indirect call targets, which are the addresses of functions whose address is taken somewhere in the program. Before each indirect call, the compiler inserts a call to `_guard_dispatch_icall`, which checks the target address against the bitmap. If the target is not a valid function entry point, the system bugchecks with `KERNEL_SECURITY_CHECK_FAILURE` (code 0x139).

The bitmap is stored in a protected region and validated during driver loading by Code Integrity. kCFG covers `ntoskrnl.exe`, `hal.dll`, and all drivers compiled with the `/guard:cf` flag. The validation granularity is 8 bytes, aligned to function entry points, meaning every 8-byte-aligned address is either valid or invalid in the bitmap.

**kCET (Kernel Control-flow Enforcement Technology)** is a hardware-based backward-edge protection that Microsoft enabled in Windows 11 24H2, making it the first Windows release to ship with hardware shadow stacks active in the kernel. The mechanism uses a secondary stack (pointed to by the SSP register) that stores copies of return addresses. When a `CALL` instruction executes, the return address is pushed onto both the regular stack and the shadow stack. When a `RET` instruction executes, the CPU compares the return address from both stacks. A mismatch triggers a #CP (Control Protection) exception, which Windows handles as a bugcheck.

The shadow stack pages are marked with a special page table attribute and can only be written by `CALL`, `WRSSD`, and `WRSS` instructions, not by normal `MOV` or `PUSH` instructions. This means an attacker with an arbitrary write primitive can corrupt the regular stack but cannot forge corresponding entries on the shadow stack. Shadow stack memory is managed by the kernel and protected from arbitrary writes through a dedicated page table attribute.

kCET also uses the `ENDBRANCH` (`ENDBR64`) instruction as an indirect branch tracking mechanism: indirect `JMP` and `CALL` targets must begin with `ENDBR64` or a #CP exception is raised. This complements kCFG's bitmap check by adding hardware enforcement to forward-edge validation.

## What They Block

The two mechanisms together eliminate the three main categories of control flow hijacking in kernel exploitation.

**ROP chains** are the primary target of kCET. Return-oriented programming relies on corrupting return addresses to chain gadgets. The shadow stack detects this tampering at the first `RET` instruction, long before the chain can accomplish anything useful. **Stack pivot attacks** fail for a related reason: pivoting RSP to attacker-controlled memory causes a shadow stack mismatch on the next `RET`, because the SSP is independent of RSP and cannot be redirected via normal memory writes.

**JOP and indirect call hijacking** are blocked by kCFG. Overwriting a function pointer in a vtable or callback table succeeds at the memory level but fails the bitmap validation check when the corrupted pointer is dispatched. The CR4 modification bypass for SMEP (a `mov cr4, <reg>` gadget reached via ROP) is now doubly blocked: kCET catches the ROP chain, and kCFG validates any indirect call targets along the way.

**Callback overwrites, interrupt handler replacement, and vtable corruption** all fail validation when the corrupted pointer targets an address outside the valid function bitmap. Even C++ virtual function table pointer overwrites, where the attacker replaces a vtable with a fake one pointing to arbitrary gadgets, are caught because each dispatched call is validated.

## How Attackers Work Around Them

Despite the comprehensive coverage, several bypass strategies remain viable.

**CFG-valid gadgets** represent the most important ongoing limitation of kCFG. The bitmap validation only checks whether a target is a legitimate function entry point, not whether it is the intended target for that specific call site. An indirect call can be redirected to any valid function in the bitmap, even if it was never meant to be called from that location. Functions like `NtWriteVirtualMemory`, system call stubs, and utility routines like `RtlSetBit` and `RtlClearAllBits` are all valid targets. This is sometimes called "CFG-aware exploitation." [CVE-2026-21241](../case-studies/CVE-2026-21241.md) demonstrates this technique by redirecting a controlled callback to `RtlSetBit` and `RtlClearAllBits`, both of which pass kCFG validation. The [bit-manipulation primitive](../primitives/exploitation/bit-manipulation.md) built from these calls is fully kCFG-compliant.

**Data-only attacks** bypass both kCFG and kCET completely by never hijacking control flow at all. Token swapping, `PreviousMode` manipulation, and ACL/SD modification require no indirect call corruption and no return address tampering. This is the dominant reason modern kernel exploits have shifted away from code-reuse techniques. Every CVE in the 2024-2026 portion of the corpus that was exploited in the wild used a data-only post-exploitation strategy.

**Unprotected callbacks** in certain kernel paths (exception dispatch, APC user-mode callbacks, I/O completion routines) may not be fully covered by kCFG validation. Microsoft has been progressively closing these gaps with each release, but coverage is not yet complete.

**Third-party driver gaps** are another ongoing concern. Drivers not compiled with `/guard:cf` have unprotected indirect call sites. An attacker who can hijack control flow within such a driver is not subject to kCFG checks at those call sites. This is a driver-quality problem rather than a kCFG design flaw, but it creates real gaps in the defense.

**kCET hardware shadow stack (24H2, very new)** has no public bypasses as of early 2026. The attack surface is limited because shadow stack writes require special instructions that cannot be executed via normal memory writes. Research into shadow stack attacks is ongoing, but the hardware enforcement is fundamentally different from software protections and is expected to be significantly harder to defeat.

## Windows Version Availability

| Version | Status | Notes |
|---------|--------|-------|
| Windows 10 RS1 (1607) | kCFG introduced | Forward-edge CFI for kernel indirect calls |
| Windows 10 RS2-21H2 | kCFG active | Progressive coverage improvements |
| Windows 11 21H2-23H2 | kCFG active | Extended to more kernel components |
| Windows 11 24H2 | kCFG + kCET active | Hardware shadow stacks enabled in kernel |

kCFG requires drivers to be compiled with `/guard:cf`. Third-party drivers without this flag have unprotected indirect calls. kCET requires a CPU with Intel CET (11th Gen Tiger Lake or newer) or AMD Shadow Stack (Zen 3 or newer) support. Both features are enforced independently: kCFG works on any CPU, while kCET requires hardware support.

## The Data-Only Future

kCFG and kCET, combined with SMEP/SMAP and HVCI, have systematically closed every code execution and code-reuse path in modern Windows kernel exploitation. The trajectory visible in the corpus is clear: CVE-2024-21338 (appid.sys, Lazarus Group), CVE-2024-30088 (ntoskrnl TOCTOU), and CVE-2024-38106 (ntoskrnl race condition) all use data-only post-exploitation. None attempt shellcode, ROP chains, or function pointer hijacking.

The remaining attack surface is data: tokens, process objects, security descriptors, feature flags, and the kernel structures that enforce access control. kCFG and kCET do not protect data. Until mitigations like [KDP](kdp.md) and [Secure Pool](secure-pool.md) expand their coverage to encompass the structures that data-only attacks target, the shift from control flow hijacking to data manipulation will continue to define the state of the art.

## Cross-References

- [SMEP / SMAP](smep-smap.md) -- kCET blocks the ROP-based CR4 flip that was used to bypass SMEP
- [Token Swapping](../primitives/exploitation/token-swapping.md) -- data-only bypass unaffected by kCFG/kCET
- [Previous Mode Manipulation](../primitives/exploitation/previous-mode-manipulation.md) -- data-only bypass unaffected by kCFG/kCET
- [I/O Ring](../primitives/exploitation/io-ring.md) -- data-only exploitation primitive that sidesteps CFI
- [VBS / HVCI](vbs-hvci.md) -- complementary mitigation that enforces W^X alongside CFI
- [CVE-2024-21338](../case-studies/CVE-2024-21338.md) -- appid.sys exploit that used a controlled kernel callback
- [CVE-2024-30085](../case-studies/CVE-2024-30085.md) -- pool overflow exploit where kCFG forces data-only strategies
