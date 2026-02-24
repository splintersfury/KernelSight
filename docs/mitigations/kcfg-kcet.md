# kCFG / kCET

Kernel Control Flow Guard (kCFG) and kernel Control-flow Enforcement Technology (kCET) enforce control flow integrity for indirect calls and return instructions in the Windows kernel.

## Overview

kCFG is a software-based forward-edge control flow integrity mechanism introduced in Windows 10 RS1 (Anniversary Update, build 14393). It validates that indirect call targets are legitimate function entry points by checking them against a compiler-generated bitmap. kCET is a hardware-based backward-edge protection that leverages Intel Control-flow Enforcement Technology (CET) or AMD Shadow Stack to protect return addresses. Microsoft enabled kCET enforcement in Windows 11 24H2, making it the first Windows release to ship with hardware shadow stacks active in the kernel.

Together, kCFG and kCET cover both directions of control flow: kCFG protects forward edges (indirect calls and jumps) while kCET protects backward edges (return instructions). This makes traditional ROP and JOP chains much harder to execute. The shift from code-reuse attacks to data-only attacks in modern Windows kernel exploitation is largely driven by these two mitigations.

## Mechanism

**kCFG (Kernel Control Flow Guard):**

- At compile time, the MSVC compiler generates a bitmap of all valid indirect call targets (functions whose address is taken).
- Before each indirect call, the compiler inserts a call to `_guard_dispatch_icall`, which checks the target address against the bitmap.
- If the target is not a valid function entry point, the system bugchecks with `KERNEL_SECURITY_CHECK_FAILURE` (code 0x139).
- The bitmap is stored in a protected region and validated during driver loading by Code Integrity.
- kCFG covers `ntoskrnl.exe`, `hal.dll`, and all drivers compiled with `/guard:cf`.
- The validation granularity is 8 bytes (aligned to function entry points), meaning every 8-byte-aligned address is either valid or invalid.

**kCET (Kernel Control-flow Enforcement Technology):**

- Uses the CPU's Shadow Stack mechanism: a secondary stack (pointed to by the SSP register) that stores copies of return addresses.
- When a `CALL` instruction executes, the return address is pushed onto both the regular stack and the shadow stack.
- When a `RET` instruction executes, the CPU compares the return address on the regular stack with the shadow stack copy. A mismatch triggers a #CP (Control Protection) exception, which Windows handles as a bugcheck.
- The shadow stack pages are marked with a special page table attribute and can only be written by `CALL`/`WRSSD`/`WRSS` instructions, not by normal `MOV` or `PUSH` instructions.
- Shadow stack memory is managed by the kernel and protected from arbitrary writes through a dedicated page table attribute.
- Additionally, kCET uses the `ENDBRANCH` (`ENDBR64`) instruction as an indirect branch tracking mechanism: indirect `JMP` and `CALL` targets must begin with `ENDBR64` or a #CP exception is raised.

## Primitives Blocked

- **ROP chains (kCET):** Return-oriented programming relies on corrupting return addresses to chain gadgets. The shadow stack detects return address tampering at the first `RET` instruction, making ROP chains unviable on kCET-enabled systems.
- **Stack pivot attacks (kCET):** Pivoting the stack pointer to attacker-controlled memory causes shadow stack mismatch on the next `RET`, because the shadow stack pointer (SSP) is independent of RSP and cannot be redirected via normal memory writes.
- **JOP / indirect call hijacking (kCFG):** Overwriting an indirect call target (e.g., a function pointer in a vtable or callback table) fails validation unless the target is in the valid function bitmap.
- **CR4 modification via ROP (kCET):** The classic SMEP bypass of ROP-chaining to `mov cr4, <reg>` is blocked because the ROP chain itself is detected by kCET at the first return.
- **Callback overwrites to arbitrary addresses (kCFG):** Replacing a kernel callback pointer with an arbitrary address fails the bitmap check on dispatch.
- **Interrupt handler replacement (kCFG/kCET):** Modifying IDT entries or ISR pointers is detected by kCFG validation, and any ROP-based setup is caught by kCET.
- **Arbitrary code execution via vtable corruption (kCFG):** C++ virtual function table pointer overwrites, where the attacker replaces a vtable with a fake one pointing to arbitrary gadgets, are caught because each dispatched call is validated against the bitmap.

## Bypass History

- **CFG-valid gadgets (ongoing):** kCFG only validates that a target is a legitimate function entry point. An indirect call can be redirected to any valid function, even if it was not the intended target. Functions like `NtWriteVirtualMemory` or system call stubs are all valid targets. This is sometimes called "CFG-aware exploitation" -- it narrows the usable gadget set but does not eliminate it.
- **Data-only attacks (always viable):** Attacks that modify data structures without hijacking control flow are completely unaffected by both kCFG and kCET. Token swapping, `PreviousMode` manipulation, and ACL/SD modification require no indirect call corruption. This is the primary reason modern kernel exploits have shifted to data-only techniques.
- **Unprotected callbacks (ongoing, shrinking):** Some kernel callback mechanisms (e.g., certain exception dispatch paths, APC user-mode callbacks, I/O completion routines) may not be fully covered by kCFG validation. Microsoft has been progressively closing these gaps with each Windows release.
- **Third-party driver gaps (ongoing):** Drivers not compiled with `/guard:cf` have unprotected indirect call sites. An attacker who can hijack control flow within such a driver is not subject to kCFG checks at those call sites.
- **kCET hardware shadow stack (24H2, very new):** As of early 2026, no public bypasses exist for the hardware shadow stack enforcement in Windows 11 24H2. The attack surface is limited because shadow stack writes require special instructions that cannot be executed via normal memory writes.
- **Exception handler abuse (historical, partially mitigated):** Structured Exception Handling (SEH) and Vectored Exception Handling (VEH) handler overwrites were historically used to hijack control flow. Kernel-mode SEH is now protected by SafeSEH and kCFG validation of handler addresses. Some exception dispatch paths remain less protected than standard indirect calls.
- **Counterfeit Object-Oriented Programming (COOP, theoretical):** An academic technique that chains calls to legitimate virtual methods of different objects to achieve Turing-complete computation. While theoretically applicable to kCFG (since all targets are valid functions), no practical kernel COOP exploits have been demonstrated.

## Windows Version Availability

| Version | Status | Notes |
|---------|--------|-------|
| Windows 10 RS1 (1607) | kCFG introduced | Forward-edge CFI for kernel indirect calls |
| Windows 10 RS2-21H2 | kCFG active | Progressive coverage improvements |
| Windows 11 21H2-23H2 | kCFG active | Extended to more kernel components |
| Windows 11 24H2 | kCFG + kCET active | Hardware shadow stacks enabled in kernel |

kCFG requires drivers to be compiled with `/guard:cf`. Third-party drivers without this flag have unprotected indirect calls. kCET requires a CPU with Intel CET (11th Gen Tiger Lake or newer) or AMD Shadow Stack (Zen 3 or newer) support. Both features are enforced independently: kCFG works on any CPU, while kCET requires hardware support.

## Impact on Exploit Development

kCFG and kCET together have shifted kernel exploitation strategy. Before kCFG, a single function pointer overwrite was often enough to hijack kernel execution. After kCFG, exploits must either find a useful CFG-valid target function or avoid control flow hijacking entirely. With kCET added in 24H2, the ROP/JOP fallback is also eliminated, leaving data-only attacks as the primary viable strategy on fully updated systems.

Recent kernel exploits (CVE-2024-21338, CVE-2024-30088, CVE-2024-38106) all use data-only post-exploitation rather than shellcode or ROP chains. The combination of kCFG, kCET, SMEP, SMAP, and HVCI has made code execution-based exploitation prohibitively difficult on Windows 11 24H2 systems with hardware support.

## Cross-References

- [SMEP / SMAP](smep-smap.md) -- kCET blocks the ROP-based CR4 flip that was used to bypass SMEP
- [Token Swapping](../primitives/exploitation/token-swapping.md) -- data-only bypass unaffected by kCFG/kCET
- [Previous Mode Manipulation](../primitives/exploitation/previous-mode-manipulation.md) -- data-only bypass unaffected by kCFG/kCET
- [I/O Ring](../primitives/exploitation/io-ring.md) -- data-only exploitation primitive that sidesteps CFI
- [VBS / HVCI](vbs-hvci.md) -- complementary mitigation that enforces W^X alongside CFI
- [CVE-2024-21338](../case-studies/CVE-2024-21338.md) -- appid.sys exploit that used a controlled kernel callback
- [CVE-2024-30085](../case-studies/CVE-2024-30085.md) -- pool overflow exploit where kCFG forces data-only strategies
