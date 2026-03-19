---
description: "Windows kernel exploit mitigations -- SMEP, SMAP, kCFG, kCET, VBS, HVCI, KDP, pool hardening, Secure Pool, ACG, and KASLR. How each defence works and what bypasses exist."
---

# Mitigations

<div class="ks-pipeline-pos">
  Driver Type &rarr; Attack Surface &rarr; Vuln Class &rarr; Primitive &rarr; Case Study &nbsp;|&nbsp; <span class="ks-active">Mitigations</span>
</div>

A kernel vulnerability gives an attacker a single corruption. Turning that corruption into SYSTEM requires a chain of steps: leaking addresses, shaping memory, constructing read/write primitives, and finally modifying a privilege token or security descriptor. Mitigations work by breaking links in that chain. No single defense stops exploitation on its own. Instead, they compose into a defense-in-depth stack where each layer forces the attacker to solve an additional problem, and each additional problem demands another primitive that may not be available from the original bug.

This philosophy is visible in the corpus. CVE-2024-21338 (appid.sys) gave Lazarus Group a controlled kernel callback, but SMEP blocked the obvious step of jumping to user-mode shellcode, kCFG constrained which functions the callback could target, and KASLR meant the callback address had to be leaked first. The exploit worked because it found data-only paths around every layer. But remove any one of those constraints from the attacker's burden and the chain becomes simpler, faster, more reliable. Defense-in-depth does not prevent exploitation; it taxes it.

The stack is ordered by bypass difficulty. Hardware mitigations at the bottom are relatively straightforward to work around if the attacker already holds a write primitive. VBS-backed protections at the top require defeating the hypervisor, something no public exploit has accomplished through direct assault.

<div class="ks-figure" markdown>
  <span class="ks-figure-label">FIG_006 -- Defense-in-Depth Stack</span>
  <svg viewBox="0 0 820 320" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Defense-in-depth stack from hardware at bottom to VBS at top">
    <!-- Stack bars - bottom to top -->
    <!-- HW Layer -->
    <rect class="ks-box" x="40" y="270" width="740" height="36"/>
    <text class="ks-label" x="100" y="293" text-anchor="start" fill="currentColor">HARDWARE</text>
    <text class="ks-annotation" x="740" y="293" text-anchor="end">NX bit, SMEP, SMAP, CET shadow stack</text>
    <!-- Pool hardening -->
    <rect class="ks-box" x="40" y="224" width="740" height="36"/>
    <text class="ks-label" x="100" y="247" text-anchor="start" fill="currentColor">POOL HARDENING</text>
    <text class="ks-annotation" x="740" y="247" text-anchor="end">Segment heap, pool cookies, NX pool, safe unlinking</text>
    <!-- KASLR -->
    <rect class="ks-box" x="40" y="178" width="740" height="36"/>
    <text class="ks-label" x="100" y="201" text-anchor="start" fill="currentColor">KASLR</text>
    <text class="ks-annotation" x="740" y="201" text-anchor="end">Kernel base randomization, high-entropy ASLR</text>
    <!-- CFI -->
    <rect class="ks-box" x="40" y="132" width="740" height="36"/>
    <text class="ks-label" x="100" y="155" text-anchor="start" fill="currentColor">kCFG / kCET</text>
    <text class="ks-annotation" x="740" y="155" text-anchor="end">Forward-edge CFG, backward-edge CET shadow stack</text>
    <!-- ACG -->
    <rect class="ks-box" x="40" y="86" width="740" height="36"/>
    <text class="ks-label" x="100" y="109" text-anchor="start" fill="currentColor">ACG</text>
    <text class="ks-annotation" x="740" y="109" text-anchor="end">Arbitrary Code Guard, W^X enforcement</text>
    <!-- VBS / HVCI / KDP / Secure Pool -->
    <rect class="ks-box" x="40" y="20" width="740" height="56"/>
    <text class="ks-label" x="100" y="43" text-anchor="start" fill="currentColor">VBS / HVCI / KDP / SECURE POOL</text>
    <text class="ks-annotation" x="740" y="43" text-anchor="end">Hypervisor code integrity, kernel data protection</text>
    <text class="ks-annotation" x="740" y="60" text-anchor="end">VBS-protected allocations, secure kernel isolation</text>
    <!-- "Blocks" annotations on right side -->
    <text class="ks-annotation" x="800" y="293" text-anchor="start">blocks code exec from data</text>
    <text class="ks-annotation" x="800" y="247" text-anchor="start">blocks pool metadata abuse</text>
    <text class="ks-annotation" x="800" y="201" text-anchor="start">blocks hardcoded addresses</text>
    <text class="ks-annotation" x="800" y="155" text-anchor="start">blocks control flow hijack</text>
    <text class="ks-annotation" x="800" y="109" text-anchor="start">blocks dynamic code gen</text>
    <text class="ks-annotation" x="800" y="50" text-anchor="start">blocks kernel data tampering</text>
    <!-- Arrow showing increasing bypass difficulty -->
    <line class="ks-line" x1="20" y1="290" x2="20" y2="30"/>
    <polyline class="ks-arrow" points="15,35 20,25 25,35"/>
    <text class="ks-annotation" x="15" y="160" text-anchor="middle" transform="rotate(-90, 15, 160)">BYPASS DIFFICULTY</text>
  </svg>
  <p class="ks-figure-caption">Each layer blocks specific primitive classes. VBS-backed protections at the top are the hardest to bypass.</p>
</div>

## How the Layers Interact

The real power of this stack is compositional. Consider an attacker who finds a pool overflow in clfs.sys. Pool hardening (Segment Heap randomization, cookies) makes the initial corruption unreliable but not impossible. If the attacker achieves a write primitive, KASLR forces them to find an information leak or corrupt the security descriptor that gates `NtQuerySystemInformation` access. SMEP and SMAP prevent them from redirecting execution to user-mode shellcode, so they must use data-only techniques like token swapping. kCFG and kCET prevent control flow hijacking even within kernel code. And if HVCI is enabled, there is no writable-and-executable memory anywhere in the kernel address space.

Each mitigation removed from this chain makes the exploit simpler. On a system without HVCI, the attacker regains the ability to allocate executable memory. Without kCET, ROP chains become viable again. Without KASLR restrictions, a simple API call reveals every kernel address. The defense-in-depth model works because these layers are independent: bypassing one does not compromise the others.

## Mitigation Catalog

| Mitigation | What It Blocks | Bypass Difficulty |
|-----------|----------------|-------------------|
| [SMEP / SMAP](smep-smap.md) | Code execution and data access across the user/kernel boundary | Medium |
| [kCFG / kCET](kcfg-kcet.md) | Control flow hijacking via function pointer and return address corruption | High |
| [VBS / HVCI](vbs-hvci.md) | Runtime code generation, unsigned driver loading, and code page modification in the kernel | Very High |
| [KDP](kdp.md) | Modification of security-critical kernel globals and driver configuration data | Very High |
| [Pool Hardening](pool-hardening.md) | Pool header corruption, deterministic heap layout, and uninitialized data leaks | Medium |
| [Secure Pool](secure-pool.md) | Pool overflow, use-after-free, and metadata corruption for VBS-protected allocations | Very High |
| [ACG](acg.md) | Dynamic code generation and modification within protected user-mode processes | High |
| [KASLR](kaslr.md) | Exploitation using hardcoded or predictable kernel addresses | Low-Medium |
| [KASLR Bypasses](kaslr-bypasses.md) | Catalog of techniques that defeat kernel address randomization | -- |

## Which Mitigations Block Which Primitives

The table below maps each mitigation to the exploitation primitives it is designed to prevent. A filled cell means the mitigation directly blocks or significantly hinders that primitive class. Empty cells indicate the mitigation is irrelevant to that technique, not that the technique is safe.

| | Pool Overflow | Write-What-Where | Token Swap | PTE Manip | Code Exec | Pool Spray |
|---|---|---|---|---|---|---|
| SMEP / SMAP | | | | | ■ | |
| kCFG / kCET | | | | | ■ | |
| VBS / HVCI | | ■ | ■ | ■ | ■ | |
| KDP | | ■ | ■ | | | |
| Pool Hardening | ■ | | | | | ■ |
| Secure Pool | ■ | | ■ | | | ■ |
| ACG | | | | | ■ | |
| KASLR | | ■ | | ■ | | |

The most important takeaway from this table is the empty column for token swapping outside of VBS/KDP/Secure Pool. Token manipulation requires only a read/write primitive and knowledge of the current process address. No hardware enforcement, no control flow integrity check, and no W^X policy touches the token swap itself. This is why [token swapping](../primitives/exploitation/token-swapping.md) has become the dominant terminal goal for modern kernel exploits, and why VBS-backed protections (which could theoretically move tokens into Secure Pool or KDP-protected memory) represent the most consequential future hardening.

For how these mitigations evolved over time and how each deployment shifted attacker techniques, see the [Mitigation Timeline](../guides/mitigation-timeline.md). For how exploit chains navigate through these layers to reach SYSTEM, see [Exploit Chain Patterns](../guides/exploit-chain-patterns.md).
