---
description: "Windows kernel exploit mitigations — SMEP, SMAP, kCFG, kCET, VBS, HVCI, KDP, pool hardening, Secure Pool, ACG, and KASLR. How each defence works and what bypasses exist."
---

# Mitigations

<div class="ks-pipeline-pos">
  Driver Type &rarr; Attack Surface &rarr; Vuln Class &rarr; Primitive &rarr; Case Study &nbsp;|&nbsp; <span class="ks-active">Mitigations</span>
</div>

Mitigations are cross-cutting defenses that intersect every stage of the exploitation pipeline. Rather than fixing individual bugs, they raise the cost of exploitation by breaking assumptions that primitives rely on: preventing code execution from data pages, randomizing kernel addresses, or isolating structures in hypervisor-protected memory.

<div class="ks-figure" markdown>
  <span class="ks-figure-label">FIG_006 — Defense-in-Depth Stack</span>
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

## Categories

| Mitigation | Description | Bypass Difficulty |
|-----------|-------------|-------------------|
| [SMEP / SMAP](smep-smap.md) | Supervisor mode execution/access prevention | Medium |
| [kCFG / kCET](kcfg-kcet.md) | Kernel control flow integrity | High |
| [VBS / HVCI](vbs-hvci.md) | Virtualization-based code integrity | Very High |
| [KDP](kdp.md) | Kernel Data Protection | Very High |
| [Pool Hardening](pool-hardening.md) | Segment heap, pool cookies, NX pool | Medium |
| [Secure Pool](secure-pool.md) | VBS-protected pool allocations | Very High |
| [ACG](acg.md) | Arbitrary Code Guard | High |
| [KASLR](kaslr.md) | Kernel address space randomization | Low-Medium |
| [KASLR Bypasses](kaslr-bypasses.md) | Catalog of KASLR defeat techniques | -- |

## Mitigation vs. Primitive

Which mitigations block which exploitation primitives:

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
