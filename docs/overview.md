---
hide:
  - toc
description: "What kernel access buys you on Windows: how it is obtained across 156 CVEs and 64 drivers, and which kernel-layer and user-layer defenses it does and does not defeat."
---

<div class="ks-hero-title" markdown>KernelSight</div>

<p class="ks-hero-subtitle">
What kernel access buys you on Windows. One half of this site covers how the access is obtained, across 156 real CVEs and 64 drivers. The other covers what that access defeats, at both kernel and user level. A read or write primitive is the hinge between them.
</p>

## Recent Updates

| Date | What's New |
|------|------------|
| **2026-09-04** | Every page now shows when it last changed, measured from git rather than asserted. Corpus totals are generated from the data and guarded by a test, after three different figures were live at once. |
| **2026-09-03** | Repositioned around what kernel access buys you. Navigation regrouped into [Means](driver-types/index.md) and [Targets](mitigations/index.md); new [bypass matrix](bypasses/index.md) evaluating every inventory against one platform selection; first user-layer defense page, [Protected Process Light](mitigations/protected-process.md). Every technique now carries a dated verdict and a basis tier. |
| **2026-03-12** | [KDU Provider Compatibility](reference/kdu-compatibility.md) and [LOLDrivers Deep Analysis](reference/loldrivers-analysis.md) updated with full 1,775-driver Tier 2 Ghidra results. 1,404 KDU-compatible (79%), 354 Tier 2 confirmed, 122 confirmed MapDriver candidates with physical + virtual memory primitives reachable from IOCTL handlers. All mitigations, ROP gadgets, and I/O methods scored. |
| **2026-03-01** | Backfill: 13 case studies added for 2022--2024 CVEs with published exploit research. CLFS ransomware chain (CVE-2022-24521, CVE-2022-35803, CVE-2023-23376), Project Zero registry audit (CVE-2022-34707, CVE-2023-23420), DEVCORE kernel streaming (CVE-2024-30090, CVE-2024-30084, CVE-2024-38144), activation context bugs (CVE-2022-22047, CVE-2022-41073). Corpus now at 156 CVEs, 57 exploited ITW. |
| **2026-03-01** | New guide: [Why Kernel Drivers?](guides/why-kernel-drivers.md) -- what hardware enforces, what only Ring 0 can do, user-mode alternatives, the security cost, and Microsoft's trajectory toward constraining kernel code. |
| **2026-02-28** | New guides: [Corpus Analytics](guides/corpus-analytics.md), [Exploit Chain Patterns](guides/exploit-chain-patterns.md), [Patch Patterns](guides/patch-patterns.md), [Mitigation Timeline](guides/mitigation-timeline.md), [Anatomy of a Secure Driver](guides/secure-driver-anatomy.md). New deep dives: [afd.sys](case-studies/afd-deep-dive.md), [win32k](case-studies/win32k-deep-dive.md), [ntfs.sys](case-studies/ntfs-deep-dive.md). |
| **2026-02-28** | 58 new case studies added across afd.sys, clfs.sys, win32k, dwmcore.dll, ntfs.sys, ntoskrnl, plus new drivers: rasman.sys, storvsp.sys, dxgkrnl.sys, msfs.sys. BYOVD additions include Paragon BioNTdrv siblings, TfSysMon.sys, STProcessMonitor.sys. |
| **2026-02-28** | 25 new case studies for 2025-2026 kernel CVEs -- ITW zero-days in [afd.sys](case-studies/CVE-2025-21418.md), [clfs.sys](case-studies/CVE-2025-32701.md), [DWM](case-studies/CVE-2025-30400.md), [ntoskrnl](case-studies/CVE-2025-62215.md), [win32k](case-studies/CVE-2025-24983.md), [Hyper-V](case-studies/CVE-2025-21334.md); BYOVD via [Paragon](case-studies/CVE-2025-0289.md), [NSecKrnl](case-studies/CVE-2025-68947.md), [EnPortv](case-studies/EnPortv-sys.md). |
| **2026-02-28** | [CVE-2025-3464](case-studies/CVE-2025-3464.md) / [CVE-2025-1533](case-studies/CVE-2025-1533.md) -- AsIO3.sys auth bypass + stack overflow via [decrement-by-one](primitives/arw/arb-increment-decrement.md), [PreviousMode flip](primitives/exploitation/previous-mode-manipulation.md), [token theft](primitives/exploitation/token-swapping.md). |
| **2026-02-25** | [CVE-2026-21241](case-studies/CVE-2026-21241.md) -- afd.sys notification UAF with [bit-manipulation primitive](primitives/exploitation/bit-manipulation.md), DACL corruption, token privilege escalation. |
| **2026-02-25** | New technique: [Bit-Manipulation Primitives](primitives/exploitation/bit-manipulation.md). Expanded: [ACL / SD Manipulation](primitives/exploitation/acl-sd-manipulation.md), [KASLR Bypasses](mitigations/kaslr-bypasses.md). |

<div class="ks-figure" markdown>
  <span class="ks-figure-label">FIG_001 : The two halves, and the hinge</span>
  <svg viewBox="0 0 900 300" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Means feeds a kernel read, write or execute primitive, which then feeds Targets. Means covers driver types, attack surfaces, vulnerability classes and case studies. Targets covers kernel-layer and user-layer defenses.">

    <!-- MEANS -->
    <text class="ks-label" x="30" y="34">MEANS &#183; HOW THE ACCESS IS OBTAINED</text>
    <rect class="ks-box" x="30" y="48" width="300" height="34"/>
    <text class="ks-annotation" x="45" y="69">Driver types &#183; 12 families</text>
    <rect class="ks-box" x="30" y="92" width="300" height="34"/>
    <text class="ks-annotation" x="45" y="113">Attack surfaces &#183; 9 entry points</text>
    <rect class="ks-box" x="30" y="136" width="300" height="34"/>
    <text class="ks-annotation" x="45" y="157">Vulnerability classes &#183; 10</text>
    <rect class="ks-box" x="30" y="180" width="300" height="34"/>
    <text class="ks-annotation" x="45" y="201">Case studies &#183; 156 CVEs, 64 drivers</text>

    <!-- feed into the hinge -->
    <path class="ks-arrow" d="M330 65 C 372 65 372 150 400 150"/>
    <path class="ks-arrow" d="M330 109 C 372 109 372 150 400 150"/>
    <path class="ks-arrow" d="M330 153 L400 150"/>
    <path class="ks-arrow" d="M330 197 C 372 197 372 150 400 150"/>
    <path class="ks-arrow" d="M394 145 L404 150 L394 155 Z" fill="currentColor"/>

    <!-- the hinge -->
    <rect class="ks-box" x="404" y="118" width="122" height="64" stroke-width="2"/>
    <text class="ks-label" x="465" y="142" text-anchor="middle">KERNEL</text>
    <text class="ks-label" x="465" y="156" text-anchor="middle">READ / WRITE</text>
    <text class="ks-annotation" x="465" y="172" text-anchor="middle">21 primitives</text>

    <!-- hinge feeds targets -->
    <path class="ks-arrow" d="M526 150 L566 150"/>
    <path class="ks-arrow" d="M560 145 L570 150 L560 155 Z" fill="currentColor"/>

    <!-- TARGETS -->
    <text class="ks-label" x="570" y="34">TARGETS &#183; WHAT IT DEFEATS</text>
    <rect class="ks-box" x="570" y="92" width="300" height="52"/>
    <text class="ks-annotation" x="585" y="112">Kernel layer &#183; 19 defenses</text>
    <text class="ks-annotation" x="585" y="130">DSE, HVCI, kCET, KDP, HLAT, KASLR</text>
    <rect class="ks-box" x="570" y="156" width="300" height="52"/>
    <text class="ks-annotation" x="585" y="176">User layer &#183; 10 defenses</text>
    <text class="ks-annotation" x="585" y="194">PPL, LSA, ETW-Ti, EDR, WDAC, UAC</text>

    <!-- out of reach -->
    <rect class="ks-box" x="570" y="230" width="300" height="34" stroke-dasharray="4 3"/>
    <text class="ks-annotation" x="585" y="251">VTL1 &#183; Credential Guard, HyperGuard: out of reach</text>
    <line class="ks-line" x1="465" y1="182" x2="465" y2="247" stroke-dasharray="3 3"/>
    <line class="ks-line" x1="465" y1="247" x2="564" y2="247" stroke-dasharray="3 3"/>
    <text class="ks-annotation" x="470" y="240">no path</text>
  </svg>
</div>

<hr class="ks-divider">

## The two halves

<ol class="ks-pipeline-list" markdown>
<li markdown>
<strong><a href="driver-types/">Driver Types</a></strong>
<p>Identify the kernel component, whether file system, network stack, Win32k, core kernel, vendor utility or GPU, then understand its role, IRP patterns and historical vulnerability profile. 12 categories covering 64 unique drivers.</p>
</li>
<li markdown>
<strong><a href="attack-surfaces/">Attack Surfaces</a></strong>
<p>Map how user-mode code reaches the driver: IOCTL handlers, filesystem IRPs, ALPC, shared memory. This determines what an attacker can control.</p>
</li>
<li markdown>
<strong><a href="vuln-classes/">Vulnerability Classes</a></strong>
<p>Classify the bug as buffer overflow, type confusion, TOCTOU or use-after-free, then understand the corruption it enables. 10 classes with typical primitives gained.</p>
</li>
<li markdown>
<strong><a href="primitives/">Primitives</a></strong>
<p>Convert the bug into a capability: arbitrary read/write, pool spray, token swap. 21 techniques split between arb R/W primitives and exploitation building blocks.</p>
</li>
<li markdown>
<strong><a href="case-studies/">Case Studies</a></strong>
<p>Walk through the full chain for 156 real CVEs, covering root cause, exploitation path, patch analysis and detection rules. 57 exploited in the wild, including 38 third-party BYOVD drivers.</p>
</li>
<li markdown>
<strong><a href="mitigations/">Mitigations</a></strong>
<p>Understand the defenses, from SMEP and SMAP through kCFG, kCET, VBS, HVCI and pool hardening, and which primitives each one blocks. Sits on the Targets side.</p>
</li>
<li markdown>
<strong><a href="tooling/">Tooling</a></strong>
<p>Static analysis, fuzzing, kernel debugging, and AutoPiff integration for automated vulnerability detection across driver patches.</p>
</li>
<li markdown>
<strong><a href="guides/">Guides</a></strong>
<p>Cross-cutting analysis that synthesizes patterns from the corpus -- what makes a driver secure, what the common mistakes look like, and how to avoid them.</p>
</li>
</ol>

<hr class="ks-divider--dots">

## Corpus

<div class="ks-stats-box" markdown>
<span class="ks-stat-num">156</span> CVE case studies &nbsp;&middot;&nbsp;
<span class="ks-stat-num">64</span> unique drivers &nbsp;&middot;&nbsp;
<span class="ks-stat-num">57</span> exploited in the wild &nbsp;&middot;&nbsp;
<span class="ks-stat-num">2</span> remotely exploitable<br>
<span class="ks-stat-num">12</span> driver type categories &nbsp;&middot;&nbsp;
<span class="ks-stat-num">57</span> technique pages &nbsp;&middot;&nbsp;
<span class="ks-stat-num">80+</span> AutoPiff detection rules<br>
<span class="ks-stat-num">1,775</span> LOLDrivers analyzed &nbsp;&middot;&nbsp;
<span class="ks-stat-num">354</span> Tier 2 Ghidra confirmed &nbsp;&middot;&nbsp;
<span class="ks-stat-num">122</span> confirmed MapDriver candidates
</div>

## Recommended Paths

<div class="ks-paths" markdown>

<a class="ks-path-card" href="../">
  <strong>Explore the corpus</strong>
  <span>Interactive dashboard. Search, filter, and visualize all 156 CVEs. Heat matrix shows where the bugs cluster.</span>
</a>

<a class="ks-path-card" href="driver-types/">
  <strong>New to kernel exploitation</strong>
  <span>Start with Driver Types to understand the landscape, then start in Means and follow it to a primitive.</span>
</a>

<a class="ks-path-card" href="case-studies/">
  <strong>Researching a specific driver</strong>
  <span>Jump to Case Studies and filter by driver name. Each CVE links back to the relevant Means pages.</span>
</a>

<a class="ks-path-card" href="tooling/autopiff-integration/">
  <strong>Building detection automation</strong>
  <span>See how AutoPiff integrates with this knowledge base to detect vulnerability patterns at scale.</span>
</a>

<a class="ks-path-card" href="guides/secure-driver-anatomy/">
  <strong>Writing or auditing a driver</strong>
  <span>The 6 anti-patterns behind most kernel driver CVEs, with fixes, a checklist, and real CVE citations.</span>
</a>

</div>

## Data & Analysis

The two halves above cover *how* kernel drivers get exploited. For a data-driven view of *which* drivers are most dangerous, see the [Reference](reference/) section, where 1,775 LOLDrivers are analyzed with automated Ghidra decompilation, scored for weaponisability, and mapped to KDU provider compatibility.
