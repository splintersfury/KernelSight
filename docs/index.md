---
hide:
  - toc
description: "Windows kernel driver exploitation knowledge base — 147 CVEs across 64 drivers, exploit chain patterns, BYOVD analysis, mitigations, and exploitation primitives."
---

<div class="ks-hero-title" markdown>KernelSight</div>

<p class="ks-hero-subtitle">
A structured knowledge base for Windows kernel driver exploitation, organized as a pipeline from driver identification through privilege escalation. Covers 134 real CVEs across Microsoft inbox and third-party BYOVD drivers.
</p>

## Recent Updates

| Date | What's New |
|------|------------|
| **2026-03-01** | Backfill: 13 case studies added for 2022--2024 CVEs with published exploit research. CLFS ransomware chain (CVE-2022-24521, CVE-2022-35803, CVE-2023-23376), Project Zero registry audit (CVE-2022-34707, CVE-2023-23420), DEVCORE kernel streaming (CVE-2024-30090, CVE-2024-30084, CVE-2024-38144), activation context bugs (CVE-2022-22047, CVE-2022-41073). Corpus now at 147 CVEs, 57 exploited ITW. |
| **2026-03-01** | New guide: [Why Kernel Drivers?](guides/why-kernel-drivers.md) -- what hardware enforces, what only Ring 0 can do, user-mode alternatives, the security cost, and Microsoft's trajectory toward constraining kernel code. |
| **2026-02-28** | New guides: [Corpus Analytics](guides/corpus-analytics.md), [Exploit Chain Patterns](guides/exploit-chain-patterns.md), [Patch Patterns](guides/patch-patterns.md), [Mitigation Timeline](guides/mitigation-timeline.md). New deep dives: [afd.sys](case-studies/afd-deep-dive.md) (13 CVEs), [win32k](case-studies/win32k-deep-dive.md) (12 CVEs), [ntfs.sys](case-studies/ntfs-deep-dive.md) (7 CVEs). |
| **2026-02-28** | New guide: [Anatomy of a Secure Driver](guides/secure-driver-anatomy.md) -- the 6 anti-patterns behind most kernel driver CVEs, with root cause distribution chart, pseudocode fixes, and a 14-point secure driver checklist. |
| **2026-02-28** | Comprehensive expansion: 58 more case studies added — filling gaps across every 2025-2026 Patch Tuesday. Coverage now spans afd.sys (13 CVEs), clfs.sys (12 CVEs), win32k (10 CVEs), dwmcore.dll (8 CVEs), ntfs.sys (8 CVEs), ntoskrnl (7 CVEs), plus new drivers: rasman.sys, storvsp.sys, dxgkrnl.sys, msfs.sys. BYOVD additions include Paragon BioNTdrv siblings, TfSysMon.sys, STProcessMonitor.sys. Corpus now at 131 CVEs, 52 exploited ITW. |
| **2026-02-28** | Bulk addition: 25 new case studies covering 2025-2026 kernel CVEs — ITW zero-days in [afd.sys](case-studies/CVE-2025-21418.md), [clfs.sys](case-studies/CVE-2025-32701.md), [DWM](case-studies/CVE-2025-30400.md), [ntoskrnl](case-studies/CVE-2025-62215.md), [win32k](case-studies/CVE-2025-24983.md), [Hyper-V](case-studies/CVE-2025-21334.md); BYOVD campaigns via [Paragon](case-studies/CVE-2025-0289.md), [NSecKrnl](case-studies/CVE-2025-68947.md), [EnPortv](case-studies/EnPortv-sys.md). Corpus now at 82 CVEs, 47 exploited ITW. |
| **2026-02-28** | [CVE-2025-3464](case-studies/CVE-2025-3464.md) / [CVE-2025-1533](case-studies/CVE-2025-1533.md) — AsIO3.sys auth bypass + stack overflow. Full exploit chain from Cisco Talos: hardlink auth bypass, `ObfDereferenceObject` [decrement-by-one](primitives/arw/arb-increment-decrement.md), [PreviousMode flip](primitives/exploitation/previous-mode-manipulation.md), [token theft](primitives/exploitation/token-swapping.md). |
| **2026-02-25** | [CVE-2026-21241](case-studies/CVE-2026-21241.md) — afd.sys notification UAF. Full 7-stage exploit chain: NPNX pool spray, `_IO_MINI_COMPLETION_PACKET_USER` callback abuse, RtlSetBit/RtlClearAllBits [bit-manipulation primitive](primitives/exploitation/bit-manipulation.md), SepMediumDaclSd DACL corruption, WIL feature flag bypass, token privilege escalation. |
| **2026-02-25** | New technique: [Bit-Manipulation Primitives](primitives/exploitation/bit-manipulation.md) — using `RtlSetBit`/`RtlClearAllBits` as kCFG-compliant kernel exploitation primitives. |
| **2026-02-25** | Expanded: [ACL / SD Manipulation](primitives/exploitation/acl-sd-manipulation.md) — SepMediumDaclSd corruption and SE_SACL_PRESENT bit-flip techniques for KASLR bypass. |
| **2026-02-25** | Expanded: [KASLR Bypasses](mitigations/kaslr-bypasses.md) — prefetch side-channel (EntryBleed for Windows), security descriptor corruption section, WIL feature flag bypass. |

<div class="ks-figure" markdown>
  <span class="ks-figure-label">FIG_001 — The Exploitation Pipeline</span>
  <svg viewBox="0 0 900 280" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Exploitation pipeline: Driver Type to Attack Surface to Vulnerability Class to Primitive to Case Study, with Mitigations below">
    <!-- Row 1: Five pipeline stages -->
    <a href="driver-types/">
      <rect class="ks-box" x="10" y="30" width="150" height="56" rx="0"/>
      <text class="ks-label" x="85" y="55" text-anchor="middle" fill="currentColor">DRIVER TYPE</text>
      <text class="ks-annotation" x="85" y="72" text-anchor="middle">Which component?</text>
    </a>
    <!-- Arrow 1 -->
    <line class="ks-line" x1="160" y1="58" x2="185" y2="58"/>
    <polyline class="ks-arrow" points="180,53 188,58 180,63"/>
    <a href="attack-surfaces/">
      <rect class="ks-box" x="190" y="30" width="150" height="56" rx="0"/>
      <text class="ks-label" x="265" y="55" text-anchor="middle" fill="currentColor">ATTACK SURFACE</text>
      <text class="ks-annotation" x="265" y="72" text-anchor="middle">How is it reached?</text>
    </a>
    <!-- Arrow 2 -->
    <line class="ks-line" x1="340" y1="58" x2="365" y2="58"/>
    <polyline class="ks-arrow" points="360,53 368,58 360,63"/>
    <a href="vuln-classes/">
      <rect class="ks-box" x="370" y="30" width="150" height="56" rx="0"/>
      <text class="ks-label" x="445" y="55" text-anchor="middle" fill="currentColor">VULN CLASS</text>
      <text class="ks-annotation" x="445" y="72" text-anchor="middle">What went wrong?</text>
    </a>
    <!-- Arrow 3 -->
    <line class="ks-line" x1="520" y1="58" x2="545" y2="58"/>
    <polyline class="ks-arrow" points="540,53 548,58 540,63"/>
    <a href="primitives/">
      <rect class="ks-box" x="550" y="30" width="150" height="56" rx="0"/>
      <text class="ks-label" x="625" y="55" text-anchor="middle" fill="currentColor">PRIMITIVE</text>
      <text class="ks-annotation" x="625" y="72" text-anchor="middle">What do you gain?</text>
    </a>
    <!-- Arrow 4 -->
    <line class="ks-line" x1="700" y1="58" x2="725" y2="58"/>
    <polyline class="ks-arrow" points="720,53 728,58 720,63"/>
    <a href="case-studies/">
      <rect class="ks-box" x="730" y="30" width="150" height="56" rx="0"/>
      <text class="ks-label" x="805" y="55" text-anchor="middle" fill="currentColor">CASE STUDY</text>
      <text class="ks-annotation" x="805" y="72" text-anchor="middle">Real-world CVEs</text>
    </a>
    <!-- Mitigations bar below -->
    <line class="ks-line" x1="10" y1="120" x2="880" y2="120" stroke-dasharray="6,4"/>
    <a href="mitigations/">
      <rect class="ks-box" x="280" y="132" width="340" height="40" rx="0"/>
      <text class="ks-label" x="450" y="157" text-anchor="middle" fill="currentColor">MITIGATIONS</text>
    </a>
    <!-- Vertical dashed lines connecting stages to mitigations -->
    <line class="ks-line" x1="445" y1="86" x2="445" y2="132" stroke-dasharray="4,4" opacity="0.4"/>
    <line class="ks-line" x1="625" y1="86" x2="625" y2="132" stroke-dasharray="4,4" opacity="0.4"/>
    <text class="ks-annotation" x="450" y="195" text-anchor="middle">Defenses intersect every stage</text>
    <!-- Tooling reference -->
    <a href="tooling/">
      <text class="ks-annotation" x="450" y="220" text-anchor="middle" text-decoration="underline">Tooling &amp; Automation</text>
    </a>
  </svg>
  <p class="ks-figure-caption">Each stage links to a section of this knowledge base. Click any box to begin.</p>
</div>

<hr class="ks-divider">

## The Analysis Pipeline

<ol class="ks-pipeline-list" markdown>
<li markdown>
<strong><a href="driver-types/">Driver Types</a></strong>
<p>Identify the kernel component — file system, network stack, Win32k, core kernel, vendor utility, GPU — and understand its role, IRP patterns, and historical vulnerability profile. 12 categories covering 62 unique drivers.</p>
</li>
<li markdown>
<strong><a href="attack-surfaces/">Attack Surfaces</a></strong>
<p>Map how user-mode code reaches the driver — IOCTL handlers, filesystem IRPs, ALPC, shared memory. Determines what an attacker can control.</p>
</li>
<li markdown>
<strong><a href="vuln-classes/">Vulnerability Classes</a></strong>
<p>Classify the bug — buffer overflow, type confusion, TOCTOU, use-after-free — and understand the corruption it enables. 10 classes with typical primitives gained.</p>
</li>
<li markdown>
<strong><a href="primitives/">Primitives</a></strong>
<p>Convert the bug into a capability — arbitrary read/write, pool spray, token swap. 19 techniques split between arb R/W primitives and exploitation building blocks.</p>
</li>
<li markdown>
<strong><a href="case-studies/">Case Studies</a></strong>
<p>Walk through the full chain for 134 real CVEs — root cause, exploitation path, patch analysis, and detection rules. 52 exploited in the wild, including 38 third-party BYOVD drivers.</p>
</li>
<li markdown>
<strong><a href="mitigations/">Mitigations</a></strong>
<p>Understand the defenses — SMEP/SMAP, kCFG/kCET, VBS/HVCI, pool hardening — and which primitives they block. Cross-cuts every pipeline stage.</p>
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
<span class="ks-stat-num">147</span> CVE case studies &nbsp;&middot;&nbsp;
<span class="ks-stat-num">64</span> unique drivers &nbsp;&middot;&nbsp;
<span class="ks-stat-num">57</span> exploited in the wild &nbsp;&middot;&nbsp;
<span class="ks-stat-num">2</span> remotely exploitable<br>
<span class="ks-stat-num">12</span> driver type categories &nbsp;&middot;&nbsp;
<span class="ks-stat-num">57</span> technique pages &nbsp;&middot;&nbsp;
<span class="ks-stat-num">80+</span> AutoPiff detection rules
</div>

## Recommended Paths

<div class="ks-paths" markdown>

<a class="ks-path-card" href="driver-types/">
  <strong>New to kernel exploitation</strong>
  <span>Start with Driver Types to understand the landscape, then follow the pipeline left-to-right.</span>
</a>

<a class="ks-path-card" href="case-studies/">
  <strong>Researching a specific driver</strong>
  <span>Jump to Case Studies and filter by driver name. Each CVE links back to relevant pipeline stages.</span>
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
