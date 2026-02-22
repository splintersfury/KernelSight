# Vulnerability Classes

<div class="ks-pipeline-pos">
  Driver Type &rarr; Attack Surface &rarr; <span class="ks-active">Vuln Class</span> &rarr; Primitive &rarr; Case Study
</div>

Once attacker-controlled input reaches the kernel through an attack surface, the question becomes: what goes wrong? Vulnerability classes describe the category of bug — the specific failure in validation, memory management, or concurrency control that enables memory corruption or privilege boundary violation.

<div class="ks-figure" markdown>
  <span class="ks-figure-label">FIG_004 — Bug to Primitive Flow</span>
  <svg viewBox="0 0 820 300" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Flow from trigger conditions through corruption types to primitives gained">
    <!-- Column headers -->
    <text class="ks-label" x="120" y="20" text-anchor="middle" fill="currentColor">TRIGGER</text>
    <text class="ks-label" x="410" y="20" text-anchor="middle" fill="currentColor">CORRUPTION</text>
    <text class="ks-label" x="700" y="20" text-anchor="middle" fill="currentColor">PRIMITIVE GAINED</text>
    <!-- Trigger column -->
    <rect class="ks-box" x="20" y="35" width="200" height="32"/>
    <text class="ks-annotation" x="120" y="56" text-anchor="middle">Unchecked size / offset</text>
    <rect class="ks-box" x="20" y="77" width="200" height="32"/>
    <text class="ks-annotation" x="120" y="98" text-anchor="middle">Integer wrap / truncation</text>
    <rect class="ks-box" x="20" y="119" width="200" height="32"/>
    <text class="ks-annotation" x="120" y="140" text-anchor="middle">Wrong object type assumed</text>
    <rect class="ks-box" x="20" y="161" width="200" height="32"/>
    <text class="ks-annotation" x="120" y="182" text-anchor="middle">Race between check &amp; use</text>
    <rect class="ks-box" x="20" y="203" width="200" height="32"/>
    <text class="ks-annotation" x="120" y="224" text-anchor="middle">Freed object reused</text>
    <rect class="ks-box" x="20" y="245" width="200" height="32"/>
    <text class="ks-annotation" x="120" y="266" text-anchor="middle">Missing access check</text>
    <!-- Arrows trigger -> corruption -->
    <line class="ks-line" x1="220" y1="51" x2="290" y2="70" stroke-dasharray="4,3" opacity="0.4"/>
    <line class="ks-line" x1="220" y1="93" x2="290" y2="70" stroke-dasharray="4,3" opacity="0.4"/>
    <line class="ks-line" x1="220" y1="135" x2="290" y2="140" stroke-dasharray="4,3" opacity="0.4"/>
    <line class="ks-line" x1="220" y1="177" x2="290" y2="140" stroke-dasharray="4,3" opacity="0.4"/>
    <line class="ks-line" x1="220" y1="219" x2="290" y2="210" stroke-dasharray="4,3" opacity="0.4"/>
    <line class="ks-line" x1="220" y1="261" x2="290" y2="260" stroke-dasharray="4,3" opacity="0.4"/>
    <!-- Corruption column -->
    <rect class="ks-box" x="290" y="50" width="240" height="38"/>
    <text class="ks-annotation" x="410" y="74" text-anchor="middle">Heap / Stack Overflow</text>
    <rect class="ks-box" x="290" y="120" width="240" height="38"/>
    <text class="ks-annotation" x="410" y="144" text-anchor="middle">Type Confusion / Object Misuse</text>
    <rect class="ks-box" x="290" y="190" width="240" height="38"/>
    <text class="ks-annotation" x="410" y="214" text-anchor="middle">Dangling Pointer / UAF</text>
    <rect class="ks-box" x="290" y="245" width="240" height="32"/>
    <text class="ks-annotation" x="410" y="266" text-anchor="middle">Logic / Authorization Bypass</text>
    <!-- Arrows corruption -> primitive -->
    <line class="ks-line" x1="530" y1="69" x2="590" y2="60" stroke-dasharray="4,3" opacity="0.4"/>
    <line class="ks-line" x1="530" y1="139" x2="590" y2="115" stroke-dasharray="4,3" opacity="0.4"/>
    <line class="ks-line" x1="530" y1="209" x2="590" y2="170" stroke-dasharray="4,3" opacity="0.4"/>
    <line class="ks-line" x1="530" y1="261" x2="590" y2="225" stroke-dasharray="4,3" opacity="0.4"/>
    <!-- Primitive column -->
    <rect class="ks-box" x="590" y="40" width="220" height="35"/>
    <text class="ks-annotation" x="700" y="62" text-anchor="middle">Arbitrary Write (OOB)</text>
    <rect class="ks-box" x="590" y="95" width="220" height="35"/>
    <text class="ks-annotation" x="700" y="117" text-anchor="middle">Controlled Pointer Deref</text>
    <rect class="ks-box" x="590" y="150" width="220" height="35"/>
    <text class="ks-annotation" x="700" y="172" text-anchor="middle">Object Reuse / Spray</text>
    <rect class="ks-box" x="590" y="205" width="220" height="35"/>
    <text class="ks-annotation" x="700" y="227" text-anchor="middle">Privilege Escalation</text>
    <rect class="ks-box" x="590" y="255" width="220" height="32"/>
    <text class="ks-annotation" x="700" y="276" text-anchor="middle">Info Leak / KASLR Bypass</text>
  </svg>
  <p class="ks-figure-caption">Each trigger condition leads to a corruption type, which yields a specific exploitation primitive.</p>
</div>

## Categories

| Class | Description | Typical Primitive | Key CVEs |
|-------|-------------|-------------------|----------|
| [Buffer Overflow](buffer-overflow.md) | Stack and heap buffer overflows | [Pool Overflow](../primitives/arw/pool-overflow.md), [Pool Spray](../primitives/exploitation/pool-spray-feng-shui.md) | CVE-2024-30085, CVE-2023-28252 |
| [Integer Overflow](integer-overflow.md) | Integer overflow/underflow | Undersized alloc → [Pool Overflow](../primitives/arw/pool-overflow.md) | CVE-2024-38063, CVE-2024-38054 |
| [Type Confusion](type-confusion.md) | Object type misinterpretation | [Write-What-Where](../primitives/arw/write-what-where.md) | CVE-2023-36802, CVE-2022-21882 |
| [TOCTOU / Double-Fetch](toctou-double-fetch.md) | Time-of-check-to-time-of-use | Depends on raced field (size → overflow, ptr → ARW) | CVE-2024-30088, CVE-2024-38106 |
| [Use-After-Free](use-after-free.md) | Dangling pointer dereference | [Pool Spray](../primitives/exploitation/pool-spray-feng-shui.md) reclaim | CVE-2024-38193, CVE-2023-29336 |
| [Race Conditions](race-conditions.md) | Concurrency and synchronization | UAF, double-free, state corruption | CVE-2024-38106, CVE-2024-30089 |
| [Uninitialized Memory](uninitialized-memory.md) | Kernel memory disclosure | KASLR bypass via leaked pointers | CVE-2023-32019, CVE-2024-38256 |
| [Arbitrary R/W Primitives](arbitrary-rw-primitives.md) | Patterns yielding arb R/W | [Direct IOCTL R/W](../primitives/arw/direct-ioctl-rw.md) | CVE-2024-21338, CVE-2023-21768 |
| [NULL Deref](null-deref.md) | NULL pointer dereference | DoS (BSOD), legacy code exec | CVE-2024-35250 |
| [Logic Bugs](logic-bugs.md) | Design-level logic errors | Direct privilege escalation | CVE-2024-26229, CVE-2024-21302 |

<div class="ks-next-pipeline">
  Next in the pipeline: <a href="../primitives/">Primitives</a> &rarr; How is the corruption converted into a reliable exploitation capability?
</div>
