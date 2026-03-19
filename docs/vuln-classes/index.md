---
description: "10 Windows kernel vulnerability classes — buffer overflow, use-after-free, type confusion, TOCTOU, race conditions, integer overflow, arbitrary R/W, and logic bugs with real CVE examples."
---

# Vulnerability Classes

<div class="ks-pipeline-pos">
  Driver Type &rarr; Attack Surface &rarr; <span class="ks-active">Vuln Class</span> &rarr; Primitive &rarr; Case Study
</div>

Every kernel exploit begins with a bug, and every bug belongs to a class. Once attacker-controlled input crosses the user/kernel boundary through an [attack surface](../attack-surfaces/), something has to go wrong inside the driver for that input to become dangerous. The vulnerability class describes *what* goes wrong: a size that is not checked, a pointer that outlives its object, a value that is read twice from memory the attacker controls. Understanding these classes is not just taxonomy for its own sake. It shapes how you read patches, where you focus during code review, and which AutoPiff rules you write.

The landscape is not uniform. Some classes, like [buffer overflow](buffer-overflow.md) and [use-after-free](use-after-free.md), dominate the CVE record because they arise naturally from the way C code manages memory and because the Windows pool allocator makes them reliably exploitable. Others, like [logic bugs](logic-bugs.md), are rarer in CVE counts but disproportionately impactful when they appear, since they bypass memory safety mitigations entirely. [TOCTOU/double-fetch](toctou-double-fetch.md) bugs occupy a middle ground: they require a race to trigger, which sounds unreliable until you realize that modern multi-core processors make the race winnable on almost every attempt.

The diagram below traces the path from initial trigger to exploitation primitive. A single trigger condition (say, an unchecked size field) can flow through different corruption types depending on context, and each corruption type yields a different primitive. This is why the same IOCTL handler bug might be classified as an integer overflow by one analyst and a buffer overflow by another; both are correct, because the integer overflow *causes* the buffer overflow. The classes are not mutually exclusive. They are lenses.

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

## How to read this section

Each vulnerability class page follows a consistent structure. It opens with the mechanics of how the bug class arises in real driver code, then walks through exploitation implications and the primitives an attacker gains. Detection strategies cover both manual approaches and AutoPiff rule references, so you can connect the theory to tooling immediately.

The classes are ordered roughly by exploitation frequency in the Windows kernel CVE record, but they are deeply interconnected. An [integer overflow](integer-overflow.md) produces a buffer overflow. A [race condition](race-conditions.md) produces a use-after-free. A [TOCTOU](toctou-double-fetch.md) bypasses a bounds check and enables a pool overflow. Reading across classes, rather than treating each in isolation, is how you develop intuition for the patterns that actually appear in Patch Tuesday diffs.

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

## The interplay between classes

One of the most important things to internalize is that vulnerability classes rarely exist in isolation during real exploitation. A typical Patch Tuesday CVE might involve an integer overflow that causes an undersized pool allocation, which leads to a heap buffer overflow, which corrupts an adjacent object's function pointer. That is three vulnerability classes collaborating in a single exploit chain. The [case studies](../case-studies/) section traces these chains in detail, showing how a trigger in one class flows through to a primitive via another.

Similarly, the boundary between [race conditions](race-conditions.md) and [use-after-free](use-after-free.md) is porous. Many UAF bugs are caused by races, and the race condition page covers the concurrency mechanics while the UAF page covers the memory reclamation exploitation. Reading both gives you the complete picture.

<div class="ks-next-pipeline">
  Next in the pipeline: <a href="../primitives/">Primitives</a> &rarr; How is the corruption converted into a reliable exploitation capability?
</div>
