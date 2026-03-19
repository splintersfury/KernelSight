# Mitigation Timeline

> When each Windows kernel defense landed and how it shifted attacker techniques.

Windows kernel mitigations have accumulated over more than a decade. Each new defense raises the cost of exploitation but rarely eliminates it. Attackers adapt by finding primitives that work within the new constraints, and the cycle continues. The result is a co-evolutionary process where each mitigation deployment produces a visible shift in exploitation technique. This page maps those shifts: what each defense blocked, and exactly how attackers responded.

## Timeline Table

| Windows Version | Build | Year | Mitigations Introduced |
|-----------------|-------|------|------------------------|
| 8.1 | 9600 | 2013 | SMEP enforcement, kernel pool cookie hardening |
| 10 v1507 | 10240 | 2015 | Kernel VA Shadow (KASLR), CFG for user-mode |
| 10 v1607 | 14393 | 2016 | Kernel Control Flow Guard (kCFG), VBS initial release |
| 10 v1703 | 15063 | 2017 | HVCI (Hypervisor-enforced Code Integrity), Arbitrary Code Guard (ACG) |
| 10 v1709 | 16299 | 2017 | SMAP enforcement, Kernel Data Protection (KDP) preview |
| 10 v1809 | 17763 | 2018 | Retpoline (Spectre v2), import address filtering |
| 10 v1903 | 18362 | 2019 | Kernel pool type isolation, KASAN debug builds |
| 10 v2004 | 19041 | 2020 | Segment Heap for kernel pool, pool randomization |
| 10 v21H2 | 19044 | 2021 | KDP general availability, enhanced KASLR entropy |
| 11 v21H2 | 22000 | 2021 | VBS / HVCI on by default (new hardware), stack protection |
| 11 v22H2 | 22621 | 2022 | Kernel CET (kCET) shadow stacks, Vulnerable Driver Blocklist |
| 11 v23H2 | 22631 | 2023 | Enhanced kCET enforcement, smart app control |
| 11 v24H2 | 26100 | 2024 | CLFS isolation, hardened Secure Pool, admin-less by default |

<div class="ks-figure" markdown>
  <span class="ks-figure-label">FIG -- Mitigation Deployment Timeline</span>
  <svg viewBox="0 0 780 200" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Horizontal timeline showing when major kernel mitigations were deployed from 2013 to 2024">
    <!-- Timeline axis -->
    <line class="ks-line" x1="40" y1="80" x2="740" y2="80"/>
    <!-- Year ticks -->
    <line class="ks-line" x1="40" y1="76" x2="40" y2="84"/>
    <text class="ks-annotation" x="40" y="98" text-anchor="middle">2013</text>
    <line class="ks-line" x1="100" y1="76" x2="100" y2="84"/>
    <text class="ks-annotation" x="100" y="98" text-anchor="middle">2015</text>
    <line class="ks-line" x1="160" y1="76" x2="160" y2="84"/>
    <text class="ks-annotation" x="160" y="98" text-anchor="middle">2016</text>
    <line class="ks-line" x1="220" y1="76" x2="220" y2="84"/>
    <text class="ks-annotation" x="220" y="98" text-anchor="middle">2017</text>
    <line class="ks-line" x1="280" y1="76" x2="280" y2="84"/>
    <text class="ks-annotation" x="280" y="98" text-anchor="middle">2018</text>
    <line class="ks-line" x1="340" y1="76" x2="340" y2="84"/>
    <text class="ks-annotation" x="340" y="98" text-anchor="middle">2019</text>
    <line class="ks-line" x1="400" y1="76" x2="400" y2="84"/>
    <text class="ks-annotation" x="400" y="98" text-anchor="middle">2020</text>
    <line class="ks-line" x1="460" y1="76" x2="460" y2="84"/>
    <text class="ks-annotation" x="460" y="98" text-anchor="middle">2021</text>
    <line class="ks-line" x1="520" y1="76" x2="520" y2="84"/>
    <text class="ks-annotation" x="520" y="98" text-anchor="middle">2022</text>
    <line class="ks-line" x1="580" y1="76" x2="580" y2="84"/>
    <text class="ks-annotation" x="580" y="98" text-anchor="middle">2023</text>
    <line class="ks-line" x1="640" y1="76" x2="640" y2="84"/>
    <text class="ks-annotation" x="640" y="98" text-anchor="middle">2024</text>
    <!-- Milestone markers (above line) -->
    <line class="ks-line" x1="40" y1="80" x2="40" y2="55" stroke-dasharray="3,3"/>
    <text class="ks-label" x="40" y="50" text-anchor="middle" font-size="7">SMEP</text>
    <line class="ks-line" x1="100" y1="80" x2="100" y2="35" stroke-dasharray="3,3"/>
    <text class="ks-label" x="100" y="30" text-anchor="middle" font-size="7">KASLR</text>
    <line class="ks-line" x1="160" y1="80" x2="160" y2="55" stroke-dasharray="3,3"/>
    <text class="ks-label" x="160" y="50" text-anchor="middle" font-size="7">kCFG</text>
    <line class="ks-line" x1="220" y1="80" x2="220" y2="35" stroke-dasharray="3,3"/>
    <text class="ks-label" x="220" y="30" text-anchor="middle" font-size="7">HVCI</text>
    <line class="ks-line" x1="250" y1="80" x2="250" y2="55" stroke-dasharray="3,3"/>
    <text class="ks-label" x="250" y="50" text-anchor="middle" font-size="7">SMAP</text>
    <line class="ks-line" x1="400" y1="80" x2="400" y2="35" stroke-dasharray="3,3"/>
    <text class="ks-label" x="400" y="22" text-anchor="middle" font-size="7">Segment</text>
    <text class="ks-label" x="400" y="32" text-anchor="middle" font-size="7">Heap</text>
    <line class="ks-line" x1="520" y1="80" x2="520" y2="55" stroke-dasharray="3,3"/>
    <text class="ks-label" x="520" y="50" text-anchor="middle" font-size="7">kCET</text>
    <line class="ks-line" x1="640" y1="80" x2="640" y2="35" stroke-dasharray="3,3"/>
    <text class="ks-label" x="640" y="22" text-anchor="middle" font-size="7">CLFS</text>
    <text class="ks-label" x="640" y="32" text-anchor="middle" font-size="7">Isolation</text>
    <!-- CVE density bands (below line) -->
    <text class="ks-annotation" x="390" y="120" text-anchor="middle">CVE density</text>
    <rect class="ks-box" x="40" y="125" width="60" height="6" rx="0" opacity="0.15"/>
    <rect class="ks-box" x="100" y="125" width="120" height="6" rx="0" opacity="0.2"/>
    <rect class="ks-box" x="220" y="125" width="120" height="6" rx="0" opacity="0.2"/>
    <rect class="ks-box" x="340" y="125" width="120" height="6" rx="0" opacity="0.3"/>
    <rect class="ks-box" x="460" y="125" width="60" height="6" rx="0" opacity="0.5"/>
    <rect class="ks-box" x="520" y="125" width="60" height="6" rx="0" opacity="0.7"/>
    <rect class="ks-box" x="580" y="125" width="60" height="6" rx="0" opacity="0.9"/>
    <rect class="ks-box" x="640" y="125" width="60" height="6" rx="0" opacity="0.6"/>
    <text class="ks-annotation" x="390" y="155" text-anchor="middle">Darker = more CVEs disclosed in that period</text>
  </svg>
  <p class="ks-figure-caption">Each milestone marks when a major mitigation first shipped. CVE density bands approximate disclosure volume -- 2025 dominates the corpus due to expanded Patch Tuesday coverage.</p>
</div>

## How Each Mitigation Shifted the Game

### Post-SMEP / SMAP (2013-2017)

**What it blocked:** Running user-space shellcode from kernel context. Before SMEP, a write-what-where could redirect a function pointer to user-mode shellcode. The attacker's payload sat at a known user-mode address, executed with kernel privileges, and returned. SMAP extended this by preventing the kernel from reading user-mode pages at all, closing the fallback technique of staging fake kernel structures in user memory.

**How attackers adapted:** Data-only attacks emerged as the dominant strategy. Rather than executing custom code, attackers began modifying kernel data structures directly: copying the SYSTEM token into the current process, flipping `PreviousMode` to gain kernel-mode access checks, or manipulating security descriptors. Pool spray plus token swap became the standard endgame, a pattern that persists to this day. See [Token Swapping](../primitives/exploitation/token-swapping.md).

### Post-Segment Heap (2020)

**What it blocked:** Predictable pool layout. The legacy NT allocator used fixed-size buckets with deterministic allocation ordering that made heap spraying trivially reliable. An attacker could predict exactly where their spray objects would land relative to the target allocation. The Segment Heap added randomized allocation order, guard pages, and metadata checks that disrupted this predictability.

**How attackers adapted:** They found spray objects with known sizes that still land in predictable pool slots. Named pipe attributes ([Pipe Attributes](../primitives/arw/pipe-attributes.md)), I/O Ring structures ([I/O Ring](../primitives/exploitation/io-ring.md)), and WNF state data ([WNF State Data](../primitives/exploitation/wnf-state-data.md)) each provide controlled-size allocations in specific pool buckets. Spraying thousands of these objects achieves reliable reclamation despite the randomized allocator, turning a deterministic technique into a probabilistic one with success rates above 90%.

### Post-kCET (2022)

**What it blocked:** ROP in kernel context. kCET uses hardware shadow stacks to verify that return addresses have not been tampered with. kCFG separately blocks function pointer overwrites by validating indirect call targets against a compiler-generated bitmap of legitimate entry points.

**How attackers adapted:** kCFG-compliant primitives appeared. [CVE-2026-21241](../case-studies/CVE-2026-21241.md) demonstrates the technique by redirecting a controlled callback to `RtlSetBit` and `RtlClearAllBits`, both of which are legitimate indirect call targets that pass kCFG validation. The [bit-manipulation technique](../primitives/exploitation/bit-manipulation.md) operates entirely within the existing control flow graph, achieving arbitrary bit modification without violating any CFI check.

### Post-CLFS Isolation (2024)

**What it blocked:** Unvalidated BLF metadata offsets, which constituted the most exploited single attack surface in the corpus. CLFS Isolation adds bounds checks on structure offsets and integrity verification during log operations, targeting the exact vulnerability pattern that produced 15 CVEs.

**How attackers adapted:** The adaptation is still evolving. Post-isolation CLFS CVEs ([CVE-2025-32713](../case-studies/CVE-2025-32713.md), [CVE-2026-20820](../case-studies/CVE-2026-20820.md)) show that the isolation is incomplete. New offset validation gaps keep appearing each Patch Tuesday, suggesting that the BLF format's complexity continues to outpace the bounds checking. The long-term question is whether Microsoft will continue patching individual offsets or eventually move to a fundamentally different parser architecture.

## What the Mitigations Have Not Solved

Despite a decade of deployment, four attack patterns remain viable on fully updated Windows 11 24H2 systems.

**File format parsing in kernel** continues to run complex parsers for NTFS, FAT, and CLFS structures in Ring 0 without any memory safety boundary. VHD mounting triggers these parsers from user context, meaning any user can exercise the full parser attack surface. No sandbox, no memory-safe language runtime, and no hypervisor protection covers these code paths.

**IOCTL authorization** has no mandatory framework. Windows provides no kernel-level MAC for IOCTL codes. Each driver implements its own access checks (or skips them). The pattern repeats across the corpus: a driver creates a device with a permissive ACL, and the IOCTL handlers trust their callers. See anti-pattern 5 in [Secure Driver Anatomy](secure-driver-anatomy.md).

**BYOVD** remains viable because the Vulnerable Driver Blocklist is opt-in on most configurations and purely reactive. Drivers get blocklisted only after exploitation is observed in the wild. The signing model still loads old signed drivers, and some (like NVIDIA's GPU drivers) cannot be blocklisted without breaking core functionality. See [BYOVD](../reference/byovd.md).

**Pool spray reliability** has not been eliminated by the Segment Heap. The hardening raises the cost (more spray iterations, lower success rate per attempt) without preventing the technique. Practical exploitation still achieves reliable reclamation via I/O Ring, named pipes, and WNF objects. The Segment Heap shifted pool exploitation from deterministic to probabilistic, but probabilistic with a 90%+ success rate is still viable for most threat actors.

## Cross-References

- [SMEP / SMAP](../mitigations/smep-smap.md) -- hardware page-level enforcement
- [kCFG / kCET](../mitigations/kcfg-kcet.md) -- control flow integrity and shadow stacks
- [VBS / HVCI](../mitigations/vbs-hvci.md) -- hypervisor-based code integrity
- [Pool Hardening](../mitigations/pool-hardening.md) -- Segment Heap and pool cookie details
- [Corpus Analytics](corpus-analytics.md) -- the data behind this timeline
- [Exploit Chain Patterns](exploit-chain-patterns.md) -- how chains adapted to each mitigation
