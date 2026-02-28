# Mitigation Timeline

> When each Windows kernel defense landed and how it shifted attacker techniques.

## Overview

Windows kernel mitigations have accumulated over a decade. Each new defense raises the cost of exploitation -- but rarely eliminates it. Attackers adapt by finding primitives that work within the new constraints. This page maps each defense to the technique shift it caused.

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
  <span class="ks-figure-label">FIG — Mitigation Deployment Timeline</span>
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

## Impact on Exploitation

### Post-SMEP / SMAP (2013--2017)

**Blocked:** Running user-space shellcode from kernel context. Before SMEP, a write-what-where could redirect a function pointer to user-mode shellcode. SMAP extended this to reads -- the kernel can no longer fetch user pages either.

**Attacker adaptation:** Data-only attacks. Attackers now modify kernel data structures (tokens, PreviousMode) instead of executing shellcode. Pool spray + token swap became the standard endgame. See [Token Swapping](../primitives/exploitation/token-swapping.md).

### Post-Segment Heap (2020)

**Blocked:** Predictable pool layout. The legacy allocator used fixed-size buckets that made heap spraying reliable. Segment Heap added randomization, guard pages, and metadata checks.

**Attacker adaptation:** Spray objects with known sizes. Named pipe attributes ([Pipe Attributes](../primitives/arw/pipe-attributes.md)), I/O Ring structures ([I/O Ring](../primitives/exploitation/io-ring.md)), and WNF state data ([WNF State Data](../primitives/exploitation/wnf-state-data.md)) still land in predictable pool slots, so reclamation stays reliable despite the new allocator.

### Post-kCET (2022)

**Blocked:** ROP in kernel context. kCET uses hardware shadow stacks to verify return addresses. kCFG separately blocks function pointer overwrites via vtable corruption.

**Attacker adaptation:** kCFG-compliant primitives. [CVE-2026-21241](../case-studies/CVE-2026-21241.md) calls `RtlSetBit`/`RtlClearAllBits` -- legitimate indirect call targets that pass kCFG validation. The [bit-manipulation technique](../primitives/exploitation/bit-manipulation.md) stays inside the existing control flow graph.

### Post-CLFS Isolation (2024)

**Blocked:** Unvalidated BLF metadata offsets -- the most exploited single attack surface in the corpus. CLFS Isolation adds bounds checks on structure offsets and verifies integrity during log operations.

**Attacker adaptation:** Still evolving. Post-isolation CLFS CVEs ([CVE-2025-32713](../case-studies/CVE-2025-32713.md), [CVE-2026-20820](../case-studies/CVE-2026-20820.md)) show the isolation is incomplete -- new offset validation gaps keep appearing each Patch Tuesday.

## What's Still Missing

These attack patterns still work despite current mitigations:

- **File format parsing in kernel.** NTFS, FAT, and CLFS parse complex on-disk structures in ring 0. VHD mounting triggers this from user context. No sandbox or memory safety boundary protects these parsers.

- **IOCTL authorization model.** Windows has no mandatory access control for IOCTL codes. Each driver rolls its own checks, and many skip them. See [Anatomy of a Secure Driver](secure-driver-anatomy.md), anti-pattern 5.

- **BYOVD.** The Vulnerable Driver Blocklist is opt-in on most configurations and purely reactive -- drivers get blocklisted only after exploitation is observed. The signing model still loads old signed drivers. See [BYOVD](../reference/byovd.md).

- **Pool spray reliability.** Segment Heap added randomization, but practical exploitation still achieves reliable reclamation via I/O Ring, named pipes, and WNF objects. The hardening raises cost without preventing the technique.

## Cross-References

- [SMEP / SMAP](../mitigations/smep-smap.md) -- hardware page-level enforcement
- [kCFG / kCET](../mitigations/kcfg-kcet.md) -- control flow integrity and shadow stacks
- [VBS / HVCI](../mitigations/vbs-hvci.md) -- hypervisor-based code integrity
- [Pool Hardening](../mitigations/pool-hardening.md) -- Segment Heap and pool cookie details
- [Corpus Analytics](corpus-analytics.md) -- the data behind this timeline
- [Exploit Chain Patterns](exploit-chain-patterns.md) -- how chains adapted to each mitigation
