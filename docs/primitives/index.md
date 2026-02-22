# Primitives

<div class="ks-pipeline-pos">
  Driver Type &rarr; Attack Surface &rarr; Vuln Class &rarr; <span class="ks-active">Primitive</span> &rarr; Case Study
</div>

A vulnerability class describes what went wrong; a primitive describes what the attacker gains. This section catalogs the exploitation building blocks — the controlled capabilities that convert a memory corruption bug into reliable privilege escalation. Primitives split into two families: techniques that achieve arbitrary kernel read/write, and techniques that leverage that R/W for exploitation.

<div class="ks-figure" markdown>
  <span class="ks-figure-label">FIG_005 — Primitive Taxonomy</span>
  <svg viewBox="0 0 820 380" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Primitive taxonomy tree with Arbitrary R/W and Exploitation branches">
    <!-- Root -->
    <rect class="ks-box" x="310" y="10" width="200" height="36"/>
    <text class="ks-label" x="410" y="33" text-anchor="middle" fill="currentColor">PRIMITIVES</text>
    <!-- Branch lines -->
    <line class="ks-line" x1="360" y1="46" x2="200" y2="80"/>
    <line class="ks-line" x1="460" y1="46" x2="620" y2="80"/>
    <!-- Left branch: Arb R/W -->
    <rect class="ks-box" x="80" y="80" width="240" height="32"/>
    <text class="ks-label" x="200" y="101" text-anchor="middle" fill="currentColor">ARBITRARY R/W</text>
    <!-- Left leaves -->
    <line class="ks-line" x1="200" y1="112" x2="200" y2="130" opacity="0.4"/>
    <rect class="ks-box" x="20" y="135" width="160" height="26"/>
    <text class="ks-annotation" x="100" y="152" text-anchor="middle">Direct IOCTL R/W</text>
    <rect class="ks-box" x="20" y="170" width="160" height="26"/>
    <text class="ks-annotation" x="100" y="187" text-anchor="middle">Pool Overflow</text>
    <rect class="ks-box" x="20" y="205" width="160" height="26"/>
    <text class="ks-annotation" x="100" y="222" text-anchor="middle">MDL Mapping</text>
    <rect class="ks-box" x="20" y="240" width="160" height="26"/>
    <text class="ks-annotation" x="100" y="257" text-anchor="middle">Arb Incr/Decr</text>
    <rect class="ks-box" x="20" y="275" width="160" height="26"/>
    <text class="ks-annotation" x="100" y="292" text-anchor="middle">Write-What-Where</text>
    <rect class="ks-box" x="200" y="135" width="160" height="26"/>
    <text class="ks-annotation" x="280" y="152" text-anchor="middle">Registry-Based</text>
    <rect class="ks-box" x="200" y="170" width="160" height="26"/>
    <text class="ks-annotation" x="280" y="187" text-anchor="middle">DMA / MMIO</text>
    <rect class="ks-box" x="200" y="205" width="160" height="26"/>
    <text class="ks-annotation" x="280" y="222" text-anchor="middle">Pipe Attributes</text>
    <rect class="ks-box" x="200" y="240" width="160" height="26"/>
    <text class="ks-annotation" x="280" y="257" text-anchor="middle">Token Manipulation</text>
    <rect class="ks-box" x="200" y="275" width="160" height="26"/>
    <text class="ks-annotation" x="280" y="292" text-anchor="middle">PTE Manipulation</text>
    <!-- Vertical connector lines -->
    <line class="ks-line" x1="100" y1="130" x2="100" y2="300" opacity="0.15"/>
    <line class="ks-line" x1="280" y1="130" x2="280" y2="300" opacity="0.15"/>
    <!-- Right branch: Exploitation -->
    <rect class="ks-box" x="500" y="80" width="240" height="32"/>
    <text class="ks-label" x="620" y="101" text-anchor="middle" fill="currentColor">EXPLOITATION</text>
    <!-- Right leaves -->
    <line class="ks-line" x1="620" y1="112" x2="620" y2="130" opacity="0.4"/>
    <rect class="ks-box" x="460" y="135" width="160" height="26"/>
    <text class="ks-annotation" x="540" y="152" text-anchor="middle">Pool Spray / Feng Shui</text>
    <rect class="ks-box" x="460" y="170" width="160" height="26"/>
    <text class="ks-annotation" x="540" y="187" text-anchor="middle">Named Pipe Objects</text>
    <rect class="ks-box" x="460" y="205" width="160" height="26"/>
    <text class="ks-annotation" x="540" y="222" text-anchor="middle">I/O Ring</text>
    <rect class="ks-box" x="460" y="240" width="160" height="26"/>
    <text class="ks-annotation" x="540" y="257" text-anchor="middle">WNF State Data</text>
    <rect class="ks-box" x="460" y="275" width="160" height="26"/>
    <text class="ks-annotation" x="540" y="292" text-anchor="middle">Palette / Bitmap</text>
    <rect class="ks-box" x="640" y="135" width="170" height="26"/>
    <text class="ks-annotation" x="725" y="152" text-anchor="middle">KUSER_SHARED_DATA</text>
    <rect class="ks-box" x="640" y="170" width="170" height="26"/>
    <text class="ks-annotation" x="725" y="187" text-anchor="middle">PreviousMode Manip</text>
    <rect class="ks-box" x="640" y="205" width="170" height="26"/>
    <text class="ks-annotation" x="725" y="222" text-anchor="middle">Token Swapping</text>
    <rect class="ks-box" x="640" y="240" width="170" height="26"/>
    <text class="ks-annotation" x="725" y="257" text-anchor="middle">ACL / SD Manipulation</text>
    <!-- Vertical connector lines -->
    <line class="ks-line" x1="540" y1="130" x2="540" y2="300" opacity="0.15"/>
    <line class="ks-line" x1="725" y1="130" x2="725" y2="265" opacity="0.15"/>
  </svg>
  <p class="ks-figure-caption">19 primitives split between achieving arbitrary R/W (left) and leveraging it for exploitation (right).</p>
</div>

## Arbitrary Read/Write Primitives

Vulnerability patterns and driver behaviors that yield controlled kernel memory access.

| Primitive | Description |
|-----------|-------------|
| [Direct IOCTL R/W](arw/direct-ioctl-rw.md) | Drivers exposing direct memory read/write IOCTLs |
| [Pool Overflow](arw/pool-overflow.md) | Heap corruption of adjacent allocations |
| [MDL Mapping](arw/mdl-mapping.md) | Abusing MDL lock/map for arbitrary mapping |
| [Arb Increment/Decrement](arw/arb-increment-decrement.md) | Controlled increment/decrement at arbitrary address |
| [Write-What-Where](arw/write-what-where.md) | Controlled address and value write |
| [Registry-Based](arw/registry-based.md) | Passing controlled data via registry values |
| [DMA / MMIO](arw/dma-mmio.md) | Physical memory access via DMA or MMIO |
| [Pipe Attributes](arw/pipe-attributes.md) | Named pipe EA-based pool read/write |
| [Token Manipulation](arw/token-manipulation.md) | Overwriting token structures |
| [PTE Manipulation](arw/pte-manipulation.md) | Modifying page table entries |

## Exploitation Primitives

Techniques for converting a vulnerability into reliable exploitation.

| Primitive | Description |
|-----------|-------------|
| [Pool Spray / Feng Shui](exploitation/pool-spray-feng-shui.md) | Heap grooming for controlled layout |
| [Named Pipe Objects](exploitation/named-pipe-objects.md) | Pipe objects as spray and R/W gadgets |
| [I/O Ring](exploitation/io-ring.md) | I/O Ring mechanism for kernel R/W |
| [WNF State Data](exploitation/wnf-state-data.md) | WNF objects as pool spray primitives |
| [Palette / Bitmap](exploitation/palette-bitmap.md) | Legacy GDI object exploitation |
| [KUSER_SHARED_DATA](exploitation/kuser-shared-data.md) | Fixed-address data structure abuse |
| [PreviousMode Manipulation](exploitation/previous-mode-manipulation.md) | KTHREAD.PreviousMode overwrite |
| [Token Swapping](exploitation/token-swapping.md) | Process token pointer replacement |
| [ACL / SD Manipulation](exploitation/acl-sd-manipulation.md) | Security descriptor modification |

<div class="ks-next-pipeline">
  Next in the pipeline: <a href="../case-studies/">Case Studies</a> &rarr; See the full chain in action across 28 real CVEs.
</div>
