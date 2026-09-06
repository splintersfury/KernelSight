---
description: "What a kernel read or write primitive defeats on a given Windows build and CPU. Every technique carries a dated verdict and a basis tier."
---

# Bypass matrix

<div class="ks-pipeline-pos">
  <a href="../driver-types/">Getting in</a> &rarr; <span class="ks-hinge">kernel access</span> &rarr; <span class="ks-half">What stops them</span> <span class="ks-active">Everything at once</span>
</div>

Same Windows version, same HVCI checkbox, different silicon, different answers. Pick a
configuration and every inventory on the site re-evaluates against it.

This page does not restate the per-defense inventories. It reads them, so a defense page joins
the matrix simply by existing.

## Where the defenses sit

A defense is filed here by the layer of the asset it protects, not by what enforces it.
Protected Process Light is enforced by the kernel but guards a user-mode process, so it is a
user-layer defense. That distinction is the whole reason a single primitive gives such
different answers across the roster.

<div class="ks-figure" markdown>
  <span class="ks-figure-label">FIG_007: Reach of a kernel read/write primitive</span>
  <svg viewBox="0 0 820 396" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Three privilege bands. A kernel read or write primitive reaches the kernel-layer and user-layer bands but not the VTL1 band above it.">

    <!-- VTL1: above the primitive -->
    <rect class="ks-box" x="40" y="30" width="620" height="74" stroke-dasharray="4 3"/>
    <text class="ks-label" x="56" y="52">VTL1: SECURE KERNEL</text>
    <text class="ks-annotation" x="56" y="70">Credential Guard, HyperGuard, the HVCI verifier itself</text>
    <text class="ks-annotation" x="56" y="86">A VTL0 primitive does not read or write here, however complete it is</text>

    <!-- the boundary that actually matters -->
    <line class="ks-line" x1="40" y1="122" x2="660" y2="122" stroke-dasharray="6 4"/>
    <text class="ks-annotation" x="660" y="118" text-anchor="end">hypervisor boundary</text>

    <!-- VTL0 kernel -->
    <rect class="ks-box" x="40" y="140" width="620" height="98"/>
    <text class="ks-label" x="56" y="162">VTL0 KERNEL: 19 DEFENSES</text>
    <text class="ks-annotation" x="56" y="182">Protects kernel-resident assets: code integrity, page tables, pool metadata,</text>
    <text class="ks-annotation" x="56" y="196">address layout, dispatch tables</text>
    <text class="ks-annotation" x="56" y="220">DSE &middot; HVCI &middot; kCFG &middot; kCET &middot; KDP &middot; HLAT &middot; KASLR &middot; PatchGuard &middot; SMEP &middot; SMAP</text>

    <!-- VTL0 user -->
    <rect class="ks-box" x="40" y="272" width="620" height="98"/>
    <text class="ks-label" x="56" y="294">VTL0 USER: 11 DEFENSES</text>
    <text class="ks-annotation" x="56" y="314">Protects user-mode assets, but the decision is stored and enforced in the</text>
    <text class="ks-annotation" x="56" y="328">kernel, which is why a kernel write reaches all of it</text>
    <text class="ks-annotation" x="56" y="352">PP/PPL &middot; LSA Protection &middot; ETW-Ti &middot; EDR callbacks &middot; WDAC &middot; AppLocker &middot; Smart App Control &middot; UAC &middot; AMSI</text>

    <!-- reach bracket -->
    <path class="ks-arrow" d="M700 140 L716 140 L716 370 L700 370"/>
    <line class="ks-arrow" x1="716" y1="255" x2="732" y2="255"/>
    <text class="ks-label" x="740" y="248">REACH OF</text>
    <text class="ks-label" x="740" y="262">KERNEL R/W</text>

    <!-- what stops it -->
    <line class="ks-line" x1="700" y1="67" x2="732" y2="67" stroke-dasharray="3 3"/>
    <text class="ks-annotation" x="740" y="64">out of</text>
    <text class="ks-annotation" x="740" y="76">reach</text>
  </svg>
</div>

Read the picture as the answer to one question. A primitive that can write anywhere in kernel
memory owns both lower bands outright, because every decision those defenses rely on is stored
there. It owns none of the top band, because that memory belongs to a different privilege level
enforced by hardware the kernel does not control.

That is why Protected Process Light falls to a single byte write while Credential Guard does
not move at all, even though both protect a user-mode process. The asset moved; the enforcement
did not.

## The matrix

<div id="ks-matrix"></div>

Basis tiers: `tested` means reproduced in lab. `cited` means a resolving public source.
`inferred` means reasoned from mechanism and not yet confirmed. An inferred verdict is a
research lead, not a finding.
