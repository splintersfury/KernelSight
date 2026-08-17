# KernelSight Bypass Registry — Design

**Date:** 2026-08-17
**Status:** Approved, pending implementation plan
**Scope:** Windows kernel only

## Problem

KernelSight is a driver-centric pipeline: Driver Types → Attack Surfaces → Vulnerability
Classes → Primitives → Case Studies, with Mitigations as nine cross-cutting prose pages.
In that architecture a *bypass* is not a first-class object. It is a paragraph inside a
mitigation page.

Three consequences, all observed in the current tree:

1. **Techniques go missing.** `SeCiCallbacks` pointer swap — the surviving DSE bypass as of
   mid-2026, effective against HVCI, HLAT, and kCET simultaneously — appears nowhere in 241
   pages, while `kCET` has 13 mentions. There is no slot for it to occupy.
2. **Claims go stale silently.** `primitives/arw/pte-manipulation.md:51` asserts that
   "physical page frame number remapping may still succeed for data (non-executable) pages."
   That was true in 2021. On any HLAT-enabled machine it is false: the processor walks
   hypervisor-owned page tables, so mutating the guest PTE's PFN accomplishes nothing.
   Nothing in the repository structure was capable of flagging it.
3. **Defenses are flattened to one bit.** Pages treat HVCI as a single switch. The
   determining factors are the exact build *and* the exact CPU — HLAT requires 11th-generation
   Intel or newer, so "24H2 with HVCI on" describes two materially different machines with
   different answers for the same technique.

Additionally, the corpus stopped in March 2026 while the field did not, and the defense roster
itself is incomplete: PatchGuard has one passing mention, HyperGuard/SKPG has zero, and
HLAT/HVPT, MBEC/GMET, DSE-as-a-target, and the vulnerable-driver blocklist as an enforcement
mechanism have no pages at all.

## Goal

Make KernelSight the comprehensive reference for Windows kernel bypasses and techniques, where
"comprehensive" is a computed number rather than an aspiration: for every enumerated Windows
kernel defense, a maintained inventory of known bypasses, each carrying a dated verdict with a
resolving citation.

## Non-goals

- Any non-Windows kernel. No Linux, no XNU, no hypervisor escapes.
- An ATT&CK-style tactic/sub-technique framework. Stable IDs only.
- A UEFI or bootkit section. Pre-boot impact is documented where a driver bug produces it, but
  no new section is built for it.
- Re-homing the existing 57 primitive pages under a new schema. They stay as they are and get
  linked.
- Verdicts for pre-2016 techniques nobody will retest. Those get `status: historical` and a
  build ceiling.

## Architecture

### Data model

Three new files in `index/`, joining the existing `cve_index.yaml`, `driver_index.yaml`,
`techniques.yaml`, and `autopiff_rule_map.yaml`.

Note on the existing `techniques.yaml`: despite its name it is a *page registry* — 47 entries,
one per docs page, keyed on `slug`/`section`/`path`/`cves`/`related`/`status`. It is not
touched by this design and is not the bypass registry.

#### `index/defenses.yaml`

The enumeration of what there is to bypass. Promotes the hand-written catalog in
`mitigations/index.md` to data and completes it.

```yaml
version: 1
defenses:
  - id: hlat
    name: "HLAT / HVPT (Intel VT-rp)"
    page: docs/mitigations/hlat.md
    protects: "Guest page-table translation integrity"
    introduced: { build: "26100", note: "default on Win11 24H2" }
    requires_hardware: intel-11th-plus
    enforced_by: hypervisor
    status: current            # current | deprecated | historical
```

Roster — 20 entries. Ten have pages; ten do not.

| ID | Page state |
|---|---|
| `smep` | exists (shared page with `smap`) |
| `smap` | exists (shared page with `smep`) |
| `kcfg` | exists (shared page with `kcet`) |
| `kcet` | exists (shared page with `kcfg`) |
| `hvci` | exists |
| `kdp` | exists |
| `pool-hardening` | exists |
| `secure-pool` | exists |
| `acg` | exists |
| `kaslr` | exists |
| `dse` | **new** |
| `hlat` | **new** |
| `mbec` | **new** (covers AMD GMET) |
| `patchguard` | **new** |
| `hyperguard` | **new** |
| `blocklist-wdac` | **new** |
| `secure-kernel` | **new** |
| `kernel-dma-protection` | **new** |
| `type-isolation` | **new** (promoted out of `pool-hardening.md`) |
| `protected-process` | **new** |

`smep`/`smap` and `kcfg`/`kcet` are separate defense IDs sharing one page each: they block
different things and are bypassed differently, but splitting the pages would churn published
URLs for no reader benefit.

`type-isolation` is promoted because `primitives/exploitation/primitive-matrix.md` already
treats it as a distinct killer in its `Blocked By` column, so burying it inside
`pool-hardening.md` contradicts data already written.

#### `index/bypass_index.yaml`

```yaml
version: 1
bypasses:
  - id: KS-B0007
    name: "SeCiCallbacks pointer swap"
    aka: ["CI callback table swap"]
    defeats: [dse, hvci]              # REQUIRED; each must resolve in defenses.yaml
    category: dse-bypass              # dse-bypass | kaslr-leak | cfi-bypass | data-only
                                      # | pool-control | integrity-check-evasion
                                      # | privilege-object | hardware-path
    depth: page                       # page | row
    requires:
      primitive: write-what-where     # must resolve to a docs/primitives/ page
      privilege: admin                # admin | medium-il | low-il | sandboxed
      provider_driver: null           # optional; resolves in driver_index.yaml
    mechanism: >
      One paragraph. What is written where, and why the defense does not notice.
    verdicts:                         # append-only, newest first
      - as_of: 2026-06-14
        builds: "26100-26200"
        platform: { hvci: true, hlat: true, kcet: true, cpu: intel-11th-plus }
        works: true
        basis: cited                  # tested | cited | inferred
        confidence: high
        source: ref-hvci-state-2026   # resolves in refs.yaml
        evidence: null                # path under verification/ when basis=tested
    killed_by: null                   # { defense: <id>, build: "<build>" } when dead
    credit: [cryptoplague]
    related_cves: []
    detection: >
      What a defender observes.
```

Five load-bearing decisions:

**`status` is derived, never authored.** It falls out of the newest verdict. A hand-maintained
status field is a field that goes stale silently, which is exactly the `pte-manipulation.md:51`
failure mode.

**`verdicts` is an append-only dated list.** Each entry renders as a row in a per-technique
timeline, so history is visible rather than overwritten, and tooling can flag any verdict older
than 12 months as needing review — turning staleness from an invisible defect into a rendered
badge.

**`platform` carries CPU features, not only build numbers.** A build-only schema cannot express
that the same build on different silicon yields different answers, which is the single most
important fact about the 2026 bypass landscape.

**`defeats` is required and must resolve.** This is the completeness constraint. It is what
makes coverage computable: defenses with a reviewed bypass inventory, over total defenses.

**`requires.provider_driver` is optional but necessary.** Some techniques need a specific
vulnerable driver, not an abstract primitive. The unelevated KKYUM.sys chain does not work
without `eneio64.sys` mapping physical memory to defeat KASLR; describing it as merely
"requires kernel read" understates it.

#### `index/refs.yaml`

One entry per source: `id`, author, title, URL, date, type (`talk` | `post` | `advisory` |
`ms-doc` | `cve`). Bypasses cite by ID, so a dead link is fixed once and every verdict citing
it stays intact.

### Page architecture

New `Bypasses` tab in `mkdocs.yml` nav, immediately after `Mitigations` — a reader needs the
defense before the technique that defeats it. `Mitigations` keeps its name and every existing
URL, gaining ten pages for the defenses that lack one.

`depth: page | row` prevents page explosion. `row` bypasses appear only in matrix and inventory
tables. `page` bypasses — alive ones, plus historically load-bearing dead ones — get prose. The
per-defense inventory renders *onto the defense page*, so `mitigations/dse.md` ends with the
live table of everything defeating DSE. No structural duplication; the section starts small and
earns pages.

### The matrix

`docs/bypasses/index.md` is the primary artifact. Rows are bypasses grouped by defense.
Columns are *platform configurations*, not defenses:

| | Win10, no VBS | 22H2 + HVCI | 24H2 + HVCI, pre-11th-gen | 24H2 + HVCI + HLAT + kCET | 26100/26200, all on |
|---|---|---|---|---|---|
| `g_CiOptions` page swap | ✓ | ✓ | ✓ | ✗ HLAT | ✗ HLAT |
| `SeCiCallbacks` swap | ✓ | ✓ | ✓ | ✓ | ✓ |
| ROP via signed kernel code | ✓ | ✓ | ✗ kCET | ✗ kCET | ✗ kCET |
| Disk DMA → Hyper-V | ✓ | ✓ | ✓ | ✓ | ✓ (IOMMU only) |
| SIDT KASLR leak | ✓ | ✓ | ✓ | ✓ | ✗ decoy base |

The two middle columns are the point: same Windows version, same HVCI checkbox, different
answers. No public resource lays this out, and the current pages cannot express it. Each cell
carries its basis tier so a reader sees which verdicts are tested, cited, or merely inferred.

The dashboard gains the interactive form — pick build, CPU features, and starting privilege,
get what is live on that machine — reusing the existing yaml → json → JS pattern of the CVE
explorer.

### Generated blocks

Every generated table sits between markers:

```
<!-- KS:GENERATED bypass-table defense=dse -->
<!-- /KS:GENERATED -->
```

`render_bypasses.py` rewrites only between markers, so hand-written narrative is never
clobbered.

### Tooling

| Script | State | Responsibility |
|---|---|---|
| `scripts/validate_index.py` | new | Schema and referential integrity; staleness warnings |
| `scripts/render_bypasses.py` | new | Marker blocks and the matrix |
| `scripts/verify_bypass.py` | new | Drives lab verification via `qga` |
| `scripts/build_dashboard_data.py` | extend | Emit defenses and bypasses into `dashboard-data.json` |

`validate_index.py` enforces: every `defeats` resolves in `defenses.yaml`; every
`requires.primitive` resolves to an existing page under `docs/primitives/`; every
`requires.provider_driver`, when present, resolves in `driver_index.yaml`; every `source`
resolves in `refs.yaml`; every verdict carries `as_of`, `basis`, and `confidence`; and any
verdict older than 12 months emits a review warning rather than passing silently.

No new CI workflow. `.github/workflows/deploy-pages.yml` already runs
`build_dashboard_data.py` before `mkdocs build`; validate and a render-drift check slot into
that same job, so a schema violation or an out-of-sync generated block fails the deploy.

### Maintenance

`collector/sources/security_blogs.py` is already a feedparser-driven source and
`collector/pr_manager.py` already opens PRs. Extending the feed set to technique-bearing
sources — afflicted.sh, TrustedSec, Connor McGarr, Satoshi Tanda, Project Zero, the offensive
conference circuit — makes collected items land as candidate bypass entries in a PR for
accept/reject. This is what prevents a repeat of the March-to-August 2026 drift.

## Verification

Verdicts are cited by default and lab-verified where feasible. `basis` records which:
`tested` | `cited` | `inferred`.

The lab is KVM/libvirt only. Never VMware, never `vmmon` or `vmnet`. `lab/tools/qga.py`
already provides guest exec. Three pinned Windows guests: 22H2, 24H2/26100, 26200.

**What KVM can verify.** The entire build-26200 leak-sanitization wave requires no VBS at all —
SIDT returning a decoy base (`0xFFFFF80000001000`), `SystemBigPoolInformation` address
scrubbing, thread-class field zeroing, System `PEB.Ldr` nulled, desktop-heap kernel pointers
converted to relative offsets. All plain build behavior, testable in a KVM guest given a driver
providing read. This is the freshest and least-documented tranche in the corpus, and it covers
the leftmost matrix columns plus plain nested HVCI.

**What KVM cannot verify.** The two rightmost columns. kCET needs a CET-capable host CPU plus
KVM support reaching the guest; HLAT/VT-rp needs 11th-generation Intel and nested exposure that
is not realistically available. HLAT-gated verdicts therefore remain `basis: cited`, with the
untested state rendered explicitly rather than blurred. Testing those columns requires
bare-metal 11th-gen-or-newer Intel hardware. This limitation is stated rather than papered
over.

Artifacts land in `verification/<bypass-id>/<date>/`: harness, raw output, guest build and CPU
feature capture, and a `result.json` that the verdict's `evidence` field points at. Entry
point: `verify_bypass.py --id KS-B0007 --guest win11-26200`.

## Workstreams

**W0 — Revive the repo.** Complete. Moved from `archive/cold/` back to `~/Documents/KernelSight`
per `archive/ARCHIVE_MANIFEST_20260625.txt`; branch `feat/bypass-registry`; toolchain confirmed
(mkdocs 1.6.1, pyyaml, `build_dashboard_data.py` regenerates 64 drivers / 18×11 matrix).
Remaining: seven untracked PNGs plus `.playwright-mcp/` and `excalidraw.log` in the repo root
become `docs/assets/` content or get gitignored. AutoPiff stays archived; only
`tooling/autopiff-integration.md` references it.

**W1 — Schema and roster.** `defenses.yaml` (20 entries), `refs.yaml`, `bypass_index.yaml`
first tranche, `validate_index.py` built test-first.

**W2 — Render and matrix.** `render_bypasses.py`, marker blocks, `docs/bypasses/index.md`,
dashboard extension, CI wiring. First milestone worth showing: the matrix renders from data and
coverage is computed.

**W3 — Ten missing defense pages**, in order: DSE, HLAT, PatchGuard, HyperGuard,
Blocklist/WDAC, MBEC, Secure Kernel, Kernel DMA Protection, Type Isolation,
Protected Process / PPL.

**W4 — Bypass prose pages** for `depth: page` entries.

**W5 — Stale-content fixes.** The false `pte-manipulation.md:51` PFN-remapping claim; the
`kaslr-bypasses.md` timeline stopping at 24H2 and its "four remaining vectors" list omitting
the physical-memory-mapping-driver route; `primitive-matrix.md` gaining 26200 rows in its
existing `Max Build`/`Blocked By` columns; the desktop-heap-offset note on `palette-bitmap.md`;
the hardware-gating caveat on `vbs-hvci.md`; the Hyper-V-runtime-hijack and IOMMU-only framing
on `dma-mmio.md`.

**W6 — Three missing case studies.** KKYUM.sys (WHQL-signed, unblocklisted, nine IOCTLs
including `MmCopyVirtualMemory` arbitrary read/write and `win32kbase!ValidateHwnd` DKOM),
amwrtdrv.sys (AOMEI Backupper 8.4.0, no security descriptor, raw disk access; related
CVE-2026-12780 filed against 8.3.0), and eneio64.sys/CVE-2020-12446 (physical memory mapping,
currently only a table row in `loldrivers-analysis.md`). Each gains a `cve_index.yaml` entry
and a `loldrivers-analysis.md` row. For amwrtdrv the GPT-redirection-to-ESP pre-boot chain is
documented as impact; no UEFI section is built.

**W7 — Lab verification**, starting with the 26200 sanitization tranche.

**Order: W0 → W5 → W1 → W2 → W3 and W6 in parallel → W4 and W7.**

W5 precedes the schema work deliberately: it is small, needs no tooling, and retires a claim
that is currently wrong on any modern machine. That should not wait behind a data-model
refactor.

## Definition of done — phase 1

- All 20 defenses enumerated in `defenses.yaml`.
- Every bypass whose derived status is `alive` carries at least one dated verdict with a
  citation resolving in `refs.yaml`.
- `docs/bypasses/index.md` matrix renders from data.
- Coverage — defenses with a reviewed bypass inventory over total defenses — is computed and
  displayed.
- CI fails on schema violations and on generated-block drift.

## Risks

**The matrix invites overconfidence.** A ✓ from a cited source reads identically to a ✓ from a
tested one unless the basis tier is rendered prominently. Mitigation: basis tier is displayed
in-cell, not in a footnote.

**Verdict rot.** The 12-month review warning is the control, but a warning nobody reads is not
a control. Mitigation: the review badge renders on the public page, not only in CI output.

**Roster drift.** A defense Microsoft ships in 2027 that nobody adds to `defenses.yaml` makes
coverage read 100% while being incomplete. Mitigation: the collector's feed sweep covers
Microsoft security documentation, and coverage is reported as "N of N enumerated defenses,"
which names the assumption rather than hiding it.
