# KernelSight Capability Spine: Amendment to the Bypass Registry Design

**Date:** 2026-09-03
**Status:** Approved, pending implementation plan
**Amends:** `2026-08-17-kernelsight-bypass-registry-design.md`
**Scope:** Windows only. Kernel access as the means; kernel-layer and user-layer defenses as the targets.

## Relationship to the August design

The August design is not replaced. Its data model, its verdict semantics, its delivery order
and its bypass inventory all carry over unchanged. This amendment changes three things and adds
one roster:

1. **The thesis becomes explicit and sits on the site**, rather than being implied by the
   section list.
2. **The target layer becomes a first-class axis.** August enumerated twenty defenses, all but
   one of them protecting kernel-layer assets. The reference is incomplete without the defenses
   that protect user-layer assets and are defeated from the kernel.
3. **The navigation regroups** around means and targets, and the homepage leads with coverage
   rather than corpus size.

Plus: **the Bypass Navigator, shipped after the August design was written, is adopted as the
phase-1 bypass registry** instead of the hand-authored matrix that design proposed. See
"The navigator is the registry".

## Problem this amendment solves

The August design set out to make KernelSight "the comprehensive reference for Windows kernel
bypasses and techniques". Read literally, that scopes the work to defenses of the kernel. But
the corpus already contains material that does not fit: the DOG toolkit inventory in the August
design lists PPL modification, LSASS `PatchWDigest`, LSASS raw-page dump, LSASS minidump with
PPL zeroing, and suspension of protected processes. Those are user-layer assets. August filed
them under a single `protected-process` defense and moved on.

That is the wrong shape for two reasons.

**It understates what the corpus is for.** A reader arriving with a kernel write primitive is
not primarily asking whether they can defeat KDP. They are asking what the primitive is worth:
whether it reaches LSASS, whether it silences the EDR sensor, whether it survives Credential
Guard. Those questions have answers, the answers differ, and nothing in the current structure
distinguishes them.

**It hides the most valuable negative result in the corpus.** Credential Guard is the case where
a complete VTL0 kernel primitive buys nothing, because the asset lives in VTL1. Filed as one
more mitigation page among nine, that fact is invisible. Placed beside PPL, where the identical
primitive succeeds completely, it becomes the sharpest illustration of where the real boundary
runs.

## The thesis

One sentence, to appear on the homepage and in `about.md`:

> KernelSight maps what kernel access buys you on Windows. The means of obtaining kernel read,
> write or execution, and the defenses at both kernel and user level that such access does or
> does not defeat, with dated verdicts tied to specific builds and CPU features.

Everything below is downstream of that sentence.

## The `layer` axis

A new required field on every entry in `defenses.yaml`:

```yaml
  - id: lsa-protection
    name: "LSA Protection"
    layer: user               # kernel | user     REQUIRED
    enforced_by: kernel       # kernel | hypervisor | hardware   (already specified in August)
    protects: "Credential material held in the LSA process"
```

**`layer` is the layer of the asset protected, not the layer of the enforcer.** The two are
independent and both matter. PPL is enforced by the kernel and protects a user-mode process, so
it is `layer: user, enforced_by: kernel`. HVCI is enforced by the hypervisor and protects kernel
code integrity, so it is `layer: kernel, enforced_by: hypervisor`. Conflating them is what
produced the August roster's single lonely `protected-process` entry.

This field is what makes the reader's real question answerable: filter to `layer: user` and the
inventory answers "what does my primitive reach outside the kernel".

### Consequences for the August roster

August listed twenty defenses. Under the layer rule, `protected-process` reclassifies to the
user layer and `blocklist-wdac` splits, because driver blocklisting and user-mode WDAC policy
protect different assets and are bypassed differently.

**Kernel layer, 19.** `smep`, `smap`, `kcfg`, `kcet`, `hvci`, `kdp`, `pool-hardening`,
`secure-pool`, `acg`, `kaslr`, `dse`, `hlat`, `mbec`, `patchguard`, `hyperguard`,
`driver-blocklist`, `secure-kernel`, `kernel-dma-protection`, `type-isolation`.

**User layer, 10.** All new pages.

| ID | Protects | Seed inventory |
|---|---|---|
| `protected-process` | PP and PPL process objects | Protection-byte downgrade; signed-driver handle duplication; protected-process termination |
| `lsa-protection` | Credential material in the LSA process | `PatchWDigest`; raw-page dump; minidump with PPL zeroing |
| `credential-guard` | VTL1-isolated credential material | **Negative result.** VTL0 kernel access does not reach it |
| `etw-ti` | Threat-intelligence telemetry channel | Provider enablement-state zeroing |
| `edr-kernel-callbacks` | Sensor notification registrations | Callback array zeroing across process, thread, image and object callbacks; minifilter altitude games |
| `edr-usermode-hooks` | Inline hooks in user-mode modules | Section restore from kernel context |
| `wdac-usermode` | User-mode code integrity policy | Policy object patching |
| `applocker` | Application allowlisting | Policy object patching; service disable |
| `uac-integrity` | Token integrity levels and UAC consent | Integrity-SID rewrite in the token object |
| `amsi` | Script and macro scanning | Provider deregistration; buffer-result patching |

Roster total: **29**.

`credential-guard` carries no bypasses and that is the point. Its page states the boundary, cites
the VTL1 architecture, and links to `protected-process` as the contrast case. A defense with an
empty, *reviewed* inventory is a completed unit of work, not a gap.

## The navigator is the registry

The August design proposed a hand-authored platform-configuration matrix in phase 1, extracted
into `bypass_index.yaml` in phase 2. Since then, `docs/javascripts/navigator.js` shipped, and it
already implements the model:

```js
(window.__ksnav = window.__ksnav || []).push({ sel, title, sub, controls, techniques });
// techniques: [{ name, cat, ev: state => [status, reqLabel, htmlReason] }]
// status: 'open' | 'gated' | 'closed'
```

That is August's `verdicts` plus `platform`, expressed as code and already rendering on four
pages carrying 37 techniques between them: KASLR bypasses (13), VBS/HVCI (11), kCFG/kCET (7),
SMEP/SMAP (6).

**Decision: the `__ksnav` config is the phase-1 registry.** Consequences:

- Every new defense page contributes by registering a config. There is one authoring path, not
  a page plus a parallel matrix entry.
- The site-wide matrix at `docs/bypasses/index.md` **aggregates registered configs** rather than
  restating them. No structural duplication, which is what the August design was protecting
  against when it introduced the `depth: page | row` distinction. That distinction is no longer
  needed and is withdrawn.
- Phase 2 extraction becomes a harvest of existing `__ksnav` configs into `bypass_index.yaml`,
  not a re-authoring pass. Cheaper and lower-risk than August assumed.

Two fields must be added to each technique entry to satisfy the August discipline, since the
current shape carries neither:

```js
{ name: 'SeCiCallbacks pointer swap',
  cat: 'dse-bypass',
  layer: 'kernel',          // NEW, required
  asOf: '2026-06-14',       // NEW, required
  basis: 'cited',           // NEW, required: tested | cited | inferred
  ev: function (s) { ... } }
```

`asOf` and `basis` are the August design's anti-staleness discipline, which it correctly
identified as the one thing phase 1 could not defer. Making them required fields rather than a
prose convention is strictly better, because the aggregate matrix can then render a staleness
badge and CI can fail on their absence.

## Navigation

A grouping change in `mkdocs.yml`. **No files move.** MkDocs derives a page URL from its path
under `docs/`, not from its position in the nav tree, so regrouping breaks no published URL, no
bookmark and no inbound link. The ten new user-layer pages are the only files added.

```yaml
nav:
  - Home: index.md
  - Overview: overview.md
  - Means:
    - driver-types/…        # unchanged paths
    - attack-surfaces/…
    - vuln-classes/…
    - primitives/…
    - case-studies/…
  - Targets:
    - Bypass matrix: bypasses/index.md
    - Kernel layer: mitigations/…      # 19, existing paths preserved
    - User layer:  mitigations/…       # 10, new pages
  - Reference:
    - tooling/…
    - Explore the corpus: explore.md
```

Two notes. `Mitigations` keeps its directory name while the nav label becomes `Targets`, because
the label is free and the directory is not. `Explore` moves under Reference: the CVE corpus
supports the argument rather than being it.

This also continues the direction of commit `802a548`, which dropped the thirteen-item section
tab row. Two groups is fewer top-level choices than the current seven.

## Homepage

The current hero leads with `156 CVEs · 64 drivers · 57 ITW · 33 PoC`. Corpus size measures
effort expended. It does not tell a reader whether the reference answers their question.

**The hero object becomes the hardening curve**: the count of techniques still open, evaluated
across five platform configurations, drawn from the registry. It is the most characteristic fact
in this subject, it is real computed data rather than a claim, and it makes the argument for the
`platform` schema visible in the first screen. The two middle rows differ only in silicon.

Coverage moves to a single quiet line beneath: defenses in the roster, how many have a reviewed
inventory, how many techniques carry a dated verdict. The middle figure is the progress bar, and
it starts at 4 of 29 because that is true.

The corpus counters are not deleted. They move to the Explore page, where they describe what
that page contains.

## Delivery

August's principle holds: content leads, machinery follows. Revised into three increments, each
independently shippable.

**Increment 1, the spine.** The nav regrouping, the homepage rewrite, the thesis sentence, the
`layer` field added to the four existing navigator configs, and the first user-layer page,
`protected-process`. That page is first because `Truesight.sys` and `viragt64.sys` case studies
already exist to cite, so it needs no new research. Ships a legible site with honest counters.

**Increment 2, the credential and telemetry pages.** `lsa-protection`, `credential-guard`,
`etw-ti`, `edr-kernel-callbacks`, `edr-usermode-hooks`. The Credential Guard negative result
lands here, which is the increment that proves the layer axis was worth adding.

**Increment 3, application control.** `wdac-usermode`, `applocker`, `uac-integrity`, `amsi`,
and the `driver-blocklist` split.

**Deferred, unchanged from August.** The nine missing kernel-layer defense pages, the schema
extraction to YAML, the generators, and CI enforcement. PatchGuard and HyperGuard remain blocked
on a literature sweep, for the reason August gave: inventing a technique list from general
knowledge is how a reference loses its authority.

## Verification

Three CI checks, cheap enough to add with increment 1.

1. **Roster resolution.** Every defense in the roster resolves to a page, or is explicitly
   marked `status: planned`. Fails on a silent gap.
2. **Verdict hygiene.** Every `__ksnav` technique carries `layer`, `asOf` and `basis`. Fails on
   an undated claim. This is the check that would have caught `pte-manipulation.md:51`.
3. **Staleness reporting.** Any verdict older than twelve months renders a badge. Reported, not
   failed, since age is not an error.

## Corrections folded in

Three defects found while surveying, all cheap to fix in increment 1.

- **Two unresolvable vuln-class labels.** The data uses `null-pointer-deref` and `toctou`; the
  pages are `null-deref` and `toctou-double-fetch`. Both orphans come from `epdlpdrv.sys`
  (`CVE-2025-11156` and `CVE-2024-11616`). Normalize the data to the page slugs.
- **Scope leak in the corpus.** 24 of 156 entries are user-mode components in a kernel-driver
  index: `ntoskrnl.exe` (14), `dwmcore.dll` (8), `csrss.exe`, `spoolsv.exe`. `ntoskrnl.exe` is
  defensible as core kernel. The rest need either an explicit component-kind field or removal.
  The layer axis gives the vocabulary to decide; it does not decide it.
- **Nine driver-name records.** Entries keyed on driver name rather than CVE ID (`Capcom-sys`,
  `AsIO3-sys`, `Truesight-sys`, `amsdk-sys`, `viragt64-sys`, `echo-driver-sys`, `EnPortv-sys`,
  `ATSZIO64-sys`, `NVDrv`). Their pages exist and resolve. They are BYOVD providers, not
  vulnerabilities, and belong in `driver_index.yaml` with a distinct record type.

## Open questions

**The HLAT family claim.** August inferred that HLAT closes the whole SSDT / Shadow SSDT / IDT /
GDT family at once, since all four depend on repointing a guest PTE. The design mockup renders
this as four rows closing together on one input, which is the clearest possible statement of the
inference. It remains **inferred, not tested**, and must ship as `basis: inferred` until someone
confirms it on 11th-generation-or-newer silicon. It is also the single highest-value lab task in
this amendment, because confirming it resolves four verdicts at once.

**Where user-layer pages live on disk.** This amendment keeps all defense pages under
`docs/mitigations/` and separates them by the `layer` field rather than by directory, to avoid
churning the nine existing URLs. If a `docs/targets/` tree is preferred later, it costs a
redirect map. Recorded rather than resolved.

**The technique-count relationship.** The four existing navigator pages hold 37 techniques, all
kernel layer. The design mockup shows a 27-technique cross-section spanning both layers. Neither
is wrong, but the aggregate matrix must state which set it is rendering, or readers will read one
count as contradicting the other. Resolve when increment 1 wires the aggregation.
