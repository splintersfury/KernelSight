# AutoPiff Integration

AutoPiff is the automated patch diffing pipeline that underpins much of KernelSight's analysis. It monitors Windows Update for new driver builds, downloads pre-patch and post-patch binaries, decompiles them with Ghidra, diffs the functions, applies semantic rules to classify the changes, performs reachability analysis to determine whether changed code is accessible from user-mode attack surfaces, and produces risk-scored reports. The pipeline runs continuously, processing each Patch Tuesday's output within hours of release.

## How AutoPiff Works

The pipeline is built on [Karton](https://github.com/CERT-Polska/karton), a distributed malware processing framework repurposed for patch analysis. Each stage is an independent Karton task that consumes inputs from the previous stage and produces outputs for the next.

1. **Stage 0** (`autopiff-driver-monitor`) watches WinBIndex and VirusTotal for new driver builds. When a new build appears for a tracked component, it downloads the updated binary and pairs it with the previous version.

2. **Stages 1-4** (`karton-driver-patch-differ`) perform structural comparison using BinDiff. Functions are matched between the two versions, and changed functions are extracted with their pre-patch and post-patch assembly.

3. **Stage 5** (`karton-driver-reachability`) decompiles the changed functions using Ghidra's headless mode, exporting C pseudocode. It then traces call paths from user-accessible entry points (IOCTL handlers, IRP dispatch routines) to the changed functions, filtering out changes that are not reachable from the attack surface.

4. **Stage 6** (`karton-driver-ranking`) applies semantic detection rules to the decompiled diff and scores each finding based on the detected pattern, the proximity to user input, and the severity of the vulnerability class.

5. **Stages 7-8** (`karton-driver-report`, `autopiff-alerter`) generate structured reports and send Telegram alerts for high-scoring findings that likely represent exploitable security fixes.

## Rule Mapping

AutoPiff's semantic rules map directly to KernelSight vulnerability classes and patch patterns. The complete mapping is maintained in [`index/autopiff_rule_map.yaml`](../../index/autopiff_rule_map.yaml).

| AutoPiff Category | KernelSight Technique | What the Rule Detects |
|---|---|---|
| `bounds_check` | [Buffer Overflow](../vuln-classes/buffer-overflow.md) | Added length/size validation before memory operations |
| `lifetime_fix` | [Use-After-Free](../vuln-classes/use-after-free.md) | Reference counting changes, free-path modifications |
| `user_boundary_check` | [Arbitrary R/W Primitives](../vuln-classes/arbitrary-rw-primitives.md) | ProbeForRead/ProbeForWrite additions, user buffer capture |
| `int_overflow` | [Integer Overflow](../vuln-classes/integer-overflow.md) | Safe integer arithmetic additions, overflow checks |
| `race_condition` | [Race Conditions](../vuln-classes/race-conditions.md) | Lock acquisitions, interlocked operations, synchronization |
| `type_confusion` | [Type Confusion](../vuln-classes/type-confusion.md) | Type field validation, object signature checks |
| `authorization` | [Logic Bugs](../vuln-classes/logic-bugs.md) | Access control additions, privilege checks |
| `info_disclosure` | [Uninitialized Memory](../vuln-classes/uninitialized-memory.md) | Buffer zeroing, pointer scrubbing |
| `ioctl_hardening` | [IOCTL Handlers](../attack-surfaces/ioctl-handlers.md) | SDDL changes, device ACL modifications |
| `mdl_handling` | [MDL Mapping](../primitives/arw/mdl-mapping.md) | MDL flag validation, mapping permission changes |

## Connection to KernelSight

All 28 CVE case studies in KernelSight were bootstrapped from AutoPiff's validation corpus. Each case study includes the vulnerable and fixed builds with KB numbers, the expected detection rules and categories, and the function patterns where AutoPiff identified the patch. This means the case studies serve double duty: they document the vulnerability for researchers and validate AutoPiff's detection accuracy for the pipeline.

When AutoPiff processes a new Patch Tuesday, its findings cross-reference against the KernelSight taxonomy. A `bounds_check` detection on `clfs.sys` maps to the [buffer overflow](../vuln-classes/buffer-overflow.md) vulnerability class, the [pool overflow](../primitives/arw/pool-overflow.md) primitive, and the file format corruption exploit chain pattern (archetype A from [Exploit Chain Patterns](../guides/exploit-chain-patterns.md)). This mapping turns a raw binary diff into a structured assessment of the vulnerability's exploitation potential.
