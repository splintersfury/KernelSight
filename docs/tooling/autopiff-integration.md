# AutoPiff Integration

Using AutoPiff's automated patch diffing pipeline with KernelSight.

## Overview

[AutoPiff](https://github.com/your-org/AutoPiff) is an automated Windows kernel driver patch diffing pipeline that:

1. Monitors WinBIndex and VirusTotal for new driver builds
2. Downloads vulnerable and fixed driver pairs
3. Decompiles with Ghidra and diffs function-level changes
4. Applies semantic rules to classify patch patterns
5. Performs reachability analysis to prioritize user-accessible changes
6. Scores and ranks findings

## Rule Mapping

AutoPiff's semantic rules map directly to KernelSight techniques. See [`index/autopiff_rule_map.yaml`](../../index/autopiff_rule_map.yaml) for the complete mapping.

## Detection Categories

| AutoPiff Category | KernelSight Technique |
|---|---|
| `bounds_check` | [Buffer Overflow](../vuln-classes/buffer-overflow.md) |
| `lifetime_fix` | [Use-After-Free](../vuln-classes/use-after-free.md) |
| `user_boundary_check` | [Arbitrary R/W Primitives](../vuln-classes/arbitrary-rw-primitives.md) |
| `int_overflow` | [Integer Overflow](../vuln-classes/integer-overflow.md) |
| `race_condition` | [Race Conditions](../vuln-classes/race-conditions.md) |
| `type_confusion` | [Type Confusion](../vuln-classes/type-confusion.md) |
| `authorization` | [Logic Bugs](../vuln-classes/logic-bugs.md) |
| `info_disclosure` | [Uninitialized Memory](../vuln-classes/uninitialized-memory.md) |
| `ioctl_hardening` | [IOCTL Handlers](../attack-surfaces/ioctl-handlers.md) |
| `mdl_handling` | [MDL Mapping](../primitives/arw/mdl-mapping.md) |

## Case Studies

All 28 CVE case studies in KernelSight were bootstrapped from AutoPiff's validation corpus. Each includes:

- Vulnerable and fixed builds with KB numbers
- Expected detection rules and categories
- Function patterns where patches were applied
