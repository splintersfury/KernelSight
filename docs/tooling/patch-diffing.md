# Patch Diffing

Methodology and tools for identifying security-relevant changes between Windows driver versions.

## Overview

Patch diffing compares two versions of a binary -- typically the pre-patch and post-patch builds of a Windows kernel component -- to identify the code changes that constitute a security fix. By reverse-engineering what changed, the root cause of the vulnerability can be determined, often before any public writeup or PoC exists.

## Why Patch Diffing Matters

- Reveals root cause of vulnerabilities from patch data alone, often before public technical analysis
- Enables 1-day exploit development from Patch Tuesday advisories
- Helps defensive teams understand exposure windows, prioritize patching, and build targeted detections
- Supports automated vulnerability detection pipelines across hundreds of patched binaries per month

## Tools

### BinDiff

BinDiff is a binary comparison tool developed by Google (formerly Zynamics). It works as an IDA Pro plugin or as a standalone application.

- Matches functions between two binaries using control flow graph similarity, call graph analysis, and instruction-level heuristics
- Best for: identifying renamed or moved functions, finding changed basic blocks within matched functions
- Limitations: requires an IDA Pro license for full integration, can be slow on very large binaries (100MB+), sometimes mismatches functions with similar structure

### Diaphora

Diaphora is an open-source IDA plugin created by Joxean Koret for advanced binary diffing.

- Offers more flexible matching heuristics than BinDiff, including partial matching and heuristic-based comparison
- Supports pseudo-code diffing via HexRays decompiler output
- Best for: deep analysis of specific function changes, identifying subtle modifications in complex functions

### ghidriff

ghidriff is a Python-based tool that leverages Ghidra's headless analysis mode for automated binary diffing.

- Free and open-source (no IDA Pro license required)
- Produces structured markdown diff reports suitable for automated processing
- Best for: batch processing large numbers of binary pairs, CI/CD integration, automated triage pipelines

### diffalyze

diffalyze applies LLM-augmented analysis to binary diffs, using AI models to explain the security implications of detected changes.

- Takes BinDiff or ghidriff output and generates natural-language explanations of patch semantics
- Experimental but promising for scaling triage across the volume of monthly Patch Tuesday changes
- Can classify changes as security-relevant vs. non-security with reasonable accuracy

## Build Acquisition with WinBIndex

WinBIndex (winbindex.m417z.com) is an index of Windows Update packages that allows downloading specific PE file versions by build number.

- Indexes all major Windows components across all public builds
- Enables downloading exact pre-patch and post-patch binaries given KB article numbers
- Required for reproducible analysis since the same CVE fix may differ across Windows versions (10 vs. 11, different feature updates)
- Supports searching by file name, build number, or update KB identifier

## Patch Diffing Workflow

1. **Identify target** -- Patch Tuesday advisory lists affected component and CVE identifier
2. **Determine build numbers** -- Map the pre-patch and post-patch KB articles to specific OS build numbers
3. **Acquire binaries** -- Download both versions from WinBIndex
4. **Initial diff** -- Run BinDiff or ghidriff to generate function-level comparison
5. **Triage changes** -- Focus on functions with small, targeted modifications (1-20 changed instructions), filtering out noise from compiler optimizations and unrelated changes
6. **Analyze** -- Examine the semantics of changes: added bounds checks, NULL checks, lock acquisitions, input validation
7. **Document** -- Classify the root cause (buffer overflow, use-after-free, race condition, type confusion) and assess exploitation potential

## Common Patch Patterns

- **Added length/bounds check before `memcpy`/`memmove`** -- Buffer overflow fix. The patch validates size parameters before a memory copy operation.
- **Added `NULL` pointer check** -- Null dereference fix. The patch adds a conditional check before dereferencing a potentially NULL pointer.
- **Added lock acquisition or interlocked operation** -- Race condition fix. The patch introduces synchronization around a shared resource access.
- **Type field validation added** -- Type confusion fix. The patch verifies an object's type field before casting or dispatching.
- **Reference count adjustment** -- Use-after-free fix. The patch adds or corrects reference counting to prevent premature object deallocation.
- **Input validation on IOCTL buffer size** -- IOCTL handler fix. The patch checks `InputBufferLength` or `OutputBufferLength` before processing device I/O control requests.

## AutoPiff Integration

AutoPiff automates the patch diffing pipeline end-to-end, from binary acquisition through risk-scored reporting.

- **Stage 0** (`autopiff-driver-monitor`) -- Monitors WinBIndex for new Windows builds and downloads updated driver binaries
- **Stages 1-4** (`karton-driver-patch-differ`) -- Automated BinDiff-based structural comparison, function matching, and change extraction
- **Stage 5** (`karton-driver-reachability`) -- Ghidra decompilation of changed functions with reachability analysis from user-accessible entry points
- **Stage 6** (`karton-driver-ranking`) -- Risk scoring based on detected patch patterns and attack surface proximity
- **Stages 7-8** (`karton-driver-report`, `autopiff-alerter`) -- Report generation and Telegram alerting for high-scoring findings

AutoPiff detection rules map directly to common patch patterns:

- `added_len_check_before_memcpy` -- Bounds check added before memory copy
- `added_null_check` -- NULL pointer validation added
- `added_lock_acquisition` -- Synchronization primitive introduced
- `added_type_validation` -- Object type field verified before use

## References

- [BinDiff](https://www.zynamics.com/bindiff.html)
- [Diaphora](https://github.com/joxeankoret/diaphora)
- [ghidriff](https://github.com/clearbluejar/ghidriff)
- [WinBIndex](https://winbindex.m417z.com/)
