# Static Analysis

Tools and techniques for analyzing Windows kernel drivers without execution.

## Overview

Static analysis is the foundation of driver vulnerability research. It encompasses disassembly, decompilation, and automated semantic code analysis to identify vulnerability patterns in kernel binaries. Because kernel drivers run at the highest privilege level, static analysis allows researchers to study dangerous code paths without risking system stability -- every potential bug can be examined in a disassembler before committing to a debugging session or exploit attempt.

## IDA Pro / HexRays

- Industry-standard disassembler and decompiler
- HexRays decompiler produces C pseudocode from x86/x64 binaries
- Extensive plugin ecosystem (`BinDiff`, `Diaphora`, FLIRT signatures)
- Key for: manual reverse engineering, understanding driver logic, analyzing IOCTL dispatch
- Workflow: Load driver -> identify `DriverEntry` -> trace IRP dispatch table -> analyze IOCTL handlers
- FLIRT signatures for Windows DDK improve function identification significantly, resolving many library calls automatically
- Cost: Commercial license required (~$1,500+ for named license)

## Ghidra

- NSA open-source reverse engineering framework
- Comparable decompilation quality to HexRays for many use cases
- Built-in scripting (Java/Python) for automated analysis
- Key for: batch analysis, scripted vulnerability scanning, free alternative to IDA
- `Ghidra` headless mode (`analyzeHeadless`) enables CI/CD integration for automated decompilation pipelines
- AutoPiff uses `Ghidra` for automated decompilation in Stage 5, exporting decompiled C code to MWDB for downstream analysis
- Version Tracking feature provides built-in binary diffing capability

## CodeQL for Drivers

- Semantic code analysis using database queries
- Microsoft provides `CodeQL` queries for common driver vulnerabilities
- Can query decompiled C code or source (if available)
- Example queries:
  - Find all `memcpy` calls where size comes from user input without validation
  - Identify IOCTL handlers using `METHOD_NEITHER` without `ProbeForRead`/`ProbeForWrite`
  - Detect missing NULL checks after `ObReferenceObjectByHandle`
- Requires building a `CodeQL` database from source or decompiled output

## Joern

- Open-source code analysis platform using Code Property Graphs (CPGs)
- Works on decompiled C output from `Ghidra`/`IDA`
- Query language (CPGQL) for pattern matching across code
- Useful for: cross-function data flow tracking, taint analysis from IOCTL input to dangerous sinks
- Can trace a user-controlled buffer from `Irp->AssociatedIrp.SystemBuffer` through multiple function calls to a vulnerable `memcpy` or pool operation

## IOCTLance

- Automated IOCTL vulnerability scanner
- Combines static analysis with symbolic execution
- Identifies: buffer overflows, integer overflows, null pointer dereferences in IOCTL handlers
- Produces ranked vulnerability reports with severity and location details
- Can be pointed at a directory of driver binaries for batch scanning
- Particularly effective at finding shallow bugs in IOCTL handler dispatch logic

## Binary Diffing

- **`BinDiff`** -- Google's binary diffing tool for matched function comparison between two versions of a binary
- **`Diaphora`** -- Open-source binary diffing plugin for `IDA Pro` with advanced heuristics
- **`ghidriff`** -- `Ghidra`-based binary diffing that works in headless mode
- These tools are critical for patch analysis: comparing a pre-patch and post-patch driver reveals exactly which functions were modified and what checks were added

## Pattern Matching

- **`Semgrep`** -- Pattern matching on decompiled C output for vulnerability signatures
- **`YARA`** -- Pattern matching on raw binary code for known vulnerable sequences
- **`AutoPiff`** -- Automated patch diffing with semantic rule matching across the full vulnerability pipeline

## Practical Workflow

A typical static analysis session for a Windows kernel driver follows these steps:

1. Acquire target driver binary (from the running system or via `WinBIndex` for specific builds)
2. Load in `IDA`/`Ghidra` -- let auto-analysis complete fully before manual review
3. Apply Windows DDK type libraries and FLIRT signatures for better function and structure recognition
4. Identify `DriverEntry` -> follow the `IRP_MJ_DEVICE_CONTROL` handler assignment
5. Map the IOCTL dispatch table (switch/case on `IoControlCode`)
6. For each IOCTL: trace input buffer handling, check size validation against `InputBufferLength`/`OutputBufferLength`
7. Flag dangerous patterns: unchecked `memcpy`, `METHOD_NEITHER` without `ProbeForRead`/`ProbeForWrite`, missing NULL checks after object reference calls
8. Cross-reference findings with `CodeQL`/`Joern` queries for systematic coverage across all code paths
