# Tooling

<div class="ks-pipeline-pos">
  Driver Type &rarr; Attack Surface &rarr; Vuln Class &rarr; Primitive &rarr; Case Study &nbsp;|&nbsp; <span class="ks-active">Tooling</span>
</div>

Tools and frameworks for Windows kernel driver vulnerability research. This section covers the practical side -- how to find, confirm, and analyze the vulnerability classes and primitives described in the pipeline.

## Overview

Tooling spans the full research pipeline: static analysis of driver binaries, dynamic fuzzing, patch diffing, and kernel debugging. Static analysis narrows the attack surface, fuzzing discovers crashes at scale, debugging confirms exploitability, and patch diffing reveals what Microsoft fixed. This section covers each category and how they fit together.

## Tool Landscape

| Category | Tools | Use Case |
|----------|-------|----------|
| Static Analysis | `IDA Pro`, `Ghidra`, `CodeQL`, `Joern` | Disassembly, decompilation, semantic queries |
| Dynamic Analysis | `WinDbg`, `x64dbg`, `Process Monitor` | Runtime debugging, behavior analysis |
| Fuzzing | `kAFL`, `WTF`, `HEVD` | Automated vulnerability discovery |
| Patch Diffing | `BinDiff`, `Diaphora`, `ghidriff`, `AutoPiff` | Identifying security-relevant binary changes |
| Vulnerability Scanning | `IOCTLance` | Automated IOCTL vulnerability detection |
| Build Acquisition | `WinBIndex` | Downloading specific Windows PE versions |

## Categories

| Tool Category | Description |
|--------------|-------------|
| [Static Analysis](static-analysis.md) | Binary diffing, decompilation, pattern matching, and automated semantic code analysis |
| [Fuzzing](fuzzing.md) | Kernel driver fuzzing frameworks and coverage-guided approaches |
| [Debugging](debugging.md) | Kernel debugging tools, crash analysis, and runtime driver verification |
| [Patch Diffing](patch-diffing.md) | Binary comparison tools for identifying security-relevant changes between builds |
| [AutoPiff Integration](autopiff-integration.md) | Using AutoPiff with KernelSight for automated patch analysis |

## Typical Research Flow

A common workflow after Patch Tuesday: (1) download pre-patch and post-patch drivers from `WinBIndex`, (2) run `BinDiff` or `AutoPiff` to identify changed functions, (3) review changed functions in `Ghidra` or `IDA Pro`, (4) write a `WTF` or `kAFL` harness targeting the patched code path, (5) debug the triggered crash in `WinDbg` to confirm root cause.

<div class="ks-next-pipeline">
  <a href="../index.md">&larr; Pipeline Overview</a>
</div>
