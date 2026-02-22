# Tooling

<div class="ks-pipeline-pos">
  Driver Type &rarr; Attack Surface &rarr; Vuln Class &rarr; Primitive &rarr; Case Study &nbsp;|&nbsp; <span class="ks-active">Tooling</span>
</div>

Tools and frameworks for Windows kernel driver vulnerability research. This section covers the practical side -- how to find, confirm, and analyze the vulnerability classes and primitives described in the pipeline.

## Overview

Tooling is essential across the entire research pipeline -- from static analysis of driver binaries to dynamic fuzzing, patch diffing, and kernel debugging. Choosing the right tool for each stage of research dramatically affects efficiency: static analysis narrows the attack surface, fuzzing discovers crashes at scale, debugging confirms exploitability, and patch diffing reveals what Microsoft considered worth fixing. This section covers the key categories and how they fit together in a typical workflow.

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

A common research workflow touches multiple tool categories in sequence. For example, after Patch Tuesday a researcher might: (1) use `WinBIndex` to download the pre-patch and post-patch driver, (2) run `BinDiff` or `AutoPiff` to identify changed functions, (3) open the changed functions in `Ghidra` or `IDA Pro` for manual review, (4) write a `WTF` or `kAFL` harness targeting the patched code path, and (5) debug the triggered crash in `WinDbg` to confirm the root cause. Each tool category below supports one or more of these stages.

## Cross-References

Each sub-page dives into a specific category with tool comparisons, setup instructions, and practical workflows:

- [Static Analysis](static-analysis.md) -- covers `IDA Pro`, `Ghidra`, `CodeQL`, `Joern`, and `IOCTLance` for analyzing driver binaries without execution.
- [Fuzzing](fuzzing.md) -- covers `kAFL`, `WTF`, `Syzkaller`, and corpus strategies for automated crash discovery.
- [Debugging](debugging.md) -- covers `WinDbg` setup, essential commands, extensions, and crash dump analysis.
- [Patch Diffing](patch-diffing.md) -- covers `BinDiff`, `Diaphora`, `ghidriff`, and manual diff workflows.
- [AutoPiff Integration](autopiff-integration.md) -- covers the automated pipeline that ties patch diffing, decompilation, and vulnerability classification together.

<div class="ks-next-pipeline">
  <a href="../index.md">&larr; Pipeline Overview</a>
</div>
