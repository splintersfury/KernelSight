# Tooling

<div class="ks-pipeline-pos">
  Driver Type &rarr; Attack Surface &rarr; Vuln Class &rarr; Primitive &rarr; Case Study &nbsp;|&nbsp; <span class="ks-active">Tooling</span>
</div>

The vulnerability classes and exploitation primitives described in the pipeline are theoretical until you can find them in real binaries. This section covers the practical side: the tools and workflows that turn a driver binary into a vulnerability assessment, a Patch Tuesday advisory into a root cause analysis, and a crash dump into a confirmed exploitable condition.

## From Advisory to Exploit Understanding

A common research workflow begins on the second Tuesday of each month. Microsoft publishes advisories listing affected components and CVE identifiers. Within hours, the researcher can download pre-patch and post-patch binaries from WinBIndex, run BinDiff or AutoPiff to identify changed functions, review the changes in Ghidra or IDA Pro to understand the vulnerability, write a WTF or kAFL harness targeting the patched code path, and debug the triggered crash in WinDbg to confirm the root cause. Each tool in this chain serves a specific purpose, and the sections below explain how to use them together.

## Tool Landscape

| Category | Tools | When to Use |
|----------|-------|-------------|
| [Static Analysis](static-analysis.md) | IDA Pro, Ghidra, CodeQL, Joern, IOCTLance | Understanding driver logic, finding vulnerability patterns, batch scanning IOCTL handlers |
| [Fuzzing](fuzzing.md) | kAFL, WTF, Syzkaller, HEVD | Discovering crashes that manual analysis misses, especially race conditions and deep code paths |
| [Debugging](debugging.md) | WinDbg, Driver Verifier, VirtualKD-Redux | Confirming exploitability, analyzing crash dumps, tracing runtime behavior |
| [Patch Diffing](patch-diffing.md) | BinDiff, Diaphora, ghidriff, diffalyze | Identifying security-relevant changes between builds, 1-day root cause analysis |
| [AutoPiff Integration](autopiff-integration.md) | AutoPiff pipeline (Karton stages 0-8) | End-to-end automated patch analysis at scale, from binary acquisition through risk scoring |

The tools divide into two workflows. **Offensive research** (finding new vulnerabilities) typically starts with static analysis to map the attack surface, moves to fuzzing for automated discovery, and finishes with debugging to confirm exploitability. **Patch analysis** (understanding existing fixes) starts with patch diffing to identify what changed, uses static analysis to understand the semantic meaning of the change, and optionally uses fuzzing to verify the vulnerability in the pre-patch version. AutoPiff bridges both workflows by automating the patch analysis pipeline end-to-end.

## Choosing Your Starting Point

If you are new to Windows kernel research, start with [Debugging](debugging.md) to set up a kernel debugging environment, then move to [Static Analysis](static-analysis.md) to learn how to navigate a driver binary. If you already have debugging experience and want to find vulnerabilities, [Fuzzing](fuzzing.md) covers the automated discovery tools. If you are focused on Patch Tuesday analysis, go directly to [Patch Diffing](patch-diffing.md) and [AutoPiff Integration](autopiff-integration.md).

<div class="ks-next-pipeline">
  <a href="../index.md">&larr; Pipeline Overview</a>
</div>
