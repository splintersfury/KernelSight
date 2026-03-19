# Community Resources

Windows kernel security research is a small field with a concentrated set of contributors. The researchers listed here have published the exploits, analysis, and tooling that the KernelSight corpus is built on. The tools section covers what you need to get started, from disassemblers through fuzzers to patch analysis pipelines. The training section lists practice targets and references for building foundational skills.

## Key Researchers

### Exploit Development and Research

**Connor McGarr** publishes detailed exploitation walkthroughs for modern Windows kernel vulnerabilities, with particular focus on HVCI bypass research and the evolving data-only exploitation landscape.

**j00ru (Mateusz Jurczyk)** at Google Project Zero has driven some of the most impactful Windows kernel fuzzing campaigns, particularly targeting the font rendering subsystem, GDI, and win32k attack surfaces. His work establishing structured disclosure timelines shaped how the industry handles kernel vulnerability reporting.

**Angelboy (Wei-Chen Wang)** at DEVCORE researches pool internals and exploitation techniques against modern Windows. DEVCORE's systematic audit of the Kernel Streaming stack produced many of the ks.sys/ksthunk.sys/mskssrv.sys CVEs in the KernelSight corpus.

**exploits.forsale (k0shl / Yarden Shafir)** publishes research on named pipe exploitation, pool spray techniques, and I/O Ring primitives. Their work on the 24H2 NT exploit (prefetch-based KASLR bypass) is referenced throughout the KASLR bypass documentation.

**Alex Ionescu** is a Windows internals expert whose understanding of kernel architecture, security subsystem design, and the OS boot chain informs much of the foundational knowledge that kernel research builds on.

**Boris Larin** at Kaspersky GReAT specializes in in-the-wild exploit analysis, with particular focus on CLFS exploitation chains used by ransomware groups. His team's discovery and analysis of multiple CLFS zero-days (Nokoyawa, Storm-2460) provided the campaign details referenced in several case studies.

**Quan Jin** at DBAPPSecurity focuses on Windows kernel exploit analysis and Patch Tuesday research, contributing detailed technical analysis of multiple kernel CVEs.

**valentinpaliy** publishes Windows driver vulnerability research and contributes to the community understanding of driver attack surfaces.

### Academic and Institutional

**Google Project Zero** sets the standard for cross-platform vulnerability research, combining bug hunting with root cause analysis and disclosure timeline enforcement. Their Windows kernel work spans syscall fuzzing, registry races, and GDI exploitation.

**Kaspersky GReAT** discovers and analyzes in-the-wild exploits as part of APT tracking operations. Their zero-day discovery capability has produced multiple kernel CVEs that were being actively exploited before patch availability.

**MSRC** (Microsoft Security Response Center) coordinates patch development, publishes security advisories, and manages the vulnerability disclosure process for all Microsoft products. Their advisories are the starting point for every Patch Tuesday analysis.

## Blogs and Publications

These blogs produce the technical analysis that kernel security research depends on. Each covers a distinct niche.

- [Project Zero Blog](https://googleprojectzero.blogspot.com/) -- Deep vulnerability analysis and exploitation research across platforms, with systematic root cause analysis
- [exploits.forsale](https://exploits.forsale/) -- Windows kernel exploitation techniques, pool internals, and modern primitive development
- [Connor McGarr's Blog](https://connormcgarr.github.io/) -- Step-by-step exploitation walkthroughs for Windows kernel vulnerabilities on current builds
- [DEVCORE Blog](https://blog.devcore.tw/) -- Research publications covering kernel, hypervisor, and application security
- [Kaspersky Securelist](https://securelist.com/) -- In-the-wild exploit reports, APT campaign analysis, and zero-day disclosures
- [Windows Internals Blog](https://windows-internals.com/) -- Alex Ionescu's kernel architecture analysis and internals documentation
- [MSRC Blog](https://msrc.microsoft.com/blog/) -- Official Microsoft security communications, advisory details, and mitigation guidance

## Tools

### Analysis and Reverse Engineering

- **IDA Pro** -- Industry standard disassembler with HexRays decompiler for C pseudocode output. Commercial license required. See [Static Analysis](../tooling/static-analysis.md).
- **Ghidra** -- NSA open-source reverse engineering suite with decompilation, scripting (Java/Python), and headless analysis mode for automation. See [Static Analysis](../tooling/static-analysis.md).
- **WinDbg** -- Microsoft kernel debugger. WinDbg Preview recommended for modern UI, JavaScript scripting, and TTD support. See [Debugging](../tooling/debugging.md).
- **x64dbg** -- Open-source user-mode debugger for Windows with a plugin ecosystem. Useful for user-mode components of kernel exploit chains.

### Vulnerability Discovery

- **IOCTLance** -- Automated IOCTL vulnerability scanner combining static analysis with symbolic execution. See [Static Analysis](../tooling/static-analysis.md).
- **kAFL** -- Hardware-assisted kernel fuzzer using Intel Processor Trace for coverage feedback. See [Fuzzing](../tooling/fuzzing.md).
- **WTF (What The Fuzz)** -- Snapshot-based kernel fuzzer supporting full-system emulation. See [Fuzzing](../tooling/fuzzing.md).
- **CodeQL** -- Semantic code analysis via database queries, with Microsoft-provided driver vulnerability queries. See [Static Analysis](../tooling/static-analysis.md).

### Patch Analysis

- **WinBIndex** (winbindex.m417z.com) -- Windows binary index for downloading specific PE versions by build number. Essential for reproducible patch analysis. See [Patch Diffing](../tooling/patch-diffing.md).
- **BinDiff** -- Google/Zynamics binary comparison tool for function-level diffing. See [Patch Diffing](../tooling/patch-diffing.md).
- **Diaphora** -- Open-source IDA binary diffing plugin with HexRays pseudo-code diffing. See [Patch Diffing](../tooling/patch-diffing.md).
- **ghidriff** -- Ghidra-based automated binary diffing with structured markdown output. See [Patch Diffing](../tooling/patch-diffing.md).

### Catalog and Tracking

- **LOLDrivers** (loldrivers.io) -- Vulnerable driver catalog with hashes, YARA rules, and Sigma rules for detection. See [BYOVD](byovd.md) and [LOLDrivers Deep Analysis](loldrivers-analysis.md).
- **AutoPiff** -- Automated patch diffing pipeline for Windows kernel drivers. See [AutoPiff Integration](../tooling/autopiff-integration.md).
- **MSRC Security Update Guide** -- Official CVE and patch tracking for all Microsoft products.

## Training Resources

### Practice Targets

**HEVD** (HackSysExtremeVulnerableDriver) is the essential starting point for learning kernel exploitation. This purpose-built vulnerable driver contains intentional bugs across every major vulnerability class: stack overflow, pool overflow, use-after-free, type confusion, integer overflow, null pointer dereference, double fetch, and uninitialized memory. Each vulnerability has a separate IOCTL code, and the full source code is available on GitHub. Start with the stack buffer overflow, then progress through pool overflow and use-after-free as your understanding of kernel memory management develops. See [Fuzzing](../tooling/fuzzing.md) for using HEVD as a fuzzing target.

**Windows Kernel Exploitation Training** by Offsec covers modern exploitation techniques against current Windows versions, including the mitigation-aware strategies that the KernelSight pipeline documents.

### Books

- *Windows Internals* (7th Edition) by Yosifovich, Ionescu, Russinovich, Solomon -- The definitive Windows kernel architecture reference. Chapters on memory management, process/thread structures, and the I/O system are directly relevant to understanding the vulnerability classes and exploitation primitives in this knowledge base.
- *A Guide to Kernel Exploitation* by Perla, Oldani -- Kernel exploitation concepts across operating systems, providing cross-platform context for the Windows-specific techniques documented here.
- *Practical Reverse Engineering* by Dang, Gazet, Bachaalany -- x86/x64 and ARM reverse engineering with a Windows kernel focus, covering the skills needed for static analysis and patch diffing.

### Conferences

The conference circuit is where new kernel exploitation research debuts. Attending these (or reviewing their published proceedings) is the best way to stay current with technique evolution.

- **OffensiveCon** -- The primary venue for Windows kernel exploitation research presentations. Many of the techniques documented in KernelSight were first presented here.
- **BlueHat** -- Microsoft-hosted conference bridging internal and external security research, with talks covering both offensive research and Microsoft's defensive response.
- **Hexacon** -- European offensive security conference with a strong binary exploitation track, including kernel research.
- **TyphoonCon** -- Korean offensive security conference with a strong Windows kernel track, featuring researchers who publish detailed exploitation writeups.
- **POC** -- Korean security conference with frequent kernel exploitation and driver research talks.

### Video Resources

- OffensiveCon presentations (published on YouTube) -- Annual talks covering cutting-edge Windows kernel exploitation
- BlueHat IL recordings -- Microsoft security conference content spanning offensive and defensive research
- Hexacon recordings -- European offensive security talks including kernel exploitation content
