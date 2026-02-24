# Community Resources

Researchers, tools, and learning resources for Windows kernel security research.

## Key Researchers

### Exploit Development and Research

- **Connor McGarr** -- Windows kernel exploitation, HVCI bypass research, detailed exploitation writeups
- **j00ru (Mateusz Jurczyk)** -- Google Project Zero, Windows kernel fuzzing, font and GDI attack surface research
- **Angelboy (Wei-Chen Wang)** -- DEVCORE, pool internals, exploitation techniques for modern Windows
- **exploits.forsale (k0shl / Yarden Shafir)** -- Named pipe exploitation, pool spray techniques, I/O Ring research
- **Alex Ionescu** -- Windows internals expert, kernel architecture, security subsystem design
- **Boris Larin** -- Kaspersky GReAT, in-the-wild exploit analysis, CLFS research
- **Quan Jin** -- DBAPPSecurity, Windows kernel exploit analysis, Patch Tuesday research
- **valentinpaliy** -- Windows driver vulnerability research

### Academic and Institutional

- **Google Project Zero** -- Bug hunting across platforms, disclosure timelines, root cause analysis
- **Kaspersky GReAT** -- In-the-wild exploit discovery, APT tracking, vulnerability analysis
- **MSRC** -- Microsoft Security Response Center, patch coordination, security advisories

## Blogs and Publications

- [Project Zero Blog](https://googleprojectzero.blogspot.com/) -- In-depth vulnerability analysis and exploitation research
- [exploits.forsale](https://exploits.forsale/) -- Windows kernel exploitation techniques and pool internals
- [Connor McGarr's Blog](https://connormcgarr.github.io/) -- Detailed exploitation walkthroughs for Windows kernel
- [DEVCORE Blog](https://blog.devcore.tw/) -- Research publications including kernel and hypervisor work
- [Kaspersky Securelist](https://securelist.com/) -- In-the-wild exploit reports and APT analysis
- [Windows Internals Blog](https://windows-internals.com/) -- Alex Ionescu's kernel architecture insights
- [MSRC Blog](https://msrc.microsoft.com/blog/) -- Official Microsoft security communications and advisories

## Tools

### Analysis and Reverse Engineering

- **IDA Pro** -- Disassembler with HexRays decompiler for C pseudocode output
- **Ghidra** -- NSA open-source reverse engineering suite with decompilation and scripting
- **WinDbg** -- Microsoft kernel debugger (Preview version recommended for modern UI and TTD support)
- **x64dbg** -- Open-source user-mode debugger for Windows with plugin ecosystem

### Vulnerability Discovery

- **IOCTLance** -- Automated IOCTL vulnerability scanner for Windows drivers, identifies reachable attack surface
- **kAFL** -- Kernel-mode AFL fuzzer using Intel Processor Trace for hardware-assisted coverage
- **WTF (What The Fuzz)** -- Snapshot-based kernel fuzzer that supports full-system emulation
- **CodeQL** -- Semantic code analysis for compiled binaries via SARIF, supports custom vulnerability queries

### Patch Analysis

- **WinBIndex** (winbindex.m417z.com) -- Windows binary index for downloading specific PE versions by build number
- **BinDiff** -- Binary comparison tool by Google/Zynamics for function-level diffing
- **Diaphora** -- Open-source binary diffing IDA plugin with advanced heuristic matching
- **ghidriff** -- Ghidra-based automated binary diffing with markdown report output

### Catalog and Tracking

- **LOLDrivers** (loldrivers.io) -- Vulnerable driver catalog for BYOVD detection and prevention
- **AutoPiff** -- Automated patch diffing pipeline for Windows kernel drivers (this project)
- **MSRC Security Update Guide** -- Official CVE and patch tracking for all Microsoft products

## Training Resources

### Practice Targets

- **HEVD** (HackSysExtremeVulnerableDriver) -- Purpose-built vulnerable driver for learning kernel exploitation, covers stack overflow, pool overflow, use-after-free, type confusion, and more
- **Windows Kernel Exploitation Training** by Offsec -- Advanced course covering modern exploitation techniques on current Windows versions

### Books

- *Windows Internals* (7th Edition) by Yosifovich, Ionescu, Russinovich, Solomon -- Windows kernel architecture reference
- *A Guide to Kernel Exploitation* by Perla, Oldani -- Kernel exploitation concepts across operating systems
- *Practical Reverse Engineering* by Dang, Gazet, Bachaalany -- x86/x64 and ARM reverse engineering with Windows kernel focus

### Video Resources

- OffensiveCon presentations -- Annual conference with Windows kernel exploitation talks
- BlueHat IL -- Microsoft-hosted security conference recordings covering offensive and defensive research
- Hexacon -- European offensive security conference with kernel exploitation content

## Conferences

- **OffensiveCon** -- Windows kernel exploitation research presentations
- **BlueHat** -- Microsoft security conference bridging internal and external security research
- **Hexacon** -- European offensive security conference with strong binary exploitation track
- **TyphoonCon** -- Korean offensive security conference with strong Windows kernel track
- **POC** -- Korean security conference featuring frequent kernel exploitation and driver research talks
