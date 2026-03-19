# Patch Diffing

Every second Tuesday of the month, Microsoft publishes security updates that fix kernel vulnerabilities. The advisory lists the affected component and a CVE identifier, but the technical details are deliberately sparse. Patch diffing fills that gap by comparing the pre-patch and post-patch binaries to determine exactly what code changed, revealing the root cause of the vulnerability before any public writeup or proof of concept exists.

This capability matters for both offense and defense. Offensive researchers use patch diffs to understand 1-day vulnerabilities and develop exploits during the window between patch release and target update. Defensive teams use them to understand their exposure, prioritize patching, and build targeted detections. Automated pipelines like AutoPiff use them to classify the vulnerability at scale across hundreds of patched binaries per month.

## Build Acquisition with WinBIndex

Before diffing, you need both versions of the binary. WinBIndex (winbindex.m417z.com) is an index of Windows Update packages that lets you download specific PE file versions by build number.

The workflow starts with the Patch Tuesday advisory, which identifies the affected component and the KB article number for the fix. Map the pre-patch and post-patch KB articles to specific OS build numbers (the advisory or the Microsoft Update Catalog provides these). Then search WinBIndex by file name and build number to download both versions. This is important for reproducibility: the same CVE fix may differ across Windows versions (10 vs. 11, different feature updates), so you need the exact builds relevant to your target.

## Diffing Tools

### BinDiff

BinDiff is the most established binary comparison tool, developed by Google (formerly Zynamics). It matches functions between two binaries using control flow graph similarity, call graph position, and instruction-level heuristics. The output highlights which functions were added, removed, or modified, and shows the specific basic blocks that changed within modified functions.

BinDiff works as an IDA Pro plugin or as a standalone application using exported IDB databases. The matching algorithms are mature and handle compiler optimizations well, though they can produce false matches on very large binaries (100MB+) where many functions share similar structure. BinDiff is the best choice for identifying renamed or moved functions and for understanding control flow changes at the basic block level.

### Diaphora

Diaphora is an open-source IDA plugin by Joxean Koret that offers more flexible matching heuristics than BinDiff. Its most valuable feature is pseudo-code diffing via HexRays output, which shows the change in decompiled C rather than assembly. This makes it significantly easier to understand the semantic meaning of a patch, especially for complex functions where assembly-level changes span many basic blocks.

Diaphora is the best choice for deep analysis of specific function changes and for understanding subtle modifications in complex functions where the C-level diff is more informative than the assembly-level diff.

### ghidriff

ghidriff is a Python-based tool that uses Ghidra's headless analysis mode for automated binary diffing. It requires no IDA Pro license, runs entirely from the command line, and produces structured markdown diff reports that can be processed programmatically.

ghidriff is the best choice for batch processing large numbers of binary pairs, CI/CD integration, and automated triage pipelines. AutoPiff uses ghidriff (along with BinDiff) in its automated stages for function-level comparison.

### diffalyze

diffalyze applies LLM-augmented analysis to binary diffs, using AI models to generate natural-language explanations of patch semantics. It takes BinDiff or ghidriff output and classifies changes as security-relevant or non-security with reasonable accuracy. The tool is experimental but promising for scaling triage across the volume of monthly Patch Tuesday changes, where a human analyst cannot review every modified function across every patched component.

## The Patch Diffing Workflow

A complete patch diff analysis follows seven steps.

**1. Identify target.** The Patch Tuesday advisory names the affected component and CVE.

**2. Determine build numbers.** Map the pre-patch and post-patch KB articles to specific OS build numbers. The Microsoft Security Update Guide and the Update Catalog provide this mapping.

**3. Acquire binaries.** Download both versions from WinBIndex by file name and build number.

**4. Initial diff.** Run BinDiff or ghidriff to produce a function-level comparison. The output lists all functions with their match status (matched-identical, matched-changed, unmatched).

**5. Triage changes.** Focus on functions with small, targeted modifications (1-20 changed instructions). Filter out noise from compiler optimizations, unrelated refactoring, and code reordering. Security fixes are almost always surgical: a few lines of validation added to an existing function. Large-scale restructuring is rarely a security fix.

**6. Analyze.** For each candidate function, examine the semantic meaning of the change. The [patch patterns](../guides/patch-patterns.md) page catalogs the seven most common shapes. An added bounds check suggests a buffer overflow. An added lock suggests a race condition. An added type check suggests type confusion. The pattern tells you the vulnerability class.

**7. Document.** Classify the root cause and assess exploitation potential. Map the vulnerability to the KernelSight taxonomy: vulnerability class, exploitation primitive, affected attack surface.

## Recognizing Common Patch Patterns

The majority of kernel security patches follow one of these recognizable shapes. Seeing a bounds check appear before `memcpy` or `memmove` indicates a buffer overflow fix. A new NULL pointer check before dereferencing indicates a null dereference fix. Lock acquisition or interlocked operations appearing around a shared resource access indicate a race condition fix. Type field validation before casting indicates a type confusion fix. Reference count adjustments around object acquisition and release indicate a use-after-free fix. Input validation on IOCTL buffer size indicates an IOCTL handler fix.

Each of these patterns maps to AutoPiff detection rules that fire automatically during pipeline analysis. See [Patch Patterns](../guides/patch-patterns.md) for detailed before/after pseudocode examples.

## AutoPiff: Automating the Pipeline

AutoPiff automates every step of the patch diffing workflow, from binary acquisition through risk-scored reporting.

**Stage 0** (`autopiff-driver-monitor`) monitors WinBIndex for new Windows builds and downloads updated driver binaries as they appear.

**Stages 1-4** (`karton-driver-patch-differ`) perform automated BinDiff-based structural comparison, function matching, and change extraction.

**Stage 5** (`karton-driver-reachability`) uses Ghidra headless decompilation on changed functions and performs reachability analysis from user-accessible entry points, filtering out changes that are not reachable from the IOCTL attack surface.

**Stage 6** (`karton-driver-ranking`) applies risk scoring based on detected patch patterns and attack surface proximity. High scores indicate changes that are both security-relevant and user-reachable.

**Stages 7-8** (`karton-driver-report`, `autopiff-alerter`) generate reports and send Telegram alerts for findings above the score threshold.

AutoPiff's detection rules map directly to common patch patterns. `added_len_check_before_memcpy` fires on bounds check additions. `added_null_check` fires on NULL pointer validation. `added_lock_acquisition` fires on synchronization primitives. `added_type_validation` fires on type field verification. See [AutoPiff Integration](autopiff-integration.md) for setup and the full rule set.

## References

- [BinDiff](https://www.zynamics.com/bindiff.html)
- [Diaphora](https://github.com/joxeankoret/diaphora)
- [ghidriff](https://github.com/clearbluejar/ghidriff)
- [WinBIndex](https://winbindex.m417z.com/)
