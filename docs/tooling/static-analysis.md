# Static Analysis

A kernel driver binary arrives as a PE file, typically 50KB to 5MB, containing the compiled logic that runs at Ring 0. Static analysis lets you understand that logic without executing it, which matters because executing vulnerable kernel code means risking a BSOD. Every potential bug can be examined in a disassembler before committing to a debugging session or exploit attempt. The tools below range from manual reverse engineering (IDA Pro, Ghidra) to automated semantic queries (CodeQL, Joern) to specialized driver scanners (IOCTLance).

## IDA Pro / HexRays

IDA Pro is the industry standard disassembler. HexRays, its decompiler component, produces C pseudocode from x86/x64 binaries that is often close enough to the original source to reason about vulnerabilities directly. The extensive plugin ecosystem (BinDiff, Diaphora, FLIRT signatures) makes it the primary tool for manual reverse engineering.

A typical workflow for analyzing a driver in IDA starts by loading the binary and letting auto-analysis complete fully. Apply Windows DDK type libraries and FLIRT signatures to improve function and structure recognition, which resolves many library calls automatically. Identify `DriverEntry`, the driver's initialization function, and trace the IRP dispatch table assignment. The `IRP_MJ_DEVICE_CONTROL` handler is the primary attack surface, dispatching to specific IOCTL handlers via a switch/case on `IoControlCode`. For each IOCTL handler, trace input buffer handling and check whether size validation occurs against `InputBufferLength` and `OutputBufferLength` before any copy or dereference.

IDA Pro requires a commercial license (~$1,500+ for a named license). For teams with budget constraints, Ghidra provides comparable capability at no cost.

## Ghidra

Ghidra is NSA's open-source reverse engineering framework, offering decompilation quality that is comparable to HexRays for many use cases. Its built-in scripting (Java and Python) enables automated analysis pipelines that scale beyond what manual review can achieve.

The headless mode (`analyzeHeadless`) is particularly valuable for batch processing. AutoPiff uses Ghidra headless analysis in Stage 5 to decompile changed functions and export C pseudocode for downstream semantic analysis. The Version Tracking feature provides built-in binary diffing capability, though specialized tools like BinDiff and Diaphora generally produce better results for patch analysis.

For getting started, Ghidra's auto-analysis produces good results on most Windows drivers. Apply the Windows type archives (available through the Ghidra data type manager) and import PDB symbols when available. The decompiler output can be exported for processing with CodeQL or Joern.

## CodeQL for Drivers

CodeQL transforms code (source or decompiled) into a relational database and lets you query it with a SQL-like language. Microsoft provides CodeQL queries specifically designed for common driver vulnerabilities.

The power of CodeQL is systematic coverage. Rather than manually checking each IOCTL handler for unchecked copies, a single query finds all `memcpy` calls where the size parameter derives from user input without passing through a validation check. Other useful queries include: identifying IOCTL handlers using `METHOD_NEITHER` without `ProbeForRead`/`ProbeForWrite`; detecting missing NULL checks after `ObReferenceObjectByHandle`; and finding data flows from `Irp->AssociatedIrp.SystemBuffer` to dangerous sinks like `RtlCopyMemory` or `ExAllocatePoolWithTag`.

Building a CodeQL database from decompiled output requires exporting the Ghidra or IDA decompilation as C source files, then running the CodeQL CLI to create the database. The setup is non-trivial but pays off when auditing large drivers or multiple drivers simultaneously.

## Joern

Joern is an open-source code analysis platform that represents code as Code Property Graphs (CPGs), combining abstract syntax trees, control flow graphs, and program dependence graphs into a single queryable structure. It works on decompiled C output from Ghidra or IDA.

Joern's query language (CPGQL) excels at cross-function data flow tracking. You can trace a user-controlled buffer from `Irp->AssociatedIrp.SystemBuffer` through multiple function calls to a vulnerable `memcpy` or pool operation, even when the data passes through wrapper functions and intermediate variables. This taint analysis capability is harder to express in CodeQL and impossible with simple pattern matching.

## IOCTLance

IOCTLance is an automated IOCTL vulnerability scanner that combines static analysis with symbolic execution. Point it at a driver binary and it identifies the IOCTL dispatch table, enumerates each handler, and runs symbolic execution to find buffer overflows, integer overflows, and null pointer dereferences. The output is a ranked vulnerability report with severity estimates and code locations.

IOCTLance is most effective at finding shallow bugs in IOCTL handler dispatch logic, the kind of vulnerabilities where user input reaches a dangerous operation within a few function calls. Deep bugs that require specific state setup or multi-call sequences are better found by fuzzing. For batch scanning a directory of driver binaries, IOCTLance provides the fastest time-to-findings.

## Binary Diffing

Three tools serve the binary diffing use case, each with different tradeoffs. **BinDiff** (Google/Zynamics) provides the most mature function-matching algorithms but requires an IDA Pro license for full integration. **Diaphora** (open-source IDA plugin) offers more flexible matching heuristics and supports pseudo-code diffing via HexRays output, making it better for deep analysis of specific function changes. **ghidriff** (Python-based, Ghidra backend) runs in headless mode and produces structured markdown reports, making it the best choice for automated pipelines and CI/CD integration. See [Patch Diffing](patch-diffing.md) for detailed workflows.

## Pattern Matching

For lighter-weight analysis, pattern matching tools can scan binaries or decompiled output for known vulnerable sequences. **Semgrep** works on decompiled C output and supports custom vulnerability signature rules. **YARA** operates on raw binary code, matching byte sequences and instruction patterns associated with known vulnerability classes. **AutoPiff** integrates pattern matching with the full patch diffing pipeline, applying semantic rules to classify changes automatically. See [AutoPiff Integration](autopiff-integration.md).

## Putting It Together

A practical static analysis session for a Windows kernel driver follows a consistent pattern. Acquire the target binary from the running system or from WinBIndex for a specific build. Load it in IDA or Ghidra and let auto-analysis complete fully. Apply Windows DDK type libraries and FLIRT signatures. Identify `DriverEntry` and follow the `IRP_MJ_DEVICE_CONTROL` handler assignment to map the IOCTL dispatch table. For each IOCTL, trace input buffer handling, checking size validation against `InputBufferLength` and `OutputBufferLength`. Flag dangerous patterns: unchecked `memcpy`, `METHOD_NEITHER` without `ProbeForRead`/`ProbeForWrite`, missing NULL checks after object reference calls, and unvalidated offsets from user-supplied structures. Cross-reference findings with CodeQL or Joern queries for systematic coverage that catches what manual review misses.
