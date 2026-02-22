# Fuzzing

Automated vulnerability discovery through intelligent input generation for Windows kernel drivers.

## Overview

Kernel fuzzing discovers vulnerabilities by feeding malformed inputs to driver interfaces and monitoring for crashes (BSODs, assertions, memory corruption). Kernel fuzzing is more complex than user-mode fuzzing due to several factors: a crash means a full system reboot, coverage feedback requires hypervisor or hardware tracing support, and reproducing race conditions requires precise scheduling control. Despite these challenges, fuzzing remains one of the most effective ways to find bugs that manual analysis misses.

## kAFL (Kernel AFL)

- Intel PT-based feedback-driven kernel fuzzer
- Uses hardware tracing (Intel Processor Trace) for coverage feedback without binary instrumentation
- Runs target in QEMU/KVM with snapshot support for fast reset after each execution
- Workflow: create harness that exercises target IOCTL -> `kAFL` mutates input -> Intel PT collects coverage -> new coverage triggers corpus entry retention
- Strengths: no source code needed, no instrumentation overhead, fast snapshot restore between iterations
- Limitations: Intel PT hardware required (specific CPU generations), coverage granularity is at basic block level, initial setup is complex
- Best suited for: systematic fuzzing of IOCTL interfaces on Linux host machines with Intel CPUs

## WTF (What The Fuzz)

- Snapshot-based kernel fuzzer by Axel Souchet (ex-MSRC)
- Takes a full kernel memory snapshot -> mutates inputs -> executes in emulator -> detects crashes
- Uses `bochscpu` or KVM as execution backend
- Key advantage: can fuzz arbitrary kernel code paths by snapshotting at exactly the right moment
- Workflow: break at target function in `WinDbg` -> take full memory snapshot -> write harness that modifies function arguments -> fuzz with mutations
- Good for: targeted fuzzing of specific functions, fuzzing code paths unreachable via normal I/O, and functions deep in the call chain
- Snapshot creation requires a working kernel debugging setup (see [Debugging](debugging.md))

## HEVD (HackSys Extreme Vulnerable Driver)

- Practice vulnerable driver with intentional bugs across many vulnerability classes
- Includes: stack buffer overflow, pool overflow, use-after-free, type confusion, integer overflow, null pointer dereference, double fetch, uninitialized memory, and more
- Ideal for: learning exploitation techniques, testing fuzzer effectiveness, developing and validating harnesses
- Each vulnerability type has a separate IOCTL code, making it easy to target specific bug classes
- Available on GitHub with full source code and documentation

## Syzkaller

- Google's kernel fuzzer with experimental Windows support
- Uses system call descriptions (`syzlang`) to generate structured, grammar-aware inputs
- Coverage-guided via `KCOV` or similar kernel coverage mechanisms
- Strong for: syscall-level fuzzing, reproducing complex multi-call interaction bugs
- Can discover bugs that require specific sequences of system calls to trigger
- Windows support is less mature than Linux, but active development continues

## IOCTLpus and DIFUZE

- **`IOCTLpus`** -- Windows-focused IOCTL fuzzer that enumerates device objects and fuzzes their IOCTL interfaces
- **`DIFUZE`** -- Originally designed for Android/Linux driver interface fuzzing, but the interface recovery concepts apply to Windows drivers as well
- Both focus on automatically discovering and fuzzing driver entry points without manual harness writing

## Corpus Strategies

- Seed corpus from legitimate driver usage: capture valid IOCTLs with IRP logging or `Process Monitor` to establish a baseline of well-formed inputs
- Structure-aware mutators: define IOCTL input buffer structure for smarter mutation that respects field boundaries and type constraints
- Coverage-guided evolution: let the fuzzer discover new code paths incrementally, retaining inputs that trigger new basic blocks
- Dictionary tokens: include common magic values, sizes, flags, and constants extracted from driver headers or reverse engineering
- Multi-stage fuzzing: fuzz setup IOCTLs first (device open, mode configuration, initialization) then target the main processing IOCTLs once the driver is in the correct state

## Practical Considerations

- **Crash triage**: use `!analyze -v` in `WinDbg` on crash dumps to identify root cause, faulting module, and call stack
- **Deduplication**: hash crash call stacks to avoid reporting the same bug multiple times; bucket by faulting instruction and top 3 stack frames
- **Reproducibility**: kernel race conditions may not reproduce deterministically -- use multi-core replay and repeated execution with the exact same input
- **Driver Verifier**: enable Windows Driver Verifier on the target driver for enhanced runtime checking (pool tracking, IRQL checks, deadlock detection)
- **Special Pool**: enable for target driver to catch off-by-one pool overflows with guard pages placed immediately after allocations
- **Hypervisor considerations**: nested virtualization may be required when running `kAFL` inside a VM -- check that your host CPU and hypervisor support this
- **Resource management**: kernel fuzzing consumes significant resources; allocate dedicated machines or VMs with sufficient RAM for full memory snapshots
