# Fuzzing

Static analysis finds bugs you can reason about. Fuzzing finds bugs you cannot: race conditions that require specific thread interleavings, deep code paths triggered only by unusual input sequences, and memory corruption that manifests only under particular heap layouts. Kernel fuzzing is harder than user-mode fuzzing because a crash means a full system reboot, coverage feedback requires hypervisor or hardware tracing, and reproducing race conditions demands precise scheduling control. But for vulnerability classes like synchronization errors and complex parser bugs, fuzzing discovers what manual analysis misses.

## kAFL (Kernel AFL)

kAFL is an Intel PT-based feedback-driven kernel fuzzer that uses hardware tracing for coverage feedback without binary instrumentation. It runs the target in QEMU/KVM with snapshot support for fast reset after each execution.

**Getting started:** You need a Linux host with an Intel CPU that supports Processor Trace (generally Broadwell or newer). Install QEMU/KVM, set up a Windows guest VM, and create a harness that exercises the target IOCTL. kAFL mutates the IOCTL input buffer, Intel PT collects coverage data, and inputs that trigger new basic blocks are retained in the corpus. The snapshot mechanism allows hundreds of executions per second by restoring the VM state to a clean snapshot after each run.

**Strengths:** No source code needed, no instrumentation overhead, fast snapshot restore. kAFL can fuzz any IOCTL interface on a closed-source Windows driver without modification.

**Limitations:** Intel PT hardware is required (specific CPU generations only). Coverage granularity is at the basic block level, which can miss intra-block bugs. Initial setup is complex, requiring kernel patching of the QEMU host for PT support. AMD CPUs are not supported.

**Best for:** Systematic fuzzing of IOCTL interfaces where you have access to an Intel host machine. kAFL is the most practical choice for long-running fuzzing campaigns against specific driver interfaces.

## WTF (What The Fuzz)

WTF is a snapshot-based kernel fuzzer created by Axel Souchet (formerly MSRC). Instead of fuzzing at the IOCTL boundary, WTF takes a full kernel memory snapshot at a specific point in execution and fuzzes from there, mutating function arguments or memory contents.

**Getting started:** Set up a kernel debugging environment (see [Debugging](debugging.md)). Break at the target function in WinDbg. Take a full memory snapshot (WTF provides tooling for this). Write a harness that specifies which function arguments or memory regions to mutate. WTF uses bochscpu or KVM as the execution backend to replay from the snapshot with mutated inputs.

**Strengths:** Can fuzz arbitrary kernel code paths by snapshotting at exactly the right moment, including functions deep in the call chain that are unreachable via normal I/O. The snapshot captures full system state, so the fuzzer starts with the driver in exactly the right configuration.

**Limitations:** Snapshot creation requires a working kernel debugging setup. The snapshot captures a specific moment in time, which means the fuzzer cannot discover bugs that require a sequence of operations to set up state. Write harness development takes significant effort.

**Best for:** Targeted fuzzing of specific functions, especially parser routines, validation functions, and code paths deep in the call chain that are hard to reach via IOCTL-level fuzzing.

## HEVD (HackSys Extreme Vulnerable Driver)

HEVD is not a fuzzing tool but a practice target that is essential for developing fuzzing skills. This purpose-built vulnerable driver contains intentional bugs across every major vulnerability class: stack buffer overflow, pool overflow, use-after-free, type confusion, integer overflow, null pointer dereference, double fetch, and uninitialized memory. Each vulnerability type has a separate IOCTL code.

**Getting started:** Download HEVD from GitHub, load it on a test VM with kernel debugging enabled, and start by exploiting the stack buffer overflow manually. Then write a kAFL or WTF harness that discovers the bug automatically. Comparing your manual analysis with the fuzzer's findings teaches you what fuzzing catches and what it misses. HEVD is also useful for validating that your fuzzing setup works correctly before pointing it at real drivers.

## Syzkaller

Google's kernel fuzzer has experimental Windows support. Syzkaller generates structured, grammar-aware inputs using system call descriptions written in `syzlang`, and uses coverage feedback to guide mutation. Its strength is discovering bugs that require specific sequences of system calls to trigger, making it better at finding multi-step interaction bugs than single-IOCTL fuzzers.

Windows support is less mature than Linux, but active development continues. The syscall descriptions for Windows are incomplete, so you may need to write custom descriptions for the specific driver interfaces you target.

## IOCTLpus and DIFUZE

**IOCTLpus** is a Windows-focused IOCTL fuzzer that automatically enumerates device objects and fuzzes their IOCTL interfaces. It handles device discovery and IOCTL enumeration without requiring a manually written harness, making it useful for broad-surface scanning of a system's driver landscape. **DIFUZE** was originally designed for Android/Linux driver interface fuzzing, but its interface recovery concepts (extracting IOCTL handler structure from the binary) apply to Windows drivers as well.

## Building an Effective Corpus

The quality of fuzzing results depends heavily on the seed corpus and mutation strategy.

**Seed from legitimate usage** by capturing valid IOCTLs with IRP logging or Process Monitor. This establishes a baseline of well-formed inputs that reach deeper code paths than random bytes would.

**Structure-aware mutators** dramatically improve results over blind byte mutation. Define the IOCTL input buffer structure so the mutator respects field boundaries, type constraints, and magic values. A mutator that knows field X is a 4-byte length and field Y is a pointer-sized offset will find vulnerabilities much faster than one that treats the buffer as opaque bytes.

**Multi-stage fuzzing** handles drivers that require setup before the interesting code paths are reachable. Fuzz the initialization IOCTLs first (device open, mode configuration, initialization) to get the driver into the correct state, then target the main processing IOCTLs.

## Practical Considerations

**Crash triage** starts with `!analyze -v` in WinDbg on the crash dump. Hash crash call stacks (faulting instruction + top 3 stack frames) to deduplicate reports that hit the same underlying bug.

**Reproducibility** is the biggest challenge with race conditions. A crash triggered by a specific thread interleaving may not reproduce deterministically. Use multi-core replay, repeated execution with the exact same input, and consider reducing the test VM to a single CPU core to narrow the interleaving space.

**Driver Verifier** is a force multiplier for fuzzing. Enable it for the target driver (`verifier /standard /driver target.sys`) to add runtime checking for pool tracking, IRQL violations, deadlock detection, and most importantly, **Special Pool**, which places each allocation on a page boundary with a guard page immediately after. Special Pool converts off-by-one pool overflows into immediate crashes, catching bugs that would otherwise corrupt silently and manifest later as an unrelated BSOD.

**Resource planning:** Kernel fuzzing is resource-intensive. Full memory snapshots can be 2-4GB each. A dedicated machine or VM with sufficient RAM and fast storage is recommended. Nested virtualization may be required when running kAFL inside a VM; verify that your host CPU and hypervisor support this configuration.
