# Kernel Streaming Drivers

<div class="ks-pipeline-pos">
  <span class="ks-active">Driver Type</span> &rarr; Attack Surface &rarr; Vuln Class &rarr; Primitive &rarr; Case Study
</div>

DevCore's winning entry at Pwn2Own Vancouver 2024 used a single untrusted pointer dereference in ks.sys to achieve local privilege escalation on a fully patched Windows 11 system. That bug, CVE-2024-35250, was one of six kernel streaming CVEs in the KernelSight corpus, all found within a two-year window. Kernel Streaming has quietly become one of the most productive attack surfaces in the Windows kernel, not because the individual bugs are novel, but because the framework combines three vulnerability-prone patterns in a single subsystem: a large IOCTL dispatch table, cross-architecture structure translation, and direct MDL manipulation.

## How Kernel Streaming Works

The Kernel Streaming (KS) framework provides a standardized interface for multimedia data flow in Windows. Audio devices, video capture hardware, and camera drivers all use KS to manage data streams between user-mode applications and hardware. The framework is implemented across three drivers, each with its own vulnerability profile.

`ks.sys` is the core framework driver. It implements the KS IOCTL dispatch that routes property, method, and event requests to the appropriate handler. The dispatch table is large, with hundreds of property and method handlers accessible through `IOCTL_KS_PROPERTY`, `IOCTL_KS_METHOD`, and `IOCTL_KS_ENABLE_EVENT`.

`mskssrv.sys` is the Kernel Streaming Server, a rendezvous mechanism that allows cross-process multimedia streaming. It manages shared context objects that represent server and client endpoints, and these context objects have complex lifecycle and reference counting semantics.

`ksthunk.sys` is the WOW64 thunk layer that translates 32-bit KS structures to 64-bit format when a 32-bit process sends KS IOCTLs on a 64-bit system. This translation involves size calculations that are inherently prone to integer overflow.

``` mermaid
graph TD
    A["32-bit Process"] -->|"KS IOCTL"| B["ksthunk.sys<br/>WOW64 Thunk"]
    C["64-bit Process"] -->|"KS IOCTL"| D["ks.sys<br/>KS Framework"]
    B -->|"Struct Translation"| D
    D -->|"Property/Method<br/>Dispatch"| E["KS Minidriver<br/>Audio/Video/Camera"]
    D -->|"Stream Setup"| F["mskssrv.sys<br/>Rendezvous Server"]
    F -->|"Context Objects"| G["FsContextReg<br/>FsStreamReg"]

    style A fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    style B fill:#152a4a,stroke:#f59e0b,color:#e2e8f0
    style C fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    style D fill:#152a4a,stroke:#ef4444,color:#e2e8f0
    style E fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    style F fill:#152a4a,stroke:#ef4444,color:#e2e8f0
    style G fill:#0d1320,stroke:#ef4444,color:#e2e8f0
```

## Three Distinct Bug Families

The six CVEs in the corpus break cleanly into three bug families, each tied to a specific driver and a specific architectural pattern.

### IOCTL Dispatch Bugs in ks.sys

The ks.sys IOCTL dispatch table is the entry point for all KS operations. When a process sends a KS IOCTL, the framework parses the property or method request and dispatches it to the appropriate handler. CVE-2024-35250, the Pwn2Own winner, exploits a fundamental flaw in this dispatch: the handler dereferences a pointer from the IOCTL input buffer without validating it. Because KS IOCTLs use `METHOD_NEITHER` transfer type, the kernel receives the raw user-mode buffer pointer without copying it to a kernel buffer, and the driver must explicitly call `ProbeForRead`/`ProbeForWrite` before accessing the data. The missing probe means the attacker controls a pointer that the kernel dereferences at ring 0.

This pattern, untrusted pointers in `METHOD_NEITHER` IOCTLs, is a classic vulnerability class that KernelSight tracks across driver types. What makes ks.sys particularly vulnerable is the size of its dispatch table: with hundreds of property and method handlers, each one must independently validate its input, and a single missing probe in any handler is exploitable.

### Object Lifecycle Bugs in mskssrv.sys

The rendezvous server manages context objects (`FsContextReg` and `FsStreamReg`) that represent the two endpoints of a cross-process streaming connection. Three CVEs target this object management code, each exploiting a different aspect of the lifecycle.

CVE-2023-36802 is a type confusion between `FsContextReg` and `FsStreamReg` objects. Both types pass through shared dispatch paths, and when the dispatch code treats one type as the other, it interprets fields at incorrect offsets, giving the attacker control over values that the driver uses as pointers or sizes. This was exploited in the wild.

CVE-2023-29360 exploits the MDL handling in mskssrv.sys. The driver calls `MmProbeAndLockPages` with `KernelMode` access on an MDL that describes user-mode memory. The `KernelMode` parameter tells the memory manager to skip the check that the pages are in user space, allowing the attacker to lock and map kernel pages through a user-mode MDL.

CVE-2024-30089 is a use-after-free caused by a reference count logic error. When a context object is closed, the reference count is decremented, but under specific timing conditions, the object can be freed while another path still holds a reference. The freed memory is then reused, and the stale reference accesses the reallocated buffer.

### Integer Overflow in ksthunk.sys

When a 32-bit process sends KS IOCTLs on a 64-bit system, ksthunk.sys must translate the 32-bit `KSSTREAM_HEADER` structures to their 64-bit equivalents. This involves calculating the total size of the translated buffer: the number of headers multiplied by the 64-bit header size. CVE-2024-38054 triggers an integer overflow in this multiplication, producing a small allocation that receives a large copy.

CVE-2024-38238 exploits a different path in ksthunk.sys where the driver calls `MmMapLockedPages` on an MDL without first calling `MmProbeAndLockPages`. The missing probe means the MDL's page frame number (PFN) array may contain uninitialized or stale values, causing the map operation to access arbitrary physical memory.

## Vulnerability Patterns and Detection

| Pattern | Description | AutoPiff Rules |
|---------|-------------|----------------|
| Untrusted pointer in IOCTL | METHOD_NEITHER without ProbeForRead/Write | `method_neither_probe_added`, `ioctl_input_size_validation_added` |
| Integer overflow in thunking | KSSTREAM_HEADER size calculation overflows | `ioctl_input_size_validation_added` |
| Type confusion on context | FsContextReg/FsStreamReg objects confused | `object_type_validation_added` |
| MDL probe with KernelMode | MmProbeAndLockPages called with KernelMode on user MDL | `mdl_probe_access_mode_fix` |
| MDL map without probe | MmMapLockedPages without prior MmProbeAndLockPages | `mdl_safe_mapping_replacement`, `mdl_null_check_added` |
| UAF from refcount error | Reference count logic error on context close | `null_after_free_added`, `guard_before_free_added` |

## CVEs

| CVE | Driver | Description | Class | ITW |
|-----|--------|-------------|-------|-----|
| [CVE-2024-35250](../case-studies/CVE-2024-35250.md) | `ks.sys` | Untrusted pointer dereference in IOCTL dispatch | IOCTL Hardening | Yes |
| [CVE-2024-38054](../case-studies/CVE-2024-38054.md) | `ksthunk.sys` | Integer overflow in KSSTREAM_HEADER thunking | Integer Overflow | No |
| [CVE-2024-38238](../case-studies/CVE-2024-38238.md) | `ksthunk.sys` | MmMapLockedPages without MmProbeAndLockPages | MDL Handling | No |
| [CVE-2023-36802](../case-studies/CVE-2023-36802.md) | `mskssrv.sys` | FsContextReg/FsStreamReg type confusion | Type Confusion | Yes |
| [CVE-2023-29360](../case-studies/CVE-2023-29360.md) | `mskssrv.sys` | MmProbeAndLockPages with KernelMode on user MDL | MDL Handling | No |
| [CVE-2024-30089](../case-studies/CVE-2024-30089.md) | `mskssrv.sys` | Ref-count logic error causes UAF | Use-After-Free | No |

## Research Outlook

Kernel Streaming has produced a steady stream of bugs because it combines several vulnerability-prone architectural patterns in a single subsystem. The ks.sys IOCTL dispatch table is large enough that comprehensive auditing is difficult, and each handler must independently validate its input. mskssrv.sys manages complex object lifecycles with reference counting and shared dispatch paths, a recipe for type confusion and use-after-free. ksthunk.sys performs integer-sensitive structure translation that is inherently prone to overflow.

The KS framework is accessible to any user-mode process that can open a KS device handle. On most Windows systems, multiple KS devices are present (audio, camera, video capture), so the attack surface is broadly available. Researchers looking at KS should consider each of the three drivers as a separate audit target with its own bug patterns, while recognizing that they share a common IOCTL interface that can be fuzzed systematically.

For the broader context of IOCTL-based attack surfaces, see [Attack Surfaces](../attack-surfaces/). For MDL handling vulnerability patterns that appear across driver types, see [Vulnerability Classes](../vuln-classes/).
