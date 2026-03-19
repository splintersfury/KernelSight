# File System Minifilters

<div class="ks-pipeline-pos">
  <span class="ks-active">Driver Type</span> &rarr; Attack Surface &rarr; Vuln Class &rarr; Primitive &rarr; Case Study
</div>

When OneDrive syncs a file to the cloud, the kernel component doing the heavy lifting is a minifilter driver called cldflt.sys. It intercepts file I/O operations, translates between local file representations and cloud placeholders, and manages the reparse point data that tells Windows "this file lives in the cloud." Two heap overflows in cldflt.sys, patched months apart in the same reparse data parsing code, illustrate a pattern that recurs across the minifilter category: complex data structures processed in callback routines that were not designed with adversarial input in mind.

## How Minifilters Work

Minifilter drivers attach to file system stacks through the Filter Manager (`FltMgr.sys`) rather than directly inserting themselves into the I/O stack. They register pre-operation and post-operation callbacks for specific IRP major functions, and the Filter Manager invokes these callbacks at the appropriate point in the I/O path. Each minifilter has an altitude, a numeric value that determines its position in the filter stack relative to other minifilters.

This architecture means minifilters process every file operation that passes through their altitude, including operations on files they did not create. A cloud sync minifilter like cldflt.sys sees file creates, reads, writes, and metadata queries for any file in its monitored directories. The data it processes, particularly reparse point buffers and extended attributes, comes from the file system layer below and may ultimately originate from on-disk structures or user-mode API calls.

``` mermaid
graph TD
    A["User Mode<br/>File Operation"] -->|IRP| B["Filter Manager<br/>FltMgr.sys"]
    B -->|"Pre-Op Callback"| C["Minifilter<br/>cldflt.sys"]
    C -->|"Reparse Data"| D["Reparse Buffer<br/>(attacker-controlled)"]
    C -->|"Context Mgmt"| E["FltGetStreamContext<br/>FltReleaseContext"]
    B -->|"Post-Op Callback"| C
    B --> F["File System Driver<br/>ntfs.sys"]

    style A fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    style B fill:#152a4a,stroke:#3b82f6,color:#e2e8f0
    style C fill:#152a4a,stroke:#3b82f6,color:#e2e8f0
    style D fill:#0d1320,stroke:#ef4444,color:#e2e8f0
    style E fill:#0d1320,stroke:#f59e0b,color:#e2e8f0
    style F fill:#152a4a,stroke:#3b82f6,color:#e2e8f0
```

## Where the Bugs Live

The vulnerability surface in minifilters is distinct from the underlying file system drivers discussed in [File System Drivers](filesystem.md). While file system drivers parse on-disk metadata, minifilters process higher-level abstractions: reparse data, extended attributes, and context objects. The bugs tend to cluster in three areas.

**Reparse data handling** is the primary source of vulnerabilities in the KernelSight corpus. Cloud file minifilters like cldflt.sys process reparse points that encode cloud provider metadata, placeholder state, and sync information. These reparse buffers contain nested structures with their own offset and length fields, and the minifilter must parse them to decide how to handle the file operation. Both CVE-2024-30085 and CVE-2023-36036 are heap overflows caused by missing bounds checks on reparse data sizes before a memcpy call. The fact that the same driver had the same class of bug patched twice in quick succession suggests the reparse parsing code has many similar paths that were not audited holistically.

**Context reference management** is a subtler risk. Minifilters use the Filter Manager's context API (`FltGetStreamContext`, `FltAllocateContext`, `FltReleaseContext`) to associate per-stream, per-instance, or per-volume state with file objects. Every `FltGetStreamContext` call increments a reference count that must be balanced by a `FltReleaseContext` call. Error paths that skip the release create reference leaks, and in some cases, paths that release too early create use-after-free conditions. While neither CVE in the corpus directly exploits a context reference bug, this pattern is a known audit target in minifilter code.

**Pre/post-operation TOCTOU** affects minifilters that validate data in their pre-operation callback but act on it in the post-operation callback. If the underlying data can change between these two points (because another thread modifies the file or its metadata), the validation is worthless. This is particularly relevant for minifilters that process `IRP_MJ_CREATE` operations, where the file's attributes and reparse data can be modified by another thread between the minifilter's pre-create check and its post-create action.

## Vulnerability Patterns and Detection

| Pattern | Description | AutoPiff Rules |
|---------|-------------|----------------|
| Heap overflow via reparse data | Untrusted reparse buffer size used in memcpy | `added_len_check_before_memcpy`, `added_bounds_check_on_offset` |
| Context reference leak | FltReleaseContext not called on error path | `flt_context_reference_leak_fix` |
| TOCTOU in IRP_MJ_CREATE | Buffer validated then re-read from shared mapping | `flt_create_race_mitigation` |

## CVEs

| CVE | Driver | Description | Class | ITW |
|-----|--------|-------------|-------|-----|
| [CVE-2024-30085](../case-studies/CVE-2024-30085.md) | `cldflt.sys` | Missing size check before memcpy in Cloud Files | Buffer Overflow | No |
| [CVE-2023-36036](../case-studies/CVE-2023-36036.md) | `cldflt.sys` | Heap overflow via crafted reparse data | Buffer Overflow | Yes |

## Key Drivers

### cldflt.sys (Cloud Files Mini Filter)

The Windows Cloud Files API minifilter serves OneDrive and third-party cloud sync providers. It implements the kernel side of the cloud files placeholder system, managing the lifecycle of files that may exist locally, in the cloud, or in a partially hydrated state. Its attack surface centers on reparse point processing: every cloud file is represented by an NTFS reparse point containing provider-specific metadata, and cldflt.sys parses this metadata on virtually every file operation within a synced directory.

The recurring pattern across both CVEs is instructive. CVE-2023-36036 was exploited in the wild and patched in November 2023. CVE-2024-30085 fixed a nearly identical missing bounds check in a different code path within the same reparse data parsing logic, patched in June 2024. This suggests a targeted audit of the reparse handling code after the first bug did not catch all instances, or that the codebase has many structurally similar parsing paths that each need individual validation.

The attack vector for cldflt.sys is crafted reparse points on files within directories monitored by a cloud sync provider. Creating and modifying reparse points requires specific file system permissions, but on systems with OneDrive configured (which is the default on consumer Windows), the minifilter is loaded and processing reparse data on every file operation in the user's profile directory.

## Research Outlook

Minifilters are an underexplored category relative to their attack surface. Every major security product (AV, EDR, DLP, backup, encryption) installs at least one minifilter, and cloud sync providers add another layer. The Filter Manager's callback architecture means these drivers process data they did not originate, often in code paths that were not designed for adversarial input. Researchers auditing minifilters should focus on the data transformation boundaries: where the minifilter reads data from a lower layer and copies or interprets it, particularly in reparse data handling, extended attribute parsing, and context object serialization.

The file system drivers that sit below minifilters in the I/O stack are covered in [File System Drivers](filesystem.md). For attack surface details on how user-mode code triggers minifilter callbacks, see [Attack Surfaces](../attack-surfaces/).
