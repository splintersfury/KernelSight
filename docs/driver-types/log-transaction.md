# Log / Transaction Drivers

<div class="ks-pipeline-pos">
  <span class="ks-active">Driver Type</span> &rarr; Attack Surface &rarr; Vuln Class &rarr; Primitive &rarr; Case Study
</div>

If you had to pick a single Windows kernel driver to study for exploitation patterns, it should be clfs.sys. The Common Log File System driver has been exploited in the wild at least seven times (four in the KernelSight corpus), making it the most repeatedly targeted individual driver component in the Windows kernel. Every exploit follows the same template: craft a `.blf` log file with corrupted metadata, open it from a standard user account via `CreateLogFile`, and let clfs.sys parse the corrupted offsets into a pool overflow. The reason it keeps producing bugs is architectural: a complex binary metadata format with dozens of offset and length fields, all trusted by the parser and all controllable by anyone who can write a file.

## Architecture of CLFS

The Common Log File System is a WDM kernel-mode driver (`clfs.sys`) that provides a high-performance structured logging facility. It was originally designed for Transactional NTFS (TxF), Windows Error Reporting, and application-level transaction logging. The log data lives in two file types: base log files (`.blf`) that store metadata, and container files that store the actual log records.

The base log file is where the bugs live. A `.blf` file contains metadata blocks with a structured binary format: control records, base records, truncate records, and a symbol zone that maps symbolic names to container contexts. Each block contains offset fields that point to sub-structures within the block, length fields that determine copy sizes, and index values that select entries from arrays. The parser in clfs.sys reads these values from the file and uses them directly in memory operations.

``` mermaid
graph LR
    A["User Mode<br/>CreateLogFile"] -->|"Open .blf"| B["clfs.sys"]
    B -->|"Parse"| C["Base Log File<br/>.blf metadata"]
    C --> D["Control Block<br/>offsets, lengths"]
    C --> E["Base Record<br/>container queue"]
    C --> F["Symbol Zone<br/>name→context map"]
    B -->|"Pool Alloc"| G["Kernel Pool<br/>overflow target"]

    style A fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    style B fill:#152a4a,stroke:#3b82f6,color:#e2e8f0
    style C fill:#0d1320,stroke:#ef4444,color:#e2e8f0
    style D fill:#0d1320,stroke:#ef4444,color:#e2e8f0
    style E fill:#0d1320,stroke:#ef4444,color:#e2e8f0
    style F fill:#0d1320,stroke:#ef4444,color:#e2e8f0
    style G fill:#0d1320,stroke:#f59e0b,color:#e2e8f0
```

## Why CLFS Keeps Getting Exploited

The recurring exploitation of clfs.sys is not a coincidence. Four properties make it an ideal target, and understanding them explains why patches keep arriving.

First, the binary metadata format is large and complex. A `.blf` file contains multiple metadata blocks, each with their own offset tables, length fields, and index values. Microsoft patches one corrupted offset path, but there are dozens of similar paths through the metadata that use the same pattern: read an offset from the file, use it to index into a buffer. Each patch addresses the specific offset field used by the reported exploit, leaving structurally identical code paths unpatched until someone finds them.

Second, the attack surface is reachable from a standard user account. The `CreateLogFile` API allows any user to create and open CLFS log files. This means the entire metadata parsing surface is accessible without elevation, making CLFS bugs directly usable for local privilege escalation.

Third, the exploitation pattern is reliable. CLFS metadata parsing allocates pool memory based on values from the `.blf` file, then copies data into those allocations. When a corrupted size or offset causes the copy to exceed the allocation, the result is a heap overflow into adjacent pool objects. Because the attacker controls the file contents, they control both the overflow size and the overflow data, giving them a high degree of control over what gets corrupted.

Fourth, the post-corruption exploitation path is well-established. CLFS pool overflows typically corrupt adjacent objects (pipe attributes, WNF state data, or other kernel pool allocations) to build an arbitrary read/write primitive, which is then used for token manipulation to reach SYSTEM.

## Vulnerability Patterns and Detection

| Pattern | Description | AutoPiff Rules |
|---------|-------------|----------------|
| OOB write via offset corruption | Base log offset field points outside valid region | `added_len_check_before_memcpy`, `added_bounds_check_on_offset`, `added_index_range_check` |
| Heap overflow in container load | Container queue size not validated before copy | `added_len_check_before_memcpy`, `added_index_bounds_check` |
| Pool corruption via symbol zone | cbSymbolZone field manipulated to write past allocation | `added_index_bounds_check`, `added_struct_size_validation` |
| Pool API hardening | Legacy ExAllocatePoolWithTag without NULL checks | `deprecated_pool_api_replacement`, `pool_allocation_null_check_added` |

The common thread across all four CVEs is a failure to validate metadata values read from the `.blf` file before using them in memory operations. AutoPiff detects the fix patterns because Microsoft's patches consistently add bounds checks, length validation, and index range validation at the exact points where untrusted file data enters memory operations.

## CVEs

| CVE | Driver | Description | Class | ITW |
|-----|--------|-------------|-------|-----|
| [CVE-2024-49138](../case-studies/CVE-2024-49138.md) | `clfs.sys` | Heap overflow in LoadContainerQ | Buffer Overflow | Yes |
| [CVE-2023-28252](../case-studies/CVE-2023-28252.md) | `clfs.sys` | OOB write via corrupted base log offset | Buffer Overflow | Yes |
| [CVE-2023-36424](../case-studies/CVE-2023-36424.md) | `clfs.sys` | Pool overflow from unvalidated reparse data | Buffer Overflow | No |
| [CVE-2022-37969](../case-studies/CVE-2022-37969.md) | `clfs.sys` | SignaturesOffset OOB write via corrupted cbSymbolZone | Buffer Overflow | Yes |

Three of the four CVEs were exploited in the wild, and all four are buffer overflows caused by trusting metadata from `.blf` files. This consistency makes CLFS a strong case study for understanding how a single driver can produce a stream of structurally similar but individually distinct vulnerabilities.

## The Typical CLFS Exploitation Chain

The exploitation pattern across CLFS CVEs is remarkably consistent. First, the attacker creates a `.blf` file with a corrupted metadata field, typically an offset, a length, or an array index within the base log record or container queue. Then they open this file from user mode via `CreateLogFile`, triggering the kernel to parse the metadata.

During parsing, clfs.sys allocates a pool buffer based on a value from the file, then copies data from the file into that buffer using another value from the file as the copy length. When the length exceeds the allocation, the copy overflows into adjacent pool memory. The attacker controls the file contents, so they control the overflow data.

The corrupted adjacent object is typically chosen through heap grooming: the attacker arranges the kernel pool so that a useful object (a pipe attribute buffer, a WNF_STATE_DATA structure, or a similar controllable allocation) sits immediately after the CLFS allocation. The overflow corrupts this object's metadata, giving the attacker a relative or arbitrary read/write primitive. From there, the path to SYSTEM follows established patterns: locate the current process token in memory and overwrite it with a SYSTEM token, or manipulate the token's privileges field.

## Research Outlook

CLFS remains one of the highest-value audit targets in the Windows kernel. Microsoft has been adding validation checks incrementally with each patch, but the metadata format contains many offset and length fields that follow the same untrusted-value-to-memory-operation pattern. Researchers looking at CLFS should focus on the metadata block parsing functions (`ReadMetadataBlock`, `WriteMetadataBlock`, `FlushImage`, `LoadContainerQ`) and trace every value read from the `.blf` file to its use in a memory operation, checking whether bounds validation exists for each one.

For the broader context of how kernel pool overflows are exploited, see the [vulnerability classes](../vuln-classes/) section. For the file system drivers that store the `.blf` files on disk, see [File System Drivers](filesystem.md).
