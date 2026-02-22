# KernelSight

**A structured knowledge base for Windows kernel driver exploitation techniques.**

KernelSight catalogs attack surfaces, vulnerability classes, exploitation primitives, and mitigations — each grounded in real CVEs with specific driver names, versions, and builds.

## Sections

<div class="grid cards" markdown>

-   **[Driver Types](driver-types/index.md)**

    ---

    File system, minifilter, log/transaction, network stack, kernel streaming, Win32k, core kernel, security/policy, storage

-   **[Attack Surfaces](attack-surfaces/index.md)**

    ---

    IOCTL handlers, filesystem IRPs, NDIS/network, PnP/Power, WDF, registry callbacks, ALPC, shared memory, WMI/ETW

-   **[Vulnerability Classes](vuln-classes/index.md)**

    ---

    Buffer overflows, integer overflows, type confusion, TOCTOU, use-after-free, race conditions, uninitialized memory, logic bugs

-   **[Primitives](primitives/index.md)**

    ---

    10 arbitrary R/W primitive families + 9 exploitation technique families

-   **[Mitigations](mitigations/index.md)**

    ---

    SMEP/SMAP, kCFG/kCET, VBS/HVCI, KDP, pool hardening, Secure Pool, ACG, KASLR

-   **[Case Studies](case-studies/index.md)**

    ---

    28+ real CVEs with driver names, vulnerable/fixed builds, and exploitation details

-   **[Tooling](tooling/index.md)**

    ---

    Static analysis, fuzzing, debugging, and AutoPiff integration

</div>

## Quick Stats

| Metric | Count |
|--------|-------|
| CVE case studies | 28 |
| Unique drivers | 16 |
| Attack surfaces | 9 |
| Vulnerability classes | 10 |
| Exploitation primitives | 19 |
| Mitigations | 8 |
| Exploited in the wild | 12 |

## How This Knowledge Base Works

Each technique page links to:

- **Real CVEs** with specific driver names and build numbers
- **AutoPiff detection rules** that identify the patch pattern
- **Related techniques** for cross-referencing
- **Mitigations** that defend against the technique

The [automated collector](https://github.com/your-org/KernelSight) continuously monitors security feeds and proposes additions via GitHub PRs.
