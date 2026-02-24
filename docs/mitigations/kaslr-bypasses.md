# KASLR Bypasses

Catalog of techniques used to defeat Kernel Address Space Layout Randomization across Windows builds.

## Overview

Kernel Address Space Layout Randomization (KASLR) randomizes the base address of `ntoskrnl.exe` and major kernel-mode drivers at each boot. On Windows 10+, the kernel base is randomized with approximately 8 bits of entropy, placing it at one of 256 possible locations within a reserved range. Defeating KASLR is a prerequisite for most kernel exploits because reliable exploitation requires knowledge of kernel object and function addresses.

## Information Disclosure APIs

### NtQuerySystemInformation

The `NtQuerySystemInformation` syscall has historically been the most straightforward KASLR bypass vector.

- **SystemModuleInformation (class 11)** -- Returned the load address of every kernel module. Available to any user-mode process until Windows 10 20H1, when Microsoft restricted it to medium integrity level and above. Low-IL processes (sandboxed browsers, UWP apps) can no longer query this class.
- **SystemBigPoolInformation (class 66)** -- Leaked addresses of large pool allocations, including their pool tags. Restricted in later builds to prevent kernel heap address disclosure.
- **SystemExtendedHandleInformation (class 64)** -- Returns handle table entries including kernel object addresses. Still partially available at medium integrity level, making it a viable leak source for non-sandboxed processes.

### Other APIs

- **EnumDeviceDrivers / GetDeviceDriverBaseAddress** -- PSAPI functions that wrap `NtQuerySystemInformation`. Restricted in Windows 11 24H2, returning errors for non-elevated callers.
- **NtQueryVirtualMemory with MemoryWorkingSetExInformation** -- Can leak page frame numbers and virtual address metadata. Usable for inferring kernel layout through working set analysis.

## ETW-Based Leaks

Event Tracing for Windows (ETW) kernel logger sessions can inadvertently expose kernel pointers through event payloads.

- Kernel logger trace sessions include raw pointer values in certain event classes
- Circular buffer timing attacks allow inferring kernel activity patterns
- Thread and process creation events historically included kernel addresses in callback data
- Status: Most ETW pointer leaks were patched in Windows 11 22H2 and backported to 21H2 via servicing updates

## Timing Side-Channels

Hardware-level side channels provide KASLR bypass capabilities independent of software restrictions.

- **Prefetch instruction timing (EntryBleed for Windows)** -- The CPU `prefetch` instruction executes faster when the target virtual address is present in the current page tables versus unmapped. On modern Windows 11 (24H2) where KVA shadowing is disabled, the entire kernel address space remains in user-mode page tables, making kernel pages distinguishable by timing. An attacker probes the 256 possible kernel base addresses by measuring `prefetch` + `rdtsc` latency for each candidate, identifying the correct base within milliseconds. Demonstrated to work reliably on modern Intel CPUs; AMD results are less consistent. See [24H2 NT Exploit](https://exploits.forsale/24h2-nt-exploit/) for a working implementation. This technique requires no software vulnerability — only user-mode code execution.
- **KASLR entropy bruteforce** -- With only 256 possible base addresses, an attacker with a partial info leak can enumerate all possibilities
- **Interrupt timing variations** -- Kernel interrupt handling time varies based on cache state, which correlates with address layout
- Status: These attacks are hardware-dependent and have not been fully mitigated. Windows 11 24H2 increased kernel entropy but did not eliminate timing channels.

## Security Descriptor Corruption

With an arbitrary write or [bit-manipulation primitive](../primitives/exploitation/bit-manipulation.md), an attacker can bypass KASLR restrictions by corrupting the kernel structures that enforce them, rather than exploiting an information disclosure vulnerability.

- **SepMediumDaclSd DACL zeroing** -- The global `SepMediumDaclSd` security descriptor gates `NtQuerySystemInformation` access for sensitive info classes. Zeroing the DACL (e.g., via `RtlClearAllBits`) removes the integrity level check, allowing Low-IL processes to query kernel module addresses. See [ACL / SD Manipulation](../primitives/exploitation/acl-sd-manipulation.md).
- **SepMediumDaclSd Control field bit-flip** -- A more surgical variant targets the `SE_SACL_PRESENT` (0x10) bit in the security descriptor's `Control` field. Clearing this bit tricks `SeAccessCheck` into skipping Mandatory Integrity Control validation entirely, bypassing both DACL and integrity label checks with a single bit write. Demonstrated in the [StarLabs Chrome sandbox escape](https://starlabs.sg/blog/2025/07-fooling-the-sandbox-a-chrome-atic-escape/) using CVE-2024-30088's partial write primitive.
- **WIL feature flag bypass** -- Even after bypassing the DACL check, a secondary gate exists: the WIL runtime flag `Feature_RestrictKernelAddressLeaks__private_featureState` controls whether kernel addresses are scrubbed from API output. Flipping this flag's state bits (via `RtlSetBit`) disables address scrubbing. Combined with DACL corruption, this fully defeats `NtQuerySystemInformation` restrictions on modern Windows. Demonstrated in [CVE-2026-21241](../case-studies/CVE-2026-21241.md).

## Driver Info Disclosure CVEs

| CVE | Driver | Leak Type | Patched Build |
|-----|--------|-----------|---------------|
| CVE-2024-38256 | `win32kfull.sys` | Kernel pointer leak via GDI information class | 10.0.26100 (24H2) |
| CVE-2024-21338 | `appid.sys` | Kernel address disclosure via IOCTL return data | 10.0.22621.3155 (22H2) |
| CVE-2023-32019 | `ntoskrnl.exe` | Kernel memory disclosure via information class | 10.0.22621.1928 (22H2) |
| CVE-2023-36038 | `HTTP.sys` | Kernel stack address leak | 10.0.22621.2506 (22H2) |
| CVE-2022-21881 | `win32k.sys` | Kernel pointer leak via window message handling | 10.0.19041.1466 (21H2) |

## Windows Version Timeline

| Version | KASLR Entropy | Key Changes |
|---------|---------------|-------------|
| RS1-RS5 (2016-2018) | ~8 bits kernel base | Basic KASLR for ntoskrnl and major drivers. All info disclosure APIs available to any IL. |
| 19H1-19H2 (2019) | ~8 bits | No significant KASLR changes. |
| 20H1-20H2 (2020) | ~8 bits | `NtQuerySystemInformation` restricted for Low-IL processes. Sandbox escape now required for API-based leaks. |
| 21H1-21H2 (2021) | ~8 bits | Further API restrictions. `SystemBigPoolInformation` access tightened. |
| 22H2 (2022) | ~8 bits | ETW pointer leak fixes. Multiple info disclosure CVEs patched. |
| 23H2 (2023) | ~8 bits | Continued incremental API hardening. |
| 24H2 (2024) | Increased entropy | `EnumDeviceDrivers` restricted for non-elevated callers. Kernel base entropy expanded. Most reliable remaining vector is driver-specific info disclosure vulns. |

## Current Status (24H2+)

On Windows 11 24H2, the primary KASLR bypass mechanisms are:

- **Driver-specific information disclosure vulnerabilities** remain the most practical KASLR defeat method. Each Patch Tuesday potentially introduces new info leak CVEs in kernel components.
- **Medium-IL NtQuerySystemInformation** still returns some kernel information, though the most sensitive classes are restricted.
- **Security descriptor corruption** (SepMediumDaclSd + WIL feature flag) allows converting any write primitive into a KASLR bypass without a dedicated info leak vulnerability.
- **Prefetch side-channel** works on Intel CPUs without any software vulnerability, though it is hardware-dependent.
- **ETW and API-based leaks** are largely closed for low-IL and partially restricted for medium-IL.

For exploit chains targeting 24H2, researchers increasingly use security descriptor corruption (when they already have a write primitive) or prefetch timing (when they need a standalone leak), treating KASLR bypass as its own stage in the exploit chain.

## See Also

- [KASLR](kaslr.md) -- overview of the mitigation mechanism
- [ACL / SD Manipulation](../primitives/exploitation/acl-sd-manipulation.md) -- SepMediumDaclSd corruption technique
- [Bit-Manipulation Primitives](../primitives/exploitation/bit-manipulation.md) -- RtlSetBit/RtlClearAllBits used for SD and feature flag corruption
- [CVE-2026-21241](../case-studies/CVE-2026-21241.md) -- full exploit chain using SD corruption + WIL bypass for KASLR defeat
