# KASLR Bypasses

Techniques for defeating Kernel Address Space Layout Randomization across Windows builds.

## Overview

KASLR randomizes the base address of `ntoskrnl.exe` and major kernel-mode drivers at boot. On Windows 10+, the kernel base has ~8 bits of entropy (256 possible locations). Most kernel exploits require knowing kernel object and function addresses, making KASLR bypass a standard exploit chain stage.

## Information Disclosure APIs

### NtQuerySystemInformation

- **SystemModuleInformation (class 11)** — Returns load addresses of all kernel modules. Available to any process until 20H1, which restricted it to medium-IL and above.
- **SystemBigPoolInformation (class 66)** — Leaked large pool allocation addresses with pool tags. Restricted in later builds.
- **SystemExtendedHandleInformation (class 64)** — Returns handle table entries including kernel object addresses. Still partially available at medium-IL.

### Other APIs

- **EnumDeviceDrivers / GetDeviceDriverBaseAddress** — PSAPI wrappers around `NtQuerySystemInformation`. Restricted in 24H2 for non-elevated callers.
- **NtQueryVirtualMemory with MemoryWorkingSetExInformation** — Leaks page frame numbers and VA metadata. Usable for inferring kernel layout via working set analysis.

## ETW-Based Leaks

ETW kernel logger sessions can expose kernel pointers through event payloads.

- Certain event classes include raw pointer values
- Thread and process creation events historically included kernel addresses in callback data
- Circular buffer timing attacks allow inferring kernel activity patterns
- Status: Most pointer leaks patched in 22H2, backported to 21H2 via servicing updates

## Timing Side-Channels

Hardware-level side channels bypass software restrictions entirely.

- **Prefetch timing** — `prefetch` executes faster when the target VA is in the current page tables. On 24H2 with KVA shadowing disabled, kernel pages remain in user-mode page tables. Probing the 256 candidate base addresses via `prefetch` + `rdtsc` latency identifies the correct base within milliseconds. Works reliably on Intel; inconsistent on AMD. See [24H2 NT Exploit](https://exploits.forsale/24h2-nt-exploit/). Requires no software vulnerability.
- **Entropy bruteforce** — With only 256 possible bases, a partial info leak enables enumeration of all possibilities.
- **Interrupt timing** — Kernel interrupt handling time varies with cache state, which correlates with address layout.
- Status: Hardware-dependent, not fully mitigated. 24H2 increased entropy but did not eliminate timing channels.

## Security Descriptor Corruption

With an arbitrary write or [bit-manipulation primitive](../primitives/exploitation/bit-manipulation.md), KASLR restrictions can be removed by corrupting the kernel structures that enforce them — no info disclosure vulnerability needed.

- **SepMediumDaclSd DACL zeroing** — This global security descriptor gates `NtQuerySystemInformation` access for sensitive info classes. Zeroing the DACL (e.g., via `RtlClearAllBits`) removes the integrity level check, letting Low-IL processes query kernel module addresses. See [ACL / SD Manipulation](../primitives/exploitation/acl-sd-manipulation.md).
- **SepMediumDaclSd Control bit-flip** — Clearing the `SE_SACL_PRESENT` (0x10) bit in the descriptor's `Control` field tricks `SeAccessCheck` into skipping MIC validation entirely, bypassing both DACL and integrity label checks with a single bit write. Demonstrated in the [StarLabs Chrome sandbox escape](https://starlabs.sg/blog/2025/07-fooling-the-sandbox-a-chrome-atic-escape/) using CVE-2024-30088's partial write primitive.
- **WIL feature flag bypass** — A secondary gate: the WIL runtime flag `Feature_RestrictKernelAddressLeaks__private_featureState` controls whether kernel addresses are scrubbed from API output. Flipping its state bits via `RtlSetBit` disables scrubbing. Combined with DACL corruption, this fully defeats `NtQuerySystemInformation` restrictions. Demonstrated in [CVE-2026-21241](../case-studies/CVE-2026-21241.md).

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
| RS1–RS5 (2016–2018) | ~8 bits | Basic KASLR. All info disclosure APIs available at any IL. |
| 19H1–19H2 (2019) | ~8 bits | No KASLR changes. |
| 20H1–20H2 (2020) | ~8 bits | `NtQuerySystemInformation` restricted for Low-IL. Sandbox escape now required for API-based leaks. |
| 21H1–21H2 (2021) | ~8 bits | `SystemBigPoolInformation` access tightened. |
| 22H2 (2022) | ~8 bits | ETW pointer leak fixes. Multiple info disclosure CVEs patched. |
| 23H2 (2023) | ~8 bits | Incremental API hardening. |
| 24H2 (2024) | Increased | `EnumDeviceDrivers` restricted for non-elevated callers. Kernel base entropy expanded. Most reliable remaining vector: driver-specific info disclosure vulns. |

## Current Status (24H2+)

Primary bypass mechanisms on Windows 11 24H2:

- **Driver-specific info disclosure vulns** — most practical method. New info leak CVEs appear regularly in kernel components.
- **Medium-IL NtQuerySystemInformation** — still returns some kernel information; most sensitive classes restricted.
- **Security descriptor corruption** (SepMediumDaclSd + WIL flag) — converts any write primitive into a KASLR bypass without a dedicated info leak.
- **Prefetch side-channel** — works on Intel CPUs without any software vulnerability; hardware-dependent.
- **ETW and API leaks** — largely closed for Low-IL, partially restricted for medium-IL.

On 24H2, exploit chains typically use SD corruption (when a write primitive is already available) or prefetch timing (for a standalone leak).

## See Also

- [KASLR](kaslr.md) -- overview of the mitigation mechanism
- [ACL / SD Manipulation](../primitives/exploitation/acl-sd-manipulation.md) -- SepMediumDaclSd corruption technique
- [Bit-Manipulation Primitives](../primitives/exploitation/bit-manipulation.md) -- RtlSetBit/RtlClearAllBits used for SD and feature flag corruption
- [CVE-2026-21241](../case-studies/CVE-2026-21241.md) -- full exploit chain using SD corruption + WIL bypass for KASLR defeat
