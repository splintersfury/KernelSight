# KASLR

Kernel Address Space Layout Randomization randomizes the base addresses of the kernel image, HAL, drivers, and pool regions to prevent exploitation using hardcoded addresses.

## Overview

Microsoft introduced basic kernel address randomization in Windows Vista and has significantly improved it across subsequent releases. KASLR forces attackers to obtain a kernel address leak before they can construct reliable exploits, because kernel image base addresses, driver load addresses, pool regions, and kernel stack addresses all vary between boots. Windows 8 improved entropy and randomized driver load order. Windows 10 progressively restricted the APIs that could leak kernel addresses (particularly `NtQuerySystemInformation`), and Windows 11 22H2/24H2 added further entropy and restricted additional information disclosure vectors.

KASLR is foundational: nearly every kernel exploit requires defeating KASLR as a prerequisite step, making information disclosure vulnerabilities (or KASLR bypass techniques) a critical component of exploit chains.

## Mechanism

**Kernel Image Base Randomization:**

- On each boot, `ntoskrnl.exe` is loaded at one of approximately 256 possible base addresses on x64 systems (8 bits of entropy), selected from a 32MB range.
- The HAL (`hal.dll`) is loaded at a randomized address adjacent to the kernel image.
- The randomization is performed by the Windows Boot Manager (bootmgr) during the boot process, before the kernel begins execution.

**Driver Load Address Randomization:**

- Starting with Windows 10, the load order and base addresses of boot-start and system-start drivers are randomized.
- Drivers are no longer loaded at predictable addresses relative to the kernel base.
- The driver load order itself is shuffled where dependencies permit.

**Pool and Stack Randomization:**

- Kernel pool regions (paged and non-paged) are allocated at randomized virtual addresses.
- Kernel-mode thread stacks have randomized base addresses and include stack cookies for overflow detection.
- The initial stack pointer offset within a stack page is randomized (limited entropy).

**API Restrictions (Progressive):**

- Windows 10 20H1: `NtQuerySystemInformation` with `SystemModuleInformation` class restricted to processes running at Medium Integrity Level or above (blocks Low IL sandboxed processes).
- Windows 10 21H2+: Additional restrictions on `SystemExtendedHandleInformation`, which previously leaked kernel object addresses.
- Windows 11: `SystemBigPoolInformation` restrictions, ETW-based leak mitigations.

**Additional Entropy (22H2/24H2):**

- Windows 11 22H2 expanded the randomization range for the kernel image.
- Windows 11 24H2 added further entropy to kernel stack randomization and restricted additional information leak vectors.

## Primitives Blocked

- **Hardcoded kernel address exploitation:** Exploits that rely on known, fixed addresses for kernel functions, gadgets, or data structures fail because addresses change each boot.
- **Static ROP gadget addresses:** ROP chains that use hardcoded gadget offsets from a known kernel base are unusable without first leaking the actual base address.
- **Known-offset EPROCESS/token access:** Even with a relative offset from the kernel base to the target structure, the absolute address is unknown without an info leak.
- **Fixed-address kernel shellcode placement:** Mapping shellcode at a known kernel address (e.g., via pool spray) requires knowing pool region addresses, which are randomized.

## Bypass History

See the dedicated [KASLR Bypasses](kaslr-bypasses.md) page for a comprehensive bypass catalog.

**Known Leak Vectors (summary):**

- **NtQuerySystemInformation (pre-20H1):** `SystemModuleInformation`, `SystemExtendedHandleInformation`, and `SystemBigPoolInformation` classes returned kernel pointers to any caller. This was the easiest and most common KASLR bypass for years. Progressively restricted starting in 20H1.
- **NtQuerySystemInformation (post-20H1):** Still available to Medium IL processes. Sandbox escapes that elevate to Medium IL can still use this API. Full restriction has not been implemented due to application compatibility.
- **Driver-specific info disclosure:** Individual driver vulnerabilities that leak uninitialized stack or pool data containing kernel pointers. These are patched individually as they are discovered (e.g., CVE-2023-32019, CVE-2024-38256).
- **Timing side-channels:** Microarchitectural side-channels (cache timing, TLB state) can be used to infer kernel page mappings. These attacks are low-bandwidth but do not require any software vulnerability.
- **ETW-based leaks:** Event Tracing for Windows providers that log kernel pointers in event data. Microsoft has been progressively sanitizing ETW output.
- **KUSER_SHARED_DATA:** The shared data page at a fixed user-mode address contains some kernel timing information that can be used for limited side-channel inferences, though not direct address leakage.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2023-32019](../case-studies/CVE-2023-32019.md) | `ntoskrnl.exe` | Kernel heap memory leak |
| [CVE-2024-38256](../case-studies/CVE-2024-38256.md) | `win32k.sys` | Uninitialized memory leak |

## AutoPiff Detection

- `buffer_zeroing_before_copy_added` -- Detects patches that zero buffers before copying to user mode
- `stack_variable_initialization_added` -- Detects addition of stack variable initialization
- `kernel_pointer_scrubbing_added` -- Detects removal of kernel pointers from user-visible output

## Windows Version Availability

| Version | Status | Notes |
|---------|--------|-------|
| Windows Vista | Basic KASLR | Limited kernel base randomization |
| Windows 7 | Basic KASLR | Minimal improvements over Vista |
| Windows 8 / 8.1 | Improved | Increased entropy, driver load order randomization |
| Windows 10 RS1-RS5 | Enhanced | Progressive improvements, NonPagedPoolNx |
| Windows 10 20H1 (2004) | API restricted | `NtQuerySystemInformation` restricted below Medium IL |
| Windows 10 21H2 | Further restricted | Handle table info leak restrictions |
| Windows 11 21H2-23H2 | Enhanced | BigPool info restrictions, ETW sanitization |
| Windows 11 24H2 | Further hardened | Additional entropy, expanded API restrictions |

## Cross-References

- [KASLR Bypasses](kaslr-bypasses.md) -- comprehensive catalog of KASLR bypass techniques
- [Pool Hardening](pool-hardening.md) -- pool address randomization is part of KASLR
- [SMEP / SMAP](smep-smap.md) -- SMEP/SMAP enforcement is independent of address knowledge
- [Write-What-Where](../primitives/arw/write-what-where.md) -- requires known addresses, making KASLR a prerequisite bypass
- [CVE-2023-32019](../case-studies/CVE-2023-32019.md) -- kernel heap info disclosure
- [CVE-2024-38256](../case-studies/CVE-2024-38256.md) -- uninitialized memory info disclosure
- [CVE-2024-21338](../case-studies/CVE-2024-21338.md) -- appid.sys exploit that requires KASLR bypass as first step
