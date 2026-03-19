# KASLR

Nearly every kernel exploit begins the same way: the attacker needs to know where something is. A token to swap, an EPROCESS to read, a function to call. Kernel Address Space Layout Randomization makes those addresses unpredictable by randomizing the base addresses of the kernel image, HAL, drivers, and pool regions on every boot. Without KASLR, kernel exploitation is dramatically simpler. With it, the attacker must first solve an information disclosure problem before they can use whatever corruption primitive they hold.

This makes KASLR the most frequently bypassed mitigation in the corpus. It appears as a prerequisite step in virtually every exploit chain documented in the [case studies](../case-studies/index.md), and the techniques for defeating it have evolved from simple API calls to security descriptor corruption and hardware side-channels.

## How It Works

Microsoft introduced basic kernel address randomization in Windows Vista and has improved it across each subsequent release. The randomization operates at several levels, each adding a layer of uncertainty for the attacker.

**Kernel image base randomization** is the foundational mechanism. On each boot, `ntoskrnl.exe` is loaded at one of approximately 256 possible base addresses on x64 systems, providing 8 bits of entropy within a 32MB range. The HAL (`hal.dll`) is loaded at a randomized address adjacent to the kernel image. The Windows Boot Manager (bootmgr) performs this randomization during the boot process, before the kernel begins execution, so the selected base address is fixed for the lifetime of the boot session.

**Driver load address randomization** was strengthened starting with Windows 10. Boot-start and system-start drivers are loaded at randomized addresses, and the load order itself is shuffled where dependency constraints permit. This means drivers are no longer at predictable offsets relative to the kernel base, forcing the attacker to leak each driver's address independently or compute offsets from a known module base.

**Pool and stack randomization** adds entropy to the data side. Kernel pool regions (paged and non-paged) are allocated at randomized virtual addresses. Kernel-mode thread stacks have randomized base addresses and include stack cookies for overflow detection. The initial stack pointer offset within a stack page is also randomized, though with limited entropy.

**API restrictions** represent Microsoft's progressive effort to close the software-based information disclosure paths. Before Windows 10 20H1, `NtQuerySystemInformation` with `SystemModuleInformation` returned kernel module load addresses to any process at any integrity level. This was the easiest KASLR bypass for years. Windows 10 20H1 restricted these queries to Medium integrity level and above, blocking sandboxed (Low IL) processes. Subsequent releases tightened `SystemExtendedHandleInformation` (which leaked kernel object addresses through the handle table), `SystemBigPoolInformation` (which exposed large pool allocation addresses), and ETW providers that logged kernel pointers in event data. Windows 11 24H2 expanded the randomization range for the kernel image and restricted `EnumDeviceDrivers` for non-elevated callers.

Despite this progressive hardening, the restrictions have never been total. `NtQuerySystemInformation` still returns some kernel information to Medium IL processes, because fully restricting it would break too many applications. This compromise is the root of the ongoing cat-and-mouse game between Microsoft's API hardening and attacker techniques for regaining access to the restricted data.

## What KASLR Blocks

Without KASLR, an attacker with a write-what-where primitive can immediately target known-good addresses for kernel functions, ROP gadgets, EPROCESS structures, and token objects. KASLR forces the attacker to solve four problems before the write becomes useful.

First, hardcoded kernel address exploitation fails because addresses change each boot. An exploit compiled to write to a fixed offset from `ntoskrnl.exe` base will crash on any system where the base differs. Second, static ROP gadget addresses are unusable because the gadget locations depend on the kernel base. Third, even with a relative offset from the kernel base to a target structure, the absolute address is unknown without an information leak. Fourth, mapping shellcode at a known kernel address (for example, via pool spray) requires knowing where the pool regions start, and those are randomized too.

The net effect is that KASLR converts every write primitive into a two-step problem: first leak an address, then use it. This is why information disclosure vulnerabilities and KASLR bypass techniques appear as a mandatory stage in almost every [exploit chain pattern](../guides/exploit-chain-patterns.md).

## How Attackers Defeat It

The dedicated [KASLR Bypasses](kaslr-bypasses.md) page catalogs every technique in detail. The summary below covers the major categories.

**NtQuerySystemInformation (pre-20H1)** was the dominant bypass for years. `SystemModuleInformation`, `SystemExtendedHandleInformation`, and `SystemBigPoolInformation` classes returned kernel pointers to any caller. Progressively restricted starting in 20H1, but still available to Medium IL processes, meaning a sandbox escape that elevates to Medium IL can still use this API.

**SepMediumDaclSd corruption** represents a newer, more powerful approach. The integrity level restriction on `NtQuerySystemInformation` is enforced via a DACL check against the global `SepMediumDaclSd` security descriptor. An attacker with a write or [bit-manipulation primitive](../primitives/exploitation/bit-manipulation.md) can zero the DACL (for example, via `RtlClearAllBits`), removing the restriction entirely and allowing Low IL processes to query kernel module addresses. Used in [CVE-2026-21241](../case-studies/CVE-2026-21241.md). See [ACL / SD Manipulation](../primitives/exploitation/acl-sd-manipulation.md).

**WIL Feature Flag bypass** adds a second gate that must be defeated alongside the DACL. Even after the DACL check passes, Microsoft added a secondary control via the Windows Implementation Library (WIL) feature flag system. The runtime flag `Feature_RestrictKernelAddressLeaks__private_featureState` controls whether kernel addresses are scrubbed from `NtQuerySystemInformation` output. This flag is stored in kernel memory as a simple integer, and an attacker with a [bit-manipulation primitive](../primitives/exploitation/bit-manipulation.md) can flip its state bits to disable the scrubbing. Combined with `SepMediumDaclSd` corruption, this two-step approach fully defeats the `NtQuerySystemInformation` restrictions on modern Windows. Demonstrated in [CVE-2026-21241](../case-studies/CVE-2026-21241.md).

**Driver-specific information disclosure** vulnerabilities leak uninitialized stack or pool data containing kernel pointers. These are patched individually as they are discovered (CVE-2023-32019, CVE-2024-38256), but new ones appear regularly.

**Timing side-channels** bypass software restrictions entirely. The `prefetch` instruction executes faster when the target virtual address is in the current page tables. On Intel CPUs, probing the 256 candidate kernel base addresses via `prefetch` + `rdtsc` latency identifies the correct base within milliseconds, requiring no software vulnerability at all. See the [24H2 NT Exploit writeup](https://exploits.forsale/24h2-nt-exploit/).

**ETW-based leaks** and **KUSER_SHARED_DATA** provide smaller, more limited windows for information disclosure that Microsoft has been progressively closing.

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
- [ACL / SD Manipulation](../primitives/exploitation/acl-sd-manipulation.md) -- SepMediumDaclSd corruption bypasses NtQuerySystemInformation DACL check
- [Bit-Manipulation Primitives](../primitives/exploitation/bit-manipulation.md) -- RtlSetBit used to flip WIL feature flags
- [CVE-2023-32019](../case-studies/CVE-2023-32019.md) -- kernel heap info disclosure
- [CVE-2024-38256](../case-studies/CVE-2024-38256.md) -- uninitialized memory info disclosure
- [CVE-2024-21338](../case-studies/CVE-2024-21338.md) -- appid.sys exploit that requires KASLR bypass as first step
- [CVE-2026-21241](../case-studies/CVE-2026-21241.md) -- SepMediumDaclSd + WIL feature flag bypass chain
