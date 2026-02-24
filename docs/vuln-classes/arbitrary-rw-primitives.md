# Arbitrary Read/Write Primitives

Vulnerabilities that directly provide the ability to read from or write to arbitrary kernel memory addresses without requiring multi-step exploitation.

## Description

Arbitrary read/write (R/W) vulnerabilities directly grant the ability to read from or write to any virtual address in the kernel, without requiring heap manipulation or object corruption chains. These bugs most commonly appear in IOCTL handlers that accept a kernel address and a value from user mode and perform a direct read or write operation at that address without validation. The driver acts as a kernel memory access proxy for user-mode code.

Unlike buffer overflows or use-after-free bugs that require multiple exploitation stages (pool spray, object corruption, reclaim), these vulnerabilities provide the primitive directly. The driver's own code performs the read or write -- no metadata corruption, control flow hijacking, or thread racing needed. A single IOCTL call is often sufficient for each read or write.

Common sources include drivers that expose physical memory mapping (via `MmMapIoSpace` or `ZwMapViewOfSection` on `\Device\PhysicalMemory`), drivers that implement debug or diagnostic interfaces with direct memory access, and drivers that perform offset-based operations with user-controlled base addresses. Some vulnerable drivers are signed third-party drivers (BYOVD -- Bring Your Own Vulnerable Driver), which attackers deliberately load to gain kernel access. The MSI `RTCore64.sys`, Gigabyte `gdrv.sys`, and Capcom `Capcom.sys` drivers are well-known examples of this pattern.

First-party Microsoft drivers can also exhibit this pattern, though typically more subtly. Rather than a blatant "read/write any address" IOCTL, the vulnerability may involve a missing access check that allows an unprivileged caller to reach a code path intended only for kernel-mode callers, where that code path performs unchecked memory operations. `csc.sys` (Client-Side Caching) and `appid.sys` (AppLocker) are examples of this variant.

## Common Patterns in Drivers

- IOCTL handler that takes a user-supplied kernel virtual address and a value, then writes the value to that address using direct assignment or `RtlCopyMemory`
- Physical memory mapping via `MmMapIoSpace` with user-controlled physical address and size parameters, returning a mapped kernel virtual address accessible through the IOCTL
- `ZwOpenSection` / `ZwMapViewOfSection` on `\Device\PhysicalMemory` with user-controlled offset and size, providing direct physical memory access
- MDL-based mapping with user-controlled base address: `IoAllocateMdl` with user-supplied virtual address, `MmBuildMdlForNonPagedPool`, `MmMapLockedPagesSpecifyCache` creates a second mapping of arbitrary kernel memory
- IOCTL that reads from a user-supplied kernel address and returns the data in the output buffer, providing arbitrary read
- Increment or decrement operation at a user-controlled address (e.g., `(*user_ptr)++`), providing an arbitrary increment primitive
- PCI configuration space read/write with user-controlled bus/device/function and register offset
- MSR (Model-Specific Register) read/write with user-controlled register index, providing access to CPU control registers
- Registry-based arbitrary write through corrupted hive structures loaded by the configuration manager
- DMA (Direct Memory Access) region accessible via IOCTL, allowing user-mode code to read/write physical memory through the DMA controller
- Shared memory section created by the driver and mapped into user space with kernel-range virtual addresses also accessible, providing a read window into kernel memory

## Exploitation Implications

Exploitation of direct arbitrary R/W is straightforward. The most common approach is to locate the current process's EPROCESS structure (via `PsGetCurrentProcess` address leaked through KASLR bypass or hardcoded offset from GS segment), then overwrite the `Token` field to copy the SYSTEM process token for immediate privilege escalation. Alternatively, `_SEP_TOKEN_PRIVILEGES` can be modified directly to enable all privileges.

For arbitrary write-only primitives (no read), the attacker may use the `PreviousMode` overwrite technique: write 0 (KernelMode) to the current thread's `PreviousMode` field, then use `NtReadVirtualMemory` / `NtWriteVirtualMemory` to perform arbitrary kernel reads and writes through the normal syscall interface, since KernelMode bypasses all access checks. For increment/decrement-only primitives, the attacker repeatedly increments or decrements bytes in a token's privilege bitmask to enable `SeDebugPrivilege` or other powerful privileges.

BYOVD (Bring Your Own Vulnerable Driver) attacks have made this vulnerability class a persistent operational problem. Threat actors including Lazarus Group, ALPHV/BlackCat, and various ransomware operators routinely deploy known-vulnerable signed drivers to obtain kernel R/W primitives on fully patched systems. Microsoft's Vulnerable Driver Blocklist and HVCI attempt to mitigate this by blocking known-bad driver hashes, but new vulnerable drivers are continually discovered.

## Typical Primitives Gained

- [Direct IOCTL R/W](../primitives/arw/direct-ioctl-rw.md) -- the IOCTL itself provides unchecked kernel memory read/write capability
- [MDL Mapping](../primitives/arw/mdl-mapping.md) -- abusing MDL lock and map operations to create user-accessible mappings of arbitrary kernel memory
- [Arbitrary Increment/Decrement](../primitives/arw/arb-increment-decrement.md) -- controlled increment or decrement at an attacker-chosen kernel address
- [Write-What-Where](../primitives/arw/write-what-where.md) -- direct controlled write of an attacker-chosen value to an attacker-chosen kernel address
- [Token Manipulation](../primitives/arw/token-manipulation.md) -- direct overwrite of process token or privilege fields for privilege escalation

## Mitigations

- **HVCI (Hypervisor-protected Code Integrity)** -- Prevents execution of arbitrary code in kernel space, limiting the impact of write primitives to data-only attacks
- **Vulnerable Driver Blocklist** -- Microsoft maintains a blocklist of known-vulnerable signed drivers that HVCI-enabled systems refuse to load
- **WDAC (Windows Defender Application Control)** -- Can be configured to block unsigned or untrusted drivers, preventing BYOVD attacks
- **VBS (Virtualization-Based Security)** -- Protects critical kernel structures (e.g., CI policies, hypervisor code integrity) from modification even with kernel R/W
- **KDP (Kernel Data Protection)** -- Marks certain kernel data pages as read-only at the hypervisor level, preventing write primitives from modifying them

## Detection Strategies

- **Patch diffing**: Look for added access checks (`SeAccessCheck`, `SeSinglePrivilegeCheck`) or address validation before memory operations in IOCTL handlers. Also look for removal of entire IOCTL codes that provided direct memory access.
- **IOCTL auditing**: Enumerate all IOCTL codes handled by a driver and classify them. Any IOCTL that takes an address parameter and performs a read/write at that address is a critical finding.
- **Static analysis**: Track user-controlled IOCTL input fields through to memory access operations. Flag any path where a user-supplied value is used as a pointer for a read, write, or mapping operation.
- **BYOVD scanning**: Maintain a database of known vulnerable drivers (e.g., LOLDrivers project) and monitor for their presence on systems. Block loading of known-vulnerable signed drivers via HVCI or driver blocklist.
- **Physical memory access monitoring**: Flag any driver that opens `\Device\PhysicalMemory` or calls `MmMapIoSpace` with parameters originating from IOCTL input.

## Related CVEs

| CVE | Driver | Primitive Type |
|-----|--------|---------------|
| [CVE-2024-21338](../case-studies/CVE-2024-21338.md) | `appid.sys` | Direct IOCTL -- arbitrary callback invocation as kernel |
| [CVE-2023-21768](../case-studies/CVE-2023-21768.md) | `afd.sys` | Write-what-where via completion port manipulation |
| [CVE-2024-26229](../case-studies/CVE-2024-26229.md) | `csc.sys` | Missing access check enabling arbitrary IOCTL access |
| [CVE-2024-35250](../case-studies/CVE-2024-35250.md) | `ks.sys` | Kernel streaming untrusted pointer dereference |
| [CVE-2023-28252](../case-studies/CVE-2023-28252.md) | `clfs.sys` | Arbitrary write via corrupted log file base block |
| [CVE-2021-21551](../case-studies/CVE-2021-21551.md) | `DBUtil_2_3.sys` | Direct IOCTL R/W — Dell BIOS utility driver |
| [CVE-2019-16098](../case-studies/CVE-2019-16098.md) | `RTCore64.sys` | Physical memory R/W via MmMapIoSpace |
| [CVE-2018-19320](../case-studies/CVE-2018-19320.md) | `gdrv.sys` | Physical memory R/W via MmMapIoSpace |
| [CVE-2015-2291](../case-studies/CVE-2015-2291.md) | `iqvw64e.sys` | Direct IOCTL R/W — Intel diagnostics driver |
| [CVE-2020-12928](../case-studies/CVE-2020-12928.md) | `AMDRyzenMasterDriver.sys` | Physical memory R/W via MmMapIoSpace |

## AutoPiff Detection

- `direct_arw_ioctl_detected` -- Detects IOCTL handlers that pass user-controlled values directly to kernel memory read/write operations without address validation
- `physical_memory_mapping_exposed` -- Detects drivers that map physical memory regions based on user-controlled IOCTL parameters via `MmMapIoSpace` or section mapping
- `mmmapiospace_user_controlled` -- Detects `MmMapIoSpace` calls where the physical address and size parameters originate from user-mode input
- `added_access_check` -- Detects patches adding privilege or access validation to IOCTL handlers that previously allowed unchecked memory operations
- `handle_force_access_check_added` -- Detects addition of `OBJ_FORCE_ACCESS_CHECK` flag to handle operations, preventing kernel-mode bypass of access controls
