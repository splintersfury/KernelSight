# Arbitrary Read/Write Primitives

Most kernel exploits are multi-stage affairs. You find a buffer overflow, groom the heap, corrupt an adjacent object, convert the corruption into a write-what-where, and then use that primitive to overwrite a token. With arbitrary read/write vulnerabilities, you skip all of that. The driver itself performs unchecked memory operations at addresses the user specifies. One IOCTL call to read. One IOCTL call to write. No heap spray, no object corruption, no race condition. The driver is the exploit.

This page covers how direct arbitrary R/W vulnerabilities arise in Windows kernel drivers, why they power the BYOVD (Bring Your Own Vulnerable Driver) ecosystem, and how to detect them through static analysis and patch diffing.

## The driver as a memory access proxy

The Windows kernel does not expose direct memory read/write to user mode. There is no syscall for "write this value to this kernel address." But kernel drivers can do anything, and some drivers expose IOCTLs that are functionally equivalent to that non-existent syscall.

The pattern is simple. An IOCTL handler receives a user-supplied structure containing a kernel virtual address and a value. The handler writes the value to the address, or reads from the address and returns the data in the output buffer. No validation of the address. No check of the caller's privileges. The driver trusts its IOCTL input, and the IOCTL input comes from an unprivileged user.

Some of these drivers are deliberately designed this way. Hardware diagnostic tools, BIOS update utilities, and overclocking software need to read and write physical memory, MSR registers, or PCI configuration space. They expose these capabilities through IOCTLs because that is how user-mode applications communicate with kernel drivers. The developers intended for the application to be the only user of these IOCTLs, but the device object is accessible to any process, and any process can send any IOCTL.

Others arrive at the same vulnerability more subtly. A Microsoft first-party driver may have an IOCTL intended only for kernel-mode callers (another driver in the stack), but the device object lacks a restrictive security descriptor, and the IOCTL handler does not check `Irp->RequestorMode`. The result is the same: unprivileged user-mode access to a privileged memory operation.

## The BYOVD problem

Arbitrary R/W vulnerabilities have created an operational security problem that goes beyond individual CVEs. Bring Your Own Vulnerable Driver (BYOVD) attacks exploit the fact that these vulnerable drivers are legitimately signed. An attacker who has achieved initial access (say, through a phishing email) can drop a known-vulnerable signed driver onto the target system, load it, and use its IOCTLs to gain kernel-level access.

The threat actors using this technique are not hobbyists. Lazarus Group used CVE-2024-21338 in `appid.sys` (a Microsoft first-party driver) to disable security products. ALPHV/BlackCat ransomware operators routinely deploy vulnerable third-party drivers for kernel access. The technique works on fully patched systems because the vulnerable driver is not the system's own driver; it is one the attacker brought along.

Microsoft's response has been the Vulnerable Driver Blocklist, a list of known-vulnerable driver hashes that HVCI-enabled systems refuse to load. WDAC (Windows Defender Application Control) can also block untrusted drivers. But the blocklist is reactive: it only covers drivers that have been identified, analyzed, and added. The LOLDrivers project maintains a community database of known-vulnerable drivers, and the list continues to grow.

## Common patterns

### Direct address R/W via IOCTL

The most blatant pattern. The IOCTL input contains a kernel virtual address and a value. The handler performs `*(PVOID*)address = value` or `RtlCopyMemory(address, data, size)` without any address validation.

CVE-2021-21551 in Dell's `DBUtil_2_3.sys` is the textbook example. The BIOS utility driver exposed IOCTLs for direct memory read and write at arbitrary kernel addresses. Any user could open the device and send these IOCTLs. Dell signed the driver, so it loaded on HVCI-disabled systems without restriction.

### Physical memory mapping

Several drivers provide access to physical memory by calling `MmMapIoSpace` or mapping `\Device\PhysicalMemory` with user-controlled offset and size parameters. The returned kernel virtual address provides a window into arbitrary physical memory, which can be used to read or modify any kernel structure whose physical address is known (or can be determined through page table walking).

CVE-2019-16098 in MSI's `RTCore64.sys`, CVE-2018-19320 in Gigabyte's `gdrv.sys`, and CVE-2020-12928 in AMD's `AMDRyzenMasterDriver.sys` all follow this pattern. The drivers map physical memory based on IOCTL input and return the mapping to the caller.

### MDL-based remapping

A more subtle variant uses Memory Descriptor Lists (MDLs) to create a second mapping of kernel memory. The driver calls `IoAllocateMdl` with a user-supplied virtual address, `MmBuildMdlForNonPagedPool` to describe the physical pages, and `MmMapLockedPagesSpecifyCache` to create a new mapping accessible to user mode. The result is a user-mode pointer that reads and writes kernel memory directly, without any further IOCTL calls.

### Increment/decrement primitives

Some drivers expose IOCTLs that increment or decrement a value at a user-controlled address: `(*user_ptr)++`. While less powerful than a full write, an increment primitive can be used to modify individual bytes in a token's privilege bitmask, enabling `SeDebugPrivilege` or other powerful privileges one byte at a time. The attacker repeatedly invokes the IOCTL, incrementing the target byte until it reaches the desired value.

### MSR and PCI configuration access

Drivers that expose Model-Specific Register (MSR) read/write or PCI configuration space access provide control over CPU control registers and device configuration. MSR writes can disable security features (like SMEP) at the hardware level. PCI configuration writes can reprogram DMA controllers to access physical memory directly.

## From R/W to SYSTEM

Once arbitrary read/write is established, privilege escalation follows a well-known sequence. The most common approach targets the current process's EPROCESS structure.

``` mermaid
graph TD
    A["1. Leak kernel base\n(info disclosure or\nhardcoded offset)"] --> B["2. Find EPROCESS\n(PsGetCurrentProcess\nor PsInitialSystemProcess)"]
    B --> C["3. Read Token field\n(offset from EPROCESS)"]
    C --> D["4. Copy SYSTEM token\nto current process"]
    D --> E["5. Current process\nruns as SYSTEM"]
    style A fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    style B fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    style C fill:#1e293b,stroke:#f59e0b,color:#e2e8f0
    style D fill:#1e293b,stroke:#ef4444,color:#e2e8f0
    style E fill:#1e293b,stroke:#10b981,color:#e2e8f0
```

The attacker reads the SYSTEM process token pointer from the EPROCESS of PID 4 (the System process), then writes that pointer into their own process's EPROCESS token field. The process now runs with SYSTEM privileges. Alternatively, the `_SEP_TOKEN_PRIVILEGES` structure can be modified directly to enable all privileges without copying the token.

For write-only primitives (no read capability), the **PreviousMode overwrite** technique is standard. The attacker writes 0 (KernelMode) to the current thread's `PreviousMode` field. With PreviousMode set to KernelMode, `NtReadVirtualMemory` and `NtWriteVirtualMemory` bypass all access checks, effectively converting the write-only primitive into full arbitrary R/W through the normal syscall interface.

## Typical primitives gained

- [Direct IOCTL R/W](../primitives/arw/direct-ioctl-rw.md), the IOCTL itself provides unchecked kernel memory read/write capability
- [MDL Mapping](../primitives/arw/mdl-mapping.md), abusing MDL lock and map operations to create user-accessible mappings of arbitrary kernel memory
- [Arbitrary Increment/Decrement](../primitives/arw/arb-increment-decrement.md), controlled increment or decrement at an attacker-chosen kernel address
- [Write-What-Where](../primitives/arw/write-what-where.md), direct controlled write of an attacker-chosen value to an attacker-chosen kernel address
- [Token Manipulation](../primitives/arw/token-manipulation.md), direct overwrite of process token or privilege fields for privilege escalation

## Mitigations

Mitigating arbitrary R/W is fundamentally different from mitigating memory corruption bugs. The driver's code is not broken; it is doing exactly what it was designed to do. The problem is that the design is insecure.

**HVCI (Hypervisor-protected Code Integrity)** prevents execution of arbitrary code in kernel space, limiting the impact of write primitives to data-only attacks. An attacker cannot inject and execute shellcode, but token manipulation and privilege flag modification remain viable.

**Vulnerable Driver Blocklist** maintains a list of known-vulnerable driver hashes that HVCI-enabled systems refuse to load. This is the primary defense against BYOVD, but it is reactive: new vulnerable drivers must be identified and added to the list.

**WDAC (Windows Defender Application Control)** can block unsigned or untrusted drivers entirely, preventing BYOVD attacks. This is the strongest defense but requires policy configuration and can break legitimate applications that depend on third-party drivers.

**VBS (Virtualization-Based Security)** protects critical kernel structures (CI policies, hypervisor code integrity) from modification even with kernel R/W. Certain data is stored in the secure kernel (VTL 1), inaccessible even to code running at ring-0 in the normal kernel (VTL 0).

**KDP (Kernel Data Protection)** marks specific kernel data pages as read-only at the hypervisor level. Even with arbitrary write capability, the attacker cannot modify KDP-protected data without compromising the hypervisor.

## Detection strategies

**IOCTL auditing** is the most direct detection approach. Enumerate all IOCTL codes handled by a driver and classify them. Any IOCTL that takes an address parameter and performs a read/write at that address is a critical finding. This is a manual process but yields high-signal results, especially for third-party drivers.

**Patch diffing** for arbitrary R/W fixes looks for added access checks (`SeAccessCheck`, `SeSinglePrivilegeCheck`) or address validation before memory operations in IOCTL handlers. Also look for removal of entire IOCTL codes that provided direct memory access, which is the most definitive fix.

**Static analysis** tracks user-controlled IOCTL input fields through to memory access operations. Flag any path where a user-supplied value is used as a pointer for a read, write, or mapping operation. This can be expressed as a taint-flow query from IOCTL input buffer to `RtlCopyMemory`, `MmMapIoSpace`, or pointer dereference.

**BYOVD scanning** should maintain awareness of known-vulnerable drivers. The LOLDrivers project provides a community database. Monitor for the presence of known-vulnerable drivers on production systems, and block their loading through HVCI or driver blocklist.

**Physical memory access monitoring** should flag any driver that opens `\Device\PhysicalMemory` or calls `MmMapIoSpace` with parameters originating from IOCTL input. Legitimate drivers that map physical memory do so with hardcoded addresses (for MMIO registers), not with user-supplied addresses.

## Related CVEs

| CVE | Driver | Primitive Type |
|-----|--------|---------------|
| [CVE-2024-21338](../case-studies/CVE-2024-21338.md) | `appid.sys` | Direct IOCTL, arbitrary callback invocation as kernel |
| [CVE-2023-21768](../case-studies/CVE-2023-21768.md) | `afd.sys` | Write-what-where via completion port manipulation |
| [CVE-2024-26229](../case-studies/CVE-2024-26229.md) | `csc.sys` | Missing access check enabling arbitrary IOCTL access |
| [CVE-2024-35250](../case-studies/CVE-2024-35250.md) | `ks.sys` | Kernel streaming untrusted pointer dereference |
| [CVE-2023-28252](../case-studies/CVE-2023-28252.md) | `clfs.sys` | Arbitrary write via corrupted log file base block |
| [CVE-2021-21551](../case-studies/CVE-2021-21551.md) | `DBUtil_2_3.sys` | Direct IOCTL R/W, Dell BIOS utility driver |
| [CVE-2019-16098](../case-studies/CVE-2019-16098.md) | `RTCore64.sys` | Physical memory R/W via MmMapIoSpace |
| [CVE-2018-19320](../case-studies/CVE-2018-19320.md) | `gdrv.sys` | Physical memory R/W via MmMapIoSpace |
| [CVE-2015-2291](../case-studies/CVE-2015-2291.md) | `iqvw64e.sys` | Direct IOCTL R/W, Intel diagnostics driver |
| [CVE-2020-12928](../case-studies/CVE-2020-12928.md) | `AMDRyzenMasterDriver.sys` | Physical memory R/W via MmMapIoSpace |

## AutoPiff Detection

- `direct_arw_ioctl_detected` detects IOCTL handlers that pass user-controlled values directly to kernel memory read/write operations without address validation
- `physical_memory_mapping_exposed` detects drivers that map physical memory regions based on user-controlled IOCTL parameters via `MmMapIoSpace` or section mapping
- `mmmapiospace_user_controlled` detects `MmMapIoSpace` calls where the physical address and size parameters originate from user-mode input
- `added_access_check` detects patches adding privilege or access validation to IOCTL handlers that previously allowed unchecked memory operations
- `handle_force_access_check_added` detects addition of `OBJ_FORCE_ACCESS_CHECK` flag to handle operations, preventing kernel-mode bypass of access controls

Arbitrary R/W vulnerabilities occupy a unique position in the kernel security landscape because they collapse the entire exploitation process into a single step. Every other vulnerability class on this site describes how to *get* a read or write primitive. This class describes drivers that *are* the primitive. The defense is not mitigation at the exploitation level but prevention at the design level: drivers should never expose unchecked memory access to user mode, and the system should never load drivers that do. Until both of those conditions are met, BYOVD remains the easiest path from user to kernel, and [logic bugs](logic-bugs.md) in first-party drivers remain the most persistent.
