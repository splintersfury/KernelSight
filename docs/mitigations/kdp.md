# Kernel Data Protection (KDP)

VBS-backed mechanism that marks kernel data structures as read-only after initialization, preventing modification even by ring-0 code.

## Overview

Microsoft introduced Kernel Data Protection in Windows 10 version 20H1 (May 2020 Update, build 19041). KDP uses the Hyper-V hypervisor and VBS infrastructure to enforce read-only protections on specific kernel data at the Second Level Address Translation (SLAT) level. Unlike traditional memory protection that can be bypassed by kernel-mode code modifying page table entries, KDP protections are enforced by the hypervisor in VTL 1, making them immune to VTL 0 modification. The feature protects security-relevant kernel variables from tampering, even after a kernel compromise in VTL 0.

KDP comes in two forms: Static KDP for protecting entire driver data sections, and Dynamic KDP for protecting individual pool allocations. Both rely on the same underlying hypervisor mechanism but target different use cases. The design philosophy is "initialize then lock" -- the protected data is writable during setup and becomes permanently read-only once the component signals it is fully configured.

## Mechanism

**Static KDP:**

- Drivers call `MmProtectDriverSection` to mark their own data sections as read-only.
- The kernel communicates with the Secure Kernel (VTL 1) via a secure hypercall to update the EPT/NPT entries for the specified pages, removing write permissions at the SLAT level.
- Once protected, even the kernel itself (VTL 0) cannot write to these pages. Any write attempt triggers a hypervisor-level page fault that results in a bugcheck.
- Protection is permanent for the lifetime of the driver -- there is no `MmUnprotectDriverSection` API.
- This is suitable for driver configuration data that is set once during `DriverEntry` and never modified.

**Dynamic KDP:**

- Individual allocations are protected by using `ExAllocatePool3` with the `POOL_FLAG_PROTECT` flag, or by calling `ExSecurePoolAlloc`.
- The allocated memory can be written during initialization, then explicitly locked via a secure call to VTL 1.
- The Secure Kernel maintains a list of protected allocations and their EPT permissions.
- Metadata about protected regions is stored in VTL 1 address space, inaccessible from VTL 0.
- Unlike Static KDP, Dynamic KDP can be applied to individual heap allocations rather than entire sections.

**Hypervisor Enforcement:**

- All KDP protections are enforced through SLAT (EPT on Intel, NPT on AMD).
- VTL 0 cannot modify the EPT entries because those are managed exclusively by the hypervisor and VTL 1.
- Even if an attacker has a full arbitrary read/write primitive in VTL 0 and modifies the VTL 0 page table entries, the SLAT entries still prevent writes.
- Read access remains unrestricted: VTL 0 code can freely read KDP-protected data, only writes are blocked.

**Known Protected Data (first-party):**

- Code Integrity (CI) policy configuration variables
- Secure Boot policy state
- Selected kernel security configuration globals
- Driver Verifier configuration on some builds

## Primitives Blocked

- **Modification of CI policy variables:** Code Integrity configuration stored in KDP-protected globals cannot be tampered with to disable driver signature enforcement or weaken code integrity checks.
- **Security descriptor tampering on protected objects:** If security descriptors or ACLs reside in KDP-protected memory, they cannot be modified to escalate privileges.
- **Callback table overwrites:** KDP-protected callback registration tables cannot be patched to redirect execution (complementing kCFG).
- **Protected global variable tampering:** Any security-critical global variable that has opted into KDP protection is immune to write primitives.
- **Boot policy modification:** Secure Boot and integrity policy state protected by KDP cannot be altered post-boot.

## Bypass History

- **Targeting unprotected data (always viable):** KDP is opt-in. Only data structures explicitly registered for protection are secured. The vast majority of kernel allocations and global variables, including `_EPROCESS`, `_TOKEN`, `_OBJECT_HEADER`, and most pool allocations, are NOT KDP-protected. Exploits simply target unprotected structures.
- **Limited adoption (ongoing):** As of Windows 11 24H2, few kernel components and drivers use KDP. The `_TOKEN` structure, the primary target for privilege escalation, remains in standard pool memory. Microsoft has been incrementally adding KDP protection to more components, but coverage remains incomplete.
- **Initialization-phase attacks (theoretical):** If an attacker can trigger a vulnerability during the window between allocation and protection lockdown, the data can be modified before KDP is applied. This requires precise timing and a vulnerability that can be triggered early in the initialization sequence.
- **Read-based exfiltration (by design):** KDP does not prevent reading protected data. An attacker can read CI policy state, security configuration, or any KDP-protected variable. Only write access is blocked.

## Windows Version Availability

| Version | Status | Notes |
|---------|--------|-------|
| Windows 10 20H1 (2004) | Introduced | Static KDP via `MmProtectDriverSection` |
| Windows 10 20H2-21H2 | Available | Incremental adoption by first-party components |
| Windows 11 21H2 | Available | Extended API surface, Dynamic KDP |
| Windows 11 22H2-23H2 | Available | Additional kernel components opted in |
| Windows 11 24H2 | Available | Further expansion of protected data |

KDP requires VBS to be enabled. On systems without VBS, the APIs are available but provide no actual hypervisor-backed protection. Third-party drivers can use KDP to protect their own data, but adoption outside of Microsoft first-party components remains minimal.

## Cross-References

- [VBS / HVCI](vbs-hvci.md) -- KDP depends on the VBS infrastructure for hypervisor enforcement
- [Secure Pool](secure-pool.md) -- complementary VBS-backed protection for pool allocations
- [Token Manipulation](../primitives/arw/token-manipulation.md) -- tokens remain unprotected by KDP, making this primitive viable
- [ACL/SD Manipulation](../primitives/exploitation/acl-sd-manipulation.md) -- KDP could protect SDs but adoption is limited
- [Pool Hardening](pool-hardening.md) -- software-level pool protections that complement KDP
- [CVE-2024-21302](../case-studies/CVE-2024-21302.md) -- VBS downgrade that could affect KDP enforcement
