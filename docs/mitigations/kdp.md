# Kernel Data Protection (KDP)

Data-only attacks have become the dominant exploitation strategy precisely because existing mitigations (SMEP, SMAP, kCFG, kCET, HVCI) focus on preventing code execution and control flow hijacking. An attacker who can read and write kernel memory does not need to execute a single instruction of custom code. They simply modify the right data structure: a token, a security descriptor, a `PreviousMode` field. Kernel Data Protection is Microsoft's response to this gap. By using the hypervisor to make selected kernel data structures permanently read-only after initialization, KDP aims to take the most critical targets off the table for data-only attacks.

Microsoft introduced KDP in Windows 10 version 20H1 (May 2020 Update, build 19041). The mechanism uses VBS infrastructure to enforce read-only protections at the Second Level Address Translation (SLAT) level. Unlike traditional memory protection that can be bypassed by kernel-mode code modifying page table entries, KDP protections are enforced by the hypervisor in VTL 1, making them immune to anything running in VTL 0.

## How It Works

KDP operates on a simple principle: "initialize then lock." The protected data is writable during setup and becomes permanently read-only once the owning component signals that configuration is complete.

**Static KDP** protects entire driver data sections. A driver calls `MmProtectDriverSection` to mark its own data sections as read-only. The kernel communicates with the Secure Kernel (VTL 1) via a secure hypercall to update the EPT/NPT entries for the specified pages, removing write permissions at the SLAT level. Once protected, even the kernel itself cannot write to these pages. Any write attempt triggers a hypervisor-level page fault that results in a bugcheck. Protection is permanent for the lifetime of the driver; there is no `MmUnprotectDriverSection` API. This suits driver configuration data that is set once during `DriverEntry` and never modified.

**Dynamic KDP** extends the model to individual pool allocations. Components allocate memory with `ExAllocatePool3` using the `POOL_FLAG_PROTECT` flag, or through `ExSecurePoolAlloc`. The allocated memory can be written during initialization, then explicitly locked via a secure call to VTL 1. The Secure Kernel maintains a list of protected allocations and their EPT permissions, with all metadata stored in VTL 1 address space, inaccessible from VTL 0. Unlike Static KDP, Dynamic KDP can protect individual heap allocations rather than entire sections.

The hypervisor enforcement is the key property that distinguishes KDP from any software-based protection. VTL 0 cannot modify the EPT entries because those are managed exclusively by the hypervisor and VTL 1. Even if an attacker has a full arbitrary read/write primitive in VTL 0 and modifies the VTL 0 page table entries to mark a protected page as writable, the SLAT entries still prevent writes. Read access remains unrestricted: VTL 0 code can freely read KDP-protected data, because the protection targets integrity (preventing tampering) rather than confidentiality.

**Known protected data** as of Windows 11 24H2 includes Code Integrity (CI) policy configuration variables, Secure Boot policy state, selected kernel security configuration globals, and Driver Verifier configuration on some builds.

## What KDP Blocks

When a data structure is KDP-protected, it becomes immune to the write primitives that data-only attacks depend on. Modification of CI policy variables is prevented, so an attacker cannot tamper with Code Integrity configuration to disable driver signature enforcement. Security descriptor tampering on protected objects fails because the write to the SD causes a hypervisor fault. Callback table overwrites are blocked for tables that have opted into KDP protection (complementing kCFG's forward-edge validation). Any security-critical global variable registered for KDP protection is immune to write primitives, including boot policy state that controls Secure Boot and integrity verification.

## The Adoption Problem

KDP's design is sound. Its impact is limited by adoption. The mechanism is opt-in, and as of Windows 11 24H2, few kernel components and drivers use it. The structures that matter most for exploitation remain unprotected.

**Targeting unprotected data** is the primary bypass, and it is not really a bypass at all. The vast majority of kernel allocations and global variables are not KDP-protected. The `_EPROCESS` structure, the `_TOKEN` structure, `_OBJECT_HEADER`, and most pool allocations remain in standard kernel memory. Exploits simply target these unprotected structures, which is exactly what every data-only exploit in the corpus does.

**Limited first-party adoption** means that even Microsoft's own critical security structures are mostly unprotected by KDP. The `_TOKEN`, which is the primary target for privilege escalation via token swapping, sits in standard pool memory. Security descriptors that gate access to kernel APIs reside in unprotected allocations. The WIL feature flags that control KASLR information scrubbing are ordinary kernel globals. Each of these would benefit from KDP protection, but none currently have it.

**Initialization-phase attacks** represent a theoretical window. If an attacker can trigger a vulnerability during the period between allocation and protection lockdown, the data can be modified before KDP takes effect. This requires precise timing and a vulnerability that fires during the initialization sequence.

**Read-based exfiltration** is permitted by design. KDP does not prevent reading protected data. An attacker can read CI policy state, security configuration, or any KDP-protected variable. The protection is write-only, reflecting KDP's focus on integrity rather than confidentiality.

## Windows Version Availability

| Version | Status | Notes |
|---------|--------|-------|
| Windows 10 20H1 (2004) | Introduced | Static KDP via `MmProtectDriverSection` |
| Windows 10 20H2-21H2 | Available | Incremental adoption by first-party components |
| Windows 11 21H2 | Available | Extended API surface, Dynamic KDP |
| Windows 11 22H2-23H2 | Available | Additional kernel components opted in |
| Windows 11 24H2 | Available | Further expansion of protected data |

KDP requires VBS to be enabled. On systems without VBS, the APIs are available but provide no actual hypervisor-backed protection. Third-party drivers can use KDP to protect their own data, but adoption outside of Microsoft first-party components remains minimal.

## The Path Forward

KDP is the mitigation with the most unrealized potential in the Windows kernel. If Microsoft expanded KDP coverage to include `_TOKEN` structures, security descriptors like `SepMediumDaclSd`, and the WIL feature flags used for KASLR enforcement, the data-only attack surface would contract significantly. Token swapping would require finding an alternative escalation target. Security descriptor corruption for KASLR bypass would become impossible. The bit-manipulation technique demonstrated in CVE-2026-21241 would lose its targets.

The barrier is compatibility and performance. Protecting tokens with KDP would require rearchitecting how the kernel modifies token privileges during normal operation. Protecting security descriptors would need careful handling of legitimate DACL modifications. Each structure that moves into KDP requires the owning component to adopt the initialize-then-lock pattern, which is a non-trivial code change for structures that are currently modified throughout their lifetime. Until those engineering challenges are addressed, KDP will remain a strong mechanism with narrow coverage.

## Cross-References

- [VBS / HVCI](vbs-hvci.md) -- KDP depends on the VBS infrastructure for hypervisor enforcement
- [Secure Pool](secure-pool.md) -- complementary VBS-backed protection for pool allocations
- [Token Manipulation](../primitives/arw/token-manipulation.md) -- tokens remain unprotected by KDP, making this primitive viable
- [ACL/SD Manipulation](../primitives/exploitation/acl-sd-manipulation.md) -- KDP could protect SDs but adoption is limited
- [Pool Hardening](pool-hardening.md) -- software-level pool protections that complement KDP
- [CVE-2024-21302](../case-studies/CVE-2024-21302.md) -- VBS downgrade that could affect KDP enforcement
