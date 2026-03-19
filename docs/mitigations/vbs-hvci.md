# VBS / HVCI

What happens when the kernel itself cannot be trusted? Virtualization-Based Security answers that question by placing a hypervisor beneath the kernel and using it to enforce policies that Ring 0 code cannot override. The kernel can be fully compromised, every driver loaded with malware, every function pointer corrupted, and the hypervisor will still prevent execution of unsigned code, still protect credential material, still enforce page-level W^X. VBS and its code integrity enforcement layer, HVCI, represent the ceiling of the defense-in-depth stack because breaking them requires defeating the hypervisor, not just the kernel.

Microsoft introduced VBS and HVCI in Windows 10 version 1607 (RS1) as optional features and made them enabled by default on new Windows 11 devices meeting hardware requirements. Together with [kCFG/kCET](kcfg-kcet.md) and [SMEP/SMAP](smep-smap.md), HVCI completes a model where no memory in the kernel address space can be both written to and executed, and control flow cannot be arbitrarily redirected.

## How It Works

**VBS Architecture.** The Hyper-V hypervisor runs below both the normal kernel and a Secure Kernel, creating two Virtual Trust Levels. VTL 0 (Normal World) contains the standard Windows kernel (`ntoskrnl.exe`), all drivers, and user-mode processes. VTL 1 (Secure World) contains the Secure Kernel (`securekernel.exe`) and Isolated User Mode (IUM) processes called trustlets. Second Level Address Translation (SLAT), implemented via Intel EPT or AMD NPT, enforces memory permissions at the hypervisor level. VTL 0 code cannot modify permissions controlled by VTL 1. Communication between the two levels occurs via secure calls, similar to syscalls but crossing the VTL boundary.

**HVCI (Memory Integrity)** uses the hypervisor's control over EPT/NPT entries to enforce a strict W^X policy on all kernel memory. A page can be marked Writable or Executable in the EPT, but never both simultaneously. Before kernel code is loaded, the Code Integrity module in VTL 1 (Secure Kernel Code Integrity, SKCI) validates the digital signature. Runtime code generation in kernel mode is impossible because there is no mechanism to allocate memory that is both writable and executable. Pool allocations are always non-executable. Code sections of loaded drivers are read-only and executable.

**Credential Guard** extends VBS to protect authentication material. A VTL 1 trustlet (`lsaiso.exe`) isolates credential material (NTLM hashes, Kerberos tickets) from VTL 0 access. Even a complete kernel compromise in VTL 0 cannot read credentials stored in VTL 1 memory, because the SLAT entries enforced by the hypervisor prevent the access.

## What VBS/HVCI Blocks

The protections are sweeping. **Kernel shellcode injection** fails because the W^X policy prevents creating executable+writable memory anywhere in the kernel address space. **PTE manipulation for code execution** is neutralized because even if an attacker modifies PTEs in VTL 0 to mark a page as executable, the hypervisor's EPT entries take precedence and block execution of writable pages. **Unsigned driver loading** is prevented by SKCI in VTL 1, which validates all driver signatures before allowing execution. **Direct modification of kernel code pages** is blocked because loaded kernel code is marked read-only+executable in the EPT, and VTL 0 writes cannot override that protection. **Credential theft via memory read** fails against Credential Guard because the credentials reside in VTL 1 memory that is physically inaccessible from VTL 0.

## How Attackers Work Around It

VBS/HVCI's strength is code integrity. Its limitation is that it does not protect data. This asymmetry has driven the entire modern kernel exploit landscape toward data-only techniques.

**Data-only attacks** bypass HVCI completely because they modify kernel data structures (token swapping, `PreviousMode` manipulation, ACL/SD modification) without executing attacker code or modifying existing code pages. This is the primary reason that modern exploitation has converged on data-only strategies, as documented across the [exploit chain patterns](../guides/exploit-chain-patterns.md).

**CVE-2024-21302 "Windows Downdate" (2024)** demonstrated that VBS itself has attack surface. Discovered by SafeBreach researcher Alon Leviev, this vulnerability in the Windows Update Secure Kernel component allowed downgrading VTL 1 components to older vulnerable versions, effectively undoing VBS protections without directly breaking the hypervisor boundary. The attack targeted the trust model rather than the enforcement mechanism.

**Living-off-the-land signed code** exploits the fact that all legitimately signed kernel code passes HVCI checks. Existing system call handlers, documented APIs, and signed driver functions can be chained to achieve exploitation goals without custom code execution. The [I/O Ring exploitation primitive](../primitives/exploitation/io-ring.md) exemplifies this approach: it provides kernel read/write through documented kernel interfaces, making HVCI entirely irrelevant.

**VTL 0 secure call interface abuse** represents a theoretical attack surface. The interface between VTL 0 and VTL 1 must exist for normal operation, and any interface can potentially be misused. No public exploits have demonstrated full VTL 1 compromise through this vector, but the attack surface exists.

## BYOVD Blocking

VBS/HVCI plays a direct role in the [BYOVD](../reference/byovd.md) defense model, both enabling and limiting it.

On the enabling side, the **Vulnerable Driver Blocklist** (`DriverSiPolicy.p7b`) is enforced at the hypervisor level on HVCI-enabled systems, preventing known-vulnerable drivers from loading even if the attacker has administrator privileges. HVCI also **neutralizes Capcom.sys** by preventing CR4 modification (blocking SMEP disable) and enforcing W^X (blocking user-mode code execution in Ring 0). See [Capcom.sys](../case-studies/Capcom-sys.md). Similarly, drivers that call `MmMapIoSpace` with user-controlled parameters are blocked if they appear on the blocklist, affecting [RTCore64.sys](../case-studies/CVE-2019-16098.md), [gdrv.sys](../case-studies/CVE-2018-19320.md), [ATSZIO64.sys](../case-studies/ATSZIO64-sys.md), [AsIO3.sys](../case-studies/AsIO3-sys.md), and others.

On the limiting side, **data-only BYOVD attacks still work**. HVCI does not prevent BYOVD drivers from performing data-only operations like token swapping or callback manipulation. [viragt64.sys](../case-studies/viragt64-sys.md) (process termination) and [Truesight.sys](../case-studies/Truesight-sys.md) (handle duplication) attacks function regardless of HVCI status if the driver is not blocklisted. Furthermore, **unblocklisted drivers** such as [NVDrv](../case-studies/NVDrv.md) (NVIDIA GPU) cannot be blocklisted without breaking display functionality, representing an architectural gap in the HVCI BYOVD defense.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-21302](../case-studies/CVE-2024-21302.md) | `ntoskrnl.exe` | Secure kernel version downgrade bypass |

## Windows Version Availability

| Version | Status | Notes |
|---------|--------|-------|
| Windows 10 1607 (RS1) | Optional | First release with VBS/HVCI support |
| Windows 10 1709-21H2 | Optional | Improved compatibility and performance |
| Windows 11 21H2 | Default on new devices | Enabled by default on qualifying hardware |
| Windows 11 22H2-23H2 | Default on new devices | Expanded hardware support |
| Windows 11 24H2 | Default + enhanced | Additional VBS protections, kCET integration |

Requirements include a CPU with VT-x (Intel) or AMD-V, SLAT (EPT/NPT), TPM 2.0, UEFI Secure Boot, and compatible drivers. Systems with incompatible drivers may have HVCI automatically disabled, which is a practical concern: HVCI adoption depends on driver ecosystem compatibility, not just hardware support.

## The Evolving Attack Surface

VBS and HVCI have shifted the research frontier in two directions. For exploitation, the constraint is total: no shellcode, no ROP-to-code, no driver patching. Modern kernel exploits documented in the corpus (CVE-2024-21338, CVE-2024-30088, CVE-2024-38106) all use data-only post-exploitation. The combination of kCFG, kCET, SMEP, SMAP, and HVCI has made code execution-based exploitation prohibitively difficult on fully equipped Windows 11 24H2 systems.

For researchers, VBS itself has become a target. The "Windows Downdate" attack (CVE-2024-21302) showed that VTL 1 components have their own vulnerability classes. The secure call interface, the update mechanism, and the VTL boundary enforcement each present attack surface that operates outside the protections that VBS provides to VTL 0. As VBS adoption grows and data-only attacks against VTL 0 reach their theoretical limits, research attention will increasingly focus on the hypervisor and Secure Kernel themselves.

## Cross-References

- [Kernel Data Protection (KDP)](kdp.md) -- builds on VBS to protect specific data structures
- [Secure Pool](secure-pool.md) -- VBS-backed pool allocations
- [Token Swapping](../primitives/exploitation/token-swapping.md) -- data-only technique that bypasses HVCI
- [I/O Ring](../primitives/exploitation/io-ring.md) -- exploitation primitive that does not require code execution
- [PTE Manipulation](../primitives/arw/pte-manipulation.md) -- EPT enforcement overrides VTL 0 PTE changes
- [CVE-2024-21302](../case-studies/CVE-2024-21302.md) -- VBS downgrade attack
- [SMEP / SMAP](smep-smap.md) -- complementary CPU-level enforcement
