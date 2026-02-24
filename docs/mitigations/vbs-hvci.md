# VBS / HVCI

Virtualization-Based Security (VBS) and Hypervisor-Protected Code Integrity (HVCI) use the hypervisor to create an isolated security boundary that enforces kernel code integrity and protects security assets from ring-0 compromise.

## Overview

Microsoft introduced VBS and HVCI in Windows 10 version 1607 (RS1) as optional features and made them enabled by default on new Windows 11 devices meeting hardware requirements. VBS uses the Hyper-V hypervisor to create Virtual Trust Levels (VTLs), establishing a security boundary that cannot be crossed by kernel-mode code. HVCI (also called Memory Integrity) uses this hypervisor enforcement to apply a W^X (Write XOR Execute) policy on all kernel memory, preventing execution of unsigned or dynamically generated code in ring 0.

## Mechanism

**VBS Architecture:**

- The Hyper-V hypervisor runs below both the normal kernel and a Secure Kernel, creating two Virtual Trust Levels.
- VTL 0 (Normal World): Contains the standard Windows kernel (`ntoskrnl.exe`), drivers, and user-mode processes.
- VTL 1 (Secure World): Contains the Secure Kernel (`securekernel.exe`) and Isolated User Mode (IUM) processes called trustlets.
- SLAT (Second Level Address Translation) via Intel EPT or AMD NPT enforces memory permissions at the hypervisor level. VTL 0 code cannot modify permissions controlled by VTL 1.
- Communication between VTL 0 and VTL 1 occurs via secure calls (similar to syscalls but crossing the VTL boundary).

**HVCI (Memory Integrity):**

- All kernel memory pages are controlled by the hypervisor through EPT/NPT entries.
- A page can be marked Writable or Executable in the EPT, but never both simultaneously (W^X enforcement).
- Before kernel code is loaded, the Code Integrity module in VTL 1 (Secure Kernel Code Integrity, SKCI) validates the digital signature.
- Runtime code generation in kernel mode is impossible: there is no mechanism to allocate memory that is both writable and executable.
- Pool allocations are always non-executable. Code sections of loaded drivers are read-only + executable.

**Credential Guard:**

- A VTL 1 trustlet (`lsaiso.exe`) isolates credential material (NTLM hashes, Kerberos tickets) from VTL 0 access.
- Even a full kernel compromise in VTL 0 cannot read credential material stored in VTL 1.

## Primitives Blocked

- **Kernel shellcode injection:** The W^X policy prevents allocating executable+writable memory, so injecting and executing shellcode in kernel space is impossible.
- **PTE manipulation for code execution:** Even if an attacker modifies PTEs in VTL 0 to mark a page as executable, the hypervisor's EPT entries take precedence and will block execution of writable pages.
- **Unsigned driver loading:** SKCI in VTL 1 validates all driver signatures before allowing code execution. A VTL 0 compromise cannot bypass this validation.
- **Direct modification of kernel code pages:** Loaded kernel code is marked read-only+executable in the EPT. Even with an ARW primitive in VTL 0, the attacker cannot patch kernel code.
- **Credential theft via memory read:** With Credential Guard active, credentials in VTL 1 are inaccessible from VTL 0.

## Bypass History

- **Data-only attacks (always viable):** Since HVCI only prevents code execution and code modification, attacks that manipulate data structures (token swapping, `PreviousMode`, ACL/SD modification) bypass HVCI entirely. This has driven the modern shift toward data-only exploitation.
- **CVE-2024-21302 "Windows Downdate" (2024):** A vulnerability in the Windows Update Secure Kernel component allowed downgrading VTL 1 components to older vulnerable versions, effectively undoing VBS protections. Demonstrated by SafeBreach researcher Alon Leviev.
- **Living-off-the-land signed code:** Using existing signed kernel code paths (system calls, documented APIs) to achieve exploitation goals without needing custom code execution.
- **I/O Ring exploitation chain:** The I/O Ring primitive provides kernel read/write without requiring code execution, making HVCI irrelevant for this attack path.
- **VTL 0 secure call interface abuse (theoretical):** The interface between VTL 0 and VTL 1 presents attack surface, though no public exploits have demonstrated full VTL 1 compromise through this vector.

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

Requirements: CPU with VT-x (Intel) or AMD-V, SLAT (EPT/NPT), TPM 2.0, UEFI Secure Boot, compatible drivers. Systems with incompatible drivers may have HVCI automatically disabled.

## Impact on Exploit Development

VBS and HVCI force exploit developers to adopt entirely data-only strategies: no shellcode, no ROP-to-code, no driver patching. Combined with kCFG/kCET and SMEP/SMAP, HVCI completes a defense-in-depth model where no memory on the system can be both written to and executed, and control flow cannot be arbitrarily redirected. Modern exploitation research focuses almost exclusively on data-structure manipulation (token swapping, `PreviousMode`, I/O Ring primitives) rather than code execution.

The VBS attack surface itself has become a research target, as demonstrated by the "Windows Downdate" attack (CVE-2024-21302), which targeted the VTL 1 update mechanism rather than breaking through VBS protections directly.

## BYOVD Blocking

VBS/HVCI plays a direct role in the BYOVD defense model:

- **Vulnerable Driver Blocklist enforcement**: On HVCI-enabled systems, the Microsoft Vulnerable Driver Blocklist (`DriverSiPolicy.p7b`) is enforced at the hypervisor level, preventing known-vulnerable drivers from loading even if an attacker has administrator privileges
- **Capcom.sys neutralized**: HVCI prevents Capcom.sys from disabling SMEP (CR4 modification blocked by hypervisor) and from executing user-mode code pages in ring 0 (W^X enforcement). See [Capcom.sys](../case-studies/Capcom-sys.md)
- **Physical memory mapping restricted**: Drivers that call `MmMapIoSpace` with user-controlled parameters are blocked if they appear on the blocklist — affects [RTCore64.sys](../case-studies/CVE-2019-16098.md), [gdrv.sys](../case-studies/CVE-2018-19320.md), [ATSZIO64.sys](../case-studies/ATSZIO64-sys.md), [AsIO3.sys](../case-studies/AsIO3-sys.md), and others
- **Data-only attacks still viable**: HVCI does not prevent BYOVD drivers from performing data-only operations (token swap, callback manipulation) — [viragt64.sys](../case-studies/viragt64-sys.md) (process termination) and [Truesight.sys](../case-studies/Truesight-sys.md) (handle duplication) attacks work regardless of HVCI status if the driver is not blocklisted
- **Unblocklisted drivers**: Drivers like [NVDrv](../case-studies/NVDrv.md) (NVIDIA GPU) cannot be blocklisted without breaking display functionality, representing a gap in the HVCI BYOVD defense

See [BYOVD Reference](../reference/byovd.md) for the full BYOVD landscape.

## Cross-References

- [Kernel Data Protection (KDP)](kdp.md) -- builds on VBS to protect specific data structures
- [Secure Pool](secure-pool.md) -- VBS-backed pool allocations
- [Token Swapping](../primitives/exploitation/token-swapping.md) -- data-only technique that bypasses HVCI
- [I/O Ring](../primitives/exploitation/io-ring.md) -- exploitation primitive that does not require code execution
- [PTE Manipulation](../primitives/arw/pte-manipulation.md) -- EPT enforcement overrides VTL 0 PTE changes
- [CVE-2024-21302](../case-studies/CVE-2024-21302.md) -- VBS downgrade attack
- [SMEP / SMAP](smep-smap.md) -- complementary CPU-level enforcement
