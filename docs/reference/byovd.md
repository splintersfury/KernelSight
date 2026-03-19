---
description: "BYOVD (Bring Your Own Vulnerable Driver) attack technique -- how attackers use signed drivers like Dell DBUtil, RTCore64, Capcom.sys, and Paragon BioNTdrv to gain kernel access. 41 BYOVD drivers analysed."
---

# Bring Your Own Vulnerable Driver (BYOVD)

Most kernel exploits require finding a vulnerability, building a primitive, and navigating the mitigation stack. BYOVD skips all of that. The attacker drops a legitimately signed but vulnerable driver onto the target system, loads it through normal Windows mechanisms, and uses the driver's own functionality to gain kernel read/write. No memory corruption needed. No exploit development beyond a client that sends the right IOCTLs. The driver *is* the weapon.

This technique has become the standard approach for ransomware groups and APTs that need kernel access. BlackByte uses RTCore64.sys to disable EDR. Lazarus Group uses ene.sys to patch security callbacks. Cuba ransomware commissioned custom vulnerable drivers. The pattern works because Windows enforces driver signing (the driver must be signed by a trusted CA) but does not prevent loading old, signed drivers that contain known vulnerabilities. A driver signed in 2015 with a critical vulnerability will load on Windows 11 in 2026 unless it appears on the Vulnerable Driver Blocklist.

## How BYOVD Works

The attack follows a consistent five-step pattern.

First, the attacker identifies a signed driver with a known kernel vulnerability. The most valuable drivers expose arbitrary read/write (physical memory mapping via `MmMapIoSpace`), but process termination capabilities and MSR access are also useful. The [LOLDrivers Deep Analysis](loldrivers-analysis.md) scores 1,775 such drivers, and the [KDU Provider Compatibility](kdu-compatibility.md) analysis identifies 122 that could load unsigned kernel code.

Second, the vulnerable driver is deployed to the target system through initial access malware or a dropper. The driver file is typically extracted from a resource embedded in the malware payload.

Third, the driver is loaded using `sc.exe create` and `sc.exe start`, the `NtLoadDriver` system call, or an exploitation framework like KDU. Because the driver carries a valid Authenticode signature, Windows loads it without complaint (unless it appears on the blocklist and HVCI is enabled).

Fourth, the known vulnerability in the loaded driver is exercised. For a physical memory mapping driver, this means sending IOCTLs that map arbitrary physical addresses into user-mode virtual memory. For a process termination driver, it means specifying the PID of the EDR process.

Fifth, kernel access is used for the actual objective: disabling EDR kernel callbacks, installing rootkits, dumping credentials from LSASS, or manipulating security tokens for privilege escalation.

## Commonly Abused Drivers

| Driver | Vendor | Vulnerability | Used By |
|--------|--------|---------------|---------|
| [DBUtil_2_3.sys](../case-studies/CVE-2021-21551.md) | Dell | Arbitrary kernel R/W via IOCTL | Multiple ransomware groups |
| [RTCore64.sys](../case-studies/CVE-2019-16098.md) | MSI Afterburner | Physical memory R/W via IOCTL | BlackByte, Cuba ransomware |
| `AsIO64.sys` | ASUS | Physical memory mapping to user mode | AvosLocker ransomware |
| `ProcExp.sys` | Microsoft (Sysinternals) | Arbitrary process termination | Medusa Locker |
| [gdrv.sys](../case-studies/CVE-2018-19320.md) | GIGABYTE | Arbitrary kernel R/W via IOCTL | RobbinHood ransomware |
| `ene.sys` | ENE Technology | Physical memory R/W | Lazarus Group |
| [HW64.sys](../case-studies/CVE-2020-15368.md) | Marvin Test Solutions | Port I/O and physical memory R/W | Various threat actors |

These seven drivers appear most frequently in threat intelligence reports, but the [LOLDrivers catalog](https://loldrivers.io) tracks over 700 known vulnerable drivers, and DriverAtlas analysis shows that 1,404 of 1,775 analyzed drivers have the import profile to serve as potential KDU providers.

## Real-World Campaigns

### Lazarus Group

The North Korean Lazarus Group used `ene.sys` (an ENE Technology hardware monitoring driver) to disable Windows security features including Microsoft Defender and other endpoint protection products. The driver was deployed through social engineering campaigns disguised as fake job offers targeting cryptocurrency exchanges and aerospace companies. Once loaded, the vulnerable driver provided physical memory access used to locate and zero out kernel notification callbacks registered by security products, effectively blinding endpoint detection.

### BlackByte Ransomware

BlackByte operators used `RTCore64.sys` (MSI Afterburner's kernel-mode component) to disable EDR products before deploying their ransomware payload. The attack specifically targeted kernel notification callbacks registered by security products, finding them in memory through known kernel structure offsets and zeroing them out. This was part of a double-extortion scheme combining data theft with file encryption.

### Cuba Ransomware

The Cuba ransomware group deployed a custom BYOVD variant using `ApcHelper.sys`, combined with the BIRDDOG backdoor for initial access. This campaign demonstrated that threat actors invest in finding or commissioning new vulnerable drivers rather than relying solely on publicly known ones, because custom drivers are less likely to be blocklisted.

### GhostEmperor

The GhostEmperor APT, [documented by Kaspersky in 2021](https://securelist.com/ghostemperor-from-proxylogon-to-kernel-mode/104407/), used a BYOVD chain to load an unsigned rootkit. The campaign exploited ProxyLogon for initial access, loaded a signed vulnerable driver to bypass Driver Signature Enforcement, then used the driver's kernel R/W capabilities to load an unsigned rootkit payload. This chain demonstrated the full BYOVD pipeline: initial access to driver deployment to rootkit installation.

## Detection Strategies

Detecting BYOVD requires monitoring at multiple levels because the individual steps (file write, service creation, driver load) are all legitimate operations when performed by authorized software.

**Hash-based blocking** is the most direct approach. Block known vulnerable driver file hashes using WDAC (Windows Defender Application Control) or AppLocker policies. The LOLDrivers project provides SHA256 hashes for every cataloged driver.

**Driver load monitoring** catches the moment the vulnerable driver enters the kernel. Monitor Sysmon Event ID 6 (driver loaded), ETW kernel providers, or EDR telemetry for driver loads from non-standard paths, especially temporary directories, user-writable locations, or paths containing randomly generated names.

**Windows Vulnerable Driver Blocklist** is Microsoft's curated list of known vulnerable drivers, shipped as `DriverSiPolicy.p7b` with Windows. On HVCI-enabled systems, this list is enforced at the hypervisor level. On systems without HVCI, it is enforced only if explicitly enabled.

**Microsoft Recommended Driver Block Rules** provide regularly updated WDAC policy rules for enterprise deployment, offering broader coverage than the default blocklist.

**Behavioral detection** looks for patterns rather than specific hashes: `sc.exe` or `NtLoadDriver` calls from non-standard process trees, driver service creation immediately followed by driver start, and driver files written to disk shortly before loading.

**Certificate-based rules** block all drivers signed by specific certificates known to have vulnerable drivers in their portfolio, providing coverage against both known and undiscovered vulnerable driver versions from the same vendor.

## Mitigation Landscape

**HVCI (Memory Integrity)** is the strongest defense. On HVCI-enabled systems, the Vulnerable Driver Blocklist is enforced at the hypervisor level, preventing known-vulnerable drivers from loading even with administrator privileges. HVCI also blocks the most dangerous BYOVD capabilities: CR4 modification (neutralizing Capcom.sys), W^X enforcement (preventing user-mode code execution from Ring 0), and code page modification. See [VBS / HVCI](../mitigations/vbs-hvci.md) for details.

**The Vulnerable Driver Blocklist** is enabled by default on Windows 11 22H2+ with HVCI, but is opt-in on other configurations. Its coverage is purely reactive: drivers are added only after exploitation is observed in the wild, creating a window of exposure for newly discovered vulnerable drivers.

**WDAC custom policies** allow enterprise environments to restrict driver loading to an explicit allow-list, which is the most restrictive approach but requires careful management to avoid breaking legitimate driver updates.

**Attestation-signed driver requirements** in Windows 11 24H2 tighten the signing requirements for new drivers, requiring Microsoft attestation signing. This does not affect old drivers that were signed under previous requirements.

## BYOVD Exploitation Frameworks

Several open-source tools automate BYOVD exploitation, lowering the barrier for threat actors.

**[KDU (Kernel Driver Utility)](https://github.com/hfiref0x/KDU)** integrates dozens of vulnerable drivers as exploitation providers, supporting DSE bypass, arbitrary kernel R/W, and shellcode execution. See [KDU Provider Compatibility](kdu-compatibility.md) for our analysis of which LOLDrivers could serve as KDU providers.

**[DSEFix](https://github.com/hfiref0x/DSEFix)** disables Driver Signature Enforcement using a vulnerable driver, allowing loading of unsigned drivers.

**[Turla Driver Loader (TDL)](https://github.com/hfiref0x/TDL)** loads unsigned drivers using vulnerable signed drivers as a proxy.

**[Stryker](https://github.com/hfiref0x/Stryker)** is a mitigation-aware BYOVD exploitation toolkit that adapts its approach based on the target system's security configuration.

## LOLDrivers Integration

The [LOLDrivers project](https://www.loldrivers.io/) catalogs known vulnerable and malicious drivers with SHA256 hashes, vendor information, vulnerability descriptions, YARA rules, and Sigma detection rules. KernelSight case studies cross-reference LOLDrivers entries for each documented driver. The [LOLDrivers Deep Analysis](loldrivers-analysis.md) page presents our DriverAtlas scoring of all 1,775 LOLDrivers entries, and the [KDU Provider Compatibility](kdu-compatibility.md) page maps which of those drivers could serve as KDU exploitation providers.

## References

- [LOLDrivers](https://www.loldrivers.io/)
- [Microsoft Recommended Driver Block Rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules)
