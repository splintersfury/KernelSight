# Bring Your Own Vulnerable Driver (BYOVD)

Technique where attackers load a legitimately signed but vulnerable driver to gain kernel access.

## Concept

Windows enforces driver signing, requiring all kernel-mode drivers to be signed by a trusted certificate authority. However, this policy does not prevent loading old, signed drivers that contain known vulnerabilities. In a BYOVD attack, the adversary ships a legitimately signed but vulnerable driver alongside their malware payload. Because the driver carries a valid signature, Windows loads it without complaint, giving the attacker a reliable path from user-mode to kernel-mode access.

## How BYOVD Works

1. Attacker identifies a signed driver with a known kernel vulnerability (arbitrary read/write, physical memory mapping, or process termination capability)
2. The vulnerable driver is deployed to the target system, typically through initial access malware or a dropper
3. The driver is loaded using `sc.exe create` and `sc.exe start`, `NtLoadDriver`, or an exploitation framework such as KDU
4. The attacker exploits the known vulnerability in the loaded driver to obtain kernel read/write or code execution
5. Kernel access is used for high-impact post-exploitation: disabling EDR kernel callbacks, installing rootkits, dumping credentials from LSASS, or manipulating security tokens

## Commonly Abused Drivers

| Driver | Vendor | Vulnerability | Used By |
|--------|--------|---------------|---------|
| `DBUtil_2_3.sys` | Dell | Arbitrary kernel R/W via IOCTL | Multiple ransomware groups |
| `RTCore64.sys` | MSI Afterburner | Physical memory R/W via IOCTL | BlackByte, Cuba ransomware |
| `AsIO64.sys` | ASUS | Physical memory mapping to user mode | AvosLocker ransomware |
| `ProcExp.sys` | Microsoft (Sysinternals) | Arbitrary process termination | Medusa Locker |
| `gdrv.sys` | GIGABYTE | Arbitrary kernel R/W via IOCTL | RobbinHood ransomware |
| `ene.sys` | ENE Technology | Physical memory R/W | Lazarus Group |
| `HW64.sys` | Marvin Test Solutions | Port I/O and physical memory R/W | Various threat actors |

## LOLDrivers Project

The Living Off The Land Drivers (LOLDrivers) project is a community-maintained catalog of known vulnerable, malicious, and abused drivers. Hosted at loldrivers.io, the project serves as the definitive reference for BYOVD defense.

- Catalogs over 700 known vulnerable drivers with SHA256 hashes, vendor information, and vulnerability descriptions
- Provides YARA rules and Sigma detection rules for each driver
- Driver entries include Authenticode signer information for certificate-based blocking
- Regularly updated as new vulnerable drivers are discovered in the wild
- Used by SOC teams and detection engineers to build prevention and alerting rules

## Real-World Campaigns

### Lazarus Group

The North Korean Lazarus Group used `ene.sys` (an ENE Technology hardware monitoring driver) to disable Windows security features including Microsoft Defender and other endpoint protection products. The driver was deployed through social engineering campaigns disguised as fake job offers targeting cryptocurrency exchanges and aerospace companies. Once loaded, the vulnerable driver provided physical memory access used to patch kernel security callbacks.

### BlackByte Ransomware

BlackByte operators used `RTCore64.sys` (MSI Afterburner's kernel-mode component) to disable EDR products before deploying their ransomware payload. The attack specifically targeted kernel notification callbacks registered by security products, zeroing them out to blind endpoint detection. This was part of a double-extortion scheme combining data theft with file encryption.

### Cuba Ransomware

The Cuba ransomware group deployed a custom BYOVD variant using `ApcHelper.sys`, combined with the BIRDDOG backdoor for initial access. This campaign demonstrated that threat actors are willing to invest in finding or commissioning new vulnerable drivers rather than relying solely on publicly known ones.

## Detection Strategies

- **Hash-based blocking** -- Block known vulnerable driver file hashes using WDAC (Windows Defender Application Control) or AppLocker policies
- **Driver load monitoring** -- Monitor driver loading events via Sysmon Event ID 6, ETW kernel providers, or EDR telemetry
- **Windows Vulnerable Driver Blocklist** -- The `DriverSiPolicy.p7b` file ships with Windows and blocks a Microsoft-curated list of known vulnerable drivers
- **Microsoft Recommended Driver Block Rules** -- Regularly updated WDAC policy rules for enterprise deployment
- **Behavioral detection** -- Monitor for `sc.exe` or `NtLoadDriver` calls from non-standard paths, especially temporary directories or user-writable locations
- **Certificate-based rules** -- Block drivers signed by specific certificates known to have vulnerable drivers in their portfolio

## Mitigations

- **HVCI (Memory Integrity)** -- Hypervisor-protected Code Integrity blocks loading of many unsigned and known-vulnerable drivers by enforcing code integrity at the hypervisor level
- **Microsoft Vulnerable Driver Blocklist** -- Enabled by default on Windows 11 22H2+ and Windows 11 devices with HVCI, blocks a curated set of vulnerable drivers at the kernel level
- **WDAC custom policies** -- Enterprise environments can deploy custom Windows Defender Application Control policies that restrict driver loading to an explicit allow-list
- **Attestation-signed driver requirements** -- Windows 11 24H2 tightens requirements for driver signing, requiring Microsoft attestation signing for new drivers

## References

- [LOLDrivers](https://www.loldrivers.io/)
- [Microsoft Recommended Driver Block Rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules)
