# EnPortv.sys

> Guidance Software EnCase forensic driver -- a 16-year-old signed driver with a revoked certificate that Windows still loads, weaponized as a pre-ransomware EDR killer

!!! danger "Exploited in the Wild"
    Observed in a February 2026 intrusion by Huntress. Used as a pre-ransomware EDR killer.

## Summary

| Field | Value |
|-------|-------|
| **Driver** | `EnPortv.sys` (EnCase Forensic Driver) |
| **Vendor** | Guidance Software (now OpenText) |
| **Vulnerability Class** | Process Termination / Certificate Verification Bypass |
| **Exploited ITW** | Yes (February 2026, pre-ransomware) |
| **Status** | Certificate expired 2010, revoked, but still loads due to cross-signing grandfathering |

## The Irony

EnCase is a forensic investigation tool used by law enforcement and incident response teams worldwide. Its kernel driver, `EnPortv.sys`, was designed to give forensic examiners low-level system access during investigations. In February 2026, Huntress documented an intrusion where threat actors turned this forensic tool against its intended purpose: they loaded the driver to kill EDR products before deploying ransomware. A tool built for defenders became a weapon against them.

The driver's signing story makes this case especially instructive. EnPortv.sys was signed with a certificate issued on December 15, 2006. That certificate expired in 2010 and was subsequently revoked. Under normal certificate validation rules, Windows should refuse to load it. But Microsoft's Driver Signature Enforcement has a grandfathering exception: any driver signed with a certificate issued before July 29, 2015 is accepted, regardless of whether the certificate has expired or been revoked. This cross-signing grandfathering policy creates a systemic gap in DSE. Drivers signed in the pre-2015 era effectively have permanent loading privileges.

## Root Cause

The driver exposes an IOCTL interface that lets user-mode processes terminate arbitrary processes from kernel mode. The termination bypasses Protected Process Light (PPL) protections because it operates at the kernel level using `ZwTerminateProcess` with a kernel handle. There is no validation of the caller's identity or purpose.

The combination of two weaknesses makes this driver uniquely dangerous: the process termination IOCTL has no access control, and the expired/revoked certificate still passes DSE validation. The driver cannot be blocked by revoking the certificate because Windows ignores the revocation for pre-2015 signatures.

## Exploitation

Huntress documented the full attack chain from a February 2026 intrusion. Initial access came through compromised SonicWall SSLVPN credentials. After landing on the target, the threat actor deployed a custom EDR killer binary that contained the following capabilities:

The binary drops `EnPortv.sys` to disk and creates a kernel service to load it. Windows DSE accepts the expired, revoked certificate due to the pre-2015 grandfathering exception. The binary contains a hardcoded list of 59 security product process names, stored as hashes to evade static signature scanning. It enters a continuous kill loop with 1-second intervals, sending the process termination IOCTL for each matching PID. Any security product that restarts is killed again on the next loop iteration. With all 59 security products disabled, the attacker proceeds with their primary objective.

### Exploitation Primitive

```
Load EnPortv.sys (revoked cert, pre-2015 grandfathering)
  --> IOCTL with target PID --> kernel-level process termination
  --> continuous kill loop --> disable 59 security products
```

## Detection

### Behavioral Indicators

- Loading of `EnPortv.sys` outside of a forensic investigation context
- Driver with expired/revoked certificate from Guidance Software
- Rapid termination of multiple security product processes in a loop
- Initial access via SonicWall SSLVPN followed by driver loading
- Kernel service creation for a driver with a 2006-era signing certificate

## Broader Significance

EnPortv.sys exposes a structural problem with Windows Driver Signature Enforcement that goes beyond a single driver. The pre-2015 cross-signing grandfathering policy means there is a large pool of old, signed drivers with known vulnerabilities that Windows will load indefinitely, regardless of certificate revocation. Adding individual drivers to the Vulnerable Driver Blocklist helps, but the grandfathering exception creates new candidates faster than Microsoft can blocklist them. Until the grandfathering policy is retired or a more comprehensive certificate validation model is adopted, pre-2015 signed drivers with dangerous IOCTLs will remain a permanent fixture in the BYOVD landscape.

The 59-process kill list and the continuous loop pattern also represent an evolution in EDR killer sophistication. Earlier BYOVD tools killed security processes once. Modern variants run persistent kill loops that defeat auto-restart mechanisms, ensuring the security product stays dead for the duration of the attack.

## References

- [Huntress -- EnCase BYOVD EDR Killer](https://www.huntress.com/blog/encase-byovd-edr-killer)
- [BleepingComputer -- EDR Killer Uses Signed Kernel Driver from Forensic Software](https://www.bleepingcomputer.com/news/security/edr-killer-tool-uses-signed-kernel-driver-from-forensic-software/)
- [Help Net Security -- EDR Killer Vulnerable EnCase Driver](https://www.helpnetsecurity.com/2026/02/05/edr-killer-vulnerable-encase-driver/)
