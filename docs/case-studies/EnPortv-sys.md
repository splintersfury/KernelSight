# EnPortv.sys

> Guidance Software EnCase forensic driver — revoked certificate still loads, abused as EDR killer

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

## Root Cause

The EnCase forensic driver exposes an IOCTL interface that lets user-mode processes terminate arbitrary processes from kernel mode, bypassing PPL protections. The driver was signed with a certificate issued December 15, 2006, which expired in 2010 and was later revoked.

Despite this, Windows Driver Signature Enforcement still permits loading because the certificate predates the July 29, 2015 cutoff. Microsoft's cross-signing grandfathering policy accepts any signature from a certificate issued before that date, creating a systemic gap in DSE.

## Exploitation

The February 2026 EDR killer binary (observed by Huntress after initial access via compromised SonicWall SSLVPN credentials):

1. Drops `EnPortv.sys` to disk
2. Loads it as a kernel service (DSE accepts the expired/revoked certificate)
3. Contains a hardcoded list of 59 security product process names (hashed)
4. Runs a continuous kill loop with 1-second intervals
5. Terminates all matching security processes

### Exploitation Primitive

```
Load EnPortv.sys (revoked cert, pre-2015 grandfathering)
  → IOCTL with target PID → kernel-level process termination
  → continuous kill loop → disable 59 security products
```

## Detection

### Behavioral Indicators

- Loading of `EnPortv.sys` outside of a forensic investigation context
- Driver with expired/revoked certificate from Guidance Software
- Rapid termination of multiple security product processes in a loop
- Initial access via SonicWall SSLVPN followed by driver loading

## References

- [Huntress — EnCase BYOVD EDR Killer](https://www.huntress.com/blog/encase-byovd-edr-killer)
- [BleepingComputer — EDR Killer Uses Signed Kernel Driver from Forensic Software](https://www.bleepingcomputer.com/news/security/edr-killer-tool-uses-signed-kernel-driver-from-forensic-software/)
- [Help Net Security — EDR Killer Vulnerable EnCase Driver](https://www.helpnetsecurity.com/2026/02/05/edr-killer-vulnerable-encase-driver/)
