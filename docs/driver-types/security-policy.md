# Security / Policy Drivers

Security and policy enforcement drivers implement access control, code integrity, and application whitelisting. Their privileged position makes them high-value targets — a bypass here undermines the security model.

## Architecture

- **Driver model**: WDM or minifilter, depending on the security function
- **Key drivers**: `appid.sys` (AppLocker), `ci.sys` (Code Integrity), `wdfilter.sys` (Windows Defender)
- **IOCTL interface**: Policy management and hash computation IOCTLs
- **Privilege**: These drivers run at high privilege and are trusted by the security subsystem

## Attack Surface

- **IOCTL access control**: Missing or insufficient access checks on privileged IOCTLs
- **Policy evaluation logic**: Bypasses in allowlist/blocklist evaluation
- **Hash computation**: File hashing operations triggered by untrusted input
- **Callback registration**: Security callbacks that can be deregistered or bypassed

## Common Vulnerability Patterns

| Pattern | Description | AutoPiff Rules |
|---------|-------------|----------------|
| Missing IOCTL access check | Privileged IOCTL accessible without admin check | `ioctl_input_size_validation_added`, `ioctl_code_default_case_added` |
| BYOVD via policy driver | Using legitimate signed policy driver for kernel R/W | `device_acl_hardening` |

## CVEs

| CVE | Driver | Description | Class | ITW |
|-----|--------|-------------|-------|-----|
| [CVE-2024-21338](../case-studies/CVE-2024-21338.md) | `appid.sys` | IOCTL 0x22A018 missing access control allows kernel code exec | Logic Bug | Yes |

## Key Drivers

### appid.sys (AppLocker)
- **Role**: AppLocker application whitelisting enforcement
- **Attack vector**: Send IOCTL to `\Device\AppId` device
- **Note**: CVE-2024-21338 was exploited by Lazarus Group — the IOCTL dispatches a caller-controlled function pointer from a kernel pool allocation, giving direct kernel code execution without a memory corruption bug

### ci.sys (Code Integrity)
- **Role**: Enforces code signing policy (WDAC, HVCI)
- **Attack vector**: Policy manipulation, signed binary abuse
- **Note**: ci.sys is protected by KDP on HVCI systems

## Research Notes

Security driver bugs are particularly impactful because:
- They often provide **direct privilege escalation** without needing a memory corruption primitive
- The Lazarus Group's use of CVE-2024-21338 shows nation-state interest in this attack surface
- AppLocker IOCTL bugs give **admin-to-kernel** escalation, which is valuable for bypassing security software

!!! note "Third-Party Security Drivers"
    For third-party AV, EDR, anti-rootkit, and anti-cheat kernel drivers (Capcom.sys, viragt64.sys, Truesight.sys, etc.), see [Third-Party Security Drivers](third-party-security.md). This page covers only Microsoft's built-in security enforcement drivers.
