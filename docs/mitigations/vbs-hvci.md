# VBS / HVCI

Virtualization-Based Security (VBS) and Hypervisor-protected Code Integrity (HVCI) use the hypervisor to enforce code integrity and protect critical data.

## Description

- **VBS**: Creates an isolated secure world (VTL 1) using the hypervisor
- **HVCI**: Prevents unsigned/modified code from executing in kernel mode
- **Credential Guard**: Isolates credential storage in VTL 1
- **SKCI**: Secure Kernel Code Integrity module

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-21302](../case-studies/CVE-2024-21302.md) | `ntoskrnl.exe` | Secure kernel version downgrade bypass |

## Bypass Techniques

- VBS downgrade attacks (CVE-2024-21302)
- Data-only attacks within VTL 0
- VTL 0 → VTL 1 call interface abuse
