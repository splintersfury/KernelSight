# Direct IOCTL Read/Write

Drivers that expose IOCTLs allowing direct physical or virtual memory read/write — commonly seen in BYOVD (Bring Your Own Vulnerable Driver) attacks.

## Description

Some drivers intentionally expose IOCTLs for diagnostics, hardware access, or firmware updates that allow reading/writing arbitrary physical or virtual memory. Attackers abuse these via BYOVD to gain kernel R/W without needing a memory corruption bug.

## Mechanism

1. Load a signed driver with direct R/W IOCTLs
2. Open a handle to the device
3. Send IOCTL with target address and data

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-21338](../../case-studies/CVE-2024-21338.md) | `appid.sys` | IOCTL 0x22A018 missing access control |

## AutoPiff Detection

- `ioctl_input_size_validation_added`
- `device_acl_hardening`
- `new_ioctl_handler`
