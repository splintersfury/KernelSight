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
| [CVE-2021-21551](../../case-studies/CVE-2021-21551.md) | `DBUtil_2_3.sys` | Dell BIOS utility — 5 IOCTLs for kernel R/W |
| [CVE-2019-16098](../../case-studies/CVE-2019-16098.md) | `RTCore64.sys` | MSI Afterburner — physical mem, MSR, I/O port |
| [CVE-2018-19320](../../case-studies/CVE-2018-19320.md) | `gdrv.sys` | Gigabyte — kernel R/W and MSR access |
| [CVE-2015-2291](../../case-studies/CVE-2015-2291.md) | `iqvw64e.sys` | Intel — physical and virtual memory R/W |
| [CVE-2020-15368](../../case-studies/CVE-2020-15368.md) | `HW.sys` | Marvin Test — physical memory via MmMapIoSpace |

## AutoPiff Detection

- `ioctl_input_size_validation_added`
- `device_acl_hardening`
- `new_ioctl_handler`
