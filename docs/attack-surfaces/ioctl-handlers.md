# IOCTL Handlers

Device I/O control dispatch is the most common user-reachable kernel attack surface. Any driver that creates a device object and handles `IRP_MJ_DEVICE_CONTROL` exposes IOCTLs to user-mode callers via `DeviceIoControl`.

## Attack Surface Overview

- **Entry point**: `IRP_MJ_DEVICE_CONTROL` dispatch routine
- **Buffering methods**: `METHOD_BUFFERED`, `METHOD_IN_DIRECT`, `METHOD_OUT_DIRECT`, `METHOD_NEITHER`
- **User reach**: Any process that can open a handle to the device object
- **Key risk**: `METHOD_NEITHER` passes raw user pointers without kernel buffering

## Common Vulnerability Patterns

- Missing `InputBufferLength` / `OutputBufferLength` validation
- `METHOD_NEITHER` without `ProbeForRead` / `ProbeForWrite` + SEH
- Missing default case in IOCTL dispatch switch
- Insufficient access control on device object (missing `FILE_DEVICE_SECURE_OPEN`)

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-21338](../case-studies/CVE-2024-21338.md) | `appid.sys` | Missing access control on IOCTL 0x22A018 |
| [CVE-2024-35250](../case-studies/CVE-2024-35250.md) | `ks.sys` | Untrusted pointer dereference in IOCTL dispatch |
| [CVE-2024-38054](../case-studies/CVE-2024-38054.md) | `ksthunk.sys` | Integer overflow in KSSTREAM_HEADER thunking |
| [CVE-2024-26229](../case-studies/CVE-2024-26229.md) | `csc.sys` | Missing access check allows EoP |

## AutoPiff Detection

AutoPiff detects IOCTL hardening patches with these rules:

- `ioctl_input_size_validation_added` — Input/output buffer size validation added
- `method_neither_probe_added` — ProbeForRead/Write added for METHOD_NEITHER
- `ioctl_code_default_case_added` — Default case added to dispatch switch
- `device_acl_hardening` — Device object ACL hardened
- `new_ioctl_handler` — New IOCTL handler detected (attack surface rule)

## References

- [Windows IOCTL Reference](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/buffer-descriptions-for-i-o-control-codes)
