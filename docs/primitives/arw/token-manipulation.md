# Token Manipulation

Overwriting or corrupting kernel token structures to escalate privileges.

## Description

The `_TOKEN` structure contains privilege bitmasks and integrity levels. An arbitrary write primitive targeting the token's `Privileges.Enabled` field can grant `SeDebugPrivilege` or other powerful privileges, enabling full system compromise.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-30088](../../case-studies/CVE-2024-30088.md) | `ntoskrnl.exe` | TOCTOU in security attribute copy |

## AutoPiff Detection

- `privilege_check_added`
- `access_mode_enforcement_added`
