# Storage / Caching Drivers

Storage and caching drivers manage disk I/O, volume management, and client-side file caching. The Client-Side Caching (CSC) driver is the primary target in this category.

## Architecture

- **Driver model**: WDM
- **Key drivers**: `csc.sys` (Client-Side Caching / Offline Files), `disk.sys`, `partmgr.sys`
- **IOCTL interface**: Cache management operations, offline file synchronization
- **Context**: CSC provides offline access to network shares

## Attack Surface

- **IOCTL access control**: Missing authorization checks on privileged operations
- **File cache manipulation**: Controlling cached file metadata
- **SMB integration**: CSC interacts with the SMB redirector for network file caching

## Common Vulnerability Patterns

| Pattern | Description | AutoPiff Rules |
|---------|-------------|----------------|
| Missing access check | Privileged IOCTL callable without proper authorization | `added_access_check`, `added_previous_mode_gate`, `added_privilege_check` |

## CVEs

| CVE | Driver | Description | Class | ITW |
|-----|--------|-------------|-------|-----|
| [CVE-2024-26229](../case-studies/CVE-2024-26229.md) | `csc.sys` | Missing access check allows EoP | Logic Bug | No |

## Key Drivers

### csc.sys (Client-Side Caching)
- **Role**: Offline Files / Client-Side Caching driver
- **Attack vector**: Open device handle and send IOCTLs
- **Note**: CVE-2024-26229 is a logic bug — no memory corruption needed. The IOCTL handler doesn't validate the caller's access mode, allowing user-mode callers to perform privileged operations
- **Exploitation**: The missing access check was leveraged for PreviousMode manipulation -> NtReadVirtualMemory/NtWriteVirtualMemory bypass -> arbitrary R/W -> SYSTEM
