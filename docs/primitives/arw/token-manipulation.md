# Token Manipulation

Every process and thread in Windows carries a `_TOKEN` structure that defines its security identity. The token contains privilege bitmasks that determine which privileged operations the process can perform, SID arrays that control which objects the process can access, an integrity level that gates access to higher-integrity resources, and session information that ties the process to a logon session. Modifying any of these fields changes what the process is allowed to do. With an arbitrary write primitive targeting the token's internal fields, an attacker can grant privileges, elevate integrity levels, or change group memberships without replacing the token pointer itself.

Token manipulation through in-place field modification is a subtler alternative to the more commonly discussed [token swapping](../exploitation/token-swapping.md) technique. Where token swapping replaces the entire token pointer in `_EPROCESS` (carrying the risk of reference counting issues and token mismatch detection), in-place manipulation modifies specific fields within the existing token. The process keeps its original token, its original SIDs, and its original session binding. Only the targeted fields change.

## The `_TOKEN` structure

The security-relevant fields in the `_TOKEN` structure are concentrated in a few regions that are the primary targets for manipulation.

```
_TOKEN (key fields, offsets vary by build)
  +0x040  TokenId                    // LUID identifying this token
  +0x048  AuthenticationId           // LUID identifying the logon session (SYSTEM = 0x3e7)
  +0x060  Privileges                 // _SEP_TOKEN_PRIVILEGES
    +0x000  Present                  // ULONG64 bitmask of available privileges
    +0x008  Enabled                  // ULONG64 bitmask of currently enabled privileges
    +0x010  EnabledByDefault         // ULONG64 bitmask of default-enabled privileges
  +0x098  IntegrityLevelIndex        // index into SID array for integrity level
  +0x0D0  SessionId                  // logon session ID
```

The `_SEP_TOKEN_PRIVILEGES` sub-structure at offset 0x060 is the most commonly targeted region. Windows defines 36 privileges, each assigned a bit position in a 64-bit bitmask. The `Present` field indicates which privileges are available to the token (can be enabled), and the `Enabled` field indicates which are currently active. Overwriting `Enabled` with `0xFFFFFFFFFFFFFFFF` activates all privileges simultaneously, granting the process capabilities including `SeDebugPrivilege` (open any process), `SeImpersonatePrivilege` (impersonate any token), `SeLoadDriverPrivilege` (load kernel drivers), and `SeAssignPrimaryTokenPrivilege` (assign tokens to processes).

The `IntegrityLevelIndex` field controls the Mandatory Integrity Control (MIC) level. Processes at Medium integrity cannot write to High integrity objects. Corrupting this field to point to a SID with a higher integrity level bypasses these restrictions. However, integrity level changes are more detectable than privilege changes, since integrity violations generate security audit events.

## Exploitation paths

The most straightforward exploitation path is to overwrite both `Privileges.Present` and `Privileges.Enabled` with all-ones bitmasks. This requires two writes but avoids the complexities of token pointer swapping. CVE-2024-30088 demonstrated this approach: after achieving kernel R/W through a TOCTOU race in `ntoskrnl.exe`, the exploit located the current process's token through `_EPROCESS` and modified the privilege bitmasks to grant full privileges.

A more targeted approach uses [bit-manipulation primitives](../exploitation/bit-manipulation.md) to enable individual privilege bits. `RtlSetBit` with a fake `RTL_BITMAP` pointing at the `Privileges.Enabled` field can enable `SeDebugPrivilege` (bit 20) without touching other privilege bits. This is less noisy than enabling all privileges and may evade detection mechanisms that watch for wholesale privilege changes.

The [arbitrary increment/decrement](arb-increment-decrement.md) primitive can also target privilege fields, though less precisely. Incrementing a byte that contains a privilege bit can enable that privilege, but may also change adjacent bits, making the result less predictable than a direct write or bit-set.

## Detecting token manipulation

EDR products and security tools can detect token manipulation through several mechanisms. Process token changes are visible through `PsSetCreateProcessNotifyRoutine` callbacks. Privilege changes can be detected by periodically auditing process privilege sets. The Windows Security Event Log records privilege use events (Event ID 4672 for special privilege assignment, Event ID 4673 for privilege use). However, these detection mechanisms are reactive: by the time the manipulation is detected, the attacker has already used the elevated privileges.

Kernel Data Protection (KDP), available on Windows 11 with VBS, can theoretically protect token structures by marking them as read-only through the hypervisor. If applied to `_TOKEN.Privileges`, this would cause a fault on any attempt to modify the privilege bitmasks. However, KDP is not yet widely applied to token structures, and its protection requires VBS to be enabled.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-30088](../../case-studies/CVE-2024-30088.md) | `ntoskrnl.exe` | TOCTOU in security attribute copy |

## AutoPiff Detection

- `privilege_check_added`
- `access_mode_enforcement_added`

## See Also

- [Token Swapping](../exploitation/token-swapping.md) -- the alternative approach that replaces the token pointer rather than modifying token fields
- [Bit-Manipulation Primitives](../exploitation/bit-manipulation.md) -- `RtlSetBit`/`RtlSetAllBits` for precise privilege bit enabling
- [Arbitrary Increment/Decrement](arb-increment-decrement.md) -- byte-level modification of privilege fields
- [ACL / SD Manipulation](../exploitation/acl-sd-manipulation.md) -- an alternative privilege escalation path through security descriptor corruption
- [I/O Ring](../exploitation/io-ring.md) -- commonly provides the kernel R/W needed to reach the token
