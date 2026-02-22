# Registry Callbacks

Kernel-mode callback mechanism for monitoring and intercepting registry operations.

## Attack Surface Overview

- **Callback registration**: Drivers register via `CmRegisterCallbackEx` to receive notifications for all registry operations
- **Operation types**: Pre-operation (can block/modify) and post-operation callbacks
- **Altitude-based ordering**: Callbacks execute in order of registration altitude (like minifilter altitudes)
- **Callback context**: Driver-defined context pointer passed to every invocation
- **User-reachable via**: Any registry operation from user mode (`RegCreateKeyEx`, `RegSetValueEx`, `RegQueryValueEx`, `NtSetValueKey`, etc.)

## Mechanism Deep-Dive

Registry callbacks intercept operations at the Configuration Manager (Cm) level. When user-mode code performs any registry operation, the following sequence occurs:

1. The I/O manager routes the request to the Configuration Manager
2. Cm invokes each registered callback with a `REG_NOTIFY_CLASS` value indicating the operation type (e.g., `RegNtPreCreateKeyEx`, `RegNtPreSetValueKey`)
3. Pre-operation callbacks can inspect and modify arguments, or return `STATUS_CALLBACK_BYPASS` to block the operation entirely
4. The actual registry operation executes within the Configuration Manager
5. Post-operation callbacks receive the result and can perform logging, auditing, or cleanup

Key APIs:

- `CmRegisterCallbackEx` -- Register a callback routine with an altitude string that determines invocation order
- `CmUnRegisterCallback` -- Deregister a previously registered callback using the cookie returned at registration
- `REG_CREATE_KEY_INFORMATION` -- Structure passed to callbacks for key creation events, containing the key path, desired access, and creation options
- `REG_SET_VALUE_KEY_INFORMATION` -- Structure passed for value write events, containing the value name, type, data pointer, and data length

## Common Vulnerability Patterns

- **Insufficient input validation**: The callback receives untrusted `ValueName`, `Data`, and `DataSize` fields from user mode. Failure to validate these parameters before copying or processing leads to buffer overflows or integer overflow conditions.

- **TOCTOU on registry data**: A callback reads value data from user-mode memory, but a concurrent user-mode thread modifies the data between the validation check and the point where the driver acts on it. This is especially common when callbacks reference the caller's buffer directly instead of capturing a local copy.

- **Pool corruption in callback context**: Drivers that allocate per-key tracking context in their callbacks may not properly handle callback re-entrancy. A registry operation on a key triggers a callback, which itself performs a registry operation, causing recursive callback invocation that corrupts or double-frees context structures.

- **Missing altitude conflicts**: Multiple drivers registering callbacks at the same or adjacent altitudes can create race conditions where callback execution order is non-deterministic, leading to inconsistent state when both modify the same operation.

- **Unregistration races**: Calling `CmUnRegisterCallback` while callbacks are actively executing on other processors leads to use-after-free of the callback context. The Configuration Manager's callback list removal does not fully synchronize with in-flight callback invocations on all CPUs.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-21338](../case-studies/CVE-2024-21338.md) | `appid.sys` | AppLocker driver callback vulnerability, exploited by Lazarus Group for kernel code execution |
| [CVE-2023-36424](../case-studies/CVE-2023-36424.md) | `cldflt.sys` | Cloud Files minifilter registry callback issue leading to elevation of privilege |

## AutoPiff Detection

AutoPiff identifies registry callback-related vulnerabilities through the following detection rules:

- `callback_input_validation_added` -- New size or type checks on callback parameters, indicating previously missing input validation
- `callback_context_lifetime_fix` -- Reference counting changes for callback context objects, suggesting a use-after-free or double-free fix
- `cm_callback_lock_change` -- Synchronization changes around callback registration or invocation, pointing to race condition fixes
- `registry_access_mask_hardened` -- Registry key access mask reduced to least-privilege
- `double_fetch_to_capture_fix` -- TOCTOU fixed by capturing value data into a kernel buffer before processing

## References

- [CmRegisterCallbackEx documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-cmregistercallbackex)
- [Filtering Registry Calls](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/filtering-registry-calls)
