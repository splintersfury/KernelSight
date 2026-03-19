# Registry Callbacks

When an antivirus driver needs to block malware from modifying a Run key, or a security product needs to audit every registry write system-wide, it registers a kernel callback with the Configuration Manager. That callback then executes in the context of every process that touches the registry, on every core, for every operation. This is an extraordinary level of reach. A single `CmRegisterCallbackEx` call gives a driver the ability to intercept, inspect, and modify every registry operation on the system, and with that reach comes an equally extraordinary attack surface.

The vulnerability patterns in registry callbacks are distinct from those in IOCTL handlers or filesystem IRPs. The callback does not receive a structured IRP with well-defined buffer semantics. It receives a notification structure containing pointers to user-mode data, kernel objects in various states of construction, and context from the calling process. The driver must handle this data correctly under full concurrency: multiple processes performing registry operations simultaneously, each invoking the same callback code on different processors with different data.

## How registry callbacks work

``` mermaid
graph TD
    A["User Process\nRegSetValueEx()"] --> B["I/O Manager\nNtSetValueKey"]
    B --> C["Configuration Manager"]
    C --> D["Callback List\n(altitude-ordered)"]
    D --> E["Pre-Op Callback\n(can block/modify)"]
    E --> F{"Decision"}
    F -->|Allow| G["Actual Registry Op\n(Cm internal)"]
    F -->|Block| H["STATUS_CALLBACK_BYPASS\n(op denied)"]
    G --> I["Post-Op Callback\n(logging/audit)"]
    I --> J["Result to Caller"]
    H --> J
    style E fill:#152a4a,stroke:#f59e0b,color:#e2e8f0
    style G fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    style H fill:#2d1b1b,stroke:#ef4444,color:#e2e8f0
```

When user-mode code performs any registry operation, the request reaches the Configuration Manager (Cm) in the kernel. Before executing the operation, Cm walks a list of registered callbacks, invoking each one with a `REG_NOTIFY_CLASS` value that identifies the operation type. The callback receives a structure appropriate to that operation type: `REG_CREATE_KEY_INFORMATION` for key creation, `REG_SET_VALUE_KEY_INFORMATION` for value writes, and so on.

Callbacks execute in two phases. **Pre-operation callbacks** fire before the registry operation executes. They can inspect the arguments, modify them, or return `STATUS_CALLBACK_BYPASS` to block the operation entirely. This is how security products prevent malware from writing to sensitive registry locations. **Post-operation callbacks** fire after the operation completes, receiving the result status. These are used for logging, auditing, and state tracking.

Like minifilter altitudes in the filesystem stack, registry callbacks have an altitude-based ordering. The altitude string provided during `CmRegisterCallbackEx` registration determines the order in which callbacks execute. Higher altitudes execute first for pre-operations and last for post-operations. This ordering matters for security: a security callback at a high altitude can block an operation before a lower-altitude callback ever sees it.

The registration returns a cookie value that the driver must pass to `CmUnRegisterCallback` during unload. This cookie is the only link between the driver and its callback registration, and its management becomes a vulnerability surface in its own right.

## Where callback vulnerabilities arise

### Input validation on untrusted data

The callback notification structures contain fields that originate from user mode. For a `REG_SET_VALUE_KEY_INFORMATION` callback, the `ValueName`, `Data`, and `DataSize` fields all come from the calling process. A driver that copies or processes these fields without validating their sizes can overflow internal buffers.

This is conceptually similar to IOCTL input validation failures, but with a twist: the data does not arrive through the I/O Manager's buffering mechanisms. There is no `METHOD_BUFFERED` safety net. The `Data` pointer in the notification structure points directly to the caller's buffer, and the driver must treat it as untrusted user-mode memory. Drivers that forget this, that access `Data` without first verifying `DataSize` against their expected structure, read beyond the user buffer into whatever happens to be adjacent in memory.

### TOCTOU on user-mode data

A registry callback that reads value data from the caller's buffer faces the same double-fetch hazard that affects [METHOD_NEITHER IOCTL handlers](ioctl-handlers.md). The callback reads a field from the user-mode buffer, validates it, and then reads it again to act on it. Between the two reads, a concurrent user-mode thread modifies the value. The kernel validated length 100 but processes length 10,000.

The correct pattern is to capture the relevant data into a kernel-allocated buffer in a single copy, then work exclusively with the kernel copy. But many drivers reference the notification structure's pointers directly throughout their callback logic, creating multiple read points for the same user-mode data. Each additional read is another TOCTOU window.

### Callback re-entrancy and context corruption

Drivers that perform registry operations inside their own registry callbacks create re-entrancy hazards. When a callback for key A's write performs a registry read on key B, that read triggers the same callback again, this time for key B. If the driver maintains per-key tracking state (common in security products that build registries of monitored keys), the re-entrant invocation may corrupt or double-free context structures that the outer invocation is still using.

The Configuration Manager does not prevent re-entrancy. A callback that touches the registry will be called again, recursively, for that new operation. Drivers that allocate and link context structures during callbacks must either prevent re-entrancy through flags or make their context management fully re-entrant-safe.

### Unregistration races

Calling `CmUnRegisterCallback` while callbacks are actively executing on other processors creates a use-after-free window. The Configuration Manager removes the callback from its list, but callbacks already dispatched and running on other CPUs continue to execute. If those in-flight callbacks access the driver's callback context (a pointer provided during registration), and the driver frees that context after `CmUnRegisterCallback` returns, the in-flight callbacks access freed memory.

The Configuration Manager attempts to synchronize with in-flight callbacks, but the synchronization is not immediate. There is a window between when `CmUnRegisterCallback` is called and when all in-flight callbacks have completed. If the driver unloads (freeing its code and data) during this window, the in-flight callbacks execute into freed memory, producing a particularly severe use-after-free.

### Altitude conflicts

Multiple drivers registering callbacks at the same or adjacent altitudes can create non-deterministic execution ordering. If two drivers both modify the same registry operation (one allowing it, the other blocking it), the outcome depends on which callback executes first. When the ordering is non-deterministic, the system behavior becomes inconsistent, and a driver that assumes its callback runs before another driver's callback may operate on stale or incorrect state.

## Drivers that use registry callbacks

Security products are the primary users of registry callbacks. Antivirus drivers, endpoint detection and response (EDR) agents, and host intrusion prevention systems (HIPS) register callbacks to monitor and block malicious registry modifications. The AppLocker driver `appid.sys`, which was the target of CVE-2024-21338 (exploited in the wild by the Lazarus Group), uses callback mechanisms for policy enforcement. Cloud Files minifilter `cldflt.sys` was affected by CVE-2023-36424, a registry callback-related issue that led to elevation of privilege.

Beyond security products, application compatibility layers, virtualization products (that need to redirect registry operations), and enterprise management tools all register registry callbacks. The attack surface is not limited to obvious security drivers; any driver that monitors the registry is exposed.

## Detection approaches

**Input validation auditing** examines each callback function for the notification types it handles and verifies that all user-supplied fields (`ValueName`, `Data`, `DataSize`, key path components) are validated before use. The check must account for both size validation and pointer probing, since the data may point to user-mode memory.

**TOCTOU detection** identifies patterns where the callback reads the same user-mode field more than once. This can be done through static analysis (searching for multiple accesses to notification structure fields) or through dynamic analysis using tools like Bochspwn that detect kernel double-fetches at the hardware level.

**Re-entrancy testing** invokes registry operations from within a callback (via a test driver or hooking framework) to verify that the driver handles recursive callback invocation without corrupting its context state. This requires a purpose-built test harness because re-entrancy is not something that happens in normal operation.

**Unregistration stress testing** calls `CmUnRegisterCallback` while simultaneously performing high-volume registry operations to stress the synchronization between unregistration and in-flight callback execution. Driver Verifier's "Force Pending I/O" and "I/O Verification" options can help expose timing windows.

**Patch diffing** detects registry callback fixes as new size or type checks on callback parameters, reference counting changes for context objects, synchronization changes around registration or invocation, or access mask hardening on registry key operations.

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

Registry callbacks share vulnerability patterns with both [IOCTL handlers](ioctl-handlers.md) (input validation failures, TOCTOU on user data) and [PnP & Power](pnp-power.md) (lifetime races during unregistration). The difference is in the trigger: while IOCTL bugs require the attacker to open a device handle and send a control code, registry callback bugs are triggered by any registry operation, making them reachable from virtually any process context. This broad reachability, combined with the concurrency inherent in system-wide callback invocation, makes registry callbacks a high-value target for security research.
