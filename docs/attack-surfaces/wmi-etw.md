# WMI / ETW

Security researchers spend most of their time on IOCTL handlers, filesystem IRPs, and network packet parsing. WMI method handlers receive comparatively little attention, despite being functionally equivalent to IOCTL handlers: they accept user-supplied input buffers, process them in kernel mode, and return results. The difference is perception. WMI is seen as an administrative interface, a management tool for IT departments and monitoring solutions, not an attack surface. But "administrative" does not mean "authenticated" or "access-controlled." Many WMI data blocks are registered with security descriptors that grant access to `Everyone` or `Authenticated Users`, making their method handlers reachable from any process on the system, including low-privilege and sandboxed contexts.

ETW (Event Tracing for Windows) adds a complementary exposure. While WMI is primarily an inbound attack surface (user code sends data to kernel drivers through WMI methods), ETW is primarily an outbound information leak surface (kernel drivers emit diagnostic events that unprivileged consumers can read). When a driver includes raw kernel pointers or pool addresses in its ETW event fields, it hands any ETW consumer the information needed to defeat KASLR. The `NtTraceControl` syscall that manages ETW sessions also processes complex buffer management operations in the kernel, making it a direct inbound attack surface as well.

## How WMI reaches kernel drivers

``` mermaid
graph TD
    A["User Process\nGet-WmiObject / Invoke-WmiMethod"] --> B["WMI Service\nwmiprvse.exe"]
    B --> C["I/O Manager\nIRP_MJ_SYSTEM_CONTROL"]
    C --> D["Driver's System Control\nDispatch"]
    D --> E{"Minor\nFunction"}
    E --> F["IRP_MN_QUERY_ALL_DATA\n(read all instances)"]
    E --> G["IRP_MN_EXECUTE_METHOD\n⚠ Input buffer like IOCTL"]
    E --> H["IRP_MN_CHANGE_SINGLE_INSTANCE\n(write data)"]
    G --> I["Driver Method Handler\n(parse WNODE_METHOD_ITEM)"]
    I --> J["Process InBufferSize\nand method parameters"]
    style G fill:#2d1b1b,stroke:#ef4444,color:#e2e8f0
    style I fill:#152a4a,stroke:#f59e0b,color:#e2e8f0
    style J fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
```

WMI provides a standardized mechanism for drivers to expose configuration data, status information, and operational methods to management tools. A driver registers as a WMI data provider via `IoWMIRegistrationControl`, and the WMI infrastructure routes management requests as `IRP_MJ_SYSTEM_CONTROL` IRPs with minor function codes indicating the operation type. The driver processes these IRPs either directly in its system control dispatch routine or by delegating to the `WmiSystemControl` helper library (`wmilib.sys`), which parses the WNODE structures and dispatches to driver-registered callback functions.

The data format is where the complexity lives. WMI data blocks use variable-length `WNODE_*` header structures. The `WNODE_HEADER.BufferSize` field specifies the total size, and for multi-instance queries (`WNODE_ALL_DATA`), an array of offset/length pairs describes each instance's location within the buffer. Instance names can be dynamic, encoded as variable-length strings at computed offsets, or static, using index-based lookups. The driver must parse these embedded offsets and lengths to extract instance data, and any mismatch between declared sizes and actual buffer content leads to out-of-bounds access.

WMI method execution through `IRP_MN_EXECUTE_METHOD` is the most security-relevant operation. The kernel delivers a `WNODE_METHOD_ITEM` structure containing the method ID and an input data buffer. The driver's method handler is functionally identical to an IOCTL handler: it receives untrusted input of a caller-specified size and must validate the buffer before processing. The critical difference is that WMI method handlers are fuzzed far less often than IOCTL handlers, so the same buffer validation failures that have been systematically eliminated from IOCTL code through years of security research persist in WMI method handlers that have never received the same attention.

### GUID-based access control: the invisible perimeter

Each WMI data block and ETW provider is identified by a GUID with an associated security descriptor governing who can query, set, or invoke methods. This security descriptor is the access control boundary for WMI, and it is frequently misconfigured.

When a driver registers a WMI class, the GUID's security descriptor comes from one of several sources: the registry, programmatic configuration via `IoWMISetNotificationCallback`, or default values. Many drivers copy sample code that uses default GUIDs without reviewing the associated security descriptors. The result is a GUID with `GENERIC_ALL` granted to `Everyone` or `Authenticated Users`, exposing the driver's WMI methods to any process on the system.

This is the WMI equivalent of an IOCTL handler behind a device object with no security descriptor. The method handler itself might be perfectly coded, but if the GUID access control allows unprivileged callers to reach it, any bug in the handler is exploitable from low-privilege contexts. Auditing WMI GUID security descriptors is therefore a prerequisite for assessing WMI attack surface, not an afterthought.

## The ETW information leak surface

ETW operates in the opposite direction from WMI. Where WMI sends untrusted data into kernel drivers, ETW sends diagnostic data out of kernel drivers to user-mode consumers. The attack surface is information disclosure: when a driver writes kernel pointers, pool addresses, internal state machine values, or cryptographic material to ETW events, any process that can enable the ETW provider and consume its events harvests this information.

The impact depends on what leaks. A raw kernel pointer defeats KASLR, providing the kernel base address needed for most exploitation chains. A pool allocation address reveals the location of specific kernel objects, enabling targeted [pool spray](../primitives/exploitation/pool-spray-feng-shui.md). Internal state values may reveal synchronization state that helps an attacker time a race condition.

The `NtTraceControl` syscall manages ETW session lifecycle: creating trace sessions, enabling and disabling providers, flushing buffers, and querying session statistics. This syscall processes complex buffer management for trace sessions and has itself been a source of kernel vulnerabilities. The inbound and outbound surfaces combine: a bug in `NtTraceControl` session management might give arbitrary kernel memory access, while the events flowing through those sessions leak the addresses needed to exploit the access.

ETW session object lifetime introduces concurrency hazards. Creating and destroying ETW sessions rapidly can race with provider enable/disable notifications, potentially causing use-after-free of session context structures or trace buffer corruption. Similarly, enabling and disabling WMI event notifications concurrently can race with event delivery, accessing freed notification context structures.

## Common vulnerability patterns

### WMI method buffer overflows

The driver's `IRP_MN_EXECUTE_METHOD` handler copies method input parameters without validating that `InBufferSize` is sufficient for the expected parameter structure. The handler casts the input buffer to a method-specific structure and accesses fields beyond the actual buffer boundary. This is the same missing-size-check pattern that dominates [IOCTL handler](ioctl-handlers.md) vulnerabilities, but in WMI code that has received less security review.

### Instance name overflows

Variable-length instance names with attacker-controlled length fields can overflow fixed-size driver buffers during `IRP_MN_QUERY_ALL_DATA` or `IRP_MN_QUERY_SINGLE_INSTANCE` processing. The driver allocates a buffer for the instance name based on a length field from the WNODE structure, but the length field does not match the actual data available, causing the copy to read beyond the source buffer or write beyond the destination.

### WNODE size mismatches

The `WNODE_HEADER.BufferSize` field declares the total size of the WNODE structure, but this value comes from the caller and may not match the actual IRP buffer size. A driver that trusts `BufferSize` for output data placement without comparing it to the IRP's output buffer length can write beyond the actual buffer. This is a variant of the integer overflow pattern: the WNODE says there is room for 10,000 bytes, but the IRP buffer is only 100 bytes.

### Registration and deregistration races

A driver's WMI deregistration (`IoWMIRegistrationControl` with `WMIREG_ACTION_DEREGISTER`) can race with an in-flight WMI query on another processor. If the deregistration frees driver state that the in-flight query is still accessing, the result is a use-after-free. This is conceptually similar to the [PnP removal race](pnp-power.md), but in the WMI registration context rather than the device lifecycle context.

## Drivers that expose WMI and ETW

Nearly all Windows drivers register at least one WMI data block for standard device properties, but the drivers that expose WMI methods are the ones with meaningful attack surface. Storage drivers (`disk.sys`, `storport.sys` miniports, `classpnp.sys`) expose SCSI/NVMe operational statistics, SMART data, and disk geometry through WMI classes, and some expose calibration or firmware update methods. Network drivers (`ndis.sys` and miniport drivers) expose OID-equivalent configuration and network statistics through WMI. Hardware monitoring drivers for temperature sensors, fan controllers, and embedded controller interfaces often expose WMI methods for sensor calibration or firmware updates, making them particularly interesting targets.

On the ETW side, providers in `ntoskrnl.exe`, `tcpip.sys`, `storport.sys`, and `fltmgr.sys` generate high-volume diagnostic events used by performance monitoring and troubleshooting tools. The volume of events means there are many opportunities for kernel pointer leaks, and the providers are typically enabled by default for system monitoring, making the events continuously available.

## Detection approaches

**WMI class enumeration** through `wbemtest.exe`, `Get-WmiObject -List`, or WMI Explorer identifies all WMI classes on a system. Classes with methods are the priority targets because their method handlers process untrusted input buffers. Listing the methods and their parameter definitions provides a map of the WMI attack surface equivalent to enumerating IOCTL codes.

**GUID security auditing** queries WMI GUID security descriptors via `Get-WmiObject -Class __SystemSecurity` or WMI CIM Studio. Any GUIDs with `GENERIC_ALL` or `GENERIC_EXECUTE` granted to `Everyone`, `Authenticated Users`, or `Users` groups are immediate findings, regardless of the method handler's quality, because they make the handler reachable from unprivileged contexts.

**Method fuzzing** invokes each WMI method with varying input buffer sizes (zero, minimal, oversized, and boundary values) via `IWbemServices::ExecMethod` or PowerShell's `Invoke-WmiMethod`. Driver Verifier with special pool enabled converts heap corruptions into immediate bugchecks, making the fuzzing results definitive. The approach mirrors [IOCTL fuzzing](ioctl-handlers.md) but targets the WMI method path instead of `DeviceIoControl`.

**ETW provider enumeration** via `logman query providers` lists registered ETW providers. Enabling each provider in a trace session and scanning event payloads for values in the kernel address range (typically `0xFFFFF8xx` on 64-bit systems) identifies kernel pointer leaks. Custom ETW consumers can automate this scanning at scale across all providers on a system.

**Static analysis** locates the `IRP_MJ_SYSTEM_CONTROL` handler and traces `IRP_MN_EXECUTE_METHOD` processing. The key checks are that `InBufferSize` is validated before input buffer access and that `WNODE_HEADER.BufferSize` is validated against the actual IRP buffer length. Any gap in these validations is a candidate vulnerability.

**Patch diffing** on WMI and ETW code typically reveals size validation added to method handlers, GUID security descriptors tightened to restrict unprivileged access, or kernel pointers scrubbed from ETW event payloads. These changes are detectable through binary comparison of the system control dispatch routine or ETW provider registration functions using [AutoPiff](../tooling/autopiff-integration.md).

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-38256](../case-studies/CVE-2024-38256.md) | `ntoskrnl.exe` | Information disclosure through kernel management interface |
| [CVE-2024-21302](../case-studies/CVE-2024-21302.md) | `ntoskrnl.exe` | Privilege escalation via kernel management operation |
| [CVE-2023-32019](../case-studies/CVE-2023-32019.md) | `ntoskrnl.exe` | Information disclosure through kernel data exposure path |
| [CVE-2023-36424](../case-studies/CVE-2023-36424.md) | `ntoskrnl.exe` | Elevation of privilege via kernel state manipulation |
| [CVE-2024-30088](../case-studies/CVE-2024-30088.md) | `ntoskrnl.exe` | Race condition in kernel I/O handling reachable via management path |

## AutoPiff Detection

WMI and ETW vulnerabilities are detected by general-purpose and management-specific rules:

- `wmi_method_buffer_size_check_added` -- Input buffer size validation added to `IRP_MN_EXECUTE_METHOD` handler
- `wmi_guid_acl_hardened` -- WMI GUID security descriptor tightened to restrict unprivileged access
- `etw_event_pointer_scrubbed` -- Kernel pointer value removed or masked in ETW event payload to prevent KASLR bypass
- `system_control_validation_added` -- General input validation added to `IRP_MJ_SYSTEM_CONTROL` dispatch routine
- `wmi_instance_name_bounds_check` -- Variable-length instance name size validated against buffer bounds in WMI data block handler

The relative neglect of WMI as an attack surface is itself an opportunity. The same buffer validation failures that produced dozens of IOCTL CVEs over the past decade likely exist in WMI method handlers that have never been audited with the same rigor. For researchers looking for high-value targets with less competition, enumerating WMI methods accessible to unprivileged callers and fuzzing their input buffers is one of the highest-return activities available. The bugs found will map to the same [vulnerability classes](../vuln-classes/index.md) and [exploitation primitives](../primitives/index.md) as IOCTL bugs, because the underlying code patterns are identical.
