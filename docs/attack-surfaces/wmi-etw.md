# WMI / ETW

Windows Management Instrumentation and Event Tracing for Windows expose management and diagnostic interfaces into kernel drivers. Attack surface exists in WMI method invocation, data block handling, and ETW session management.

## Attack Surface Overview

- **WMI entry points**: `IRP_MJ_SYSTEM_CONTROL` dispatch routine handling WMI query, set, method, and event operations; registration via `IoWMIRegistrationControl` or the `WmiSystemControl` helper library
- **ETW entry points**: Provider registration via `EtwRegister`, event writing via `EtwWrite` / `EtwWriteTransfer`, and session management via the `NtTraceControl` syscall and `NtTraceEvent` path
- **WMI data blocks**: Variable-length instance data with embedded instance names and instance counts, described by MOF (Managed Object Format) class definitions compiled into driver binaries or provided via BMOF resources
- **GUID-based access control**: Each WMI data block and ETW provider is identified by a GUID with an associated security descriptor governing who can query, set, or invoke methods -- overly permissive descriptors expose privileged operations to unprivileged callers
- **User-mode reach**: WMI queries via `IWbemServices::ExecQuery` / PowerShell `Get-WmiObject` / `Get-CimInstance`; WMI methods via `IWbemServices::ExecMethod`; ETW sessions started via `StartTrace` / `EnableTraceEx2` / `logman.exe` / `xperf.exe`
- **Key risk**: WMI method input buffers are handled identically to IOCTL input buffers but receive less security scrutiny because WMI is perceived as an administrative-only interface; overly permissive GUID security descriptors allow unprivileged access

## Mechanism Deep-Dive

WMI provides a standardized mechanism for drivers to expose configuration data, status information, and operational methods to management tools. When a driver registers as a WMI data provider via `IoWMIRegistrationControl`, the WMI infrastructure routes management requests to the driver as `IRP_MJ_SYSTEM_CONTROL` IRPs with minor function codes such as `IRP_MN_QUERY_ALL_DATA`, `IRP_MN_QUERY_SINGLE_INSTANCE`, `IRP_MN_CHANGE_SINGLE_INSTANCE`, and `IRP_MN_EXECUTE_METHOD`. The driver processes these IRPs in its system control dispatch routine or delegates to the `WmiSystemControl` helper library (`wmilib.sys`), which parses the WNODE structures and dispatches to driver-registered callback functions.

WMI data blocks use a variable-length format with a `WNODE_*` header structure followed by instance-specific data. The `WNODE_HEADER.BufferSize` field specifies the total size, and for multi-instance queries (`WNODE_ALL_DATA`), an array of offset/length pairs describes each instance's location within the buffer. Instance names can be dynamic (variable-length strings embedded at computed offsets) or static (index-based). The driver must parse these embedded offsets and lengths to extract instance data, and any mismatch between the declared sizes and the actual buffer content leads to out-of-bounds access. WMI method execution (`IRP_MN_EXECUTE_METHOD`) passes input parameters as a `WNODE_METHOD_ITEM` structure with the method ID and an input data buffer. The driver's method handler is functionally equivalent to an IOCTL handler and must validate the input buffer size and content. Since WMI is fuzzed less often than IOCTLs, these handlers frequently contain unchecked buffer accesses.

ETW provides a high-performance event tracing mechanism where kernel-mode providers register event schemas and write structured events to trace sessions controlled by user-mode consumers. The attack surface is bidirectional. On the inbound side, the kernel ETW infrastructure processes user-mode requests via `NtTraceControl` to create trace sessions, enable/disable providers, flush buffers, and query session statistics. On the outbound side, ETW providers in drivers write event data that consumers can read. If a driver includes raw kernel pointers, pool addresses, or other internal state in ETW event fields, an unprivileged ETW consumer can harvest this information to defeat kernel address space layout randomization (KASLR). The `NtTraceControl` syscall itself handles complex buffer management for trace sessions and has been a source of vulnerabilities in the kernel ETW infrastructure.

The security model for WMI and ETW relies heavily on GUID-based access control. Each WMI data block and ETW provider has a GUID with an associated security descriptor (stored in the registry or set programmatically). If a driver registers a WMI class with a GUID whose security descriptor grants `GENERIC_ALL` to `Everyone` or `Authenticated Users`, then any user on the system can invoke WMI methods on that driver, including methods that perform privileged hardware operations. Many drivers copy sample code or use default GUIDs without reviewing the associated security descriptors, exposing sensitive functionality to unprivileged callers.

## Common Vulnerability Patterns

- **WMI method buffer overflow**: The driver's `IRP_MN_EXECUTE_METHOD` handler copies method input parameters without validating that `InBufferSize` is sufficient for the expected parameter structure, leading to out-of-bounds read or pool overflow
- **WMI data block instance name overflow**: Variable-length instance names with attacker-controlled length fields overflow fixed-size driver buffers during `IRP_MN_QUERY_ALL_DATA` or `IRP_MN_QUERY_SINGLE_INSTANCE` processing
- **Overly permissive WMI GUID security**: The WMI GUID security descriptor allows `GENERIC_ALL` for `Everyone` or `Authenticated Users`, enabling unprivileged processes to invoke sensitive WMI methods that perform privileged driver operations
- **ETW event information disclosure**: ETW events emitted by kernel drivers include raw kernel pointers, pool tag values, or internal state that an unprivileged ETW consumer can read to defeat KASLR or discover kernel object addresses
- **ETW session object lifetime**: Creating and destroying ETW sessions rapidly races with provider enable/disable notifications, potentially causing use-after-free of session context structures or trace buffer corruption
- **WMI event notification race**: Concurrent enable/disable of WMI event notifications races with event delivery, accessing freed notification context structures
- **WNODE buffer size mismatch**: The `WNODE_HEADER.BufferSize` field does not match the actual IRP output buffer size, and the driver trusts the WNODE size for output data placement, writing beyond the actual buffer
- **WMI registration re-entrancy**: Driver's WMI deregistration (`IoWMIRegistrationControl` with `WMIREG_ACTION_DEREGISTER`) races with an in-flight WMI query, accessing freed driver state

## Driver Examples

Nearly all Windows drivers register at least one WMI data block for standard device properties. Storage drivers (`disk.sys`, `storport.sys` miniports, `classpnp.sys`) expose SCSI/NVMe operational statistics, SMART data, and disk geometry via WMI classes. Network drivers (`ndis.sys` and miniport drivers) expose OID-equivalent configuration and network statistics through WMI. `wmilib.sys` is the kernel helper library used by many drivers to simplify WMI IRP handling. Hardware monitoring drivers (temperature sensors, fan controllers, embedded controller interfaces) often expose WMI interfaces with method handlers for sensor calibration or firmware updates. Disk management tools (`diskmgmt.msc`, `diskpart.exe`) rely on WMI classes from `disk.sys` and `partmgr.sys`. ETW providers in `ntoskrnl.exe`, `tcpip.sys`, `storport.sys`, and `fltmgr.sys` generate high-volume diagnostic events used by performance monitoring and troubleshooting tools.

## Detection Approach

- **WMI class enumeration**: Use `wbemtest.exe`, `Get-WmiObject -List`, or WMI Explorer to enumerate all WMI classes on a system. Identify classes with methods, since method handlers process untrusted input buffers and are the most exposed WMI surface.
- **GUID security auditing**: Query WMI GUID security descriptors via `Get-WmiObject -Class __SystemSecurity` or WMI CIM Studio. Flag any GUIDs with `GENERIC_ALL` or `GENERIC_EXECUTE` granted to `Everyone`, `Authenticated Users`, or `Users` groups.
- **Method fuzzing**: For each WMI class with methods, invoke the method with varying input buffer sizes (zero, minimal, oversized, and boundary values) and contents via `IWbemServices::ExecMethod` or PowerShell `Invoke-WmiMethod`. Monitor for kernel crashes or unexpected behavior with Driver Verifier special pool enabled.
- **ETW provider enumeration**: Use `logman query providers` to list registered ETW providers. Enable each provider in a trace session and inspect event payloads for kernel pointer leaks using `TraceEvent`, `xperf`, or custom ETW consumers that scan for values in the kernel address range.
- **Static analysis**: Locate the `IRP_MJ_SYSTEM_CONTROL` handler and trace `IRP_MN_EXECUTE_METHOD` processing. Verify that `InBufferSize` is validated before input buffer access. Check that `WNODE_HEADER.BufferSize` is validated against the actual IRP buffer length.
- **Patch diffing**: WMI fixes typically add size validation to method handlers, tighten GUID security descriptors, or scrub kernel pointers from ETW event payloads. These changes are detectable through binary comparison of the system control dispatch routine or ETW provider registration.

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
