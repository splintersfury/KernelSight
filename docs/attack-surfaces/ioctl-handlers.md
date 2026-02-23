# IOCTL Handlers

Device I/O control request handlers are the primary user-to-kernel communication interface for Windows drivers, and the single most exploited kernel attack surface.

## Attack Surface Overview

- **Entry point**: The driver's `IRP_MJ_DEVICE_CONTROL` dispatch routine, registered in the `DriverObject->MajorFunction` table
- **User-mode trigger**: Any process calls `DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, ...)`
- **Buffering methods**: The IOCTL code's two low bits select the transfer method -- `METHOD_BUFFERED` (I/O Manager copies both buffers via `Irp->AssociatedIrp.SystemBuffer`), `METHOD_IN_DIRECT` / `METHOD_OUT_DIRECT` (input copied, output MDL-mapped via `Irp->MdlAddress`), and `METHOD_NEITHER` (raw user pointers in `IrpSp->Parameters.DeviceIoControl.Type3InputBuffer` and `Irp->UserBuffer`)
- **IOCTL code encoding**: The 32-bit control code encodes device type (bits 16-31), required access (bits 14-15), function number (bits 2-13), and transfer method (bits 0-1), defined via the `CTL_CODE` macro
- **Access control**: Device objects may restrict handle creation via `FILE_DEVICE_SECURE_OPEN`, security descriptors, or namespace ACLs -- but many drivers leave devices world-accessible
- **Key risk**: `METHOD_NEITHER` passes raw user-mode pointers directly to the kernel driver without any buffering or probing by the I/O Manager

## Mechanism Deep-Dive

When a user-mode process calls `DeviceIoControl`, the I/O Manager constructs an `IRP` with major function code `IRP_MJ_DEVICE_CONTROL` and dispatches it to the driver's registered handler. The IOCTL code itself is a 32-bit value encoding the device type, access requirements, function number, and transfer method. The driver typically implements a `switch` statement over the IOCTL code to route each request to the appropriate handler logic.

For `METHOD_BUFFERED` transfers, the I/O Manager allocates a kernel buffer large enough for the larger of the input and output buffers, copies the user input into it, and after the driver completes the IRP, copies the result back to user space. This provides inherent isolation but the driver must still validate that the buffer sizes are sufficient for the expected structure. For `METHOD_IN_DIRECT` and `METHOD_OUT_DIRECT`, the output buffer is described by an MDL that the I/O Manager probes and locks, giving the driver direct access to the user pages. `METHOD_NEITHER` provides no buffering at all -- the driver receives raw user-mode pointers and is entirely responsible for probing and capturing the data safely.

The severity of IOCTL vulnerabilities stems from the combination of direct user reachability and the sheer variety of IOCTL codes a single driver may handle. A driver like `ks.sys` handles dozens of distinct control codes across multiple device types, and each code path must independently validate buffer sizes, pointer alignment, and access permissions. A single missing check on one code path is sufficient for a local privilege escalation. The `DeviceIoControl` API is callable from sandboxed processes and low-privilege contexts, making IOCTL vulnerabilities especially valuable for sandbox escapes and local privilege escalation chains.

The access control model for device objects adds another dimension. When a driver calls `IoCreateDevice` or `IoCreateDeviceSecure`, it may specify a security descriptor limiting which users can open handles. However, if the driver does not set `FILE_DEVICE_SECURE_OPEN`, the I/O Manager only checks the security descriptor on the device namespace root, not on individual opens to named paths under the device. This means a driver that exposes a device at `\\Device\\MyDriver` without `FILE_DEVICE_SECURE_OPEN` may allow unprivileged processes to open `\\Device\\MyDriver\AnySubPath` and reach the IOCTL handler.

## Common Vulnerability Patterns

- **Missing input/output buffer length validation**: The driver casts `SystemBuffer` to a structure pointer without verifying `InputBufferLength >= sizeof(EXPECTED_STRUCT)`, leading to out-of-bounds reads or writes from uninitialized pool memory
- **`METHOD_NEITHER` without probing**: Driver dereferences `Type3InputBuffer` directly without calling `ProbeForRead` / `ProbeForWrite` inside a `__try/__except` block, allowing user-mode to pass kernel addresses
- **Switch statement missing default case**: The IOCTL dispatch `switch` lacks a default handler, causing fall-through into unintended code paths or returning `STATUS_SUCCESS` without processing
- **Type confusion**: The IOCTL buffer is cast to different structure types depending on a field within the buffer itself, but the size validation only checks against the smallest variant
- **Double-fetch from `METHOD_NEITHER` buffers**: The driver reads a length field, validates it, then re-reads it from the same user-mode address -- a concurrent thread can modify the value between the two reads
- **Insufficient device object ACL**: The driver creates a device object without `FILE_DEVICE_SECURE_OPEN` or with a permissive SDDL string, allowing unprivileged processes to open handles
- **Shared dispatch across device objects**: A single IOCTL handler serves multiple device objects with different trust levels, but does not check which device the IRP targets
- **Integer overflow in size arithmetic**: The driver adds a user-supplied count to a base size for allocation, and the addition wraps around 32-bit integer bounds, resulting in an undersized allocation followed by an oversized copy
- **Output buffer information leak**: The driver writes a structure to the output buffer without first zeroing it, leaking uninitialized kernel pool data (including kernel pointers) to user mode

## Driver Examples

Nearly every WDM and KMDF driver exposes IOCTL handlers. Historically high-value targets include `ks.sys` and `ksthunk.sys` (kernel streaming), `afd.sys` (ancillary function driver for Winsock), `csc.sys` (client-side caching), `appid.sys` (AppLocker), `win32kbase.sys` (GDI system calls), and virtually all third-party antivirus, EDR, and GPU drivers. Kernel streaming drivers are particularly rich attack surfaces because they handle complex media pipeline structures with deeply nested variable-length fields. Third-party drivers from antivirus vendors (Avast, ESET, Kaspersky), virtualization products (VMware, VirtualBox), and hardware peripheral companies frequently contain IOCTL vulnerabilities due to less rigorous code review compared to Microsoft inbox drivers.

## Detection Approach

- **Static analysis**: Identify `IRP_MJ_DEVICE_CONTROL` handler registration in the `DriverEntry`, then trace the dispatch switch. For each IOCTL code, verify that `InputBufferLength` and `OutputBufferLength` are checked before any buffer dereference. Flag any `METHOD_NEITHER` code paths lacking `ProbeForRead`/`ProbeForWrite` with SEH.
- **Fuzzing**: Tools such as `kAFL`, `IOCTL Fuzzer`, or custom `DeviceIoControl` harnesses can enumerate valid IOCTL codes (by scanning the dispatch switch) and fuzz input buffers with varying sizes. Coverage-guided fuzzing is effective because IOCTL handlers are typically self-contained functions.
- **Dynamic analysis**: Monitor device object creation with `!devobj` in WinDbg, check security descriptors with `!sd`, and trace IOCTL dispatch with breakpoints on the handler to observe buffer access patterns.
- **Device enumeration**: Use `NtQueryDirectoryObject` or the WinObj tool to enumerate all device objects in the `\\Device` namespace. Attempt to open each device from a low-privilege process to identify accessible attack surface.
- **Patch diffing**: Compare consecutive driver versions to detect newly added size checks, probe calls, or ACL changes -- this is the core AutoPiff approach.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-21338](../case-studies/CVE-2024-21338.md) | `appid.sys` | Missing access control on IOCTL 0x22A018 allows kernel read/write |
| [CVE-2024-35250](../case-studies/CVE-2024-35250.md) | `ks.sys` | Untrusted pointer dereference in IOCTL dispatch |
| [CVE-2024-38054](../case-studies/CVE-2024-38054.md) | `ksthunk.sys` | Integer overflow in KSSTREAM_HEADER thunking |
| [CVE-2024-26229](../case-studies/CVE-2024-26229.md) | `csc.sys` | Missing access check on IOCTL allows EoP |
| [CVE-2023-21768](../case-studies/CVE-2023-21768.md) | `afd.sys` | Missing validation in AFD IOCTL enables arbitrary write |
| [CVE-2024-38193](../case-studies/CVE-2024-38193.md) | `afd.sys` | Use-after-free in Winsock ancillary function driver |

## AutoPiff Detection

AutoPiff detects IOCTL hardening patches with these rules:

- `ioctl_input_size_validation_added` -- Input or output buffer size validation added for a specific IOCTL code
- `method_neither_probe_added` -- `ProbeForRead` or `ProbeForWrite` call added for `METHOD_NEITHER` buffer access
- `ioctl_code_default_case_added` -- Default case added to the IOCTL dispatch switch statement
- `device_acl_hardening` -- Device object security descriptor or ACL hardened
- `new_ioctl_handler` -- New IOCTL handler function detected (attack surface expansion rule)
- `ioctl_output_buffer_zeroed` -- Output buffer zeroed before use to prevent kernel information disclosure

### Third-Party IOCTL Examples

Third-party vendor utility drivers are among the most exploited IOCTL-based attack surfaces. Unlike Microsoft inbox drivers where the vulnerability is a missing check, these drivers intentionally expose powerful IOCTLs:

| Driver | Vendor | IOCTLs Exposed | Case Study |
|--------|--------|---------------|------------|
| `DBUtil_2_3.sys` | Dell | Physical/virtual memory R/W, MSR R/W | [CVE-2021-21551](../case-studies/CVE-2021-21551.md) |
| `RTCore64.sys` | MSI | Physical memory R/W, MSR, I/O port | [CVE-2019-16098](../case-studies/CVE-2019-16098.md) |
| `gdrv.sys` | Gigabyte | Kernel memory R/W, MSR | [CVE-2018-19320](../case-studies/CVE-2018-19320.md) |
| `iqvw64e.sys` | Intel | Physical/virtual memory R/W | [CVE-2015-2291](../case-studies/CVE-2015-2291.md) |
| `HW.sys` | Marvin Test | Physical memory R/W, I/O port | [CVE-2020-15368](../case-studies/CVE-2020-15368.md) |
| `AMDRyzenMasterDriver.sys` | AMD | Physical memory R/W | [CVE-2020-12928](../case-studies/CVE-2020-12928.md) |
| `Capcom.sys` | Capcom | Ring-0 code execution | [Capcom.sys](../case-studies/Capcom-sys.md) |

See [Vendor Utility Drivers](../driver-types/vendor-utility.md) for the full category overview.
