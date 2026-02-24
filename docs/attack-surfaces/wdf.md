# WDF / KMDF

The Windows Driver Framework provides a driver development model that manages object lifetimes and IRP routing, but misuse of WDF APIs still introduces vulnerabilities in request buffer validation, object lifecycle, and callback safety.

## Attack Surface Overview

- **Entry points**: WDF I/O queue callbacks including `EvtIoDeviceControl`, `EvtIoRead`, `EvtIoWrite`, `EvtIoInternalDeviceControl`, and `EvtIoDefault` registered via `WdfIoQueueCreate`
- **Buffer retrieval**: `WdfRequestRetrieveInputBuffer` and `WdfRequestRetrieveOutputBuffer` with a `MinimumRequiredLength` parameter that the framework enforces -- but only if the driver specifies a non-zero value
- **Object model**: WDFOBJECT hierarchy with parent-child relationships governing automatic cleanup; `WdfObjectDelete`, reference counting via `WdfObjectReference` / `WdfObjectDereference`, and typed context areas
- **File object context**: `WDFFILEOBJECT` callbacks (`EvtDeviceFileCreate`, `EvtFileCleanup`, `EvtFileClose`) with per-file context that must be synchronized across concurrent access
- **Request forwarding**: `WdfRequestSend` and `WdfRequestFormatRequestUsingCurrentType` for forwarding requests to lower drivers, with completion routine registration via `WdfRequestSetCompletionRoutine`
- **UMDF consideration**: User-Mode Driver Framework runs drivers in a host process with restricted kernel access, reducing kernel attack surface but still relevant for driver-specific logic bugs and information disclosure
- **Key risk**: The framework handles IRP routing and basic buffering but does NOT validate the semantic content of IOCTL buffers -- drivers must still validate all input data within their callbacks

## Mechanism Deep-Dive

KMDF abstracts the WDM IRP model behind a framework that manages many common driver operations automatically. When a driver calls `WdfIoQueueCreate` with the appropriate dispatch type (sequential, parallel, or manual), the framework intercepts incoming IRPs, performs buffering (for buffered I/O), and dispatches them to the driver's registered `EvtIo*` callbacks. The driver retrieves input and output buffers using `WdfRequestRetrieveInputBuffer(request, MinimumRequiredLength, &buffer, &length)`. If `MinimumRequiredLength` is non-zero, the framework returns `STATUS_BUFFER_TOO_SMALL` when the actual buffer is smaller. However, many drivers pass 0 for this parameter and then cast the buffer to a structure pointer without any size check, bypassing the framework's built-in protection.

The WDF object model uses a parent-child hierarchy for automatic lifetime management. When a parent object is deleted, all child objects are deleted automatically. This simplifies resource management but introduces different failure modes. If a driver creates an object with the wrong parent, the object may be freed too early (parent deleted before the object is done being used) or too late (memory leak). For example, a `WDFMEMORY` object created as a child of `WDFDEVICE` persists for the device's entire lifetime, but if it was intended to track per-request data, it should have been created as a child of `WDFREQUEST` so it is automatically freed when the request completes. `WdfObjectReference` and `WdfObjectDereference` provide manual reference counting that must be balanced correctly -- an extra dereference causes use-after-free, a missing dereference causes a leak.

Request completion is another critical area. Each `WDFREQUEST` must be completed exactly once via `WdfRequestComplete`, `WdfRequestCompleteWithInformation`, or `WdfRequestCompleteWithPriorityBoost`. Completing a request twice causes a double-free of the underlying IRP, which can corrupt pool metadata and lead to code execution. Failing to complete a request causes the calling process to hang indefinitely and leaks kernel resources. The framework provides `WdfRequestIsCanceled` and cancellation callbacks (`EvtRequestCancel`), but race conditions between normal completion and cancellation can still cause double-completion if the driver does not use proper synchronization, such as an interlocked flag or `WdfRequestUnmarkCancelable` before completing.

The queue dispatch type has direct implications for thread safety. A sequential queue delivers one request at a time, providing implicit serialization. A parallel queue delivers requests concurrently, and the driver must protect shared state with its own synchronization. Choosing the wrong dispatch type -- or correctly using parallel dispatch but forgetting to protect shared state -- introduces race conditions that can be triggered by sending multiple IOCTLs simultaneously from separate threads.

## Common Vulnerability Patterns

- **`MinimumRequiredLength` set to 0**: Driver calls `WdfRequestRetrieveInputBuffer(request, 0, &buf, &len)`, then casts `buf` to a structure pointer without checking `len >= sizeof(STRUCT)`, allowing out-of-bounds access from a short buffer
- **Double completion**: Both a normal completion path and a cancellation callback complete the same request, causing a double-free of the underlying IRP and pool corruption
- **Missing output buffer size validation**: Driver calls `WdfRequestRetrieveOutputBuffer` with a minimal length check but writes a larger structure, overflowing into adjacent pool memory
- **Object parent misconfiguration**: A `WDFMEMORY` or `WDFTIMER` created as a child of `WDFDEVICE` when it should be a child of `WDFREQUEST`, causing the memory or timer to outlive the request context it references
- **File object context race**: Multiple threads access per-file context (`WdfObjectGetTypedContext` on `WDFFILEOBJECT`) without synchronization between create, I/O, and cleanup callbacks when using parallel dispatch queues
- **Request forwarding without completion routine**: Driver forwards a request to a lower driver with `WdfRequestSend` but does not set a completion routine, losing the ability to clean up driver-specific state when the lower driver completes the request
- **Sequential queue starvation**: Using a sequential I/O queue with long-running or blocking operations blocks all subsequent requests, creating denial-of-service conditions
- **Framework version mismatch**: Driver compiled against one KMDF version but loaded with a different framework DLL version, causing structure layout mismatches in context areas

## Driver Examples

Most modern Windows drivers use KMDF, including HID drivers (HID miniport drivers via `hidclass.sys`), sensor drivers, USB function drivers, battery drivers (`cmbatt.sys`), simple PCI device drivers, and serial port drivers. UMDF is used for printers, point-of-sale devices, portable device protocol (MTP) drivers, and sensors. Notable KMDF-based system drivers include `SerCx2.sys` (serial framework), `SpbCx.sys` (simple peripheral bus), `UCX01000.sys` (USB host controller extension), and `GPIO` client drivers. Third-party KMDF drivers for custom hardware devices (industrial control, scientific instruments, IoT peripherals) are common sources of buffer validation vulnerabilities because their developers may not account for the `MinimumRequiredLength` parameter and WDF object lifetime model.

## Detection Approach

- **Callback tracing**: Identify `WdfIoQueueCreate` calls to find all registered `EvtIo*` callbacks. For each callback, trace `WdfRequestRetrieveInputBuffer` and `WdfRequestRetrieveOutputBuffer` calls to verify that `MinimumRequiredLength` is set to at least `sizeof(expected_struct)` or that the returned length is explicitly checked before casting.
- **Completion analysis**: Track all paths that call `WdfRequestComplete` or related functions. Verify that each request is completed exactly once on every code path, including error paths and cancellation callbacks. Check for races between cancellation routines and normal completion by looking for `WdfRequestUnmarkCancelable` usage.
- **Object lifetime auditing**: Map parent-child relationships for all WDF objects created by the driver. Verify that child object lifetimes do not exceed the validity of referenced data, and that per-request allocations use the request as parent.
- **WDF Driver Verifier**: Enable KMDF Verifier via the registry (`HKLM\System\CurrentControlSet\Services\{driver}\Parameters\Wdf\VerifierOn`) to catch double completions, unreturned requests, incorrect object deletion, and other framework contract violations at runtime.
- **Patch diffing**: KMDF patches frequently change `MinimumRequiredLength` from 0 to `sizeof(STRUCT)`, add explicit length checks after buffer retrieval, or add cancellation synchronization around request completion.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-35250](../case-studies/CVE-2024-35250.md) | `ks.sys` | Untrusted pointer dereference through kernel streaming framework dispatch |
| [CVE-2024-26229](../case-studies/CVE-2024-26229.md) | `csc.sys` | Driver missing access check on privileged IOCTL |
| [CVE-2024-38054](../case-studies/CVE-2024-38054.md) | `ksthunk.sys` | Integer overflow in streaming header thunking across framework boundary |
| [CVE-2024-38238](../case-studies/CVE-2024-38238.md) | `ksthunk.sys` | Unsafe MDL mapping in WDF-managed thunking path |

## AutoPiff Detection

- `wdf_request_buffer_size_check_added` -- `MinimumRequiredLength` changed from 0 to `sizeof(struct)` in `WdfRequestRetrieveInputBuffer` or `WdfRequestRetrieveOutputBuffer`
- `wdf_request_completion_guard_added` -- Double completion guard, interlocked flag, or cancellation synchronization added to request handling
- `wdf_object_parent_fixed` -- WDF object parent-child relationship corrected to match intended lifetime semantics
- `wdf_queue_dispatch_type_changed` -- I/O queue dispatch type changed (e.g., sequential to parallel or vice versa) to address synchronization requirements
- `wdf_output_buffer_validation_added` -- Output buffer size check added before writing response data to prevent pool overflow
