# WDF / KMDF

The Windows Driver Framework was designed to make driver development safer. It manages object lifetimes automatically, routes IRPs through a framework layer that handles common validation, and provides APIs with built-in safety checks. In many ways it succeeds: a KMDF driver is generally harder to exploit than an equivalent WDM driver. But "harder" is not "impossible," and the framework's safety guarantees depend entirely on the driver using its APIs correctly. When a driver passes 0 for the `MinimumRequiredLength` parameter in `WdfRequestRetrieveInputBuffer`, it opts out of the framework's size validation. When it creates a WDF object with the wrong parent, the automatic lifetime management frees the object at the wrong time. The framework provides the safety net; the driver has to actually stand on it.

Understanding WDF attack surface is important for a practical reason: most modern Windows drivers are WDF drivers. Microsoft has pushed KMDF and UMDF as the recommended development model for over a decade, and the vast majority of new drivers, including third-party drivers for custom hardware, IoT peripherals, and enterprise devices, use the framework. Auditing kernel drivers without understanding WDF-specific vulnerability patterns means missing the bug classes that affect the largest share of the installed driver base.

## How WDF changes the attack surface model

``` mermaid
graph TD
    A["DeviceIoControl()"] --> B["I/O Manager\nBuild IRP"]
    B --> C["WDF Framework\n(Wdf01000.sys)"]
    C --> D{"Buffer\nRetrieval"}
    D --> E["WdfRequestRetrieveInputBuffer\n(MinimumRequiredLength)"]
    E -->|"MinLen > 0"| F["Framework checks size\n✓ Safe if correct"]
    E -->|"MinLen == 0"| G["No size check\n⚠ Driver must validate"]
    F --> H["EvtIoDeviceControl\nCallback"]
    G --> H
    H --> I["WdfRequestComplete\n(exactly once!)"]
    style G fill:#2d1b1b,stroke:#ef4444,color:#e2e8f0
    style F fill:#0d1320,stroke:#10b981,color:#e2e8f0
    style H fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
```

KMDF abstracts the WDM IRP model behind a framework that handles many common driver operations automatically. Instead of registering `IRP_MJ_*` handlers directly, the driver creates I/O queues via `WdfIoQueueCreate` and registers `EvtIo*` callbacks. The framework intercepts incoming IRPs, performs buffering for buffered I/O, and dispatches requests to the appropriate callback. This interposition layer is where WDF's safety properties come from, and where they break down.

### Buffer retrieval: the MinimumRequiredLength trap

When a WDF driver needs to access the input buffer for an IOCTL request, it calls `WdfRequestRetrieveInputBuffer(request, MinimumRequiredLength, &buffer, &length)`. If `MinimumRequiredLength` is non-zero, the framework returns `STATUS_BUFFER_TOO_SMALL` when the actual buffer is smaller. This is a clean, one-line size check that eliminates an entire class of vulnerabilities.

The problem is that many drivers pass 0 for this parameter. When `MinimumRequiredLength` is 0, the framework returns whatever buffer the caller provided, regardless of size. The driver then casts the buffer pointer to a structure pointer without any size check, producing the same out-of-bounds access vulnerability that affects raw WDM drivers. The framework offered protection; the driver declined it.

This pattern is extremely common in third-party drivers. Developers copy sample code, adjust the IOCTL handling logic, and never revisit the `MinimumRequiredLength` parameter. The result is a WDF driver with the same buffer validation gaps as a WDM driver, but wrapped in a framework that creates a false sense of security. Auditing for this pattern is straightforward: check every `WdfRequestRetrieveInputBuffer` and `WdfRequestRetrieveOutputBuffer` call and verify the minimum length parameter matches the structure being cast.

### The object lifetime model: parents and children

WDF uses a parent-child hierarchy for automatic lifetime management. When a parent object is deleted, all child objects are automatically deleted with it. This simplifies resource management significantly, but it introduces failure modes that do not exist in manual memory management.

The most common issue is parent misconfiguration. Consider a `WDFMEMORY` object allocated to track per-request data. If the driver creates it as a child of `WDFDEVICE`, the memory persists for the device's entire lifetime, leaking resources with every completed request. If the driver creates it as a child of `WDFREQUEST`, the memory is automatically freed when the request completes. Choosing the wrong parent means the allocation outlives or underlives its intended scope.

The more dangerous variant is a child object that outlives the data it references. A `WDFTIMER` created as a child of `WDFDEVICE` persists across request boundaries. If the timer callback accesses per-request state that was freed when the request completed, the timer fires into freed memory. The timer was correctly parented (it should live as long as the device), but its callback assumed state that existed only during request processing.

Manual reference counting through `WdfObjectReference` and `WdfObjectDereference` adds another dimension. An extra dereference causes the object's reference count to reach zero while other code still holds pointers, producing a use-after-free. A missing dereference causes a leak. These are the same reference counting bugs that affect raw kernel objects, but they occur within the WDF object model rather than on `KEVENT` or `ERESOURCE` structures.

### Request completion: exactly once, on every path

Each `WDFREQUEST` must be completed exactly once via `WdfRequestComplete`, `WdfRequestCompleteWithInformation`, or `WdfRequestCompleteWithPriorityBoost`. This invariant sounds simple but is surprisingly difficult to maintain in practice.

Completing a request twice causes a double-free of the underlying IRP, corrupting pool metadata in ways that typically lead to code execution. Failing to complete a request causes the calling process to hang indefinitely and leaks kernel resources. Both outcomes are severe, and they arise from the same root cause: complex control flow with multiple exit points.

The interaction between normal completion and cancellation is the primary source of double-completion bugs. When a request is marked cancelable via `WdfRequestMarkCancelable` and the user-mode caller cancels it, the framework invokes the `EvtRequestCancel` callback. If the normal completion path and the cancellation callback both attempt to complete the request, the result is a double-free. The correct pattern is to call `WdfRequestUnmarkCancelable` before completing, and to check its return value: if it returns `STATUS_CANCELLED`, the cancellation callback will handle completion, and the normal path must not. Drivers that skip this check introduce a race between the two completion paths.

### Queue dispatch types and thread safety

The I/O queue dispatch type has direct implications for concurrency safety. A **sequential** queue delivers one request at a time, providing implicit serialization. All callback invocations for a sequential queue are mutually exclusive, so the driver does not need to protect shared state accessed from those callbacks. A **parallel** queue delivers requests concurrently, and the driver must protect shared state with its own synchronization primitives.

Choosing the wrong dispatch type is a subtle vulnerability. A driver that uses a parallel queue but accesses device context data without locking has a data race. The race may not manifest during normal testing with a single application, but an attacker sending IOCTLs from multiple threads simultaneously can trigger it reliably. The resulting corruption depends on what data races: if it is a pointer, the result is a use-after-free; if it is a size field, the result is a buffer overflow.

## Drivers built on WDF

Most modern Windows drivers use KMDF, spanning a wide range of device types. HID miniport drivers, sensor drivers, USB function drivers, battery drivers (`cmbatt.sys`), simple PCI device drivers, and serial port drivers are commonly WDF-based. System framework drivers including `SerCx2.sys` (serial), `SpbCx.sys` (simple peripheral bus), `UCX01000.sys` (USB host controller extension), and GPIO client drivers are KMDF implementations.

UMDF (User-Mode Driver Framework) runs drivers in a host process with restricted kernel access, reducing kernel attack surface but still relevant for driver-specific logic bugs and information disclosure. UMDF is used for printers, point-of-sale devices, portable device protocol (MTP) drivers, and sensors.

Third-party KMDF drivers for custom hardware devices (industrial control systems, scientific instruments, IoT peripherals) are common sources of buffer validation vulnerabilities. These drivers are typically developed by hardware engineers who are experts in their device's protocol but may not account for the security implications of the `MinimumRequiredLength` parameter or the WDF object lifetime model.

## Detection approaches

**Callback tracing** identifies `WdfIoQueueCreate` calls to find all registered `EvtIo*` callbacks. For each callback, the audit traces `WdfRequestRetrieveInputBuffer` and `WdfRequestRetrieveOutputBuffer` calls to verify that `MinimumRequiredLength` is set to at least `sizeof(expected_struct)` or that the returned length is explicitly checked before casting. This is the single highest-value check in WDF driver auditing because it catches the most common vulnerability pattern.

**Completion analysis** tracks all paths that call `WdfRequestComplete` or related functions. The goal is to verify that each request is completed exactly once on every code path, including error paths and cancellation callbacks. Searching for `WdfRequestUnmarkCancelable` usage and verifying its return value is checked reveals potential double-completion races.

**Object lifetime auditing** maps parent-child relationships for all WDF objects created by the driver. The analysis verifies that child object lifetimes do not exceed the validity of the data they reference, and that per-request allocations use the request as their parent rather than the device.

**WDF Driver Verifier** provides runtime detection of framework contract violations. Enabling KMDF Verifier via the registry (`HKLM\System\CurrentControlSet\Services\{driver}\Parameters\Wdf\VerifierOn`) catches double completions, unreturned requests, incorrect object deletion, and other violations that static analysis might miss due to complex control flow.

**Patch diffing** on KMDF drivers frequently reveals `MinimumRequiredLength` changes from 0 to `sizeof(STRUCT)`, explicit length checks added after buffer retrieval, or cancellation synchronization added around request completion. These are small, targeted changes that [AutoPiff](../tooling/autopiff-integration.md) identifies reliably.

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

The WDF attack surface ultimately maps back to the same vulnerability classes that affect raw WDM drivers: [buffer overflows](../vuln-classes/buffer-overflow.md) from missing size checks, [use-after-free](../vuln-classes/use-after-free.md) from lifetime misconfiguration, and [race conditions](../vuln-classes/toctou-double-fetch.md) from incorrect queue dispatch types. The framework changes the API surface and the specific patterns to look for, but not the underlying bug classes. When a WDF vulnerability is found, the exploitation path follows the same sequence as any other kernel bug: determine the [primitive](../primitives/index.md) (read, write, or free), control the allocation through [pool spray](../primitives/exploitation/pool-spray-feng-shui.md), and escalate to [token manipulation](../primitives/arw/token-manipulation.md) or code execution.
