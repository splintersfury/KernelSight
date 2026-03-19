# IOCTL Handlers

Every Windows kernel exploit needs a way in. For local privilege escalation, the way in is almost always an IOCTL. The `DeviceIoControl` API is callable from any process, including sandboxed ones and low-integrity contexts. It sends a request directly from user mode into a kernel driver's dispatch routine, carrying attacker-controlled input buffers of attacker-specified sizes. No other kernel entry point combines this level of accessibility with this much attacker control over the data that reaches kernel code.

A single driver might handle dozens of distinct IOCTL codes, each taking a different input structure and exercising a different code path. Every one of those code paths must independently validate buffer sizes, probe user-mode pointers, check access permissions, and handle concurrent requests safely. One missing check on one code path in one driver is enough for a local privilege escalation. This is why IOCTL handlers account for more kernel CVEs than any other attack surface category.

## How IOCTL dispatch actually works

To find bugs in IOCTL handlers, you need to understand the full path a request takes from user mode to driver code.

``` mermaid
graph TD
    A["User Process\nDeviceIoControl()"] --> B["I/O Manager\nBuild IRP"]
    B --> C{"Transfer\nMethod?"}
    C -->|METHOD_BUFFERED| D["Allocate kernel buffer\nCopy input in\nIrp→AssociatedIrp.SystemBuffer"]
    C -->|METHOD_DIRECT| E["Copy input\nMDL-map output\nIrp→MdlAddress"]
    C -->|METHOD_NEITHER| F["Pass raw user ptrs\nType3InputBuffer\n⚠ No probing"]
    D --> G["Driver Dispatch\nswitch(IoControlCode)"]
    E --> G
    F --> G
    G --> H["Per-IOCTL Handler\n(must validate sizes,\nprobe pointers)"]
    style F fill:#2d1b1b,stroke:#ef4444,color:#e2e8f0
    style H fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
```

Here is what happens when a process calls `DeviceIoControl`:

1. The process calls `DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, ...)`.
2. The I/O Manager constructs an IRP with major function code `IRP_MJ_DEVICE_CONTROL`.
3. The IOCTL code itself is a 32-bit value encoding four fields via the `CTL_CODE` macro:

```c
// CTL_CODE layout (32-bit IOCTL code)
// Bits 31-16: Device type (e.g., FILE_DEVICE_UNKNOWN = 0x22)
// Bits 15-14: Required access (FILE_ANY_ACCESS, FILE_READ_ACCESS, FILE_WRITE_ACCESS)
// Bits 13-2:  Function number (driver-defined)
// Bits 1-0:   Transfer method (METHOD_BUFFERED, METHOD_IN_DIRECT, METHOD_OUT_DIRECT, METHOD_NEITHER)
```

4. Based on the transfer method encoded in bits 0-1, the I/O Manager sets up the buffers differently (more on this below).
5. The IRP is dispatched to the driver's registered `IRP_MJ_DEVICE_CONTROL` handler from the `DriverObject->MajorFunction` table.
6. The driver typically implements a switch statement over the IOCTL code to route each request:

```c
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctl = irpSp->Parameters.DeviceIoControl.IoControlCode;
    ULONG inLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    switch (ioctl) {
        case IOCTL_DO_THING:
            // Handler for this specific control code
            // Must validate inLen, outLen before touching buffers
            break;
        case IOCTL_DO_OTHER_THING:
            // ...
            break;
        // Missing default case = potential fall-through bug
    }
    // ...
}
```

This dispatch routine is where the driver's attack surface lives. Every `case` label is a separate entry point that must stand on its own in terms of validation and safety.

### The three buffering methods

The transfer method determines how the I/O Manager handles the user-mode buffers, and this distinction is critical for understanding where vulnerabilities arise.

**METHOD_BUFFERED** is the safest option. The I/O Manager allocates a kernel buffer large enough for the larger of the input and output buffers, copies the user input into it before dispatch, and copies the result back to user space after the driver completes the IRP. The driver accesses both input and output through `Irp->AssociatedIrp.SystemBuffer`. The kernel buffer provides inherent isolation from user-mode manipulation, but the driver must still validate that `InputBufferLength` is large enough for the expected structure before casting and dereferencing.

**METHOD_IN_DIRECT / METHOD_OUT_DIRECT** use a hybrid approach. The input buffer is copied into a system buffer (like METHOD_BUFFERED), but the output buffer is described by an MDL (Memory Descriptor List) that the I/O Manager probes and locks. The driver accesses the output through `Irp->MdlAddress`. This gives the driver direct access to the user's physical pages without the overhead of a copy, but the pages are locked and cannot be remapped during the operation.

**METHOD_NEITHER** provides no buffering at all. The driver receives raw user-mode pointers: `IrpSp->Parameters.DeviceIoControl.Type3InputBuffer` for input and `Irp->UserBuffer` for output. The I/O Manager does nothing to validate, probe, or protect these pointers. The driver is entirely responsible for calling `ProbeForRead` / `ProbeForWrite` inside a `__try/__except` block before accessing the data. This is where the most dangerous IOCTL vulnerabilities live.

## Where things go wrong

IOCTL vulnerabilities cluster into three broad categories: input validation failures, access control gaps, and concurrency issues. Each category produces different bug patterns and requires different detection approaches.

### Input validation failures

The most common IOCTL vulnerability is also the simplest: the driver casts `SystemBuffer` to a structure pointer without first checking that `InputBufferLength` is at least `sizeof(EXPECTED_STRUCT)`. When the user provides a buffer smaller than expected, the cast succeeds (it is just a pointer reinterpretation), but any subsequent field access reads past the end of the allocated kernel buffer into uninitialized pool memory. Depending on the access pattern, this produces out-of-bounds reads (information disclosure), out-of-bounds writes (memory corruption), or both.

Type confusion is a subtler variant. Some drivers multiplex a single IOCTL code for multiple operations, using a field within the input buffer to select the operation type. The buffer is then cast to different structure types depending on this selector. If the size validation checks against the smallest variant but the selected operation expects the largest, the driver reads beyond the buffer boundary. CVE-2024-35250 in `ks.sys` shows how this plays out in a real driver: an untrusted pointer dereference in the IOCTL dispatch led to a Pwn2Own win.

Integer overflow in size arithmetic is another classic. The driver reads a count field from the user buffer, multiplies it by an element size, and adds a header size to compute an allocation length. If the multiplication or addition wraps around 32-bit integer bounds, the result is a small allocation followed by a large copy, producing a heap overflow. CVE-2024-38054 in `ksthunk.sys` (kernel streaming thunk layer) demonstrated exactly this pattern with `KSSTREAM_HEADER` thunking.

Output buffer information leaks round out this category. When a driver writes a structure to the output buffer without first zeroing it, the padding bytes and alignment gaps contain whatever was previously in that kernel pool memory. This can include kernel pointers (defeating KASLR), fragments of other processes' data, or cryptographic material. These leaks are often treated as low-severity individually, but they are critical enablers for exploitation chains that need a kernel base address.

### The METHOD_NEITHER problem

`METHOD_NEITHER` deserves its own discussion because it is responsible for a disproportionate share of critical IOCTL vulnerabilities. When a driver uses this transfer method, the I/O Manager hands it raw user-mode pointers with no validation whatsoever. The driver must call `ProbeForRead` or `ProbeForWrite` to verify that the pointer actually points to user-mode memory (not kernel memory), and it must do so inside a `__try/__except` block because the user can free or remap the memory at any time.

Drivers that skip the probe allow a devastating attack: the user passes a kernel-mode address as the "buffer," and the driver reads from or writes to arbitrary kernel memory. This is an instant read-what-where or write-what-where primitive with no additional exploitation needed.

Even drivers that probe correctly face a second hazard: double-fetch. The driver reads a length field from the user buffer, validates it, and then reads the same field again to use it. Between the two reads, a concurrent thread modifies the value. The kernel validated length 100 but copies length 10,000. The same technique surfaces in CVE-2024-30088, where `AuthzBasepCopyoutInternalSecurityAttributes` in ntoskrnl validated a user-mode buffer address and then re-read it after a concurrent thread remapped the address range.

The correct pattern for METHOD_NEITHER handling is to probe the user buffer, capture its contents into a kernel-allocated copy in a single read, and then work exclusively with the kernel copy. Any code path that touches the user buffer more than once is a potential TOCTOU vulnerability.

### Access control gaps

The vulnerability might not be in the handler logic at all, but in who can reach it. When a driver calls `IoCreateDevice`, it can specify a security descriptor limiting which users can open handles to the device object. However, if the driver does not set `FILE_DEVICE_SECURE_OPEN`, the I/O Manager only checks the security descriptor on the device namespace root, not on individual opens to named paths under the device. An unprivileged process can potentially open `\\Device\\MyDriver\anything` and reach the IOCTL handler.

CVE-2024-21338 in `appid.sys` (the AppLocker driver) is the canonical example. The driver exposed IOCTL `0x22A018` without adequate access control, giving any process the ability to trigger kernel read/write operations. The Lazarus Group exploited this in the wild for months before the patch.

A related pattern occurs when a single IOCTL dispatch routine serves multiple device objects with different trust levels. If the handler does not check which device object the IRP targets, a request to the low-privilege device can exercise code paths intended only for the high-privilege one. CVE-2024-26229 in `csc.sys` (Client-Side Caching) demonstrated a missing access check enabling elevation of privilege through this exact pattern.

### Concurrency issues

IOCTL handlers that maintain state across calls, or that share state with other dispatch routines, must handle concurrent requests safely. Two threads sending IOCTLs to the same device simultaneously can race on shared data structures. If the handler reads and modifies a global or device-extension field without locking, the result is a classic TOCTOU or data race. This is less common than input validation bugs but produces high-severity vulnerabilities when it occurs, because race conditions in kernel code often lead to use-after-free or double-free conditions.

## Third-party drivers: the intentional exposure problem

The vulnerability patterns above describe *bugs*: unintentional failures in validation or access control. Third-party vendor utility drivers present a fundamentally different problem. These drivers intentionally expose privileged operations through IOCTLs as part of their design. Physical memory read/write, MSR access, I/O port operations: capabilities that should never be accessible from user mode are wrapped in IOCTLs with minimal or no access control.

These drivers are not buggy; they are architecturally insecure. They exist because hardware vendors needed a way for their user-mode utilities to talk to hardware, and writing a WDM driver with unrestricted IOCTLs was the path of least resistance. Attackers (including nation-state groups) use them as "bring your own vulnerable driver" (BYOVD) tools, loading a signed driver with known dangerous IOCTLs to gain kernel read/write primitives without needing an actual exploit.

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

## Detection approaches

**Static analysis** is the most systematic approach for auditing IOCTL handlers. Start by identifying the `IRP_MJ_DEVICE_CONTROL` handler registration in `DriverEntry`, then trace the dispatch switch. For each IOCTL code, verify that `InputBufferLength` and `OutputBufferLength` are checked before any buffer dereference. Flag any `METHOD_NEITHER` code paths that lack `ProbeForRead`/`ProbeForWrite` calls wrapped in SEH. Automated tools can enumerate the IOCTL codes handled by scanning the switch statement's comparison values, producing a map of the driver's attack surface.

**Fuzzing** is highly effective for IOCTL handlers because they are typically self-contained functions with well-defined input boundaries. Tools like `kAFL`, `IOCTL Fuzzer`, or custom `DeviceIoControl` harnesses enumerate valid IOCTL codes (by scanning the dispatch switch in the binary) and fuzz input buffers with varying sizes, types, and content. Coverage-guided fuzzing finds the subtle bugs that static analysis misses, particularly in deeply nested parsing logic.

**Dynamic analysis** with WinDbg provides ground truth. Monitor device object creation with `!devobj`, inspect security descriptors with `!sd`, and set breakpoints on the IOCTL handler to observe buffer access patterns. Watching what the driver actually does with the buffer (particularly whether it probes METHOD_NEITHER pointers) reveals vulnerabilities that source-level analysis might miss due to macro expansion or inline function complexity.

**Device enumeration** from a low-privilege process maps the accessible attack surface. Using `NtQueryDirectoryObject` or WinObj to enumerate all device objects in the `\\Device` namespace, then attempting to open each device, identifies which drivers are reachable without elevation. This is the first step in any local privilege escalation audit.

**Patch diffing** through AutoPiff closes the loop. Comparing consecutive driver versions reveals newly added size checks, probe calls, or ACL changes, pinpointing exactly which IOCTL code path was vulnerable and what the fix looks like. This is often faster than auditing from scratch, and it confirms that a vulnerability existed in the previous version.

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

- `ioctl_input_size_validation_added` flags input or output buffer size validation added for a specific IOCTL code
- `method_neither_probe_added` flags `ProbeForRead` or `ProbeForWrite` calls added for `METHOD_NEITHER` buffer access
- `ioctl_code_default_case_added` flags a default case added to the IOCTL dispatch switch statement
- `device_acl_hardening` flags device object security descriptor or ACL hardening
- `new_ioctl_handler` flags new IOCTL handler functions (an attack surface expansion rule, useful for tracking growing attack surface between versions)
- `ioctl_output_buffer_zeroed` flags output buffer zeroing before use to prevent kernel information disclosure

The IOCTL attack surface is the starting point for most kernel exploitation research. But finding a vulnerable IOCTL is only half the work. The next question is what primitive the bug gives you, and how to turn that primitive into a reliable exploit. That journey typically leads to [pool spray](../primitives/exploitation/pool-spray-feng-shui.md) for memory corruption bugs, or [token manipulation](../primitives/arw/token-manipulation.md) for arbitrary read/write primitives.
