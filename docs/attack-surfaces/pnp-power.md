# PnP & Power

Plug and Play and Power Management IRP handling creates attack surface through device state transitions, where race conditions between removal, power changes, and in-flight I/O lead to use-after-free and null pointer dereference vulnerabilities.

## Attack Surface Overview

- **PnP entry points**: `IRP_MN_REMOVE_DEVICE`, `IRP_MN_SURPRISE_REMOVAL`, `IRP_MN_QUERY_REMOVE_DEVICE`, `IRP_MN_STOP_DEVICE`, `IRP_MN_QUERY_DEVICE_RELATIONS` dispatched through the driver's `IRP_MJ_PNP` handler
- **Power entry points**: `IRP_MN_SET_POWER`, `IRP_MN_QUERY_POWER`, `IRP_MN_WAIT_WAKE` dispatched through `IRP_MJ_POWER` handler
- **Synchronization primitives**: `IoAcquireRemoveLock` / `IoReleaseRemoveLock` pattern for coordinating removal with in-flight I/O; `PoRequestPowerIrp` for asynchronous power state transitions
- **User-mode reach**: Device enable/disable via Device Manager, `SetupDi*` APIs, `devcon.exe` commands, USB device insertion/removal, `powercfg` commands, system sleep/resume/hibernate/shutdown
- **Device interface notifications**: `IoRegisterDeviceInterface` publishes device interfaces that user-mode discovers via `CM_Register_Notification` or `SetupDiGetClassDevs`, creating a registration/deregistration race window
- **Key risk**: Use-after-free conditions when device extension memory is freed during `IRP_MN_REMOVE_DEVICE` while another thread is still processing I/O through the same device object

## Mechanism Deep-Dive

The PnP Manager orchestrates the lifecycle of every hardware device in the system. When a device is physically removed or software-disabled, the PnP Manager sends an `IRP_MN_SURPRISE_REMOVAL` IRP followed by `IRP_MN_REMOVE_DEVICE` once all open handles are closed. The driver must stop processing I/O, release hardware resources, and free its device extension during removal. The problem is that I/O dispatch routines and removal handlers execute concurrently -- a thread may be in the middle of processing an IOCTL using data from the device extension while another thread processes the removal IRP and frees that same device extension memory.

The Windows Driver Model addresses this with the Remove Lock pattern: the driver acquires the remove lock at the start of every I/O dispatch, and releases it upon completion. The removal handler calls `IoReleaseRemoveLockAndWait`, which blocks until all outstanding I/O completes. However, many drivers implement this pattern incorrectly or omit it entirely. A missing remove lock acquisition on even one dispatch path means that removal can proceed while that I/O is in flight, freeing structures the I/O path is actively using. Controlling the timing of device removal (e.g., via `devcon disable` or USB eject) while simultaneously sending IOCTLs can trigger a use-after-free with controlled allocation patterns.

Power management introduces similar races. When the system transitions to sleep (S3/S4), the Power Manager sends `IRP_MN_SET_POWER` with a target device state of D3 (powered off). The driver must save hardware state and stop accessing the device. If an I/O dispatch routine accesses hardware registers without first checking the current power state, it may access unmapped MMIO regions or stale device state. The reverse transition (resume from sleep) requires re-initializing hardware before processing I/O, and a race between the power-up IRP completion and queued I/O requests can cause similar issues. Resource rebalance scenarios (`IRP_MN_STOP_DEVICE` followed by `IRP_MN_START_DEVICE` with new resources) introduce further complications, as the driver must handle re-mapping of I/O ports and memory ranges while potentially having in-flight I/O referencing old mappings.

Surprise removal is the hardest PnP transition to get right. Unlike orderly removal (which queries the driver first), surprise removal occurs without warning when hardware is physically disconnected. The driver must immediately invalidate all shared state -- cancel pending timers, flush DPC queues, complete pending IRPs with error status, and set a flag preventing new I/O dispatch. Any pending DPC routine, timer callback, or work item that fires after the device extension is freed becomes a use-after-free primitive.

## Common Vulnerability Patterns

- **Missing remove lock**: The driver does not call `IoAcquireRemoveLock` at the beginning of I/O dispatch, allowing `IRP_MN_REMOVE_DEVICE` to free the device extension while I/O is in progress, resulting in a use-after-free
- **Incomplete surprise removal cleanup**: The `IRP_MN_SURPRISE_REMOVAL` handler does not invalidate shared state (pending timers, DPC routines, work items), leaving dangling references that fire after the device extension is freed
- **Device-removed flag not checked**: I/O dispatch proceeds without checking a `DeviceRemoved` or `DevicePnPState` flag, accessing hardware or device extension fields after removal has begun
- **Power state not validated**: Driver accesses hardware MMIO registers without verifying the device is in the D0 (working) power state, causing bugcheck on unmapped memory access
- **PnP resource rebalance race**: Resource rebalance (`IRP_MN_STOP_DEVICE` followed by `IRP_MN_START_DEVICE`) re-maps hardware resources while I/O is still referencing the old mappings
- **Device interface deregistration race**: `IoSetDeviceInterfaceState(FALSE)` called during removal, but user-mode threads that already opened handles via the interface continue sending I/O
- **Pending DPC or timer not cancelled**: Removal handler does not cancel outstanding `KeSetTimer` or `IoQueueWorkItem` entries, which fire after the device object and extension are freed
- **Power IRP completion race**: The driver completes a power-up IRP and begins processing queued I/O before hardware re-initialization is fully complete
- **Child device enumeration race**: Bus driver's `IRP_MN_QUERY_DEVICE_RELATIONS` handler accesses child PDO list concurrently with child device removal, causing list corruption

## Driver Examples

Any PnP driver is affected, but USB device drivers are most susceptible due to frequent hotplug scenarios. Storage drivers (`disk.sys`, USB mass storage), display drivers (GPU hotplug, display reconfiguration), audio drivers (`portcls.sys` miniports), and Bluetooth drivers (`bthusb.sys`, `bthport.sys`) experience frequent PnP transitions. Bus drivers (`usbhub.sys`, `pci.sys`, `acpi.sys`) manage child device lifetimes and must handle cascading removal correctly. Third-party drivers for removable hardware (USB-serial adapters, software-defined radio dongles, USB Ethernet adapters) frequently have PnP race bugs because testing rarely covers surprise removal under I/O load. Streaming proxy drivers like `mskssrv.sys` have cross-process handle semantics that complicate PnP lifetime management.

## Detection Approach

- **Driver Verifier**: Enable the "I/O Verification" and "Force Pending I/O Requests" options in Driver Verifier to catch missing remove locks and improper IRP completion. The "Enhanced I/O Verification" option validates PnP and power IRP sequencing.
- **Stress testing**: Use `devcon disable/enable` in a loop while simultaneously sending I/O to the device from multiple threads. Physical hotplug testing under I/O load exposes surprise removal races. Sleep/resume cycles (`powercfg /hibernate on && shutdown /h`) under I/O load expose power transition races.
- **Static analysis**: Search for `IRP_MJ_PNP` and `IRP_MJ_POWER` handlers. Verify that all I/O dispatch paths call `IoAcquireRemoveLock` before accessing device extension data. Check that the removal handler cancels all timers, DPCs, and work items.
- **Concurrency analysis**: Identify all asynchronous callbacks (timers, DPCs, work items) registered by the driver and verify each is properly cancelled or flushed during the `IRP_MN_SURPRISE_REMOVAL` and `IRP_MN_REMOVE_DEVICE` handlers.
- **Patch diffing**: PnP/power fixes typically add remove lock calls, device-state checks, timer cancellation, or work item flush calls to existing dispatch routines.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-38106](../case-studies/CVE-2024-38106.md) | `ntoskrnl.exe` | Race condition during process state transition exploitable via PnP-related timing |
| [CVE-2023-36802](../case-studies/CVE-2023-36802.md) | `mskssrv.sys` | Use-after-free in streaming proxy due to object lifetime management failure |
| [CVE-2024-30089](../case-studies/CVE-2024-30089.md) | `Microsoft Streaming Service` | Race condition in device object handling |
| [CVE-2023-29360](../case-studies/CVE-2023-29360.md) | `mskssrv.sys` | Incorrect access mode in MDL probing during cross-process streaming |

## AutoPiff Detection

- `io_remove_lock_added` -- `IoAcquireRemoveLock` / `IoReleaseRemoveLock` calls added to I/O dispatch path for PnP safety
- `surprise_removal_guard_added` -- Device-removed state flag check added before accessing device extension or hardware resources
- `power_state_validation_added` -- Power state (D0) validation added before hardware register access
- `timer_cancellation_on_removal` -- `KeCancelTimer` or `IoStopTimer` call added to PnP removal handler
- `workitem_flush_on_removal` -- Work item flush or synchronous wait added to device removal path to drain pending callbacks
