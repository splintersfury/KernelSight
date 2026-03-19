# PnP & Power

Yank a USB drive from a laptop while a file copy is in progress. Slam the laptop lid shut while a video call is streaming through a USB webcam. Disable a network adapter in Device Manager while traffic is flowing. These are not exotic attack scenarios; they are things users do every day. Each one triggers a Plug and Play or Power Management state transition in the kernel, and each one creates a window where device resources, memory allocations, and hardware mappings can be freed while other kernel code is still using them.

PnP and Power IRP handling is less about parsing untrusted data and more about getting concurrency right. The attack surface is the timing relationship between device removal (which frees resources) and in-flight I/O (which uses those resources). A driver that handles IOCTLs flawlessly can still have a critical use-after-free if its PnP removal handler frees the device extension while an IOCTL handler on another thread is still reading from it. Every PnP driver in Windows is potentially affected, and the bug class is notoriously difficult to detect through code review alone because the vulnerability exists in the interaction between two separate code paths executing on two separate threads.

## The device lifecycle and its dangers

``` mermaid
graph LR
    A["Device\nAttached"] --> B["IRP_MN_START_DEVICE\n(resources assigned)"]
    B --> C["Normal I/O\n(IOCTLs, reads, writes)"]
    C --> D{"Removal\nTrigger"}
    D -->|Orderly| E["IRP_MN_QUERY_REMOVE"]
    D -->|Surprise| F["IRP_MN_SURPRISE_REMOVAL\n⚠ No warning"]
    E --> G["IRP_MN_REMOVE_DEVICE\n(free everything)"]
    F --> G
    C -.->|"RACE WINDOW\nI/O still in flight"| G
    style F fill:#2d1b1b,stroke:#ef4444,color:#e2e8f0
    style G fill:#2d1b1b,stroke:#ef4444,color:#e2e8f0
    style C fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
```

The PnP Manager orchestrates the lifecycle of every hardware device in the system. When a device is physically attached, the PnP Manager discovers it, loads a driver, and sends `IRP_MN_START_DEVICE` with the assigned hardware resources (I/O ports, memory ranges, interrupts). The driver maps these resources, allocates its device extension, and begins processing I/O. This is the steady state.

Removal follows two paths, and the difference between them is the source of most PnP vulnerabilities.

**Orderly removal** starts with `IRP_MN_QUERY_REMOVE_DEVICE`, which asks the driver whether removal is acceptable. If the driver agrees, it receives `IRP_MN_REMOVE_DEVICE` after all open handles are closed. This is the clean path: the driver has time to drain pending I/O, cancel timers, and release resources in an orderly fashion.

**Surprise removal** occurs without warning when hardware is physically disconnected. The driver receives `IRP_MN_SURPRISE_REMOVAL` while I/O may still be in flight, followed by `IRP_MN_REMOVE_DEVICE` once handles close. The driver must immediately invalidate all shared state: cancel pending timers, flush DPC queues, complete pending IRPs with error status, and set a flag preventing new I/O dispatch. Any pending DPC routine, timer callback, or work item that fires after the device extension is freed becomes a use-after-free primitive.

### The Remove Lock pattern (and its failures)

The Windows Driver Model addresses the removal race with the Remove Lock pattern. The driver acquires the remove lock (`IoAcquireRemoveLock`) at the start of every I/O dispatch routine, and releases it (`IoReleaseRemoveLock`) upon completion. The removal handler calls `IoReleaseRemoveLockAndWait`, which blocks until all outstanding I/O completes, ensuring that the device extension is not freed while any dispatch routine is still using it.

The pattern is conceptually simple. In practice, it fails in three ways.

First, the remove lock acquisition is missing entirely on one or more dispatch paths. The driver may acquire the lock in its IOCTL handler but forget it in its read handler, or in a fast-I/O path, or in a DPC callback that accesses the device extension. A missing acquisition on even one path means removal can proceed while that path is in flight.

Second, the remove lock is acquired but not released on an error path. If the driver returns early from a dispatch routine without releasing the lock, the removal handler blocks forever, hanging the system. This is a denial-of-service rather than a memory corruption bug, but it is still a vulnerability.

Third, the remove lock is implemented correctly, but asynchronous callbacks (timers, DPCs, work items) are not covered. A `KeSetTimer` registered during normal I/O can fire after the device extension is freed if the removal handler does not call `KeCancelTimer` and verify that the timer actually stopped. DPC routines queued via `IoQueueDpc` can execute on a different processor while the removal handler is running on the current one.

### Power transitions: the other race

Power management introduces a parallel set of races. When the system transitions to sleep (S3/S4), the Power Manager sends `IRP_MN_SET_POWER` with a target device state of D3 (powered off). The driver must save hardware state and stop accessing the device. If an I/O dispatch routine accesses hardware registers without first checking the current power state, it may read from unmapped MMIO regions after the device has been powered down, causing a bugcheck.

The reverse transition (resume from sleep) requires re-initializing hardware before processing I/O. A race between the power-up IRP completion and queued I/O requests can cause the driver to access hardware before it is ready, producing incorrect results or hardware faults. Resource rebalance scenarios (`IRP_MN_STOP_DEVICE` followed by `IRP_MN_START_DEVICE` with new resources) introduce a third variant: the driver must handle re-mapping of I/O ports and memory ranges while potentially having in-flight I/O referencing old mappings.

## Which drivers are most exposed

Any PnP driver is theoretically affected, but the risk is not uniform. USB device drivers are the most susceptible because USB devices are hot-plugged frequently and surprise removal is the common case. Storage drivers (`disk.sys`, USB mass storage), display drivers (GPU hotplug, display reconfiguration), audio drivers (`portcls.sys` miniports), and Bluetooth drivers (`bthusb.sys`, `bthport.sys`) experience frequent PnP transitions in normal operation.

Bus drivers (`usbhub.sys`, `pci.sys`, `acpi.sys`) manage child device lifetimes and must handle cascading removal correctly. When a USB hub is surprise-removed, every child device on that hub must also be removed, and the bus driver must coordinate this cascade without racing on the child PDO list.

Third-party drivers for removable hardware are the most fertile ground for PnP bugs. USB-serial adapters, software-defined radio dongles, USB Ethernet adapters, and custom USB devices are often developed by small teams that focus testing on the happy path. Surprise removal under I/O load is rarely tested because it requires specialized test harnesses and is difficult to reproduce reliably.

Streaming proxy drivers like `mskssrv.sys` present a special case. They have cross-process handle semantics that complicate PnP lifetime management: a handle opened in one process may reference resources owned by a device that is removed while the handle is still open in a different process. CVE-2023-36802 was a use-after-free in `mskssrv.sys` caused by exactly this cross-process lifetime mismatch.

## Triggering PnP races for exploitation

From an attacker's perspective, PnP races are triggered by controlling device removal timing. An attacker with physical access can yank a USB device at a precise moment. An attacker with local code execution can use `SetupDiCallClassInstaller(DIF_PROPERTYCHANGE)` to software-disable a device, or `devcon disable <device_id>` from a command prompt. Sleep/resume cycles can be triggered programmatically via `SetSuspendState` or `powercfg`. The key is to overlap the removal trigger with active I/O operations on the target device.

The exploitation pattern typically involves two threads: one sending IOCTLs or performing I/O in a tight loop, and another triggering device disable/enable cycles. When the timing aligns, the I/O thread accesses freed memory. The freed device extension can then be reclaimed with a controlled allocation (via pool spray), giving the attacker a use-after-free with controlled content. This is the same exploitation flow described in [pool spray](../primitives/exploitation/pool-spray-feng-shui.md), but the trigger is a PnP state transition rather than a buffer overflow.

## Detection approaches

**Driver Verifier** is the most effective automated tool for catching PnP bugs. The "I/O Verification" and "Force Pending I/O Requests" options catch missing remove locks and improper IRP completion. The "Enhanced I/O Verification" option validates PnP and power IRP sequencing, catching out-of-order state transitions that would not naturally occur but that an attacker can force.

**Stress testing** provides ground truth. Using `devcon disable/enable` in a loop while simultaneously sending I/O to the device from multiple threads is the standard technique. Physical hotplug testing under I/O load exposes surprise removal races. Sleep/resume cycles under I/O load expose power transition races. The bugs found this way tend to be high-severity because the failure mode is almost always a use-after-free.

**Static analysis** searches for `IRP_MJ_PNP` and `IRP_MJ_POWER` handlers, then verifies that all I/O dispatch paths call `IoAcquireRemoveLock` before accessing device extension data. The analysis must also check that the removal handler cancels all timers, DPCs, and work items. A common approach is to enumerate all `KeSetTimer`, `IoQueueDpc`, and `IoQueueWorkItem` call sites and verify that each has a corresponding cancellation in the removal path.

**Concurrency analysis** identifies all asynchronous callbacks registered by the driver and verifies each is properly cancelled or flushed during `IRP_MN_SURPRISE_REMOVAL` and `IRP_MN_REMOVE_DEVICE` processing. This requires whole-driver analysis because the callbacks may be registered in one function and cancelled (or not) in a completely different function.

**Patch diffing** reveals PnP/power fixes as newly added remove lock calls, device-state checks, timer cancellation calls, or work item flush calls in existing dispatch routines. These patches are easy to identify through [AutoPiff](../tooling/autopiff-integration.md) because they add calls to well-known APIs (`IoAcquireRemoveLock`, `KeCancelTimer`, `KeFlushQueuedDpcs`) that were absent in the previous version.

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

PnP and Power bugs occupy a unique position in the vulnerability landscape. They are not about parsing untrusted input or validating buffer sizes; they are about temporal correctness in a concurrent system. The same driver that passes every static analysis check for buffer validation can have a critical use-after-free in its PnP handling. This is why PnP testing requires dedicated stress harnesses rather than input fuzzing, and why the [use-after-free](../vuln-classes/use-after-free.md) vulnerability class discusses PnP races as a primary trigger mechanism distinct from the input-validation failures that dominate other attack surfaces.
