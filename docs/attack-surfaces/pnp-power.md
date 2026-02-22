# PnP & Power Management

Plug and Play and power state transitions create race conditions between device removal and in-flight I/O. Drivers must coordinate PnP removal with ongoing operations.

## Attack Surface Overview

- **Entry points**: `IRP_MN_REMOVE_DEVICE`, `IRP_MN_SURPRISE_REMOVAL`, power IRPs
- **Key risk**: Use-after-free when device is removed while I/O is in progress
- **Synchronization**: `IoAcquireRemoveLock` / `IoReleaseRemoveLock` pattern

## Common Vulnerability Patterns

- Missing remove lock acquisition before I/O dispatch
- I/O dispatch without checking device-removed flag
- Power state not validated before device access (D0 check missing)
- Surprise removal handler not cleaning up shared state

## AutoPiff Detection

- `surprise_removal_guard_added` — Device-removed flag check added
- `power_state_validation_added` — Power state (D0) check added
- `io_remove_lock_added` — Remove lock added for PnP safety
