# WDF / KMDF Drivers

The Windows Driver Framework provides managed driver development, but misuse of WDF APIs still leads to vulnerabilities — especially around request buffer retrieval and completion.

## Attack Surface Overview

- **Entry points**: WDF I/O queue callbacks (`EvtIoDeviceControl`, `EvtIoRead`, etc.)
- **Buffer retrieval**: `WdfRequestRetrieveInputBuffer` / `WdfRequestRetrieveOutputBuffer`
- **Key risk**: Passing 0 as MinimumRequiredLength, double completion

## Common Vulnerability Patterns

- `WdfRequestRetrieveInputBuffer` called with `MinimumRequiredLength = 0`
- Double completion of WDF requests
- Missing output buffer size validation

## AutoPiff Detection

- `wdf_request_buffer_size_check_added` — MinimumRequiredLength changed from 0 to sizeof(struct)
- `wdf_request_completion_guard_added` — Double completion guard added
