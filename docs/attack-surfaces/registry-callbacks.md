# Registry Callbacks

Drivers that register registry filtering callbacks via `CmRegisterCallbackEx` can intercept and modify registry operations. These callbacks introduce attack surface through TOCTOU and race conditions.

## Attack Surface Overview

- **Entry point**: `CmRegisterCallbackEx` callback routines
- **Operations**: `RegNtPreCreateKeyEx`, `RegNtPreSetValueKey`, etc.
- **Key risk**: Race between callback validation and actual registry operation

## Common Vulnerability Patterns

- TOCTOU between pre-operation callback validation and post-operation
- Incorrect access mask enforcement in callback
- Missing synchronization between concurrent registry operations

## AutoPiff Detection

- `registry_access_mask_hardened` — Registry key access mask reduced to least-privilege
- `double_fetch_to_capture_fix` — TOCTOU fixed by capturing value locally
