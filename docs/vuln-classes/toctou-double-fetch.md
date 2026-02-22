# TOCTOU / Double-Fetch

Time-of-check-to-time-of-use races from re-reading user buffers or shared state after validation.

## Description

TOCTOU occurs when a driver validates a value from user-accessible memory, then re-reads it for use. Between the check and the use, another thread can modify the value, bypassing the validation.

## Patterns

- Reading user buffer twice: once to validate, once to use
- Validating a mapped shared page then re-reading
- Missing capture-to-local-variable pattern

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-30088](../case-studies/CVE-2024-30088.md) | `ntoskrnl.exe` | TOCTOU in AuthzBasepCopyoutInternalSecurityAttributes |

## AutoPiff Detection

- `double_fetch_to_capture_fix` — Double-fetch fixed by capturing to local variable
- `flt_create_race_mitigation` — TOCTOU in IRP_MJ_CREATE fixed by buffer capture
