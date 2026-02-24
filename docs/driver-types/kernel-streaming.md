# Kernel Streaming Drivers

Kernel Streaming (KS) drivers handle multimedia data flow — audio, video, and camera streams. The KS framework provides a standardized IOCTL interface that has been a recurring source of vulnerabilities.

## Architecture

- **Driver model**: WDM with KS framework helpers
- **Key subsystem**: Kernel Streaming (ks.sys), Kernel Streaming Server (mskssrv.sys), WOW64 Thunk (ksthunk.sys)
- **IOCTL interface**: KS properties, methods, and events via `IOCTL_KS_PROPERTY`, `IOCTL_KS_METHOD`, `IOCTL_KS_ENABLE_EVENT`
- **WOW64 layer**: ksthunk.sys translates 32-bit KS structures to 64-bit for WOW64 processes

## Attack Surface

- **IOCTL dispatch**: Large switch table with many property/method handlers
- **WOW64 thunking**: Structure size translation between 32-bit and 64-bit layouts — integer overflow risk
- **MDL handling**: Stream data transferred via MDLs with lock/map operations
- **Object lifecycle**: Rendezvous server (mskssrv.sys) manages shared context objects with reference counting
- **Type confusion**: Context objects (FsContextReg vs FsStreamReg) share dispatch paths

## Common Vulnerability Patterns

| Pattern | Description | AutoPiff Rules |
|---------|-------------|----------------|
| Untrusted pointer in IOCTL | METHOD_NEITHER without ProbeForRead/Write | `method_neither_probe_added`, `ioctl_input_size_validation_added` |
| Integer overflow in thunking | KSSTREAM_HEADER size calculation overflows | `ioctl_input_size_validation_added` |
| Type confusion on context | FsContextReg/FsStreamReg objects confused | `object_type_validation_added` |
| MDL probe with KernelMode | MmProbeAndLockPages called with KernelMode on user MDL | `mdl_probe_access_mode_fix` |
| MDL map without probe | MmMapLockedPages without prior MmProbeAndLockPages | `mdl_safe_mapping_replacement`, `mdl_null_check_added` |
| UAF from refcount error | Reference count logic error on context close | `null_after_free_added`, `guard_before_free_added` |

## CVEs

| CVE | Driver | Description | Class | ITW |
|-----|--------|-------------|-------|-----|
| [CVE-2024-35250](../case-studies/CVE-2024-35250.md) | `ks.sys` | Untrusted pointer dereference in IOCTL dispatch | IOCTL Hardening | Yes |
| [CVE-2024-38054](../case-studies/CVE-2024-38054.md) | `ksthunk.sys` | Integer overflow in KSSTREAM_HEADER thunking | Integer Overflow | No |
| [CVE-2024-38238](../case-studies/CVE-2024-38238.md) | `ksthunk.sys` | MmMapLockedPages without MmProbeAndLockPages | MDL Handling | No |
| [CVE-2023-36802](../case-studies/CVE-2023-36802.md) | `mskssrv.sys` | FsContextReg/FsStreamReg type confusion | Type Confusion | Yes |
| [CVE-2023-29360](../case-studies/CVE-2023-29360.md) | `mskssrv.sys` | MmProbeAndLockPages with KernelMode on user MDL | MDL Handling | No |
| [CVE-2024-30089](../case-studies/CVE-2024-30089.md) | `mskssrv.sys` | Ref-count logic error causes UAF | Use-After-Free | No |

## Key Drivers

### ks.sys (Kernel Streaming)
- **Role**: Core KS framework — IOCTL dispatch for all KS devices
- **Attack vector**: Open any KS device handle and send KS IOCTLs
- **Note**: CVE-2024-35250 — the Pwn2Own 2024 winner used an untrusted pointer in ks.sys IOCTL dispatch

### mskssrv.sys (Kernel Streaming Server)
- **Role**: Cross-process multimedia streaming rendezvous server
- **Attack vector**: Create KS server/client connections
- **Note**: 3 CVEs — type confusion, MDL abuse, and refcount UAF, all in rendezvous context object management

### ksthunk.sys (Kernel Streaming WOW64 Thunk)
- **Role**: Translates 32-bit KS structures to 64-bit for WOW64 processes
- **Attack vector**: Run a 32-bit process and send KS IOCTLs
- **Note**: WOW64 thunking is inherently risky — size calculations for struct translation are prone to integer overflow

## Research Notes

Kernel Streaming has produced a steady stream of bugs due to its large IOCTL surface (ks.sys), complex object management (mskssrv.sys), integer-sensitive thunking (ksthunk.sys), and direct MDL manipulation. DevCore's Pwn2Own 2024 entry used ks.sys, and multiple researchers have found independent bugs in the KS stack.
