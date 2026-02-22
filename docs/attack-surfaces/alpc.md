# ALPC

Advanced Local Procedure Call (ALPC) is the kernel IPC mechanism underlying RPC, COM, and other Windows communication channels. ALPC port and message handling in kernel drivers introduces attack surface.

## Attack Surface Overview

- **Entry points**: `NtAlpcSendWaitReceivePort`, `NtAlpcCreatePort`, message callbacks
- **Key risk**: Complex message deserialization, view/section management
- **Kernel objects**: ALPC port objects, message attributes, views

## Common Vulnerability Patterns

- Type confusion in ALPC message attribute handling
- Use-after-free in port object lifetime management
- View mapping without proper bounds validation

## AutoPiff Detection

*No specific ALPC rules currently — general bounds_check and lifetime_fix rules may apply.*
