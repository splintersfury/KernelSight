# kCFG / kCET

Kernel Control Flow Guard (kCFG) and kernel Control-flow Enforcement Technology (kCET) protect indirect calls and returns.

## Description

- **kCFG**: Validates indirect call targets against a bitmap of valid targets
- **kCET**: Hardware shadow stack protects return addresses from corruption

## Bypass Techniques

- Calling valid but unintended functions (CFG-valid gadgets)
- Data-only attacks avoiding control flow hijack
- JIT spraying in kernel (mostly theoretical)
