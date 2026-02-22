# Arbitrary Code Guard (ACG)

Prevents dynamic code generation and modification in protected processes.

## Description

ACG (`ProcessDynamicCodePolicy`) prevents a process from allocating executable memory or modifying existing executable pages. While primarily a user-mode mitigation, it impacts kernel exploitation by preventing shellcode injection into protected processes.

## Relevance to Kernel Exploitation

- Prevents user-mode shellcode staging for kernel callbacks
- Forces data-only attack strategies
- Combined with HVCI, eliminates most code injection paths
