# Vulnerability Classes

Classification of kernel vulnerability types commonly found in Windows drivers.

## Categories

| Class | Description | Key CVEs |
|-------|-------------|----------|
| [Buffer Overflow](buffer-overflow.md) | Stack and heap buffer overflows | CVE-2024-30085, CVE-2023-28252 |
| [Integer Overflow](integer-overflow.md) | Integer overflow/underflow | CVE-2024-38063, CVE-2024-38054 |
| [Type Confusion](type-confusion.md) | Object type misinterpretation | CVE-2023-36802, CVE-2022-21882 |
| [TOCTOU / Double-Fetch](toctou-double-fetch.md) | Time-of-check-to-time-of-use | CVE-2024-30088 |
| [Use-After-Free](use-after-free.md) | Dangling pointer dereference | CVE-2024-38193, CVE-2023-29336 |
| [Race Conditions](race-conditions.md) | Concurrency and synchronization | CVE-2024-38106 |
| [Uninitialized Memory](uninitialized-memory.md) | Kernel memory disclosure | CVE-2023-32019, CVE-2024-38256 |
| [Arbitrary R/W Primitives](arbitrary-rw-primitives.md) | Patterns yielding arb R/W | CVE-2024-21338, CVE-2023-21768 |
| [NULL Deref](null-deref.md) | NULL pointer dereference | — |
| [Logic Bugs](logic-bugs.md) | Design-level logic errors | CVE-2024-26229, CVE-2024-21302 |
