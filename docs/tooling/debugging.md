# Debugging

Kernel debugging tools and techniques for Windows driver analysis.

## Kernel Debuggers

- **WinDbg** — Microsoft's kernel debugger (WinDbg Preview recommended)
- **VirtualKD-Redux** — Accelerated VM kernel debugging

## Debugging Techniques

- **Driver Verifier** — Runtime validation of driver behavior
- **Special Pool** — Detects pool overflows and use-after-free
- **Pool tagging** — Track pool allocations by tag
- **!analyze** — Automated crash analysis

## Useful WinDbg Extensions

- `!pool` / `!poolused` — Pool allocation analysis
- `!object` / `!handle` — Kernel object inspection
- `!token` — Token structure analysis
- `dt nt!_EPROCESS` — Structure layout inspection
