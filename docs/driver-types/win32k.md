# Win32k Subsystem

The Win32k subsystem handles the Windows graphical interface — window management, GDI rendering, and user input. It runs in kernel mode but is directly callable from user-mode via dedicated system calls.

## Architecture

- **Driver model**: Kernel subsystem loaded into session space
- **Components**: `win32k.sys` (legacy), `win32kbase.sys` (base layer), `win32kfull.sys` (full desktop)
- **Syscall interface**: ~1200 `NtUser*` and `NtGdi*` system calls callable from user mode
- **Session isolation**: Per-session address space with session pool

## Attack Surface

- **System call handlers**: Massive syscall table — each handler is potential attack surface
- **Window/menu object management**: Complex object hierarchies with parent/child/owner relationships
- **GDI objects**: Bitmaps, palettes, fonts, DCs — historically used for exploitation primitives
- **Callback mechanism**: User-mode callbacks from kernel (xxxClientAllocWindowClassExtraBytes) create re-entrancy risks
- **WndExtra data**: Per-window class extra bytes — type confusion between kernel and user interpretations

## Common Vulnerability Patterns

| Pattern | Description | AutoPiff Rules |
|---------|-------------|----------------|
| Type confusion via flags | Window flag misinterpretation treats kernel data as user offset | `object_type_validation_added`, `handle_object_type_check_added` |
| UAF from menu objects | Nested menu destruction frees object still referenced | `ob_reference_balance_fix` |
| Info leak via uninitialized | GDI output buffer contains stale kernel pointers | `stack_variable_initialization_added`, `kernel_pointer_scrubbing_added` |
| Callback re-entrancy | User-mode callback allows modifying objects mid-operation | (complex pattern — not directly rule-matched) |

## CVEs

| CVE | Driver | Description | Class | ITW |
|-----|--------|-------------|-------|-----|
| [CVE-2022-21882](../case-studies/CVE-2022-21882.md) | `win32kbase.sys` | ConsoleWindow flag type confusion EoP | Type Confusion | Yes |
| [CVE-2023-29336](../case-studies/CVE-2023-29336.md) | `win32kfull.sys` | UAF from unlocked nested menu object | Use-After-Free | Yes |
| [CVE-2024-38256](../case-studies/CVE-2024-38256.md) | `win32k.sys` | Uninitialized resource leaks kernel memory | Info Disclosure | No |

## Key Drivers

### win32kbase.sys
- **Role**: Base Win32k layer — handles core window management, class registration
- **Attack vector**: Any GUI process can invoke NtUser* syscalls
- **Note**: CVE-2022-21882 — the `xxxClientAllocWindowClassExtraBytes` callback is a classic Win32k exploitation vector

### win32kfull.sys
- **Role**: Full desktop Win32k — menus, cursors, hooks, message handling
- **Attack vector**: Create windows, menus, and trigger message dispatch
- **Note**: Menu object UAF (CVE-2023-29336) is part of a long history of Win32k menu bugs

### win32k.sys
- **Role**: Legacy Win32k driver (GDI operations)
- **Attack vector**: NtGdi* syscalls for font/glyph operations
- **Note**: Info disclosure bugs are common due to complex GDI output buffers

## Historical Context

Win32k has been the single most exploited Windows kernel attack surface historically. Microsoft has invested heavily in mitigations:
- **Win32k syscall filtering** — restricts which syscalls are available to specific process types
- **Win32k lockdown** — prevents Win32k from being loaded in certain processes
- **Type isolation** — moving Win32k objects to isolated pool regions

Despite these mitigations, the sheer size of the syscall surface (~1200 handlers) means bugs continue to be found.
