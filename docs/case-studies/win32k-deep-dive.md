# Win32k Attack Surface Deep-Dive

Analysis of the Win32k subsystem, one of the oldest and most exploited Windows kernel attack surfaces with 12 CVEs in the KernelSight corpus.

## Overview

The Win32k subsystem (`win32k.sys`, `win32kbase.sys`, `win32kfull.sys`) implements the Windows USER and GDI subsystems in kernel mode. It manages windows, menus, cursors, drawing objects, and the Desktop Window Manager's kernel-side state. Win32k has been a top exploitation target since Windows XP -- its mix of complex object management, user-mode callbacks, and legacy architecture keeps producing use-after-free and type confusion bugs.

## Architecture

### Key Components

- **USER Subsystem** -- Manages window objects, message queues, menus, cursors, hooks, and input processing. Window objects carry per-instance "extra bytes" (WndExtra) that can hold typed or untyped data -- a recurring source of type confusion.
- **GDI Subsystem** -- Manages graphical objects: device contexts, bitmaps, palettes, brushes, pens, regions. GDI objects are stored in a kernel-mode handle table with per-object type tags. Palette and bitmap objects were historically abused as R/W primitives (pre-RS3).
- **Menu System** -- Nested menu structures with parent-child relationships. Menu teardown must walk the tree, and reentrancy during teardown is a classic UAF source.
- **Window Manager** -- Coordinates window creation, destruction, z-ordering, and message dispatch. The message loop can trigger user-mode callbacks that re-enter the kernel, creating reentrancy hazards.

### Object Model

```
Win32k Handle Table
  ├── WINDOW_OBJECT (tagWND)
  │     ├── ExtraBytes (WndExtra) -- typed or raw data
  │     ├── MessageQueue
  │     └── ChildList
  ├── MENU_OBJECT (tagMENU)
  │     ├── MenuItems[]
  │     └── ParentMenu
  ├── PALETTE_OBJECT
  ├── BITMAP_OBJECT
  └── CURSOR_OBJECT
```

## Why Win32k Is A Top Target

1. **Massive legacy surface.** Win32k is one of the largest kernel-mode components, with hundreds of system calls and decades of accumulated code. The USER and GDI subsystems predate modern security practices.

2. **User-mode callbacks.** Win32k calls back to user mode during many operations (window procedures, hook callbacks, menu message processing). These callbacks can trigger re-entrant kernel calls that modify objects the original call path still holds references to.

3. **Complex object lifetimes.** Windows, menus, cursors, and GDI objects have intricate parent-child relationships. Destroying a parent must cascade to children, but reentrancy during destruction can leave stale references.

4. **WndExtra type confusion.** Window extra bytes store per-class data without type enforcement. If the kernel misidentifies the window class, it interprets WndExtra as the wrong type -- a controlled type confusion.

5. **Reachable without privileges.** All win32k operations are accessible from any interactive session. An unprivileged user can create windows, menus, and GDI objects to trigger vulnerable code paths.

## CVE Timeline

| CVE | Year | Class | ITW | Notes |
|-----|------|-------|-----|-------|
| CVE-2022-21882 | 2022 | Type Confusion | Yes | ConsoleWindow flag WndExtra misinterpretation |
| CVE-2023-29336 | 2023 | UAF / Object Mgmt | Yes | Unlocked nested menu object UAF |
| CVE-2024-38256 | 2024 | Info Disclosure | No | Uninitialized memory leak to user mode |
| CVE-2025-21367 | 2025 | Race Condition | No | Concurrent window operation race |
| CVE-2025-24044 | 2025 | UAF | No | Object lifetime error |
| CVE-2025-24983 | 2025 | UAF / Race | Yes | Race condition causing UAF |
| CVE-2025-27732 | 2025 | Memory Locking | No | Improper memory locking |
| CVE-2025-49667 | 2025 | Double Free | No | Double free in object handling |
| CVE-2025-49733 | 2025 | UAF | No | Object lifetime error |
| CVE-2025-55228 | 2025 | Race Condition | No | Concurrent window operation race |
| CVE-2025-62458 | 2025 | EoP | No | Elevation of privilege |
| CVE-2026-20822 | 2026 | UAF | No | Object lifetime error |

## Common Vulnerability Patterns

### Callback Reentrancy UAF

The most dangerous win32k pattern. During a kernel operation (menu display, window creation, message dispatch), win32k calls back to user mode via a window procedure or hook. The user-mode callback triggers a second kernel call that frees or modifies an object the first call path still references. When execution returns to the first path, it accesses freed memory.

[CVE-2023-29336](CVE-2023-29336.md) exploits this through nested menu objects: the menu's window procedure callback frees a child menu item while the parent's teardown path still holds a pointer to it.

### WndExtra Type Confusion

Window classes define "extra bytes" allocated alongside each window object. The kernel interprets these bytes according to the window class type. [CVE-2022-21882](CVE-2022-21882.md) exploits a ConsoleWindow flag mismatch that causes the kernel to interpret WndExtra data as a different structure type, giving controlled out-of-bounds read/write via the misinterpreted fields.

### Concurrent Window Operation Races

Multiple threads creating, destroying, or modifying windows simultaneously can race on shared state in the window manager. [CVE-2025-21367](CVE-2025-21367.md) and [CVE-2025-55228](CVE-2025-55228.md) both involve race conditions in concurrent window operations where the window manager's locking is insufficient.

### Object Lifetime Errors

Simpler than callback reentrancy -- the kernel frees an object too early or fails to increment a reference count before storing a pointer. [CVE-2025-24044](CVE-2025-24044.md), [CVE-2025-49733](CVE-2025-49733.md), and [CVE-2026-20822](CVE-2026-20822.md) follow this pattern.

## Exploitation Pattern

Win32k exploitation changed as Microsoft added mitigations:

1. Create a window or menu structure that reaches the vulnerable code path
2. Set up a user-mode callback (window procedure or hook) that triggers reentrancy or a concurrent racing thread
3. In the callback or racing thread, destroy or modify the target object to create a UAF or type confusion
4. **Legacy (pre-RS3):** spray palette or bitmap objects into the freed slot. Read/write through the GDI object gives a direct kernel R/W primitive via `GetPaletteEntries`/`SetPaletteEntries`
5. **Modern (RS3+):** spray named pipe attributes or I/O Ring structures into the freed slot. Build a R/W primitive through the corrupted metadata
6. Locate the current process token using the R/W primitive
7. Perform token swap -- copy the SYSTEM token to the current process

The palette/bitmap technique ([Palette / Bitmap](../primitives/exploitation/palette-bitmap.md)) was blocked by Microsoft's GDI object type isolation in RS3 (2017), forcing a shift to pool spray techniques.

## Mitigations

Microsoft has shipped several mitigations targeting win32k:

- **Win32k Type Isolation (RS3 / 2017)** -- GDI objects allocated in separate pools to prevent cross-type confusion. Blocked palette/bitmap primitives.
- **Win32k Lockdown** -- Reduces the win32k system call surface available from certain process types (e.g., browser sandboxes via `PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY`).
- **User-mode callback hardening** -- Incremental locking improvements around callback callsites to prevent reentrancy UAF. Applied per-CVE rather than as a full refactor.
- **win32kbase / win32kfull split** -- Separating base functionality from full GDI reduces the attack surface for processes that don't need full graphical capability.

These help, but the core problem persists: win32k calls back to user mode during object manipulation, and each callback opens a reentrancy window.

## AutoPiff Detection

AutoPiff monitors win32k patches for these change patterns:

- `added_lock_around_callback` -- New locking around user-mode callback callsites
- `added_type_check` -- Object type validation before cast, indicating type confusion fix
- `modified_object_free` -- Changes to object destruction sequence, indicating lifetime fix
- `added_ref_count` -- Reference count additions around object access

## Related Case Studies

- [CVE-2022-21882](CVE-2022-21882.md) -- ConsoleWindow type confusion, exploited ITW
- [CVE-2023-29336](CVE-2023-29336.md) -- nested menu UAF, exploited ITW
- [CVE-2025-24983](CVE-2025-24983.md) -- UAF from race condition, exploited ITW
- [CVE-2025-49667](CVE-2025-49667.md) -- double free in object handling
- [CVE-2024-38256](CVE-2024-38256.md) -- information disclosure via uninitialized memory

## References

- [Microsoft Win32k Security Research](https://msrc.microsoft.com/blog/)
- [Morten Schenk -- Type Isolation Mitigations](https://improsec.com/tech-blog/)
- [Gil Dabah -- win32k.sys Internals](https://windows-internals.com/)
