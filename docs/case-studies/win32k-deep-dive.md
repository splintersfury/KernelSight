# Win32k Attack Surface Deep-Dive

The Win32k subsystem is one of the oldest and most exploited Windows kernel attack surfaces. With 12 CVEs in the KernelSight corpus, 3 exploited in the wild, and a vulnerability history stretching back to Windows XP, it is the textbook case of how legacy architecture creates persistent security debt.

## Overview

The Win32k subsystem (`win32k.sys`, `win32kbase.sys`, `win32kfull.sys`) implements the Windows USER and GDI subsystems in kernel mode. It manages windows, menus, cursors, drawing objects, and the Desktop Window Manager's kernel-side state. Any interactive Windows session relies on Win32k for every window it displays, every menu it renders, and every input event it processes.

Win32k has been a top exploitation target for as long as Windows kernel exploitation has existed. The reasons are architectural, not incidental. The subsystem combines complex object management with user-mode callbacks that create reentrancy hazards, a legacy type system that predates modern safety practices, and an attack surface reachable from any interactive session without elevated privileges. Microsoft has spent over a decade applying targeted mitigations, and bugs keep appearing.

## Architecture

### Key Components

**USER Subsystem.** Manages window objects, message queues, menus, cursors, hooks, and input processing. Window objects carry per-instance "extra bytes" (WndExtra) that can hold typed or untyped data. This is a recurring source of type confusion because the kernel interprets WndExtra content based on the window class, and a mismatch in class identification means the data gets interpreted as the wrong type.

**GDI Subsystem.** Manages graphical objects: device contexts, bitmaps, palettes, brushes, pens, regions. GDI objects are stored in a kernel-mode handle table with per-object type tags. Palette and bitmap objects were historically the primary R/W primitives for kernel exploitation (pre-RS3), because `GetPaletteEntries`/`SetPaletteEntries` and `GetBitmapBits`/`SetBitmapBits` provided user-controllable read/write to kernel memory.

**Menu System.** Nested menu structures with parent-child relationships. Menu teardown must walk the tree, and reentrancy during teardown is a classic UAF source. The menu system was responsible for the ITW-exploited [CVE-2023-29336](CVE-2023-29336.md).

**Window Manager.** Coordinates window creation, destruction, z-ordering, and message dispatch. The message loop can trigger user-mode callbacks that re-enter the kernel, creating the reentrancy hazards that produce most Win32k UAFs.

### Object Model

```
Win32k Handle Table
  |-- WINDOW_OBJECT (tagWND)
  |     |-- ExtraBytes (WndExtra) -- typed or raw data
  |     |-- MessageQueue
  |     +-- ChildList
  |-- MENU_OBJECT (tagMENU)
  |     |-- MenuItems[]
  |     +-- ParentMenu
  |-- PALETTE_OBJECT
  |-- BITMAP_OBJECT
  +-- CURSOR_OBJECT
```

## Why Win32k Is Still A Top Target

**Massive legacy surface.** Win32k is one of the largest kernel-mode components, with hundreds of system calls and decades of accumulated code. The USER and GDI subsystems predate modern security practices. Code paths written in the Windows NT era still execute on every modern Windows system.

**User-mode callbacks.** This is the defining architectural weakness. Win32k calls back to user mode during many operations: window procedures, hook callbacks, menu message processing, and input dispatch. Each callback returns control to user-mode code that can trigger re-entrant kernel calls. Those re-entrant calls can modify or free objects that the original kernel call path still holds references to. When the kernel resumes after the callback, it accesses freed or modified memory.

**Complex object lifetimes.** Windows, menus, cursors, and GDI objects have intricate parent-child relationships. Destroying a parent must cascade to children, but reentrancy during destruction can leave stale references to child objects that have already been freed.

**WndExtra type confusion.** Window extra bytes store per-class data without type enforcement at the memory level. If the kernel misidentifies the window class, it interprets WndExtra as the wrong type. [CVE-2022-21882](CVE-2022-21882.md) exploited exactly this: a ConsoleWindow flag caused the kernel to misinterpret WndExtra, giving a controlled type confusion.

**Reachable without privileges.** All Win32k operations are accessible from any interactive session. An unprivileged user can create windows, menus, and GDI objects to trigger vulnerable code paths. No elevation is needed to reach the attack surface.

## The Vulnerability History

| CVE | Year | Class | ITW | What Happened |
|-----|------|-------|-----|---------------|
| CVE-2022-21882 | 2022 | Type Confusion | Yes | ConsoleWindow flag WndExtra misinterpretation |
| CVE-2023-29336 | 2023 | UAF / Object Mgmt | Yes | Unlocked nested menu object UAF |
| CVE-2024-38256 | 2024 | Info Disclosure | No | Uninitialized memory leak to user mode |
| CVE-2025-21367 | 2025 | Race Condition | No | Concurrent window operation race |
| CVE-2025-24044 | 2025 | UAF | No | Object lifetime error |
| CVE-2025-24983 | 2025 | UAF / Race | Yes | Race condition causing UAF, exploited ITW |
| CVE-2025-27732 | 2025 | Memory Locking | No | Improper memory locking |
| CVE-2025-49667 | 2025 | Double Free | No | Double free in object handling |
| CVE-2025-49733 | 2025 | UAF | No | Object lifetime error |
| CVE-2025-55228 | 2025 | Race Condition | No | Concurrent window operation race |
| CVE-2025-62458 | 2025 | EoP | No | Elevation of privilege |
| CVE-2026-20822 | 2026 | UAF | No | Object lifetime error |

Three ITW exploited. Twelve total. Four distinct vulnerability classes. Four years. The pattern shows no sign of slowing.

## Common Vulnerability Patterns

### Callback Reentrancy UAF

The most dangerous Win32k pattern, and the most architecturally difficult to fix. During a kernel operation (menu display, window creation, message dispatch), Win32k calls back to user mode via a window procedure or hook. The user-mode callback triggers a second kernel call that frees or modifies an object the first call path still references. When execution returns to the first path, it accesses freed memory.

[CVE-2023-29336](CVE-2023-29336.md) exploits this through nested menu objects. During menu display, the menu's window procedure callback receives a message. The attacker's callback handler destroys a child menu item. The parent's teardown path, which had been suspended during the callback, resumes and dereferences a pointer to the now-freed child. The stale pointer hits attacker-controlled memory sprayed into the freed slot.

This pattern is so fundamental to Win32k that fixing it would require restructuring the callback architecture. Microsoft instead applies per-CVE fixes, adding locks or reference counts around specific callback sites. Each fix closes one reentrancy window while leaving others open.

### WndExtra Type Confusion

Window classes define "extra bytes" allocated alongside each window object. The kernel interprets these bytes according to the window class type. [CVE-2022-21882](CVE-2022-21882.md) exploits a ConsoleWindow flag mismatch: the kernel checks whether a window is a console window, but the flag can be manipulated to cause a non-console window's WndExtra to be interpreted as a console window structure. The misinterpreted fields give controlled out-of-bounds read/write.

### Concurrent Window Operation Races

Multiple threads creating, destroying, or modifying windows simultaneously can race on shared state in the window manager. [CVE-2025-21367](CVE-2025-21367.md) and [CVE-2025-55228](CVE-2025-55228.md) both involve race conditions where the window manager's locking is insufficient to prevent concurrent threads from corrupting shared state.

### Object Lifetime Errors

The simplest variant. The kernel frees an object too early or fails to increment a reference count before storing a pointer. [CVE-2025-24044](CVE-2025-24044.md), [CVE-2025-49733](CVE-2025-49733.md), and [CVE-2026-20822](CVE-2026-20822.md) follow this pattern. These are less architecturally interesting than callback reentrancy bugs but equally exploitable.

## How Exploitation Has Evolved

Win32k exploitation has changed as Microsoft added mitigations, and the evolution illustrates how attackers adapt.

**Pre-RS3 (before 2017).** The golden age of Win32k exploitation. The attacker creates a window or menu that triggers a UAF. They spray palette or bitmap objects into the freed slot. Because palette and bitmap objects are GDI kernel objects with user-controllable read/write through `GetPaletteEntries`/`SetPaletteEntries`, reclaiming a freed slot with a palette gives a direct kernel R/W primitive. This was fast, reliable, and straightforward. See [Palette / Bitmap](../primitives/exploitation/palette-bitmap.md).

**RS3 (2017) through modern.** Microsoft shipped Win32k Type Isolation, allocating GDI objects in separate pools to prevent cross-type confusion. This killed the palette/bitmap technique. Attackers shifted to pool spray with named pipe attributes, I/O Ring structures, or other kernel objects that provide data-controllable allocations in the same pool segment as the freed Win32k object. Building a R/W primitive from these objects is more complex but still achievable.

**Modern chains.** The current exploitation pattern involves spraying the freed slot with a controlled object, building a limited R/W primitive through the corrupted metadata, locating the current process token using the R/W primitive, and performing token swap to copy the SYSTEM token to the current process. kCFG enforcement has also pushed exploits away from arbitrary code execution toward data-only attacks that manipulate tokens and security descriptors.

## Mitigations

Microsoft has shipped several mitigations targeting Win32k:

**Win32k Type Isolation (RS3 / 2017).** GDI objects allocated in separate pools to prevent cross-type confusion. Blocked palette/bitmap primitives. This was the single most impactful Win32k mitigation.

**Win32k Lockdown.** Reduces the Win32k system call surface available from certain process types (e.g., browser sandboxes via `PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY`). Effective for browser sandbox escapes but does not help for attacks from standard desktop applications.

**User-mode callback hardening.** Incremental locking improvements around callback callsites to prevent reentrancy UAF. Applied per-CVE rather than as a full refactor. Each fix closes one reentrancy window.

**win32kbase / win32kfull split.** Separating base functionality from full GDI reduces the attack surface for processes that don't need full graphical capability.

These help, but the core problem persists: Win32k calls back to user mode during object manipulation, and each callback opens a reentrancy window. The mitigations raise the cost of exploitation without eliminating the vulnerability class.

## AutoPiff Detection

AutoPiff monitors Win32k patches for these change patterns:

- `added_lock_around_callback` -- New locking around user-mode callback callsites
- `added_type_check` -- Object type validation before cast, indicating type confusion fix
- `modified_object_free` -- Changes to object destruction sequence, indicating lifetime fix
- `added_ref_count` -- Reference count additions around object access

## The Bigger Picture

Win32k is the clearest example of how architectural decisions made decades ago create security consequences that no amount of incremental patching can fully resolve. The subsystem was designed in an era when the kernel trusted user-mode callbacks to behave correctly. That trust model is fundamentally incompatible with modern threat models. Microsoft has applied impressive engineering to mitigate the consequences, from type isolation to callback hardening, but the bugs keep coming because the architecture keeps creating opportunities for them.

The question is not whether Win32k will produce more CVEs. It will. The question is whether the ongoing shift of graphical subsystem functionality to user-mode processes (through DWM, Composition, and other modern APIs) will eventually reduce Win32k's relevance enough that the remaining attack surface becomes manageable. Until then, Win32k remains one of the most productive kernel exploitation targets on any operating system.

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
