# Debugging

Kernel debugging setup and techniques for Windows driver vulnerability research.

## Overview

Kernel debugging is essential for exploit development, crash analysis, and understanding driver internals at runtime. `WinDbg` is the primary tool, with several extensions and workflows optimized for security research. A working kernel debugging setup is a prerequisite for many other activities -- snapshot-based fuzzing, exploit proof-of-concept development, and verifying that a static analysis finding is actually reachable at runtime.

## WinDbg Setup

### Hardware Debugging (Two-Machine)

- Debugger machine connected to target via: serial cable (legacy), USB 3.0 debug cable, or network (KDNET)
- KDNET (network debugging) is recommended -- fastest and most convenient for modern setups
- Target configuration: `bcdedit /debug on` followed by `bcdedit /dbgsettings net hostip:x.x.x.x port:50000`
- Debugger launch: `WinDbg -k net:port=50000,key=<generated_key>`
- The debug key is generated during target setup and must match on both sides

### Virtual Machine Debugging

- **VMware**: configure a named pipe serial port on the VM, then attach `WinDbg` to the pipe on the host
- **Hyper-V**: use `bcdedit /hypervisorsettings` for hypervisor-level debugging configuration
- **QEMU/KVM**: launch with `-serial tcp::1234,server` and connect `WinDbg` via serial over TCP
- VM debugging is recommended for safety: kernel crashes simply require a VM reset rather than a physical reboot
- `VirtualKD-Redux` accelerates VM kernel debugging significantly by replacing the slow serial protocol with a fast host-guest channel

### WinDbg Preview

- Modern UI with JavaScript scripting engine and Time Travel Debugging (TTD) support
- TTD records a full execution trace that can be replayed forward and backward
- TTD limitations: kernel-mode TTD support is limited and primarily works for user-mode scenarios
- JavaScript scripting (`dx` command and `.scriptload`) enables powerful automation of analysis tasks

## Essential Commands

| Command | Purpose |
|---------|---------|
| `!process 0 0` | List all processes with basic info |
| `!process -1 0` | Show current process EPROCESS address |
| `dt nt!_EPROCESS @$proc` | Dump EPROCESS structure fields |
| `dt nt!_TOKEN poi(@$proc+<offset>)&~0xf` | Dump process token structure |
| `!pool <address>` | Show pool allocation info for an address |
| `!poolused` | Display pool tag usage statistics across the system |
| `bp driver!DispatchDeviceControl` | Set software breakpoint on driver function |
| `ba w4 <address>` | Set hardware write breakpoint (4 bytes) |
| `!analyze -v` | Verbose automated crash dump analysis |
| `.reload /f` | Force reload all symbols from symbol server |
| `!devobj <address>` | Display device object information |
| `!drvobj <address>` | Display driver object and dispatch table |
| `!irp <address>` | Display IRP structure and stack locations |
| `lm m driver` | List loaded module info for a driver |

## Useful Extensions

- **SwishDbgExt** -- Enhanced kernel forensics commands (`!processes`, `!handles`, `!objects` with detailed output)
- **PYKD** -- Python scripting for `WinDbg` automation, enabling complex analysis scripts and custom commands
- **MEX** -- Microsoft Debugging Extension, the `WinDbg` team's utility pack with dozens of convenience commands
- **Mona** -- Pattern generation for overflow analysis, cyclic pattern creation, and offset calculation
- **BigPool** -- Assists with large pool allocation tracking and analysis

## Kernel Debugging Workflow

A typical kernel debugging session for driver vulnerability research:

1. Set up two-machine or VM debugging environment with KDNET or serial connection
2. Load target driver symbols: `.sympath+ <path_to_symbols>` followed by `.reload`
3. Identify driver entry points: `x driver!DriverEntry`, `x driver!*Dispatch*`
4. Dump the dispatch table: `!drvobj <driver_object_addr> 2` to see all IRP handlers
5. Set breakpoints on the IOCTL handler: `bp driver!DeviceIoControl` or equivalent dispatch function
6. Send test IOCTLs from a user-mode tool and observe execution hitting breakpoints
7. Trace data flow: watch user buffer addresses, pool allocations, and size calculations
8. For crash analysis: `!analyze -v`, examine faulting instruction, register state, and call stack

## Driver Verifier Integration

- Enable Driver Verifier for a specific target driver: `verifier /standard /driver target.sys`
- **Special Pool**: places each allocation on a page boundary with a guard page immediately after -- catches off-by-one overflows and use-after-free on the next access
- **Pool tracking**: monitors all allocations and frees for leak detection and double-free identification
- **IRQL checking**: detects incorrect IRQL usage, a common class of driver bug that causes subtle corruption
- **Deadlock detection**: monitors lock acquisition ordering to find potential deadlocks before they occur in production
- Reboot is required after enabling Driver Verifier -- it adds runtime overhead but catches many subtle bugs that would otherwise go unnoticed
- Query current settings: `verifier /query` to see which drivers are being verified and which checks are active

## Crash Dump Analysis

- **Full memory dumps**: configure with `bcdedit /set {default} debugtype full` -- contains a complete RAM snapshot at crash time
- **Minidumps**: faster to write but contain less context, stored in `%SystemRoot%\Minidump`
- Load a dump file: `WinDbg -z dump.dmp` -> run `!analyze -v` -> examine `FAULTING_IP`, `DEFAULT_BUCKET_ID`, and `STACK_TEXT`
- For pool corruption crashes: `!verifier 3 driver.sys` provides detailed allocation tracking including the stack trace of the original allocation
- Cross-reference the faulting address with `!pool <address>` to determine pool type, tag, and allocation size
- Use `.ecxr` to switch to the exception context record for examining register state at the time of the crash
