# Debugging

Kernel debugging is where static analysis meets reality. A vulnerability pattern identified in a disassembler might be unreachable at runtime, protected by a check in a wrapper function, or triggered only under specific system state. Debugging confirms that the path is live, the inputs are controllable, and the corruption is exploitable. It is also the foundation for snapshot-based fuzzing (WTF requires a kernel debugging setup to capture snapshots) and crash analysis (every BSOD produces a dump that WinDbg can analyze).

## Setting Up Kernel Debugging

There are three approaches, each suited to different environments.

### KDNET (Network Debugging)

KDNET is the recommended setup for modern systems. It provides the fastest debugging connection and works over standard Ethernet. On the target machine, run `bcdedit /debug on` followed by `bcdedit /dbgsettings net hostip:<debugger_ip> port:50000`. This generates a debug key. On the debugger machine, launch `WinDbg -k net:port=50000,key=<generated_key>`. The debug key must match on both sides.

KDNET requires both machines on the same network. For isolated lab setups, a direct Ethernet cable between the two machines works. KDNET is available in Windows 10 and later.

### Virtual Machine Debugging

VM debugging is recommended for safety: kernel crashes require a VM reset rather than a physical reboot, and snapshots let you restore state after a crash in seconds.

For **VMware**, configure a named pipe serial port on the VM (`\\.\pipe\com_1` with "This end is the server" and "The other end is an application"), then attach WinDbg on the host via `WinDbg -k com:pipe,port=\\.\pipe\com_1,resets=0`. **VirtualKD-Redux** accelerates this dramatically by replacing the slow serial protocol with a fast host-guest channel. Install VirtualKD-Redux on both host and guest, and debugging throughput increases by 10-50x.

For **QEMU/KVM**, launch with `-serial tcp::1234,server` and connect WinDbg via serial over TCP. For **Hyper-V**, use `bcdedit /hypervisorsettings` on the target for hypervisor-level debugging configuration.

### WinDbg Preview

WinDbg Preview provides a modern UI with JavaScript scripting and Time Travel Debugging (TTD) support. TTD records a full execution trace that can be replayed forward and backward, which is invaluable for understanding complex race conditions. The limitation is that kernel-mode TTD support is restricted and primarily works for user-mode scenarios. JavaScript scripting (`dx` command and `.scriptload`) enables automation of analysis tasks like iterating process lists, dumping token structures, and searching pool memory.

## Essential Commands

These commands form the core vocabulary for kernel driver vulnerability research.

| Command | What It Does |
|---------|-------------|
| `!process 0 0` | List all processes with EPROCESS addresses |
| `!process -1 0` | Show current process EPROCESS address |
| `dt nt!_EPROCESS @$proc` | Dump EPROCESS fields for the current process |
| `dt nt!_TOKEN poi(@$proc+<offset>)&~0xf` | Dump the process token structure (mask low bits) |
| `!pool <address>` | Show pool allocation info: size, tag, pool type |
| `!poolused` | Display pool tag usage statistics system-wide |
| `bp driver!DispatchDeviceControl` | Set breakpoint on the driver's IOCTL handler |
| `ba w4 <address>` | Set hardware write breakpoint (4 bytes) |
| `!analyze -v` | Verbose automated crash dump analysis |
| `.reload /f` | Force reload all symbols from the symbol server |
| `!devobj <address>` | Display device object info including security descriptor |
| `!drvobj <address>` | Display driver object and full dispatch table |
| `!irp <address>` | Display IRP structure and I/O stack locations |
| `lm m driver` | List loaded module info: base address, size, timestamp |

For exploit development, the token-related commands are most used. Finding the current process token: `!process -1 0` gives the EPROCESS address, then `dt nt!_EPROCESS Token @$proc` reveals the fast reference pointer. Dumping the SYSTEM token for comparison: `!process 0 0 System` gives the SYSTEM EPROCESS, and the same `dt` command shows its token. The difference between these two token values is what a token swap exploit will overwrite.

## Useful Extensions

Several WinDbg extensions provide capabilities beyond the built-in command set. **SwishDbgExt** offers enhanced kernel forensics commands with detailed process, handle, and object output. **PYKD** enables Python scripting for WinDbg automation, allowing complex analysis scripts that would be tedious to write in WinDbg's native scripting language. **MEX** (Microsoft Debugging Extension) is the WinDbg team's utility pack with dozens of convenience commands for common analysis tasks. **Mona** assists with pattern generation for overflow analysis: creating cyclic patterns and calculating offsets for stack or pool overflows.

## Typical Research Session

A kernel debugging session for driver vulnerability research follows a consistent pattern.

Start by setting up your debugging environment using one of the methods above. Load the target driver's symbols with `.sympath+ <path_to_symbols>` followed by `.reload`. Identify the driver's entry points with `x driver!DriverEntry` and `x driver!*Dispatch*`. Dump the dispatch table with `!drvobj <driver_object_addr> 2` to see all IRP handlers and confirm which function handles `IRP_MJ_DEVICE_CONTROL`.

Set breakpoints on the IOCTL handler and send test IOCTLs from a user-mode tool (DeviceIoControl from a custom C program, or the NtDeviceIoControlFile syscall). When execution hits the breakpoint, trace data flow through the handler: watch user buffer addresses, pool allocations, size calculations, and how the driver validates (or fails to validate) input parameters.

For crash analysis, load the dump file with `WinDbg -z dump.dmp` and run `!analyze -v`. The key fields are `FAULTING_IP` (the instruction that crashed), `DEFAULT_BUCKET_ID` (the crash classification), and `STACK_TEXT` (the full call stack). Cross-reference the faulting address with `!pool <address>` to determine pool type, tag, and allocation size. Use `.ecxr` to switch to the exception context record for examining register state at the crash moment.

## Driver Verifier

Driver Verifier is the single most valuable tool for catching kernel driver bugs at runtime, and it should be enabled on the target driver for all debugging and fuzzing sessions.

Enable it with `verifier /standard /driver target.sys` (requires reboot). The key checks it enables:

**Special Pool** places each allocation on a page boundary with a guard page immediately after the allocation. This catches off-by-one pool overflows and use-after-free on the very next access, converting silent corruption into an immediate bugcheck. This is essential for fuzzing because many pool bugs corrupt silently and cause BSODs much later in unrelated code, making triage impossible without Special Pool.

**Pool tracking** monitors all allocations and frees, detecting memory leaks and double-free conditions. **IRQL checking** catches incorrect IRQL usage, a common class of driver bug that causes subtle corruption through unsafe operations at elevated IRQL. **Deadlock detection** monitors lock acquisition ordering to identify potential deadlocks before they occur in production.

Query current settings with `verifier /query` to confirm which drivers are being verified and which checks are active. For pool corruption crashes, `!verifier 3 driver.sys` provides detailed allocation tracking including the stack trace of the original allocation and free, which is essential for diagnosing use-after-free bugs.
