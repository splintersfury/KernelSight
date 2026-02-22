# ALPC

Advanced Local Procedure Call is the kernel-mode IPC mechanism underlying RPC, COM, and many core Windows communication channels, providing attack surface through message handling, view section management, and handle passing operations.

## Attack Surface Overview

- **Key syscalls**: `NtAlpcCreatePort`, `NtAlpcConnectPort`, `NtAlpcSendWaitReceivePort`, `NtAlpcDisconnectPort`, `NtAlpcQueryInformation`, `NtAlpcSetInformation`
- **Message attributes**: Security attributes (impersonation tokens), view attributes (shared memory sections), handle attributes (cross-process handle duplication), context attributes, and work-on-behalf-of attributes
- **Kernel objects**: ALPC port objects (connection ports, server communication ports, client communication ports), message objects, section objects, and view regions managed by the kernel ALPC subsystem
- **User-mode reach**: RPC calls via `NdrClientCall`, COM cross-process activation, direct ALPC syscalls, Task Scheduler, Print Spooler, and hundreds of Windows services that communicate via RPC/ALPC
- **Indirect reach**: Any application using COM out-of-process servers, DCOM, WMI remote connections, or named pipe operations backed by ALPC triggers kernel ALPC code
- **Key risk**: Complex message deserialization with multiple attribute types, concurrent port access from multiple threads, and view section mapping races create a large combinatorial attack surface in core kernel code

## Mechanism Deep-Dive

ALPC is the successor to the original LPC mechanism and serves as the transport layer for nearly all local inter-process communication in Windows. When a server creates an ALPC connection port via `NtAlpcCreatePort`, clients can connect using `NtAlpcConnectPort`, which creates a pair of communication port objects -- one for the server side and one for the client side. Messages are exchanged via `NtAlpcSendWaitReceivePort`, which can both send a message and wait for a reply in a single syscall, minimizing context switches for performance-critical IPC.

The complexity of ALPC arises from its message attribute system. Each ALPC message can carry multiple attributes that trigger additional kernel operations during send and receive. A security attribute causes the kernel to capture the sender's token for impersonation by the receiver. A view attribute maps a section of shared memory into the receiver's address space, allowing efficient transfer of large data blocks without copying. A handle attribute duplicates a handle from the sender's process to the receiver's process, enabling cross-process resource sharing. Each of these operations involves kernel object manipulation with reference counting, access checks, and error handling on multiple failure paths. Bugs in attribute processing are particularly dangerous because they can affect kernel object reference counts (leading to use-after-free when a reference is dropped too many times) or bypass security checks (leading to privilege escalation through token or handle manipulation).

The ALPC subsystem also supports "message zones" -- kernel-managed memory regions that store large messages when they exceed the small inline buffer limit. Message zones are backed by section objects mapped into both the port owner and the kernel. The kernel maintains metadata structures to track allocation and deallocation within these zones, and corruption of zone metadata can lead to arbitrary kernel memory access. Additionally, the connection model introduces lifetime management complexity: when a client disconnects or a server port is closed, the kernel must clean up the communication port, drain any pending messages, unmap associated views, and release duplicated handles, all while other threads may be concurrently sending or receiving on the same port.

The sheer volume of ALPC traffic in a running Windows system makes this a high-value target. Even a default Windows installation has dozens of RPC services listening on ALPC ports, and every COM cross-process call transits through the ALPC subsystem. This means that ALPC vulnerabilities in `ntoskrnl.exe` have extremely broad exposure -- they are reachable from virtually any process on the system, often including sandboxed and AppContainer processes that can make RPC calls.

## Common Vulnerability Patterns

- **Message attribute type confusion**: The kernel processes an attribute as one type (e.g., view attribute) when the caller crafted it as another type, leading to incorrect pointer dereference or size interpretation
- **Port object use-after-free**: Concurrent disconnect and send/receive operations race on the port object's lifetime, leading to use of a freed communication port object
- **View section mapping race**: A view attribute requests mapping of a shared section, but concurrent operations on the same section or port cause double-mapping or mapping into a freed address range
- **Handle attribute validation bypass**: The handle duplication performed during handle attribute processing does not properly validate the source handle's access rights, allowing privilege escalation through handle smuggling
- **Impersonation token capture**: Security attribute processing captures the sender's token for impersonation, but insufficient validation allows a low-privilege process to craft a message that causes the receiver to impersonate at a higher privilege level
- **Message zone corruption**: Overflow or underflow in message zone allocation metadata corrupts adjacent message headers, enabling controlled kernel memory writes
- **Connection callback re-entrancy**: Server-side connection callbacks invoked during `NtAlpcConnectPort` processing re-enter ALPC code in an unexpected state, causing state corruption
- **Reference count imbalance**: Error paths in message send/receive fail to release references on port objects, view objects, or section objects, leading to reference count leaks (DoS) or extra decrements (use-after-free)

## Driver Examples

The ALPC subsystem is implemented entirely within `ntoskrnl.exe` as part of the executive. It is not a separate driver but a core kernel component. Indirectly, every Windows service that uses RPC (which is nearly all of them) relies on ALPC as the transport. Key services using ALPC include the Task Scheduler service, Print Spooler (`spoolsv.exe`), DCOM/COM activation (`svchost.exe` instances), Windows Error Reporting, the Security Account Manager (SAM), and the Local Security Authority (`lsass.exe`). The `csrss.exe` Windows subsystem process uses raw ALPC ports for console management and session notifications. Attack surface exists both in the kernel ALPC implementation within `ntoskrnl.exe` and in the user-space service logic that processes ALPC messages -- though the kernel-side bugs are more impactful.

## Detection Approach

- **Syscall fuzzing**: Use Syzkaller or custom syscall fuzzers to exercise the `NtAlpc*` syscall family with varied message sizes, attribute combinations, and concurrent operations. Focus on combining multiple attribute types in a single message and racing connect/disconnect with send/receive from multiple threads.
- **RPC interface enumeration**: Use `RpcView` or `NtObjectManager` (James Forshaw's toolkit) to enumerate RPC endpoints backed by ALPC ports. Each RPC interface with methods accepting complex structures is an indirect ALPC attack vector. Focus on interfaces accessible from low-privilege or AppContainer contexts.
- **Port object analysis**: In WinDbg, use `!alpc /p <port_address>` to inspect ALPC port objects, pending messages, connected clients, and associated sections. Monitor port handle counts and message queue depths to identify potential lifetime issues.
- **Concurrency testing**: Create multiple threads that simultaneously connect, send, receive, and disconnect on the same ALPC port to stress reference counting and state management code paths.
- **Patch diffing**: ALPC fixes in `ntoskrnl.exe` typically add reference count adjustments, lock acquisitions around attribute processing, or additional validation of message attribute fields. Diff the ALPC-related functions (prefixed with `Alpc` in the kernel symbols) across patches.
- **Impersonation auditing**: Monitor `NtAlpcSendWaitReceivePort` calls that include security attributes and verify that token impersonation level and integrity checks are enforced correctly.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-38106](../case-studies/CVE-2024-38106.md) | `ntoskrnl.exe` | Race condition in kernel exploitable via IPC-related timing window |
| [CVE-2024-30088](../case-studies/CVE-2024-30088.md) | `ntoskrnl.exe` | Race condition in I/O handling reachable through IPC paths |
| [CVE-2023-36802](../case-studies/CVE-2023-36802.md) | `mskssrv.sys` | Use-after-free in streaming proxy involving cross-process communication |
| [CVE-2023-28218](../case-studies/CVE-2023-28218.md) | `ntoskrnl.exe` | Elevation of privilege through kernel object management |
| [CVE-2023-36424](../case-studies/CVE-2023-36424.md) | `ntoskrnl.exe` | Elevation of privilege via kernel state manipulation |

## AutoPiff Detection

ALPC vulnerabilities primarily reside in `ntoskrnl.exe` and are detected by general-purpose rules:

- `race_condition_lock_added` -- Lock acquisition or interlocked operation added to protect concurrent access in ALPC-related code paths
- `reference_count_fix` -- Object reference count increment or decrement added to fix lifetime management in port or message handling
- `bounds_check_added` -- Size or bounds validation added to message attribute processing
- `access_check_added` -- Security access check added to ALPC operation that previously lacked validation
- `error_path_cleanup_added` -- Resource cleanup (reference release, memory free) added to error handling path that previously leaked
