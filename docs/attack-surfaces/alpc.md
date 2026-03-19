# ALPC

Consider what happens when a sandboxed browser renderer calls a COM method on an out-of-process server, or when a low-privilege service queries the Task Scheduler for pending jobs. Neither call looks like it touches the kernel directly. But both transit through Advanced Local Procedure Call, the kernel IPC mechanism that underpins RPC, COM, and hundreds of Windows service communication channels. Every ALPC message passes through `ntoskrnl.exe`, where the kernel deserializes message attributes, manipulates reference-counted objects, maps shared memory sections, and duplicates handles between processes. A bug in any of these operations is a bug in the kernel, reachable from virtually any process on the system, including AppContainer sandboxes.

What makes ALPC particularly interesting as an attack surface is its combinatorial complexity. A single ALPC message can carry security attributes (for token impersonation), view attributes (for shared memory mapping), handle attributes (for cross-process handle duplication), context attributes, and work-on-behalf-of attributes, all simultaneously. Each attribute type triggers a different set of kernel operations during send and receive, and the interactions between these operations under concurrent access from multiple threads create a state space that is extremely difficult to test exhaustively.

## How ALPC works under the hood

``` mermaid
graph TD
    A["Server Process\nNtAlpcCreatePort()"] --> B["Connection Port\n(listens for clients)"]
    B --> C["Client Process\nNtAlpcConnectPort()"]
    C --> D{"Connection\nAccepted?"}
    D -->|Yes| E["Server Comm Port\n+ Client Comm Port\n(paired objects)"]
    E --> F["NtAlpcSendWaitReceivePort()\nMessage + Attributes"]
    F --> G["Kernel Attribute Processing"]
    G --> H["Security: Token capture"]
    G --> I["View: Section mapping"]
    G --> J["Handle: Cross-process dup"]
    G --> K["Context: User pointer"]
    style G fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    style H fill:#152a4a,stroke:#f59e0b,color:#e2e8f0
    style I fill:#152a4a,stroke:#f59e0b,color:#e2e8f0
    style J fill:#152a4a,stroke:#f59e0b,color:#e2e8f0
    style K fill:#152a4a,stroke:#f59e0b,color:#e2e8f0
```

ALPC replaced the original LPC mechanism and serves as the transport layer for nearly all local inter-process communication in Windows. The lifecycle begins when a server creates a connection port via `NtAlpcCreatePort`. Clients connect using `NtAlpcConnectPort`, which produces a pair of communication port objects, one for the server side and one for the client side. Messages are exchanged through `NtAlpcSendWaitReceivePort`, which can send a message and wait for a reply in a single syscall, minimizing context switches for performance-critical IPC.

The complexity that matters for security lives in the message attribute system. Each ALPC message can carry multiple attributes that trigger additional kernel operations during send and receive processing:

A **security attribute** causes the kernel to capture the sender's token for impersonation by the receiver. This involves reference counting on the token object, validating impersonation levels, and ensuring the receiver is authorized to impersonate the sender. If the validation is insufficient, a low-privilege process can craft a message that causes the receiver to impersonate at a higher privilege level.

A **view attribute** maps a section of shared memory into the receiver's address space, enabling efficient transfer of large data blocks without copying. The kernel must create and manage section objects, probe the mapping parameters, and handle the case where the mapping fails partway through. View sections that are mapped concurrently from multiple threads can race on the mapping operation itself.

A **handle attribute** duplicates a handle from the sender's process to the receiver's process, enabling cross-process resource sharing. The kernel must validate the source handle's access rights and object type. If validation is incomplete, handle smuggling can escalate privileges by granting the receiver access to objects the sender should not be able to share.

Each of these attribute operations involves kernel object manipulation with reference counting, access checks, and error handling on multiple failure paths. When an error occurs partway through processing a message with multiple attributes, the kernel must unwind the operations it already completed. Missing a reference release on one error path produces either a reference count leak (denial of service through pool exhaustion) or an extra decrement (use-after-free when the reference reaches zero prematurely).

Beyond individual message processing, the ALPC subsystem supports "message zones," kernel-managed memory regions that store large messages exceeding the small inline buffer limit. Message zones are backed by section objects mapped into both the port owner and the kernel, and the kernel maintains metadata structures to track allocation and deallocation within these zones. Corruption of zone metadata can lead to arbitrary kernel memory access. The connection model adds further lifetime management complexity: when a client disconnects or a server port is closed, the kernel must clean up the communication port, drain pending messages, unmap associated views, and release duplicated handles, all while other threads may be concurrently sending or receiving on the same port.

## Where ALPC vulnerabilities arise

The vulnerability patterns in ALPC cluster around three themes: object lifetime management, attribute processing errors, and concurrency races.

### Object lifetime and reference counting

ALPC manages multiple reference-counted kernel objects: port objects, message objects, section objects, and view objects. Every code path that acquires a reference must release it, and every error path must account for references already taken. In practice, the ALPC code in `ntoskrnl.exe` has thousands of lines of error handling, and missing a single `ObDereferenceObject` on one error path is enough for a vulnerability. An extra decrement causes the reference count to reach zero while other code still holds pointers to the object, producing a use-after-free. A missing decrement leaks the object, eventually exhausting pool memory.

Concurrent disconnect and send/receive operations are particularly treacherous. When one thread calls `NtAlpcDisconnectPort` while another thread is in the middle of `NtAlpcSendWaitReceivePort` on the same port, the disconnect handler may free the communication port object while the send/receive path is still using it. The kernel must coordinate these operations through locks and state flags, and any gap in that coordination is a use-after-free window.

### Attribute type confusion and validation gaps

When the kernel processes message attributes, it parses a sequence of attribute entries, each tagged with a type identifier. If the kernel misinterprets the type of an attribute, it may dereference a pointer as a view attribute structure when the caller constructed it as a handle attribute structure, reading incorrect offsets and triggering an out-of-bounds access or type confusion.

Handle attribute validation bypass is a subtler variant. During handle duplication, the kernel should verify that the source handle's access rights are appropriate for the requested operation. If the validation is incomplete or checks the wrong access mask, the receiver ends up with a handle to an object with more access than the sender was authorized to grant.

### Connection callback re-entrancy

Server-side connection callbacks invoked during `NtAlpcConnectPort` processing can re-enter ALPC code in an unexpected state. If the callback itself performs ALPC operations (sending messages, querying port information), the re-entrant call encounters partially initialized state, causing corruption of port metadata or message queues. This re-entrancy pattern is difficult to catch through code review because it depends on what the callback implementation does, which is outside the kernel's direct control.

## The scope of exposure

A default Windows installation has dozens of RPC services listening on ALPC ports, and every COM cross-process call transits through the ALPC subsystem. The Task Scheduler, Print Spooler (`spoolsv.exe`), DCOM/COM activation, Windows Error Reporting, the Security Account Manager, and the Local Security Authority (`lsass.exe`) all communicate via ALPC. The `csrss.exe` Windows subsystem process uses raw ALPC ports for console management and session notifications. This means ALPC vulnerabilities in `ntoskrnl.exe` are reachable from virtually any process, including sandboxed and AppContainer processes that retain the ability to make RPC calls. The kernel attack surface is not limited to processes that know about ALPC; any process that uses COM or RPC exercises it implicitly.

## Detection approaches

**Syscall fuzzing** is the most direct way to find ALPC bugs. Syzkaller or custom syscall fuzzers can exercise the `NtAlpc*` syscall family with varied message sizes, attribute combinations, and concurrent operations. The key insight is to combine multiple attribute types in a single message and to race connect/disconnect with send/receive from multiple threads. Single-attribute, single-threaded testing misses the combinatorial bugs that dominate ALPC's vulnerability history.

**RPC interface enumeration** provides an indirect attack map. Tools like `RpcView` or James Forshaw's `NtObjectManager` enumerate RPC endpoints backed by ALPC ports. Each RPC interface with methods accepting complex structures is an indirect ALPC attack vector. The focus should be on interfaces accessible from low-privilege or AppContainer contexts, since those represent the realistic attacker position.

**Port object analysis** in WinDbg using `!alpc /p <port_address>` reveals ALPC port objects, pending messages, connected clients, and associated sections. Monitoring port handle counts and message queue depths helps identify potential lifetime issues. Watching for ports with unusually high pending message counts can indicate a denial-of-service condition or a reference leak in progress.

**Concurrency testing** through dedicated stress harnesses is essential. Creating multiple threads that simultaneously connect, send, receive, and disconnect on the same ALPC port stresses reference counting and state management code paths. The bugs this finds tend to be high-severity because race conditions in kernel object management typically produce use-after-free or double-free primitives.

**Patch diffing** on `ntoskrnl.exe` reveals ALPC fixes as reference count adjustments, lock acquisitions around attribute processing, or additional validation of message attribute fields. The ALPC-related functions are prefixed with `Alpc` in the kernel symbols, making them straightforward to isolate across patch versions.

**Impersonation auditing** monitors `NtAlpcSendWaitReceivePort` calls that include security attributes and verifies that token impersonation level and integrity checks are enforced correctly. A mismatch between the sender's privilege level and the impersonation token captured by the receiver indicates a potential privilege escalation path.

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

Because ALPC bugs tend to be concurrency and lifetime issues rather than simple buffer overflows, the most productive detection strategy combines patch diffing (to find the specific fix) with concurrency fuzzing (to find new instances of the same bug class). The combinatorial nature of ALPC attribute processing means that even after years of security attention, new attribute interaction bugs continue to surface. For the exploitation side of what happens after an ALPC bug gives you a corrupted object, see [pool spray](../primitives/exploitation/pool-spray-feng-shui.md) and the [use-after-free](../vuln-classes/use-after-free.md) vulnerability class.
