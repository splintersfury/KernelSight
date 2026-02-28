# AFD Attack Surface Deep-Dive

The Ancillary Function Driver for WinSock has 13 CVEs in the KernelSight corpus -- the highest count of any single driver.

## Overview

The Ancillary Function Driver (`afd.sys`) is the kernel-mode component of the Windows Sockets (WinSock) subsystem. It sits between the user-mode `ws2_32.dll` and the transport layer (TDI/WSK), handling socket lifecycle, buffer management, and I/O completion. Every networked Windows application touches afd.sys. Its complexity, concurrency, and direct exposure to user-mode input keep drawing local privilege escalation bugs.

## Architecture

### Key Components

- **Socket Objects** -- Kernel structures representing open sockets. Tracked via file objects, accessible through handles. Each socket carries state for connection, buffer tracking, and pending I/O.
- **TDI / WSK Interface** -- The Transport Driver Interface (legacy) and WinSock Kernel interface connect afd.sys to transport protocol drivers like tcpip.sys. AFD translates user-mode socket operations into TDI/WSK calls.
- **Registered I/O (RIO)** -- A high-performance I/O model introduced in Windows 8 that uses pre-registered buffers and completion queues. RIO paths share memory between user and kernel mode, which makes lifetime management harder.
- **Notification System** -- AfdNotifyPostEvents and related functions manage asynchronous event delivery to user-mode. This is the subsystem where race conditions cluster.
- **I/O Completion** -- AFD uses I/O completion ports for async operations. Pending IRPs reference socket objects and buffers that must remain valid through completion.

### Data Flow

```
User-Mode:  WSASocket() → connect() → send()/recv() → closesocket()
                ↓              ↓            ↓                ↓
Kernel:     AfdCreate    AfdConnect   AfdSend/Recv    AfdCleanup
                ↓              ↓            ↓                ↓
Transport:  TdiOpen      TdiConnect   TdiSend/Recv    TdiClose
```

## Why AFD Is A Top Target

1. **Universal reach.** Every process that opens a network socket interacts with afd.sys. No special privileges needed to trigger most code paths -- just call standard socket APIs.

2. **High concurrency.** Socket operations are asynchronous. Multiple threads can race on bind, unbind, send, receive, and close at the same time. AFD must manage object lifetimes across all these paths.

3. **Complex buffer lifetime.** Registered I/O pre-registers user buffers for kernel use. The kernel must track buffer validity across async operations that can complete out of order. Get this wrong and you get use-after-free.

4. **Large IOCTL surface.** AFD exposes dozens of internal IOCTLs beyond the standard socket API. Some of these (Registered I/O registration, notification management) have less testing coverage than core socket operations.

5. **Legacy code.** Parts of afd.sys date back to Windows NT 3.5. TDI is deprecated but still present. Later additions (RIO, notification changes) layer on top of old code with no full redesign.

## CVE Timeline

| CVE | Year | Class | ITW | Notes |
|-----|------|-------|-----|-------|
| CVE-2023-21768 | 2023 | Missing ProbeForWrite | No | WinSock IO ring write-what-where |
| CVE-2023-28218 | 2023 | Integer Overflow | No | AfdCopyCMSGBuffer overflow |
| CVE-2024-38193 | 2024 | UAF / Lifetime | Yes | Registered I/O buffer race, Lazarus Group |
| CVE-2025-21418 | 2025 | Buffer Overflow (Heap) | Yes | Heap overflow allowing SYSTEM |
| CVE-2025-32709 | 2025 | UAF | Yes | Socket closure UAF |
| CVE-2025-49661 | 2025 | Untrusted Pointer | No | Pointer dereference in IOCTL handler |
| CVE-2025-49762 | 2025 | Race Condition | No | Concurrent operation race |
| CVE-2025-53147 | 2025 | UAF | No | Object lifetime error |
| CVE-2025-53718 | 2025 | UAF | No | Object lifetime error |
| CVE-2025-60719 | 2025 | UAF / Race | No | Socket unbind race |
| CVE-2025-62213 | 2025 | UAF | No | Object lifetime error |
| CVE-2025-62217 | 2025 | EoP | No | Elevation of privilege |
| CVE-2026-21241 | 2026 | UAF / Race | No | AfdNotifyPostEvents spinlock race |

## Common Vulnerability Patterns

### Socket Teardown Races

The most common pattern -- 7 of 13 CVEs. One thread closes or unbinds a socket while another thread still uses the socket object or its buffers. The close path frees the object; the concurrent path dereferences a stale pointer. The race window is typically between spinlock release and object deallocation.

[CVE-2026-21241](CVE-2026-21241.md) is a clear example: the notification spinlock is released before the notification object is fully torn down, so a concurrent AfdNotifyPostEvents call can hit freed memory.

### Buffer Length Validation Failures

The driver accepts a user-supplied length or size without validating it against the actual buffer allocation. [CVE-2025-21418](CVE-2025-21418.md) is a heap overflow from an unchecked length field. [CVE-2023-28218](CVE-2023-28218.md) is an integer overflow in CMSG buffer size calculation.

### Missing User Buffer Validation

[CVE-2023-21768](CVE-2023-21768.md) is a missing `ProbeForWrite` on an I/O ring buffer pointer. Without the probe, the kernel writes to a user-controlled address -- a direct write-what-where primitive.

### Registered I/O Lifetime Management

RIO buffers are pre-registered with the kernel for performance. If a buffer is deregistered while an async operation still references it, the kernel hits freed memory. [CVE-2024-38193](CVE-2024-38193.md) exploited this -- the Lazarus Group used it for SYSTEM escalation.

## Exploitation Pattern

A typical afd.sys exploitation chain:

1. Create a socket using `WSASocket()` to allocate the kernel socket object
2. Set up concurrent threads -- one to trigger the vulnerable operation, one to race the close/unbind path
3. Win the race to create a use-after-free condition on the socket or notification object
4. Spray the freed pool region with controlled data using named pipe attributes (NPNX pool spray)
5. The stale pointer dereference now reads attacker-controlled data, typically a corrupted `_IO_MINI_COMPLETION_PACKET_USER` structure
6. Use the corrupted structure to get a bit-manipulation or arbitrary R/W primitive -- [CVE-2026-21241](CVE-2026-21241.md) uses `RtlSetBit`/`RtlClearAllBits` as kCFG-compliant primitives
7. Escalate via token swap, privilege bit-set, or DACL corruption to get SYSTEM

## Mitigations

Microsoft has fixed individual afd.sys vulnerabilities with incremental patches -- extending spinlock scope, adding reference counting, tightening buffer validation. No structural redesign has been announced. The driver's concurrency model remains the same across all supported Windows versions.

The [Vulnerable Driver Blocklist](../reference/byovd.md) does not apply to afd.sys since it ships inbox. HVCI and kCFG constrain exploitation techniques but do not prevent the underlying bugs. The [bit-manipulation primitive](../primitives/exploitation/bit-manipulation.md) from CVE-2026-21241 shows that exploitation still works under kCFG.

## AutoPiff Detection

AutoPiff monitors `afd.sys` patches for synchronization and lifetime changes:

- `added_spinlock_acquire` -- New spin lock acquisition around previously unprotected state access
- `modified_object_free` -- Changes to socket or buffer deallocation paths, indicating lifetime fix
- `added_ref_count` -- Reference counting additions to object management code
- `added_length_check` -- Buffer size validation in IOCTL handlers

## Related Case Studies

- [CVE-2026-21241](CVE-2026-21241.md) -- notification UAF with bit-manipulation primitive
- [CVE-2024-38193](CVE-2024-38193.md) -- Registered I/O UAF, Lazarus Group campaign
- [CVE-2025-21418](CVE-2025-21418.md) -- heap overflow, exploited ITW
- [CVE-2025-32709](CVE-2025-32709.md) -- socket closure UAF, exploited ITW
- [CVE-2023-21768](CVE-2023-21768.md) -- missing ProbeForWrite, I/O ring write-what-where

## References

- [Microsoft WinSock Architecture](https://learn.microsoft.com/en-us/windows/win32/winsock/about-winsock)
- [Registered I/O Documentation](https://learn.microsoft.com/en-us/windows/win32/winsock/registered-i-o)
- [Lazarus APT afd.sys Exploitation (Gen Digital)](https://www.gendigital.com/blog/lazarus-apt-exploits-windows-zero-day)
