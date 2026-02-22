# Network Stack Drivers

Network stack drivers implement protocol handling, socket operations, and HTTP processing. They range from the TCP/IP stack to the Windows Sockets kernel helper (AFD) and the HTTP protocol handler.

## Architecture

- **Layered model**: NDIS miniport → Protocol drivers (tcpip.sys) → TDI/Winsock (afd.sys) → User-mode Winsock
- **Key subsystems**: TCP/IP stack, Ancillary Function Driver (AFD), HTTP Protocol Stack
- **IRP dispatch**: Socket IOCTLs (AFD), network protocol processing (tcpip.sys), HTTP request handling (http.sys)

## Attack Surface

### tcpip.sys — TCP/IP Stack
- **Remote attack surface**: IPv4/IPv6 packet processing, reassembly, option parsing
- **Key risk**: Integer underflow in packet reassembly length calculations
- **Reach**: Remotely triggerable — no authentication required

### afd.sys — Ancillary Function Driver
- **Local attack surface**: Winsock kernel helper — processes socket operations from user mode
- **Key risk**: Missing ProbeForWrite on user buffers, Registered I/O (RIO) buffer races
- **Reach**: Any user-mode process can create sockets

### http.sys — HTTP Protocol Stack
- **Remote attack surface**: HTTP request parsing, header handling, trailer processing
- **Key risk**: Uninitialized structures from crafted HTTP headers
- **Reach**: Remotely triggerable against IIS and HTTP.sys-based services

## Common Vulnerability Patterns

| Pattern | Description | AutoPiff Rules |
|---------|-------------|----------------|
| Integer underflow in reassembly | Packet length subtraction underflows | `safe_size_math_helper_added`, `alloc_size_overflow_check_added` |
| Missing ProbeForWrite | User pointer written without validation | `probe_for_read_or_write_added`, `added_probe_call` |
| UAF on async buffers | RIO buffer freed while still referenced | `added_refcount_guard`, `added_use_after_free_guard` |
| Uninitialized tracker struct | HTTP header parsing leaves fields uninitialized | `safe_string_function_replacement`, `unicode_string_length_validation_added` |
| Integer overflow in CMSG buffer | Control message buffer size overflows | `safe_size_math_helper_added`, `alloc_size_overflow_check_added` |

## CVEs

| CVE | Driver | Description | Class | ITW | Remote |
|-----|--------|-------------|-------|-----|--------|
| [CVE-2024-38063](../case-studies/CVE-2024-38063.md) | `tcpip.sys` | Integer underflow in IPv6 reassembly | Integer Overflow | No | **Yes** |
| [CVE-2024-38193](../case-studies/CVE-2024-38193.md) | `afd.sys` | UAF race on Registered I/O buffers | Use-After-Free | Yes | No |
| [CVE-2023-21768](../case-studies/CVE-2023-21768.md) | `afd.sys` | Missing ProbeForWrite allows kernel write | Write-What-Where | No | No |
| [CVE-2023-28218](../case-studies/CVE-2023-28218.md) | `afd.sys` | Integer overflow in AfdCopyCMSGBuffer | Integer Overflow | No | No |
| [CVE-2022-21907](../case-studies/CVE-2022-21907.md) | `http.sys` | Uninitialized tracker via crafted HTTP headers | Uninitialized Memory | No | **Yes** |

## Key Drivers

### tcpip.sys
- **Role**: Core TCP/IP protocol stack
- **Attack vector**: Remote — send crafted IPv6 packets
- **Note**: CVE-2024-38063 is a **remote code execution** with no user interaction

### afd.sys
- **Role**: Winsock kernel helper for socket operations
- **Attack vector**: Local — any process can create sockets and invoke AFD IOCTLs
- **Note**: 3 CVEs in corpus — AFD is a persistent target due to its large IOCTL surface and complex async I/O (Registered I/O)
- **Exploitation highlight**: CVE-2023-21768 was exploited via the I/O Ring primitive — write-what-where into I/O Ring registration buffer

### http.sys
- **Role**: Kernel-mode HTTP protocol handler for IIS and HTTP API
- **Attack vector**: Remote — send crafted HTTP requests
- **Note**: Exposed on any machine running IIS or HTTP.sys listeners
