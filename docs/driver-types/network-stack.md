# Network Stack Drivers

<div class="ks-pipeline-pos">
  <span class="ks-active">Driver Type</span> &rarr; Attack Surface &rarr; Vuln Class &rarr; Primitive &rarr; Case Study
</div>

In August 2024, Microsoft patched CVE-2024-38063, an integer underflow in tcpip.sys that allowed remote code execution via crafted IPv6 packets. No authentication, no user interaction, no local access required. The attacker sends packets; the kernel parses them; the machine is compromised. Network stack drivers are the only driver category in the KernelSight corpus that includes a genuinely remote, pre-authentication kernel attack surface, and that distinction makes them fundamentally different from every other category on this page.

The Windows network stack spans three major components: the TCP/IP protocol driver (tcpip.sys) that processes packets from the wire, the Ancillary Function Driver (afd.sys) that implements the kernel side of Winsock for local socket operations, and the HTTP protocol stack (http.sys) that parses HTTP requests in kernel mode for IIS and HTTP.sys-based services. Each has a distinct threat model, but they share a common characteristic: they process untrusted data at high speed under tight performance constraints, and the code prioritizes throughput over defensive validation.

## Architecture

The Windows network stack is a layered architecture where each driver handles a specific level of abstraction.

``` mermaid
graph TD
    A["Remote Attacker<br/>Crafted Packets"] -->|"Wire"| B["NDIS Miniport<br/>NIC Driver"]
    B --> C["tcpip.sys<br/>TCP/IP Protocol Stack"]
    C --> D["afd.sys<br/>Winsock Kernel Helper"]
    D --> E["User Mode<br/>Winsock Application"]
    A2["Remote Attacker<br/>HTTP Requests"] -->|"Wire"| B
    B --> C
    C --> F["http.sys<br/>HTTP Protocol Stack"]
    F --> G["User Mode<br/>IIS / HTTP API"]

    style A fill:#0d1320,stroke:#ef4444,color:#e2e8f0
    style A2 fill:#0d1320,stroke:#ef4444,color:#e2e8f0
    style B fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    style C fill:#152a4a,stroke:#3b82f6,color:#e2e8f0
    style D fill:#152a4a,stroke:#3b82f6,color:#e2e8f0
    style E fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    style F fill:#152a4a,stroke:#3b82f6,color:#e2e8f0
    style G fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
```

At the bottom, NDIS miniport drivers interface with network hardware. Above them, tcpip.sys implements the full TCP/IP protocol stack, including IPv4/IPv6 packet processing, reassembly, option parsing, and routing. The Ancillary Function Driver (afd.sys) sits between tcpip.sys and user-mode Winsock, translating socket API calls into kernel operations. On servers, http.sys provides kernel-mode HTTP request parsing that feeds IIS and other HTTP.sys-based services.

## Attack Surfaces by Component

### tcpip.sys: Remote Pre-Auth Kernel Attack Surface

The TCP/IP stack processes every packet that arrives at the network interface. IPv6 packet reassembly, extension header parsing, and option processing all operate on untrusted data from the wire. The code performs arithmetic on header length fields to calculate buffer sizes and offsets, and these calculations are the primary vulnerability surface.

CVE-2024-38063 demonstrates the risk precisely. During IPv6 packet reassembly, tcpip.sys subtracts a header length value from a total length value. When the header length exceeds the total length, the subtraction underflows, producing a large positive value that the driver uses as a buffer size. The result is a massive out-of-bounds operation. This bug is remotely triggerable by any host that can send IPv6 packets to the target, with no authentication and no user interaction. It is about as severe as a kernel vulnerability gets.

### afd.sys: Local Socket Operations

The Ancillary Function Driver is the kernel-side implementation of Winsock. Any user-mode process that creates a socket interacts with afd.sys through a set of IOCTLs that manage socket state, send/receive operations, and buffer management. Three CVEs in the corpus target afd.sys, reflecting its large IOCTL surface and complex asynchronous I/O handling.

CVE-2024-38193 is a use-after-free race condition in Registered I/O (RIO) buffer management. RIO is a high-performance I/O API that allows user-mode code to register memory buffers for direct kernel access. The race occurs when a buffer is freed while an asynchronous operation still holds a reference to it. The Lazarus Group exploited this bug in the wild.

CVE-2023-21768 is a missing `ProbeForWrite` on a user-mode buffer. The IOCTL handler writes to a caller-supplied pointer without first verifying that the pointer is in user-mode address space. This gives the attacker a write-what-where primitive: they pass a kernel address as the output buffer, and the driver writes attacker-controlled data to it. The subsequent exploitation used the I/O Ring primitive to convert this into full kernel read/write.

CVE-2023-28218 is an integer overflow in the control message (CMSG) buffer size calculation. When `AfdCopyCMSGBuffer` computes the total size of ancillary data to copy, the multiplication overflows, producing a small allocation that receives a large copy.

### http.sys: Remote HTTP Parsing

The kernel-mode HTTP protocol stack parses HTTP requests before they reach user-mode server applications. On any machine running IIS or using the HTTP Server API, http.sys processes request lines, headers, and trailers from the network.

CVE-2022-21907 exploits uninitialized memory in HTTP trailer processing. When http.sys parses a crafted HTTP request with specific header combinations, an internal tracker structure is left partially uninitialized. The uninitialized fields contain stale data from previous kernel allocations, which can include kernel pointers or other sensitive values. This is remotely triggerable against any HTTP.sys listener.

## Vulnerability Patterns and Detection

| Pattern | Description | AutoPiff Rules |
|---------|-------------|----------------|
| Integer underflow in reassembly | Packet length subtraction underflows | `safe_size_math_helper_added`, `alloc_size_overflow_check_added` |
| Missing ProbeForWrite | User pointer written without validation | `probe_for_read_or_write_added`, `added_probe_call` |
| UAF on async buffers | RIO buffer freed while still referenced | `added_refcount_guard`, `added_use_after_free_guard` |
| Uninitialized tracker struct | HTTP header parsing leaves fields uninitialized | `safe_string_function_replacement`, `unicode_string_length_validation_added` |
| Integer overflow in CMSG buffer | Control message buffer size overflows | `safe_size_math_helper_added`, `alloc_size_overflow_check_added` |

The network stack CVEs span four different vulnerability classes (integer overflow, UAF, write-what-where, uninitialized memory), which makes this category more diverse in its bug types than most. The common thread is not a specific memory corruption pattern but rather the general challenge of processing untrusted data under performance pressure.

## CVEs

| CVE | Driver | Description | Class | ITW | Remote |
|-----|--------|-------------|-------|-----|--------|
| [CVE-2024-38063](../case-studies/CVE-2024-38063.md) | `tcpip.sys` | Integer underflow in IPv6 reassembly | Integer Overflow | No | **Yes** |
| [CVE-2024-38193](../case-studies/CVE-2024-38193.md) | `afd.sys` | UAF race on Registered I/O buffers | Use-After-Free | Yes | No |
| [CVE-2023-21768](../case-studies/CVE-2023-21768.md) | `afd.sys` | Missing ProbeForWrite allows kernel write | Write-What-Where | No | No |
| [CVE-2023-28218](../case-studies/CVE-2023-28218.md) | `afd.sys` | Integer overflow in AfdCopyCMSGBuffer | Integer Overflow | No | No |
| [CVE-2022-21907](../case-studies/CVE-2022-21907.md) | `http.sys` | Uninitialized tracker via crafted HTTP headers | Uninitialized Memory | No | **Yes** |

## Research Outlook

The network stack presents two distinct research opportunities. For remote kernel exploitation, tcpip.sys and http.sys are the targets. IPv6 processing in tcpip.sys is particularly interesting because IPv6 has more complex extension header handling than IPv4, creating more opportunities for arithmetic errors in length calculations. http.sys exposes a large HTTP parsing surface that is enabled by default on Windows Server installations.

For local privilege escalation, afd.sys is the workhorse. Its large IOCTL surface, complex async I/O model (especially Registered I/O), and the fact that any process can create sockets make it a persistent target. The three CVEs in the corpus show three different bug classes in the same driver, suggesting that afd.sys has enough complexity to produce diverse vulnerability types.

The interaction between network stack drivers and other kernel components creates additional attack surface. For example, afd.sys interacts with the I/O Manager for IRP completion, with the memory manager for MDL operations, and with the pool allocator for buffer management. Bugs at these boundaries, like the missing ProbeForWrite in CVE-2023-21768, often fall through the cracks of component-focused code reviews.

For the broader context of how IOCTL-based attack surfaces work, see [Attack Surfaces](../attack-surfaces/). For the exploitation primitives used after achieving a write-what-where or UAF, see [Primitives](../primitives/).
