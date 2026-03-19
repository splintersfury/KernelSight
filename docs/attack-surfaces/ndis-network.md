# NDIS / Network

Most kernel attack surfaces require the attacker to already have code execution on the target machine. The network stack is different. A crafted IPv6 packet sent across the internet can reach `tcpip.sys` and trigger a parsing vulnerability before any user on the target machine takes any action. CVE-2024-38063 demonstrated exactly this: an integer underflow in IPv6 packet reassembly achieved remote code execution with no authentication, no user interaction, and no special configuration, because IPv6 is enabled by default on every modern Windows installation. Network packet processing is the kernel's most exposed attack surface, and the one where a single bug carries the most impact.

The exposure is not limited to remote scenarios. Locally, the Winsock ancillary function driver `afd.sys` handles socket operations from user mode and has been patched for kernel vulnerabilities more often than nearly any other Windows component. Between the remote parsing surface of `tcpip.sys` and `http.sys` and the local socket management surface of `afd.sys`, the network stack offers attack surface at every privilege level and from every network position.

## How packets reach kernel code

``` mermaid
graph TD
    A["Network Wire\n(remote attacker)"] --> B["NIC Hardware"]
    B --> C["NDIS Miniport Driver\ne.g., e1i65x64.sys"]
    C --> D["NDIS LWF Drivers\n(packet inspection)"]
    D --> E["Protocol Driver\ntcpip.sys"]
    E --> F{"Protocol\nParsing"}
    F --> G["IPv4/IPv6 Header\nExtension Headers"]
    F --> H["TCP/UDP\nSegmentation"]
    F --> I["Fragment\nReassembly"]
    G --> J["Upper Layer\nafd.sys / http.sys"]
    H --> J
    I --> J
    K["Local Process\nWSASend / connect()"] --> L["afd.sys\nSocket Operations"]
    L --> E
    style I fill:#2d1b1b,stroke:#ef4444,color:#e2e8f0
    style G fill:#152a4a,stroke:#f59e0b,color:#e2e8f0
    style E fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
```

Network packets enter the kernel through NDIS miniport drivers that represent network interface hardware. The miniport driver receives raw frames from the NIC and indicates them up the stack as Net Buffer Lists (NBLs), the kernel data structure that describes a chain of network buffers with associated metadata. Between the miniport and protocol layers, NDIS Lightweight Filter (LWF) drivers can inspect and modify packets. Protocol drivers, primarily `tcpip.sys`, bind to miniport drivers and receive NBLs for protocol-level processing.

Each layer in this stack performs parsing on untrusted data, but the layers carry very different levels of risk. Miniport drivers parse hardware-specific frame formats and are typically only reachable from the local network segment. LWF drivers parse whatever they are designed to inspect, often for security products or network monitoring. Protocol drivers parse IP headers, extension headers, TCP/UDP segments, and perform fragment reassembly, all from data that arrives over the network from arbitrary sources.

### The TCP/IP stack: remote code execution surface

The TCP/IP stack (`tcpip.sys`) parses the most complex protocol headers from the least trusted source. IPv6 processing is particularly hazardous due to the extension header chain model. Each IPv6 extension header contains a "next header" field pointing to the subsequent header type, and the stack must parse variable-length options within each extension header. An attacker can construct a chain of extension headers with carefully chosen length values designed to trigger integer arithmetic errors in the parsing logic.

CVE-2024-38063 exploited exactly this pattern. The vulnerability was an integer underflow in IPv6 packet reassembly length calculation. When the stack reassembles fragmented IPv6 packets, it tracks the total reassembled length by subtracting header sizes from the fragment length fields. If a crafted fragment has a length field smaller than the expected header, the subtraction underflows, producing a very large value that causes a heap buffer overflow during the reassembly copy. The fix was a single bounds check, but the impact was remote code execution at the kernel level with no prerequisites on the attacker's side.

Fragment reassembly is a recurring vulnerability source across all IP stacks, not just Windows. The core problem is that the reassembly logic must handle overlapping fragments, out-of-order arrival, fragments with contradictory total-length fields, and timeout-based cleanup of incomplete reassembly queues. Each of these edge cases involves integer arithmetic on attacker-controlled values, and each has produced vulnerabilities in production code.

### HTTP in the kernel: http.sys

The HTTP protocol stack (`http.sys`) adds another remotely reachable parsing layer with its own distinct characteristics. It processes HTTP request headers, trailers, and content-encoding in kernel mode for performance, serving requests for any service using the HTTP Server API (IIS, WinRM, SSDP, and many other Windows components). CVE-2022-21907 demonstrated remote code execution through crafted HTTP trailer parsing, where a malformed trailer field caused incorrect buffer sizing during kernel-mode HTTP processing.

The decision to parse HTTP in kernel mode was a performance optimization that traded attack surface for throughput. Every header field, every content-encoding value, every transfer-encoding chunk size is parsed by kernel code from network data. A bug in any of these parsing paths is a remotely exploitable kernel vulnerability on any server running IIS or WinRM, which includes most Windows Server deployments.

### The local socket surface: afd.sys

The Winsock ancillary function driver (`afd.sys`) handles socket operations from user mode and represents the network stack's local privilege escalation surface. It processes IOCTL requests for socket creation, binding, connection, and data transfer, and its internal buffer management involves complex chain operations on I/O request structures.

CVE-2024-38193 was a use-after-free in `afd.sys` Winsock handling, and CVE-2023-21768 was a missing validation in an AFD IOCTL that enabled an arbitrary kernel write. These bugs follow the same patterns described in [IOCTL handlers](ioctl-handlers.md), but `afd.sys` is a particularly rich target because of the sheer complexity of socket state management: every socket has multiple state variables (bound, connected, listening, closing), and the transitions between these states must be synchronized against concurrent operations from multiple threads and against network events arriving asynchronously.

### OID requests: the configuration surface

NDIS Object Identifier (OID) requests function similarly to IOCTLs, allowing user-mode configuration of miniport driver parameters via `DeviceIoControl` to the NDIS device object. Each OID carries an `InformationBuffer` and `InformationBufferLength`, and the miniport driver must validate the buffer size before accessing it. The same missing-size-check patterns that produce IOCTL vulnerabilities produce OID vulnerabilities, but OID handlers receive less security scrutiny because they are perceived as a configuration interface rather than a data processing interface.

WiFi and WLAN drivers add a further dimension. 802.11 management frame processing in `nwifi.sys` and vendor WiFi drivers parses information elements (IEs) from wireless frames. Each IE has a type and length field, and the driver must validate the length before copying the IE data. Insufficient IE length validation has produced out-of-bounds reads and writes in wireless drivers, reachable over the air by any device in radio range.

## Detection approaches

**Remote fuzzing** sends crafted packets to a target system using tools like Scapy or custom packet generators. The focus should be on IPv6 extension header chains, fragmentation edge cases (overlapping fragments, fragments with contradictory totals, very small fragments), and protocol-specific fields. Monitor the target with kernel debugging attached for pool corruption or bugchecks. Remote fuzzing is the only testing approach that validates the full remote attack scenario end to end.

**HTTP fuzzing** sends malformed HTTP requests to systems running `http.sys`, emphasizing unusual header combinations, trailer fields, and content-encoding values. The key is to test the parsing paths that handle edge cases in the HTTP specification, particularly transfer-encoding chunking, trailer fields after chunked data, and content-length mismatches. These are the paths where `http.sys` vulnerabilities have historically lived.

**OID fuzzing** enumerates supported OIDs via `NdisOidRequest` and fuzzes the `InformationBuffer` with varying sizes and contents. The approach is identical to IOCTL fuzzing: enumerate the supported codes, then send requests with zero-length buffers, undersized buffers, oversized buffers, and boundary-value sizes for each code.

**Static analysis** traces packet receive paths from miniport indication through protocol dispatch. The critical analysis target is length arithmetic: identify all subtractions from packet length variables and verify that underflow checks exist. A subtraction without a preceding comparison is a candidate for integer underflow. In `tcpip.sys`, the IPv6 extension header parsing functions and the fragment reassembly functions are the highest-value targets.

**Coverage-guided kernel fuzzing** through tools like kAFL or Syzkaller with NDIS-aware syscall descriptions systematically explores socket operations and raw packet injection paths. The coverage feedback helps reach deep parsing states that random fuzzing struggles to find, particularly in the TCP state machine and fragment reassembly queue management.

**Patch diffing** on network stack components is highly productive because the patches are typically surgical: a single bounds check or integer overflow guard added to a parsing routine. Comparing consecutive versions of `tcpip.sys`, `http.sys`, and `afd.sys` through [AutoPiff](../tooling/autopiff-integration.md) identifies the exact function and offset where the vulnerability existed.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-38063](../case-studies/CVE-2024-38063.md) | `tcpip.sys` | Integer underflow in IPv6 packet reassembly enables remote code execution |
| [CVE-2022-21907](../case-studies/CVE-2022-21907.md) | `http.sys` | Remote code execution via crafted HTTP trailer parsing |
| [CVE-2024-38193](../case-studies/CVE-2024-38193.md) | `afd.sys` | Use-after-free in ancillary function driver Winsock handling |
| [CVE-2023-21768](../case-studies/CVE-2023-21768.md) | `afd.sys` | Missing validation in AFD IOCTL enables arbitrary kernel write |
| [CVE-2024-30088](../case-studies/CVE-2024-30088.md) | `ntoskrnl.exe` | Race condition in kernel I/O operation exploitable via network socket operations |

## AutoPiff Detection

- `oid_request_validation_added` -- OID request `InformationBuffer` size validation added in miniport driver
- `nbl_chain_length_validation_added` -- NBL chain `DataLength` bounds check added against actual MDL byte count
- `packet_header_length_check_added` -- Packet header or extension header length validation added to prevent integer underflow
- `reassembly_size_limit_added` -- Maximum reassembled datagram size check added to fragmentation handling
- `http_header_validation_added` -- HTTP header or trailer field validation added to `http.sys` request parsing

The network attack surface connects to nearly every other part of the KernelSight knowledge base. Packet parsing overflows lead to [heap overflow](../vuln-classes/buffer-overflow.md) exploitation through [pool spray](../primitives/exploitation/pool-spray-feng-shui.md). Socket management bugs in `afd.sys` produce [use-after-free](../vuln-classes/use-after-free.md) conditions. And because the network stack is remotely reachable, even moderate-severity bugs receive intense attacker interest, making patch diffing on network components one of the highest-return activities for both offensive and defensive research.
