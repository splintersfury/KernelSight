# NDIS / Network

Network Driver Interface Specification drivers and the TCP/IP stack provide kernel attack surface through network packet processing, with some vulnerabilities reachable remotely without authentication.

## Attack Surface Overview

- **Entry points**: NDIS miniport `MiniportSendNetBufferLists` / `MiniportReturnNetBufferLists`, protocol driver receive handlers, OID request handlers (`MiniportOidRequest`), and lightweight filter (LWF) `FilterReceiveNetBufferLists` callbacks
- **Protocol parsing**: The TCP/IP stack (`tcpip.sys`) parses IPv4, IPv6, TCP, UDP, ICMP, and extension headers from raw network data
- **HTTP parsing**: The HTTP protocol stack (`http.sys`) parses HTTP request and response headers in kernel mode for IIS and HTTP-based services
- **Remote reachability**: Packet parsing vulnerabilities in `tcpip.sys` or `http.sys` can be triggered by sending crafted packets over the network without any authentication or user interaction
- **Local reachability**: Raw sockets, loopback traffic, and Winsock API calls trigger kernel-side packet construction and parsing in `afd.sys` and `tcpip.sys`
- **OID interface**: NDIS Object Identifier (OID) requests function similarly to IOCTLs, allowing user-mode configuration of miniport driver parameters via `DeviceIoControl` to the NDIS device object
- **Key risk**: Integer arithmetic errors in packet length calculations during reassembly and header parsing, especially in IPv6 extension header chains with attacker-controlled length fields

## Mechanism Deep-Dive

Network packets enter the kernel through NDIS miniport drivers that represent network interface hardware. The miniport driver receives raw frames from the NIC and indicates them up the stack as Net Buffer Lists (NBLs). Protocol drivers such as `tcpip.sys` bind to miniport drivers and receive these NBLs for protocol-level processing. Between the miniport and protocol layers, NDIS Lightweight Filter (LWF) drivers can inspect and modify packets. Each of these layers performs parsing of packet data and represents a potential attack surface.

The TCP/IP stack is the most critical component because it parses complex protocol headers from untrusted network data. IPv6 processing is particularly dangerous due to the extension header chain model, where each header contains a "next header" field pointing to the subsequent header type, and the stack must parse variable-length options within each extension header. The CVE-2024-38063 vulnerability demonstrated that an integer underflow in IPv6 packet reassembly length calculation could be triggered remotely by sending specially crafted IPv6 packets, achieving remote code execution without any user interaction. This class of vulnerability is especially severe because IPv6 is enabled by default on all modern Windows installations and the attack requires no authentication.

The HTTP protocol stack (`http.sys`) adds another remotely reachable parsing layer. It processes HTTP request headers, trailers, and content-encoding in kernel mode for performance, meaning malformed HTTP requests directed at any service using the HTTP Server API can trigger kernel vulnerabilities. The CVE-2022-21907 vulnerability in HTTP trailer parsing allowed remote code execution via a crafted HTTP request. Since `http.sys` is used by IIS, WinRM, SSDP, and many other Windows components, the exposure is broad on server systems.

Locally, the Winsock ancillary function driver `afd.sys` handles socket operations from user mode and has been a persistent source of local privilege escalation vulnerabilities. It processes complex IOCTL requests for socket creation, binding, connection, and data transfer, and its internal buffer management involves intricate chain operations on I/O request structures. The combination of complex state management and direct user-mode reachability makes `afd.sys` one of the most frequently patched Windows kernel components.

## Common Vulnerability Patterns

- **Integer underflow in packet length**: Packet reassembly code subtracts header lengths from a total length field without checking for underflow, resulting in a very large allocation or buffer overflow
- **IPv6 extension header chain parsing**: Malformed next-header values or option lengths cause the parser to read beyond the actual packet data or miscalculate total header length
- **Fragmentation reassembly overflow**: Overlapping fragment offsets or total reassembled size exceeding the original datagram length field lead to heap buffer overflows
- **OID request buffer validation**: NDIS miniport OID handlers cast `InformationBuffer` without checking `InformationBufferLength`, similar to IOCTL buffer validation failures
- **NBL chain length mismatch**: `NET_BUFFER_LIST` `DataLength` field does not match the actual number of bytes described by the chained MDLs, causing over-read or over-write
- **HTTP header parsing**: Malformed content-length, transfer-encoding, or trailer fields in `http.sys` cause incorrect buffer sizing for kernel-mode HTTP processing
- **WiFi/WLAN frame parsing**: 802.11 management frame processing in `nwifi.sys` and vendor WiFi drivers with insufficient information element (IE) length validation
- **TCP option parsing**: Malformed TCP option lengths or types cause out-of-bounds reads during connection setup or data processing
- **Checksum offload mismatch**: Disagreement between driver-reported checksum offload capabilities and actual NIC behavior leads to unvalidated data being passed up the stack

## Driver Examples

The core TCP/IP stack `tcpip.sys` is the primary remote attack surface and handles all IPv4/IPv6 packet processing. `http.sys` provides kernel-mode HTTP parsing for IIS and HTTP-based services. `afd.sys` is the Winsock kernel helper and a frequent local privilege escalation target. NDIS miniport drivers for specific NICs (Intel `e1i65x64.sys`, Realtek `rt640x64.sys`, Broadcom `b57nd60a.sys`) handle OID requests and sometimes perform packet processing in hardware-offload paths. `nwifi.sys` and vendor WiFi drivers parse 802.11 management and data frames. VPN drivers such as `vpnva64.sys` (Cisco AnyConnect) and `netvsc.sys` (Hyper-V network) add kernel-mode packet encapsulation/decapsulation. `tdx.sys` and `netio.sys` handle transport and network I/O layer operations respectively.

## Detection Approach

- **Remote fuzzing**: Send crafted packets to a target system using tools like Scapy or custom packet generators. Focus on IPv6 extension header chains, fragmentation edge cases, and protocol-specific fields. Monitor the target with kernel debugging attached for pool corruption or bugchecks.
- **HTTP fuzzing**: Send malformed HTTP requests to systems running `http.sys` with emphasis on unusual header combinations, trailer fields, and content-encoding values. Use HTTP fuzzing frameworks against the `HttpReceiveHttpRequest` code path.
- **OID fuzzing**: Enumerate supported OIDs via `NdisOidRequest` and fuzz the `InformationBuffer` with varying sizes and contents, similar to IOCTL fuzzing.
- **Static analysis**: Trace packet receive paths from miniport indication through protocol dispatch. Focus on length arithmetic -- identify all subtractions from packet length variables and verify underflow checks exist.
- **Coverage-guided kernel fuzzing**: Tools like kAFL or Syzkaller with NDIS-aware syscall descriptions can systematically explore socket operations and raw packet injection paths.
- **Patch diffing**: Network stack patches frequently add bounds checks or integer overflow guards in parsing routines and are detectable through binary comparison of `tcpip.sys`, `http.sys`, and `afd.sys`.

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
