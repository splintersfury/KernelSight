# NDIS / Network Drivers

NDIS miniport, protocol, and filter drivers handle network packets and OID requests. The TCP/IP stack (`tcpip.sys`) processes protocol-level input from the network.

## Attack Surface Overview

- **Entry points**: OID requests, send/receive NBL chains, protocol handlers
- **Remote reach**: Some vulnerabilities (e.g., IPv6 parsing) are remotely triggerable
- **Key risk**: Complex packet reassembly and header parsing with size arithmetic

## Common Vulnerability Patterns

- Integer underflow in packet length calculations during reassembly
- Missing OID InformationBuffer NULL/length checks
- NBL chain DATA_LENGTH vs actual MDL byte count mismatch
- Buffer overflows in protocol header parsing

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-38063](../case-studies/CVE-2024-38063.md) | `tcpip.sys` | Integer underflow in IPv6 reassembly (RCE) |

## AutoPiff Detection

- `oid_request_validation_added` — OID request validation added
- `nbl_chain_length_validation_added` — NBL chain bounds check added
