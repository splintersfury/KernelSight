# Storage / Caching Drivers

<div class="ks-pipeline-pos">
  <span class="ks-active">Driver Type</span> &rarr; Attack Surface &rarr; Vuln Class &rarr; Primitive &rarr; Case Study
</div>

Sometimes the most dangerous bugs are the simplest ones. CVE-2024-26229 in csc.sys is a single missing access check: the IOCTL handler does not verify whether the caller is a kernel-mode or user-mode caller before performing a privileged operation. No heap overflow, no race condition, no integer arithmetic gone wrong. Just an `if` statement that should have been there and was not. The exploitation path from this missing check to SYSTEM is elegant: PreviousMode manipulation gives the attacker unrestricted access to `NtReadVirtualMemory` and `NtWriteVirtualMemory`, which provides arbitrary kernel read/write without ever corrupting memory.

## What csc.sys Does

The Client-Side Caching (CSC) driver implements the Offline Files feature in Windows. When a user accesses files on a network share, csc.sys maintains a local cache so that the files remain available when the network connection is lost. The driver interacts with the SMB redirector to synchronize cached files with the remote server, and it exposes an IOCTL interface for cache management operations like flushing, invalidating, and querying cached file metadata.

CSC is a WDM driver loaded as a kernel-mode service. It creates a device object that applications (primarily the Offline Files service) interact with through `DeviceIoControl`. The intended caller is the system service running at elevated privileges, but the device object's security descriptor and the IOCTL handler's access validation determine who can actually send IOCTLs to the driver.

## The Missing Access Check

The vulnerability in CVE-2024-26229 is conceptually simple. When the IOCTL handler receives a request, it should check the `RequestorMode` (also known as `PreviousMode`) of the calling thread to determine whether the request originated from kernel mode or user mode. Kernel-mode callers are trusted; user-mode callers are not. The handler in csc.sys skips this check for a specific IOCTL, treating all callers as trusted regardless of their origin.

This matters because the IOCTL performs operations that should only be available to kernel-mode callers. By sending the IOCTL from user mode, an attacker can trigger the privileged operation and manipulate kernel state that should be inaccessible.

The exploitation chain leverages this missing check in a particularly clever way. The attacker uses the IOCTL to manipulate the `PreviousMode` value of their own thread. Once `PreviousMode` is set to `KernelMode`, all subsequent `Nt*` system calls from that thread bypass the user/kernel access checks. Specifically, `NtReadVirtualMemory` and `NtWriteVirtualMemory` will operate on any address, including kernel addresses, because the security check assumes the caller is the kernel itself. This gives the attacker a clean arbitrary read/write primitive without any memory corruption.

From there, the path to SYSTEM is standard: read the current process's token pointer from the `EPROCESS` structure, read a SYSTEM token from a known SYSTEM process, and overwrite the current token pointer with the SYSTEM token.

## Vulnerability Patterns and Detection

| Pattern | Description | AutoPiff Rules |
|---------|-------------|----------------|
| Missing access check | Privileged IOCTL callable without proper authorization | `added_access_check`, `added_previous_mode_gate`, `added_privilege_check` |

The AutoPiff detection rules for this pattern are straightforward: the patch adds a check for `PreviousMode` or an explicit access validation call that was not present in the vulnerable version. This is one of the most reliable patch diffing signals because adding an access check to an IOCTL handler is almost never done for any reason other than fixing a missing authorization vulnerability.

## CVEs

| CVE | Driver | Description | Class | ITW |
|-----|--------|-------------|-------|-----|
| [CVE-2024-26229](../case-studies/CVE-2024-26229.md) | `csc.sys` | Missing access check allows EoP | Logic Bug | No |

## Key Drivers

### csc.sys (Client-Side Caching)

The Offline Files / Client-Side Caching driver is a WDM driver that creates a device object accessible through `DeviceIoControl`. Its IOCTL surface is relatively small compared to drivers like afd.sys or ks.sys, but the impact of a missing access check is just as severe because the resulting PreviousMode manipulation provides a universal privilege escalation primitive.

The exploitation technique used for CVE-2024-26229, manipulating PreviousMode to unlock unrestricted NtReadVirtualMemory/NtWriteVirtualMemory access, is worth studying independently of the specific driver. It demonstrates that logic bugs with no memory corruption can be just as powerful as complex heap overflow chains, and often more reliable because there is no heap state to groom and no race to win.

## Research Outlook

Storage and caching drivers are an underexplored category. Most kernel security research focuses on the high-profile targets: Win32k, CLFS, the network stack. But drivers like csc.sys sit quietly in the kernel, exposing IOCTL interfaces that were designed for trusted system services and may not have been audited with the same rigor as more prominent components.

The lesson from CVE-2024-26229 generalizes: any kernel driver that exposes IOCTLs should be audited for PreviousMode / RequestorMode checking. If the IOCTL handler performs operations that depend on the caller being in kernel mode, and the handler does not verify this, the result is a logic bug that provides privilege escalation without memory corruption. This audit is simple to perform (grep for the IOCTL dispatch table and check each handler for access validation) and the payoff is high when a gap is found.

For the broader discussion of IOCTL access control patterns, see [Attack Surfaces](../attack-surfaces/). For the PreviousMode exploitation technique, see [Primitives](../primitives/).
