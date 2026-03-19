---
description: "9 Windows kernel attack surfaces — IOCTL handlers, filesystem IRPs, NDIS/network, PnP/Power, WDF/KMDF, registry callbacks, ALPC, shared memory, and WMI/ETW entry points."
---

# Attack Surfaces

<div class="ks-pipeline-pos">
  Driver Type &rarr; <span class="ks-active">Attack Surface</span> &rarr; Vuln Class &rarr; Primitive &rarr; Case Study
</div>

A kernel exploit begins with a question that sounds simple but carries enormous consequences: how does user-mode code reach the vulnerable driver? The answer determines everything that follows. It dictates what data the attacker controls, how much of it they control, what validation (if any) sits between them and the bug, and whether the vulnerability is reachable from a sandbox, a low-integrity process, or even a remote machine with no authentication at all.

Windows kernel drivers do not expose a single entry point. They expose many, and each one operates under different rules. An IOCTL handler receives structured input buffers through `DeviceIoControl` with attacker-controlled sizes. A filesystem minifilter parses reparse data buffers embedded in on-disk structures that might arrive on a USB stick. A network protocol driver reassembles fragmented IPv6 packets from the wire. An ALPC message carries multiple attribute types that trigger kernel object operations during deserialization. These are fundamentally different trust boundaries with fundamentally different bug patterns, and treating them as interchangeable leads to blind spots in both offense and defense.

<div class="ks-figure" markdown>
  <span class="ks-figure-label">FIG_003 — User-Kernel Boundary</span>
  <svg viewBox="0 0 820 320" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="User-kernel boundary showing user mode APIs connecting to kernel handlers">
    <!-- User Mode APIs -->
    <text class="ks-label" x="410" y="20" text-anchor="middle" fill="currentColor">USER MODE</text>
    <rect class="ks-box" x="10" y="30" width="130" height="40"/>
    <text class="ks-annotation" x="75" y="55" text-anchor="middle">DeviceIoControl</text>
    <rect class="ks-box" x="160" y="30" width="110" height="40"/>
    <text class="ks-annotation" x="215" y="55" text-anchor="middle">CreateFile</text>
    <rect class="ks-box" x="290" y="30" width="100" height="40"/>
    <text class="ks-annotation" x="340" y="55" text-anchor="middle">WSASend</text>
    <rect class="ks-box" x="410" y="30" width="100" height="40"/>
    <text class="ks-annotation" x="460" y="55" text-anchor="middle">NtAlpcSend</text>
    <rect class="ks-box" x="530" y="30" width="130" height="40"/>
    <text class="ks-annotation" x="595" y="55" text-anchor="middle">RegSetValueEx</text>
    <rect class="ks-box" x="680" y="30" width="130" height="40"/>
    <text class="ks-annotation" x="745" y="55" text-anchor="middle">MapViewOfFile</text>
    <!-- Boundary line -->
    <line class="ks-line" x1="10" y1="95" x2="810" y2="95" stroke-dasharray="8,4"/>
    <text class="ks-annotation" x="410" y="110" text-anchor="middle">SYSCALL BOUNDARY</text>
    <!-- Connecting lines -->
    <line class="ks-line" x1="75" y1="70" x2="75" y2="150" stroke-dasharray="4,3" opacity="0.5"/>
    <line class="ks-line" x1="215" y1="70" x2="215" y2="150" stroke-dasharray="4,3" opacity="0.5"/>
    <line class="ks-line" x1="340" y1="70" x2="340" y2="150" stroke-dasharray="4,3" opacity="0.5"/>
    <line class="ks-line" x1="460" y1="70" x2="460" y2="150" stroke-dasharray="4,3" opacity="0.5"/>
    <line class="ks-line" x1="595" y1="70" x2="595" y2="150" stroke-dasharray="4,3" opacity="0.5"/>
    <line class="ks-line" x1="745" y1="70" x2="745" y2="150" stroke-dasharray="4,3" opacity="0.5"/>
    <!-- Kernel Handlers -->
    <text class="ks-label" x="410" y="140" text-anchor="middle" fill="currentColor">KERNEL MODE</text>
    <rect class="ks-box" x="10" y="150" width="130" height="45"/>
    <text class="ks-annotation" x="75" y="170" text-anchor="middle">IOCTL Dispatch</text>
    <text class="ks-annotation" x="75" y="183" text-anchor="middle">IRP_MJ_DEVICE_CONTROL</text>
    <rect class="ks-box" x="160" y="150" width="110" height="45"/>
    <text class="ks-annotation" x="215" y="170" text-anchor="middle">FS IRP Dispatch</text>
    <text class="ks-annotation" x="215" y="183" text-anchor="middle">IRP_MJ_CREATE/READ</text>
    <rect class="ks-box" x="290" y="150" width="100" height="45"/>
    <text class="ks-annotation" x="340" y="170" text-anchor="middle">NDIS / TDI</text>
    <text class="ks-annotation" x="340" y="183" text-anchor="middle">Packet handlers</text>
    <rect class="ks-box" x="410" y="150" width="100" height="45"/>
    <text class="ks-annotation" x="460" y="170" text-anchor="middle">ALPC Port</text>
    <text class="ks-annotation" x="460" y="183" text-anchor="middle">Message dispatch</text>
    <rect class="ks-box" x="530" y="150" width="130" height="45"/>
    <text class="ks-annotation" x="595" y="170" text-anchor="middle">Registry CB</text>
    <text class="ks-annotation" x="595" y="183" text-anchor="middle">CmRegisterCallback</text>
    <rect class="ks-box" x="680" y="150" width="130" height="45"/>
    <text class="ks-annotation" x="745" y="170" text-anchor="middle">Shared Memory</text>
    <text class="ks-annotation" x="745" y="183" text-anchor="middle">MDL / Section obj</text>
    <!-- Additional surfaces below -->
    <rect class="ks-box" x="210" y="225" width="180" height="40"/>
    <text class="ks-annotation" x="300" y="250" text-anchor="middle">PnP &amp; Power (IRP_MJ_PNP)</text>
    <rect class="ks-box" x="430" y="225" width="180" height="40"/>
    <text class="ks-annotation" x="520" y="250" text-anchor="middle">WMI / ETW (IRP_MJ_SYSTEM)</text>
    <rect class="ks-box" x="320" y="280" width="180" height="30"/>
    <text class="ks-annotation" x="410" y="300" text-anchor="middle">WDF / KMDF Framework</text>
  </svg>
  <p class="ks-figure-caption">User-mode APIs cross the syscall boundary into kernel handler dispatch. Each path represents a distinct attack surface.</p>
</div>

## The nine surfaces

The table below maps each attack surface to the kinds of drivers it applies to and the entry points it exposes. But the real differences between these surfaces are not captured in a table; they live in the details of how input reaches kernel code, what validation the I/O Manager performs (or does not perform) before the driver ever sees the data, and what concurrency model governs request processing. The individual pages explore these differences in depth.

| Surface | Description | Key Drivers |
|---------|-------------|-------------|
| [IOCTL Handlers](ioctl-handlers.md) | Device I/O control dispatch | appid.sys, ks.sys, csc.sys |
| [Filesystem IRPs](filesystem-irps.md) | File system and minifilter operations | cldflt.sys, ntfs.sys, fastfat.sys |
| [NDIS / Network](ndis-network.md) | Network packet and OID handling | tcpip.sys |
| [PnP & Power](pnp-power.md) | Plug and Play and power transitions | All PnP drivers |
| [WDF / KMDF](wdf.md) | WDF-managed driver framework | KMDF drivers |
| [Registry Callbacks](registry-callbacks.md) | Registry filtering callbacks | Minifilter/security drivers |
| [ALPC](alpc.md) | Advanced Local Procedure Call | System services |
| [Shared Memory](shared-memory.md) | Kernel-user shared memory regions | mskssrv.sys, ksthunk.sys |
| [WMI / ETW](wmi-etw.md) | WMI and ETW interfaces | Instrumented drivers |

## How attack surfaces map to driver types

Not every driver exposes every surface. A filesystem minifilter has no reason to handle IOCTLs (though some do). A network stack driver has no reason to register registry callbacks. The matrix below shows which attack surfaces are relevant to which [driver types](../driver-types/index.md), and this mapping is the first filter when scoping an audit: once you know what kind of driver you are looking at, you can focus on the surfaces it is likely to expose and ignore the rest.

| | IOCTL | FS IRP | Network | Shared Mem | Registry CB | ALPC |
|---|---|---|---|---|---|---|
| File System | | ■ | | | | |
| Minifilter | | ■ | | | | |
| Log / Transaction | | ■ | | | | |
| Network Stack | ■ | | ■ | | | |
| Kernel Streaming | ■ | | | ■ | | |
| Win32k | | | | | | |
| Core Kernel | | | | | | ■ |
| Security / Policy | ■ | | | | ■ | |
| Storage / Caching | ■ | | | | | |

That said, the matrix is a starting point, not a complete picture. Drivers occasionally expose unexpected surfaces. A filesystem driver might register WMI data blocks for management telemetry. A security driver might use ALPC for policy distribution. The only way to know for certain is to check the driver's `DriverEntry` and `AddDevice` routines for the registration calls that attach it to each surface.

<div class="ks-next-pipeline">
  Next in the pipeline: <a href="../vuln-classes/">Vulnerability Classes</a> &rarr; What goes wrong when attacker-controlled data reaches kernel code?
</div>
