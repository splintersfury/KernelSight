---
description: "9 Windows kernel attack surfaces — IOCTL handlers, filesystem IRPs, NDIS/network, PnP/Power, WDF/KMDF, registry callbacks, ALPC, shared memory, and WMI/ETW entry points."
---

# Attack Surfaces

<div class="ks-pipeline-pos">
  Driver Type &rarr; <span class="ks-active">Attack Surface</span> &rarr; Vuln Class &rarr; Primitive &rarr; Case Study
</div>

Once a target driver is identified, the next question is: how does user-mode code reach it? Windows kernel drivers expose multiple attack surfaces depending on their type and the IRP/callback interfaces they implement. The attack surface determines what data an attacker controls and what code path the input traverses.

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

## Categories

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

## Attack Surface vs. Driver Type

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

<div class="ks-next-pipeline">
  Next in the pipeline: <a href="../vuln-classes/">Vulnerability Classes</a> &rarr; What goes wrong when attacker-controlled data reaches kernel code?
</div>
