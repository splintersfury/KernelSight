# Why Kernel Drivers?

> Why the attack surface exists -- what hardware enforces, what only Ring 0 can do, and where Microsoft is trying to draw the line.

Every CVE in this corpus exists because some code ran at Ring 0. This page explains why that code needs to be there -- and where it doesn't.

## Ring 0 vs Ring 3

x86-64 processors enforce privilege through the Current Privilege Level (CPL), stored in bits 0--1 of the CS selector. Windows uses two of the four available rings: Ring 3 for user-mode processes, Ring 0 for the kernel and drivers.

The split is hardware-enforced. The CPU traps any attempt to execute privileged instructions at Ring 3:

| Instruction | What It Does | Why Ring 3 Cannot |
|-------------|-------------|-------------------|
| `IN` / `OUT` | Read/write I/O ports | Direct hardware access |
| `RDMSR` / `WRMSR` | Read/write model-specific registers | CPU configuration control |
| `MOV CR0-4` | Modify control registers | Paging, protection, feature enable |
| `LGDT` / `LIDT` | Load descriptor tables | Redefine memory segmentation, interrupt dispatch |
| `HLT` | Halt the processor | Denial of service by design |
| `VMXON` / `VMLAUNCH` | Enter VMX operation | Hypervisor control |
| `INVLPG` | Invalidate TLB entries | Page table manipulation |

The only legal Ring 3 to Ring 0 transition is `SYSCALL` (or its legacy equivalent `SYSENTER`). The kernel's system call handler validates the request, performs the operation, and returns via `SYSRETQ`. Every other path from user mode to kernel mode -- page faults, interrupts, debug exceptions -- is hardware-mediated and enters at a kernel-controlled handler.

Two additional hardware features extend this boundary:

- **SMEP** (Supervisor Mode Execution Prevention) -- the CPU faults if Ring 0 tries to execute code on a user-mode page. Blocks the classic "allocate shellcode in user space, redirect kernel EIP" technique. See [SMEP / SMAP](../mitigations/smep-smap.md).
- **SMAP** (Supervisor Mode Access Prevention) -- the CPU faults if Ring 0 tries to read or write a user-mode page without explicit opt-in (`STAC`/`CLAC`). Prevents the kernel from being tricked into dereferencing user-controlled pointers. See [SMEP / SMAP](../mitigations/smep-smap.md).

Below Ring 0, VBS-enabled systems add a hypervisor layer (sometimes called Ring -1) that enforces [HVCI](../mitigations/vbs-hvci.md) -- code integrity at page granularity, even against a compromised kernel.

<div class="ks-figure" markdown>
  <span class="ks-figure-label">FIG — x86-64 Privilege Rings on Windows</span>
  <svg viewBox="0 0 700 260" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Diagram showing privilege rings: Ring 3 user mode, Ring 0 kernel mode, Ring -1 hypervisor, with SYSCALL boundary">
    <!-- Ring -1 (Hypervisor) -->
    <rect class="ks-box" x="50" y="180" width="600" height="55" rx="0"/>
    <text class="ks-label" x="65" y="212">Ring −1 &nbsp; Hypervisor (Hyper-V / VBS)</text>
    <text class="ks-annotation" x="550" y="212">VMXON, VMLAUNCH</text>
    <!-- Ring 0 (Kernel) -->
    <rect class="ks-box" x="100" y="100" width="500" height="65" rx="0"/>
    <text class="ks-label" x="115" y="130">Ring 0 &nbsp; ntoskrnl.exe + Drivers</text>
    <text class="ks-annotation" x="465" y="130">IN/OUT, RDMSR, MOV CR*</text>
    <text class="ks-annotation" x="115" y="150">Full hardware access · IRQL scheduling · Kernel objects</text>
    <!-- Ring 3 (User) -->
    <rect class="ks-box" x="175" y="20" width="350" height="55" rx="0"/>
    <text class="ks-label" x="190" y="50">Ring 3 &nbsp; Applications + Services</text>
    <text class="ks-annotation" x="190" y="65">Limited to SYSCALL interface</text>
    <!-- SYSCALL arrow -->
    <line class="ks-line" x1="350" y1="75" x2="350" y2="100" stroke-dasharray="4,3"/>
    <text class="ks-annotation" x="365" y="93">SYSCALL</text>
    <!-- SMEP/SMAP annotation -->
    <text class="ks-annotation" x="480" y="93">SMEP · SMAP</text>
    <!-- VTL boundary -->
    <line class="ks-line" x1="100" y1="175" x2="600" y2="175" stroke-dasharray="2,4" opacity="0.4"/>
    <text class="ks-annotation" x="105" y="175">HVCI boundary</text>
  </svg>
  <p class="ks-figure-caption">Windows uses Ring 3 (CPL=3) for user processes and Ring 0 (CPL=0) for the kernel. VBS adds a hypervisor-enforced boundary that constrains even kernel code.</p>
</div>

## What Only Ring 0 Can Do

Ring 0 code isn't always a CPU requirement. Some capabilities are hardware-enforced (the CPU traps the instruction at Ring 3), while others are OS-enforced (the kernel checks `PreviousMode` or IRQL and rejects the call). Both require a kernel driver.

| Capability | Mechanism | Why Ring 3 Cannot | KernelSight Reference |
|-----------|-----------|-------------------|----------------------|
| Physical memory mapping | `MmMapIoSpace`, DMA | CPU enforces page-level access; no user API exposes physical addresses | [DMA / MMIO](../primitives/arw/dma-mmio.md) |
| MSR read/write | `RDMSR` / `WRMSR` | CPU traps at Ring 3 | [Vendor Utility](../driver-types/vendor-utility.md) |
| I/O port access | `IN` / `OUT` | CPU traps at Ring 3 | [Vendor Utility](../driver-types/vendor-utility.md) |
| Interrupt handling | IDT registration, IRQL management | IDT is kernel-only; IRQL is OS-enforced | [Core Kernel](../driver-types/core-kernel.md) |
| Kernel object access | `ObReferenceObjectByHandle` with `KernelMode` | OS checks `PreviousMode`; user callers get `UserMode` | [PreviousMode Manipulation](../primitives/exploitation/previous-mode-manipulation.md) |
| Cross-process memory | `MmCopyVirtualMemory` | OS enforces process isolation; user APIs (`ReadProcessMemory`) check access rights | [Token Manipulation](../primitives/arw/token-manipulation.md) |
| Callback registration | `PsSetCreateProcessNotifyRoutine`, `ObRegisterCallbacks` | OS restricts to kernel callers only | [Security / Policy](../driver-types/security-policy.md) |
| Page table manipulation | Direct PTE access, `MOV CR3` | CPU traps `MOV CR3`; PTE pages are kernel-only | [PTE Manipulation](../primitives/arw/pte-manipulation.md) |
| File system filter stacking | Minifilter altitude registration | Filter Manager is kernel-only; no user-mode equivalent | [File System Minifilters](../driver-types/minifilter.md) |
| NDIS packet interception | Miniport/protocol driver registration | NDIS stack is kernel-only | [NDIS / Network](../attack-surfaces/ndis-network.md) |
| Virtualization | `VMXON` / `VMLAUNCH` | CPU traps at Ring 3 | [VBS / HVCI](../mitigations/vbs-hvci.md) |
| Kernel pool allocation | `ExAllocatePool2` | OS restricts to kernel callers; no user-mode pool access | [Pool Spray / Feng Shui](../primitives/exploitation/pool-spray-feng-shui.md) |

These break into two groups:

**Hardware-enforced.** The CPU itself traps the instruction. `IN`/`OUT`, `RDMSR`/`WRMSR`, `MOV CR*`, `VMXON` cannot execute at CPL=3, regardless of OS configuration.

**OS-enforced.** The kernel checks `PreviousMode` (set by `SYSCALL` to `UserMode` for Ring 3 callers) and rejects the request. `ObReferenceObjectByHandle`, `MmCopyVirtualMemory`, and callback registration work at Ring 0 because `PreviousMode` is `KernelMode`. This is why [PreviousMode manipulation](../primitives/exploitation/previous-mode-manipulation.md) works: changing a single byte allows a user-mode thread to pass kernel-level access checks.

**IRQL as kernel-only scheduling.** Interrupt Request Level controls which code can preempt what. User-mode code always runs at IRQL 0 (`PASSIVE_LEVEL`). Only kernel code can raise IRQL to block interrupts (`DISPATCH_LEVEL`, `DIRQL`). This is why certain operations -- deferred procedure calls, spin lock acquisitions, DMA completion routines -- can only happen in a driver.

**DMA access is the most critical.** A driver that programs a DMA controller can read or write any physical address, bypassing both CPU access checks and OS page protections. This is why [DMA / MMIO](../primitives/arw/dma-mmio.md) primitives are so difficult to defend against and why IOMMU configuration matters.

## Legitimate Use Cases

Kernel drivers exist because hardware access, security enforcement, and OS plumbing demand Ring 0 privileges. Here are the eight main categories:

| Use Case | What It Needs from Ring 0 | Example Driver | Why Not User Mode |
|----------|--------------------------|---------------|-------------------|
| File system implementation | IRP dispatch, cache manager integration, paging I/O | ntfs.sys, refs.sys | Paging I/O requires kernel; cache manager is Ring 0 only |
| Network protocol stack | NDIS miniport/protocol registration, DPC for packet processing | tcpip.sys, ndis.sys | NDIS registration is kernel-only; DPC requires elevated IRQL |
| AV / EDR | Kernel callbacks (`ObRegisterCallbacks`, `PsSetCreateProcessNotifyRoutine`), minifilter | WdFilter.sys, CrowdStrike csagent.sys | Callbacks that can block operations require kernel presence |
| Full-disk encryption | Storage miniport filter, pre-boot authentication | BitLocker fvevol.sys | Must intercept I/O below the file system |
| GPU driver | DMA to GPU memory, interrupt handling, MMIO register programming | nvlddmkm.sys, dxgkrnl.sys | GPU hardware requires DMA + MMIO + interrupts |
| Hardware sensors / HID | I/O ports, interrupts, USB pipe access | hidusb.sys, sensor minidriver | Direct hardware register access (though UMDF covers many HID cases) |
| Virtualization host | VMX instructions, EPT management, VMCS manipulation | hvix64.exe, vmswitch.sys | CPU traps VMX at Ring 3 |
| USB host controller | DMA ring buffer management, interrupt handling, MMIO | usbxhci.sys | Host controller requires DMA and MMIO |

These fit into three groups:

**Hardware access** -- GPU drivers, USB host controllers, sensor drivers. Anything that touches hardware registers, programs DMA, or handles interrupts runs at Ring 0 by hardware requirement.

**Security enforcement** -- AV/EDR products that intercept process creation, object access, and file operations before they complete. The kernel callback model allows a driver to return "deny this operation" synchronously. User mode has no equivalent.

**OS plumbing** -- File systems, network stacks, storage drivers. These hook into the OS I/O path. The cache manager, memory manager, and I/O manager are Ring 0 components that require Ring 0 clients.

The July 2024 CrowdStrike incident (8.5 million machines crashed from a faulty update) focused attention on security-enforcement drivers. A user-mode crash affects one process. A kernel-mode crash brings down the entire system. Microsoft's response—the Windows Resiliency Initiative—committed to building user-mode alternatives for security vendors.

## The Security Cost

Every kernel driver is a liability. A bug in Ring 0 code grants the attacker full control of the machine -- not a process, not a sandbox, but the entire kernel address space.

The KernelSight corpus quantifies this cost: 134 CVEs across 62 drivers, with 52 exploited in the wild. The consequences break down by impact:

<div class="ks-figure" markdown>
  <span class="ks-figure-label">FIG — CVE Distribution by Consequence (134 CVEs)</span>
  <svg viewBox="0 0 700 230" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Horizontal bar chart showing CVE distribution by consequence type">
    <!-- EoP -->
    <text class="ks-label" x="155" y="35" text-anchor="end">EoP</text>
    <rect class="ks-box" x="160" y="22" width="380" height="20" rx="0"/>
    <text class="ks-annotation" x="548" y="36">~95</text>
    <!-- Info Disclosure -->
    <text class="ks-label" x="155" y="67" text-anchor="end">Info Disclosure</text>
    <rect class="ks-box" x="160" y="54" width="60" height="20" rx="0"/>
    <text class="ks-annotation" x="228" y="68">~15</text>
    <!-- DoS -->
    <text class="ks-label" x="155" y="99" text-anchor="end">DoS</text>
    <rect class="ks-box" x="160" y="86" width="48" height="20" rx="0"/>
    <text class="ks-annotation" x="216" y="100">~12</text>
    <!-- Process Kill -->
    <text class="ks-label" x="155" y="131" text-anchor="end">Process Kill</text>
    <rect class="ks-box" x="160" y="118" width="40" height="20" rx="0"/>
    <text class="ks-annotation" x="208" y="132">~10</text>
    <!-- RCE -->
    <text class="ks-label" x="155" y="163" text-anchor="end">RCE</text>
    <rect class="ks-box" x="160" y="150" width="8" height="20" rx="0"/>
    <text class="ks-annotation" x="176" y="164">~2</text>
  </svg>
  <p class="ks-figure-caption">Elevation of privilege dominates. The two RCE entries are http.sys (CVE-2022-21907) and tcpip.sys (CVE-2024-38063). "Process Kill" is the EDR-bypass primitive used by BYOVD anti-cheat and security product drivers.</p>
</div>

EoP dominates because the typical attack chain starts with local code execution (phishing, watering hole, initial access broker) and needs kernel access to disable security products, steal credentials, or persist. The two remote kernel bugs are outliers.

The 41 BYOVD drivers in the corpus are not coding errors -- they are architectural choices. A signed driver that maps physical memory to any caller is functioning as designed. It just happens to function as a universal kernel read/write primitive for anyone who drops it on disk. See [BYOVD](../reference/byovd.md).

The remaining 93 inbox CVEs are coding errors in Microsoft-shipped drivers: missing length checks, unsynchronised teardown, unchecked on-disk offsets. These are the bugs the [Secure Driver Anatomy](secure-driver-anatomy.md) anti-patterns address.

For how these bugs chain together to reach SYSTEM, see [Exploit Chain Patterns](exploit-chain-patterns.md). For the specific vulnerability classes, see [Vulnerability Classes](../vuln-classes/index.md).

## User-Mode Alternatives

Microsoft has shipped several frameworks that move driver functionality out of Ring 0. Each replaces some kernel capabilities but leaves others untouched.

| Framework | Replaces | Cannot Replace | Status |
|-----------|----------|----------------|--------|
| UMDF 2.x | HID, sensor, NFC, simple USB drivers | DMA, interrupts, storage filters | Stable since Windows 8.1 |
| WFP (Windows Filtering Platform) | Network packet filtering, connection auth | Raw packet injection, NDIS miniport | Stable since Vista |
| ETW (Event Tracing for Windows) | Kernel telemetry, system call tracing | Blocking/interposition (observe-only) | Stable since Windows 2000 |
| WinUSB | USB bulk, interrupt, control transfers | USB host controller, isochronous, DMA | Stable since Vista |
| ProjFS (Projected File System) | Virtual filesystem projections | Full filesystem implementation, paging I/O | Stable since Windows 10 1809 |
| App containers / Enclaves | Isolated computation, credential isolation | Kernel callbacks, interposition | Evolving (VBS enclaves) |
| User-mode security agents | Telemetry, basic detection | Kernel callbacks, tamper resistance | Proposed (2024 onward) |

The honest assessment of each:

**UMDF** provides crash isolation -- a UMDF driver crash kills the driver host process, not the machine. But UMDF cannot handle DMA, elevated IRQL, or storage filters. It covers the easy cases (HID, sensors) but not the ones that generate CVEs (file systems, network stacks, security products).

**WFP** lets user-mode services set packet filtering rules without a kernel driver. But deep packet inspection still needs a callout driver at Ring 0. And anything below the IP layer (NDIS miniport, raw Ethernet) has no user-mode path.

**ETW** shows the gap for security vendors. ETW can observe kernel events after they happen: process creation, image loads, registry operations. But it cannot block them. A kernel callback via `ObRegisterCallbacks` can return `STATUS_ACCESS_DENIED` and stop an operation. ETW cannot. This is the core problem: observing is different from blocking.

**Tamper resistance is unsolved.** Even when user-mode detection works, a user-mode agent runs at the same privilege level as the malware. An admin attacker can kill the process, patch its memory, or unload its DLLs. PPL (Protected Process Light) offers some protection, but researchers have bypassed it multiple times ([CVE-2024-21302](../case-studies/CVE-2024-21302.md) and others). No user-mode method provides the tamper resistance of a kernel-mode driver with kernel callbacks.

## Microsoft's Trajectory

Each generation of Windows constrains third-party kernel code more tightly. The direction is clear, even if the destination is still years away.

| Year | Milestone | Effect |
|------|-----------|--------|
| 2006 | PatchGuard (Vista x64) | Blocks kernel patching of SSDT, IDT, GDT |
| 2007 | Mandatory driver signing (Vista x64) | Unsigned drivers cannot load |
| 2015 | VBS / HVCI (Windows 10) | Hypervisor-enforced code integrity; blocks unsigned kernel code even from Ring 0 |
| 2016 | SMAP enforcement | Kernel cannot accidentally read user-mode pages |
| 2019 | Vulnerable Driver Blocklist | Microsoft-maintained list of revoked driver hashes; blocks known BYOVD vectors |
| 2022 | HVCI default on new installs | New Windows 11 devices ship with hypervisor code integrity enabled |
| 2023 | CLFS container isolation | Sandboxes the log-file parser after repeated in-the-wild exploitation |
| 2024 | Windows Resiliency Initiative | Post-CrowdStrike commitment to user-mode security APIs |
| 2024 | Quick Machine Recovery | Remote remediation for boot-loop crashes caused by kernel drivers |
| 2025 | kCFG / kCET expansion | Kernel-mode Control Flow Guard and CET shadow stack on more hardware |

The pattern is clear: Vista blocked kernel patching. Windows 10 added hypervisor enforcement. Windows 11 made it standard. CrowdStrike accelerated the shift toward user-mode security.

CrowdStrike changed the equation. Before July 2024, vendors argued "we need kernel callbacks and tamper resistance." After 8.5 million machines crashed, the argument flipped to "a faulty driver update can take down your entire fleet." Microsoft responded by committing to user-mode alternatives.

The gap remains open. The Resiliency Initiative announced APIs but has not released them. PPL bypasses ([CVE-2024-21302](../case-studies/CVE-2024-21302.md) and others) show user-mode tamper resistance is still weak. Until Microsoft ships synchronous user-mode callbacks with solid tamper protection, security vendors will stay in the kernel.

For the full timeline of kernel defences and how each one shifted attacker techniques, see [Mitigation Timeline](mitigation-timeline.md). For how VBS and HVCI constrain even Ring 0 code, see [VBS / HVCI](../mitigations/vbs-hvci.md). For how attackers bypass driver signing through legitimate signed drivers, see [BYOVD](../reference/byovd.md).

## The Irreducible Kernel

Some work will stay at Ring 0 forever. This is not an API limitation—it is a hardware constraint.

**Cannot leave Ring 0 (CPU requirement):**

- **Interrupt Descriptor Table (IDT)** — The CPU dispatches hardware and software interrupts through the IDT. Loading the IDT (`LIDT`) requires Ring 0.
- **Page tables** — The CPU walks page tables on every memory access. `MOV CR3` (switches address spaces) requires Ring 0. Page table entries are kernel-only pages.
- **DMA configuration** — Programming DMA and IOMMU page tables requires MMIO access to hardware registers. User mode cannot access these. IOMMU (VT-d) mitigation requires Ring 0 setup.
- **Control registers** — `CR0` (protection, write protect), `CR4` (SMEP, SMAP, UMIP), `CR8` (TPR) require Ring 0.

**Cannot leave Ring 0 (design requirement):**

- **Paging I/O** — The memory manager pages data to/from disk at elevated IRQL. The file system driver handling this must be Ring 0.
- **File system stack** — The cache manager, memory manager, and I/O manager are coupled. Moving file systems to user mode would require marshalling every page fault across the kernel boundary—performance would suffer critically.
- **Network protocol stack** — NDIS, TCP/IP, and sockets run in kernel for the same reason: per-packet transitions to user mode would destroy throughput.
- **Boot path** — Boot-start drivers and early-launch modules load before user mode exists, so they must be Ring 0.

The irreducible kernel will always pose a security risk. The real question is whether that surface can shrink further.

## Cross-References

**Internal:**

- [Driver Types](../driver-types/index.md) -- categorisation of the 62 drivers in the corpus
- [Attack Surfaces](../attack-surfaces/index.md) -- how kernel drivers expose themselves to user-mode callers
- [Corpus Analytics](corpus-analytics.md) -- visual breakdown of 134 CVEs
- [Anatomy of a Secure Driver](secure-driver-anatomy.md) -- the six anti-patterns behind most kernel driver bugs
- [Exploit Chain Patterns](exploit-chain-patterns.md) -- how kernel bugs chain to SYSTEM
- [Mitigation Timeline](mitigation-timeline.md) -- when each defence landed
- [BYOVD](../reference/byovd.md) -- when the driver is the weapon

**External:**

- [Intel SDM Vol 3A, Chapter 5 -- Protection](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html) -- definitive reference for x86-64 privilege rings, CPL, DPL, and gate descriptors
- [Microsoft Learn -- Kernel-Mode Driver Architecture](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/) -- Windows driver model documentation
- [Microsoft Learn -- UMDF Overview](https://learn.microsoft.com/en-us/windows-hardware/drivers/wdf/overview-of-the-umdf) -- user-mode driver framework
- [Microsoft Learn -- Windows Filtering Platform](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page) -- WFP documentation
- [Microsoft Blog -- Windows Resiliency Initiative](https://blogs.windows.com/windowsexperience/2024/11/22/our-commitment-to-security-november-2024/) -- post-CrowdStrike commitment to user-mode security APIs
- [LOLDrivers](https://www.loldrivers.io/) -- community-maintained catalogue of vulnerable and malicious drivers
