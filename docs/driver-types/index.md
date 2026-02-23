# Driver Types

<div class="ks-pipeline-pos">
  <span class="ks-active">Driver Type</span> &rarr; Attack Surface &rarr; Vuln Class &rarr; Primitive &rarr; Case Study
</div>

Every kernel exploitation chain begins with a target component. Windows kernel drivers are categorized by their role and the subsystem they interact with — each type has distinct IRP handling patterns, accessible attack surfaces, and historical vulnerability profiles.

<div class="ks-figure" markdown>
  <span class="ks-figure-label">FIG_002 — Windows Kernel Architecture</span>
  <svg viewBox="0 0 820 380" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Windows kernel architecture showing user mode, kernel subsystems, and HAL layers">
    <!-- User Mode Layer -->
    <rect class="ks-box" x="10" y="10" width="800" height="50"/>
    <text class="ks-label" x="410" y="40" text-anchor="middle" fill="currentColor">USER MODE</text>
    <text class="ks-annotation" x="120" y="40" text-anchor="middle">Win32 API</text>
    <text class="ks-annotation" x="310" y="40" text-anchor="middle">Winsock</text>
    <text class="ks-annotation" x="500" y="40" text-anchor="middle">CreateFile</text>
    <text class="ks-annotation" x="690" y="40" text-anchor="middle">DeviceIoControl</text>
    <!-- Boundary -->
    <line class="ks-line" x1="10" y1="75" x2="810" y2="75" stroke-dasharray="8,4"/>
    <text class="ks-annotation" x="410" y="90" text-anchor="middle">KERNEL BOUNDARY</text>
    <!-- Win32k -->
    <rect class="ks-box" x="10" y="105" width="180" height="70"/>
    <text class="ks-label" x="100" y="130" text-anchor="middle" fill="currentColor">Win32k</text>
    <text class="ks-annotation" x="100" y="148" text-anchor="middle">win32k*.sys</text>
    <text class="ks-annotation" x="100" y="162" text-anchor="middle">3 CVEs | 2 ITW</text>
    <!-- Network Stack -->
    <rect class="ks-box" x="210" y="105" width="180" height="70"/>
    <text class="ks-label" x="300" y="130" text-anchor="middle" fill="currentColor">Network Stack</text>
    <text class="ks-annotation" x="300" y="148" text-anchor="middle">tcpip / afd / http.sys</text>
    <text class="ks-annotation" x="300" y="162" text-anchor="middle">5 CVEs | 2 Remote</text>
    <!-- Kernel Streaming -->
    <rect class="ks-box" x="410" y="105" width="180" height="70"/>
    <text class="ks-label" x="500" y="130" text-anchor="middle" fill="currentColor">Kernel Streaming</text>
    <text class="ks-annotation" x="500" y="148" text-anchor="middle">ks / mskssrv / ksthunk</text>
    <text class="ks-annotation" x="500" y="162" text-anchor="middle">6 CVEs | 2 ITW</text>
    <!-- Security/Policy -->
    <rect class="ks-box" x="610" y="105" width="200" height="70"/>
    <text class="ks-label" x="710" y="130" text-anchor="middle" fill="currentColor">Security / Policy</text>
    <text class="ks-annotation" x="710" y="148" text-anchor="middle">appid.sys / ci.sys</text>
    <text class="ks-annotation" x="710" y="162" text-anchor="middle">1 CVE | ITW</text>
    <!-- File System Layer -->
    <rect class="ks-box" x="10" y="195" width="250" height="70"/>
    <text class="ks-label" x="135" y="220" text-anchor="middle" fill="currentColor">File System + Minifilter</text>
    <text class="ks-annotation" x="135" y="238" text-anchor="middle">ntfs / fastfat / cldflt.sys</text>
    <text class="ks-annotation" x="135" y="252" text-anchor="middle">4 CVEs</text>
    <!-- Log/Transaction -->
    <rect class="ks-box" x="280" y="195" width="200" height="70"/>
    <text class="ks-label" x="380" y="220" text-anchor="middle" fill="currentColor">Log / Transaction</text>
    <text class="ks-annotation" x="380" y="238" text-anchor="middle">clfs.sys</text>
    <text class="ks-annotation" x="380" y="252" text-anchor="middle">4 CVEs | 3 ITW</text>
    <!-- Storage/Caching -->
    <rect class="ks-box" x="500" y="195" width="160" height="70"/>
    <text class="ks-label" x="580" y="220" text-anchor="middle" fill="currentColor">Storage / Cache</text>
    <text class="ks-annotation" x="580" y="238" text-anchor="middle">csc.sys</text>
    <text class="ks-annotation" x="580" y="252" text-anchor="middle">1 CVE</text>
    <!-- Core Kernel -->
    <rect class="ks-box" x="10" y="290" width="800" height="50"/>
    <text class="ks-label" x="410" y="320" text-anchor="middle" fill="currentColor">CORE KERNEL — ntoskrnl.exe</text>
    <text class="ks-annotation" x="160" y="320" text-anchor="middle">4 CVEs | 2 ITW</text>
    <text class="ks-annotation" x="660" y="320" text-anchor="middle">Security Reference Monitor / VBS / Process Mgmt</text>
    <!-- HAL -->
    <rect class="ks-box" x="10" y="355" width="800" height="30" opacity="0.5"/>
    <text class="ks-annotation" x="410" y="375" text-anchor="middle">HARDWARE ABSTRACTION LAYER</text>
  </svg>
  <p class="ks-figure-caption">Driver types positioned within their kernel subsystem. CVE counts from the KernelSight corpus.</p>
</div>

## Categories

| Driver Type | Examples | CVEs in Corpus | Key Attack Surface |
|---|---|---|---|
| [File System Drivers](filesystem.md) | ntfs.sys, fastfat.sys | 2 | On-disk structure parsing, IRP dispatch |
| [File System Minifilters](minifilter.md) | cldflt.sys | 2 | Pre/post-operation callbacks, reparse data |
| [Log / Transaction Drivers](log-transaction.md) | clfs.sys | 4 | Metadata parsing, base log manipulation |
| [Network Stack](network-stack.md) | tcpip.sys, afd.sys, http.sys | 5 | Packet parsing, socket operations, protocol handling |
| [Kernel Streaming](kernel-streaming.md) | ks.sys, mskssrv.sys, ksthunk.sys | 5 | IOCTL dispatch, WOW64 thunking, MDL operations |
| [Win32k Subsystem](win32k.md) | win32k.sys, win32kbase.sys, win32kfull.sys | 3 | Syscall handlers, GDI objects, window management |
| [Core Kernel](core-kernel.md) | ntoskrnl.exe | 4 | Syscall handlers, security subsystem, VBS |
| [Security / Policy Drivers](security-policy.md) | appid.sys | 1 | IOCTL access control, policy enforcement |
| [Storage / Caching Drivers](storage-caching.md) | csc.sys | 1 | IOCTL handlers, file caching |
| [Vendor Utility](vendor-utility.md) | DBUtil, RTCore64, gdrv, iqvw64e, HW.sys, ATSZIO64, AsIO3, WinRing0, etc. | 14 | Physical memory R/W, MSR access, I/O port |
| [Performance & GPU](performance-gpu.md) | AMDRyzenMasterDriver.sys, ThrottleStop.sys, nvlddmkm.sys | 4 | MSR write, GPU memory mapping, MMIO |
| [Third-Party Security](third-party-security.md) | Capcom.sys, echo_driver.sys, viragt64.sys, Truesight.sys, amsdk.sys | 5 | Ring-0 exec, callback manipulation, process termination |

## Browse by Driver Type

<div class="driver-grid">

<a class="driver-card" href="filesystem/">
  <span class="card-icon">&#x1F4C1;</span>
  <span class="card-title">File System Drivers</span>
  <span class="card-drivers">ntfs.sys &middot; fastfat.sys</span>
  <span class="card-desc">On-disk structure parsing, MFT records, FAT bitmaps. VHD mount gives unprivileged local access.</span>
  <span class="card-stats">
    <span class="stat"><strong>2</strong> CVEs</span>
    <span class="stat">Buffer Overflow &middot; Integer Overflow</span>
  </span>
</a>

<a class="driver-card" href="minifilter/">
  <span class="card-icon">&#x1F50D;</span>
  <span class="card-title">File System Minifilters</span>
  <span class="card-drivers">cldflt.sys</span>
  <span class="card-desc">Pre/post-operation callbacks, reparse data parsing, context reference management.</span>
  <span class="card-stats">
    <span class="stat"><strong>2</strong> CVEs</span>
    <span class="stat">Heap Overflow</span>
  </span>
</a>

<a class="driver-card" href="log-transaction/">
  <span class="card-icon">&#x1F4D3;</span>
  <span class="card-title">Log / Transaction</span>
  <span class="card-drivers">clfs.sys</span>
  <span class="card-desc">CLFS base log metadata parsing &mdash; the most exploited single driver. User-reachable via CreateLogFile.</span>
  <span class="card-stats">
    <span class="stat"><strong>4</strong> CVEs</span>
    <span class="stat"><span class="badge badge-itw">3 ITW</span></span>
  </span>
</a>

<a class="driver-card" href="network-stack/">
  <span class="card-icon">&#x1F310;</span>
  <span class="card-title">Network Stack</span>
  <span class="card-drivers">tcpip.sys &middot; afd.sys &middot; http.sys</span>
  <span class="card-desc">TCP/IP packet processing, Winsock kernel helper, HTTP protocol stack. Includes remote attack surface.</span>
  <span class="card-stats">
    <span class="stat"><strong>5</strong> CVEs</span>
    <span class="stat"><span class="badge badge-remote">2 Remote</span></span>
  </span>
</a>

<a class="driver-card" href="kernel-streaming/">
  <span class="card-icon">&#x1F3AC;</span>
  <span class="card-title">Kernel Streaming</span>
  <span class="card-drivers">ks.sys &middot; mskssrv.sys &middot; ksthunk.sys</span>
  <span class="card-desc">KS IOCTL dispatch, WOW64 thunking, MDL operations, rendezvous server context management.</span>
  <span class="card-stats">
    <span class="stat"><strong>6</strong> CVEs</span>
    <span class="stat"><span class="badge badge-itw">2 ITW</span></span>
  </span>
</a>

<a class="driver-card" href="win32k/">
  <span class="card-icon">&#x1F5A5;</span>
  <span class="card-title">Win32k Subsystem</span>
  <span class="card-drivers">win32k.sys &middot; win32kbase.sys &middot; win32kfull.sys</span>
  <span class="card-desc">~1200 NtUser/NtGdi syscall handlers, GDI objects, window and menu management.</span>
  <span class="card-stats">
    <span class="stat"><strong>3</strong> CVEs</span>
    <span class="stat"><span class="badge badge-itw">2 ITW</span></span>
  </span>
</a>

<a class="driver-card" href="core-kernel/">
  <span class="card-icon">&#x2699;</span>
  <span class="card-title">Core Kernel</span>
  <span class="card-drivers">ntoskrnl.exe</span>
  <span class="card-desc">Security reference monitor, VBS transitions, process/thread management. Highest impact bugs.</span>
  <span class="card-stats">
    <span class="stat"><strong>4</strong> CVEs</span>
    <span class="stat"><span class="badge badge-itw">2 ITW</span></span>
  </span>
</a>

<a class="driver-card" href="security-policy/">
  <span class="card-icon">&#x1F6E1;</span>
  <span class="card-title">Security / Policy</span>
  <span class="card-drivers">appid.sys &middot; ci.sys</span>
  <span class="card-desc">AppLocker, Code Integrity, WDAC enforcement. Lazarus Group ITW exploitation.</span>
  <span class="card-stats">
    <span class="stat"><strong>1</strong> CVE</span>
    <span class="stat"><span class="badge badge-itw">ITW</span></span>
  </span>
</a>

<a class="driver-card" href="storage-caching/">
  <span class="card-icon">&#x1F4BE;</span>
  <span class="card-title">Storage / Caching</span>
  <span class="card-drivers">csc.sys</span>
  <span class="card-desc">Client-Side Caching, Offline Files. Logic bugs in access control enforcement.</span>
  <span class="card-stats">
    <span class="stat"><strong>1</strong> CVE</span>
    <span class="stat">Logic Bug</span>
  </span>
</a>

<a class="driver-card" href="vendor-utility/">
  <span class="card-icon">&#x1F527;</span>
  <span class="card-title">Vendor Utility</span>
  <span class="card-drivers">DBUtil &middot; RTCore64 &middot; gdrv &middot; iqvw64e &middot; HW.sys &middot; WinRing0 &middot; +8 more</span>
  <span class="card-desc">OEM hardware utility and diagnostic drivers. Expose physical memory R/W, MSR, I/O port access. Canonical BYOVD targets.</span>
  <span class="card-stats">
    <span class="stat"><strong>14</strong> CVEs</span>
    <span class="stat"><span class="badge badge-itw">9 ITW</span></span>
  </span>
</a>

<a class="driver-card" href="performance-gpu/">
  <span class="card-icon">&#x1F3AE;</span>
  <span class="card-title">Performance & GPU</span>
  <span class="card-drivers">AMDRyzenMaster &middot; ThrottleStop &middot; nvlddmkm &middot; AMD chipset</span>
  <span class="card-desc">CPU tuning, GPU, and chipset drivers. Expose MSR writes, GPU memory mapping, MMIO register access.</span>
  <span class="card-stats">
    <span class="stat"><strong>4</strong> CVEs</span>
    <span class="stat"><span class="badge badge-itw">1 ITW</span></span>
  </span>
</a>

<a class="driver-card" href="third-party-security/">
  <span class="card-icon">&#x1F6A8;</span>
  <span class="card-title">Third-Party Security</span>
  <span class="card-drivers">Capcom.sys &middot; echo_driver.sys &middot; viragt64.sys &middot; Truesight.sys &middot; amsdk.sys</span>
  <span class="card-desc">AV/EDR/anti-cheat kernel modules. Abused for process termination, callback manipulation, ring-0 code execution.</span>
  <span class="card-stats">
    <span class="stat"><strong>5</strong> CVEs</span>
    <span class="stat"><span class="badge badge-itw">4 ITW</span></span>
  </span>
</a>

</div>

## Driver Type vs. Vulnerability Class Heatmap

| Driver Type | Buffer Overflow | Integer Overflow | Type Confusion | Race Condition | UAF | Info Disclosure | Logic Bug |
|---|---|---|---|---|---|---|---|
| File System | ■■ | ■ | | | | | |
| Minifilter | ■■ | | | | | | |
| Log / Transaction | ■■■■ | | | | | | |
| Network Stack | ■ | ■■ | | | ■ | | |
| Kernel Streaming | | ■ | ■ | | ■ | | |
| Win32k | | | ■ | | ■ | ■ | |
| Core Kernel | | | | ■■ | | ■ | ■ |
| Security / Policy | | | | | | | ■ |
| Storage / Caching | | | | | | | ■ |
| Vendor Utility | | | | | | | ■■■■■■■■■■■■■■ |
| Performance & GPU | | | | | | ■ | ■■■ |
| Third-Party Security | | | | | | | ■■■■■ |

<div class="ks-next-pipeline">
  Next in the pipeline: <a href="../attack-surfaces/">Attack Surfaces</a> &rarr; How does user-mode code reach these drivers?
</div>
