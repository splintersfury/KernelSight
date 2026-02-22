# KernelSight

<p class="hero-subtitle">
Windows kernel driver exploitation knowledge base — organized by driver type, grounded in real CVEs with specific builds and patches.
</p>

## Browse by Driver Type

<div class="driver-grid">

<a class="driver-card" href="driver-types/filesystem/">
  <span class="card-icon">&#x1F4C1;</span>
  <span class="card-title">File System Drivers</span>
  <span class="card-drivers">ntfs.sys &middot; fastfat.sys</span>
  <span class="card-desc">On-disk structure parsing, MFT records, FAT bitmaps. VHD mount gives unprivileged local access.</span>
  <span class="card-stats">
    <span class="stat"><strong>2</strong> CVEs</span>
    <span class="stat">Buffer Overflow &middot; Integer Overflow</span>
  </span>
</a>

<a class="driver-card" href="driver-types/minifilter/">
  <span class="card-icon">&#x1F50D;</span>
  <span class="card-title">File System Minifilters</span>
  <span class="card-drivers">cldflt.sys</span>
  <span class="card-desc">Pre/post-operation callbacks, reparse data parsing, context reference management.</span>
  <span class="card-stats">
    <span class="stat"><strong>2</strong> CVEs</span>
    <span class="stat">Heap Overflow</span>
  </span>
</a>

<a class="driver-card" href="driver-types/log-transaction/">
  <span class="card-icon">&#x1F4D3;</span>
  <span class="card-title">Log / Transaction</span>
  <span class="card-drivers">clfs.sys</span>
  <span class="card-desc">CLFS base log metadata parsing &mdash; the most exploited single driver. User-reachable via CreateLogFile.</span>
  <span class="card-stats">
    <span class="stat"><strong>4</strong> CVEs</span>
    <span class="stat"><span class="badge badge-itw">3 ITW</span></span>
  </span>
</a>

<a class="driver-card" href="driver-types/network-stack/">
  <span class="card-icon">&#x1F310;</span>
  <span class="card-title">Network Stack</span>
  <span class="card-drivers">tcpip.sys &middot; afd.sys &middot; http.sys</span>
  <span class="card-desc">TCP/IP packet processing, Winsock kernel helper, HTTP protocol stack. Includes remote attack surface.</span>
  <span class="card-stats">
    <span class="stat"><strong>5</strong> CVEs</span>
    <span class="stat"><span class="badge badge-remote">2 Remote</span></span>
  </span>
</a>

<a class="driver-card" href="driver-types/kernel-streaming/">
  <span class="card-icon">&#x1F3AC;</span>
  <span class="card-title">Kernel Streaming</span>
  <span class="card-drivers">ks.sys &middot; mskssrv.sys &middot; ksthunk.sys</span>
  <span class="card-desc">KS IOCTL dispatch, WOW64 thunking, MDL operations, rendezvous server context management.</span>
  <span class="card-stats">
    <span class="stat"><strong>6</strong> CVEs</span>
    <span class="stat"><span class="badge badge-itw">2 ITW</span></span>
  </span>
</a>

<a class="driver-card" href="driver-types/win32k/">
  <span class="card-icon">&#x1F5A5;</span>
  <span class="card-title">Win32k Subsystem</span>
  <span class="card-drivers">win32k.sys &middot; win32kbase.sys &middot; win32kfull.sys</span>
  <span class="card-desc">~1200 NtUser/NtGdi syscall handlers, GDI objects, window and menu management.</span>
  <span class="card-stats">
    <span class="stat"><strong>3</strong> CVEs</span>
    <span class="stat"><span class="badge badge-itw">2 ITW</span></span>
  </span>
</a>

<a class="driver-card" href="driver-types/core-kernel/">
  <span class="card-icon">&#x2699;</span>
  <span class="card-title">Core Kernel</span>
  <span class="card-drivers">ntoskrnl.exe</span>
  <span class="card-desc">Security reference monitor, VBS transitions, process/thread management. Highest impact bugs.</span>
  <span class="card-stats">
    <span class="stat"><strong>4</strong> CVEs</span>
    <span class="stat"><span class="badge badge-itw">2 ITW</span></span>
  </span>
</a>

<a class="driver-card" href="driver-types/security-policy/">
  <span class="card-icon">&#x1F6E1;</span>
  <span class="card-title">Security / Policy</span>
  <span class="card-drivers">appid.sys &middot; ci.sys</span>
  <span class="card-desc">AppLocker, Code Integrity, WDAC enforcement. Lazarus Group ITW exploitation.</span>
  <span class="card-stats">
    <span class="stat"><strong>1</strong> CVE</span>
    <span class="stat"><span class="badge badge-itw">ITW</span></span>
  </span>
</a>

<a class="driver-card" href="driver-types/storage-caching/">
  <span class="card-icon">&#x1F4BE;</span>
  <span class="card-title">Storage / Caching</span>
  <span class="card-drivers">csc.sys</span>
  <span class="card-desc">Client-Side Caching, Offline Files. Logic bugs in access control enforcement.</span>
  <span class="card-stats">
    <span class="stat"><strong>1</strong> CVE</span>
    <span class="stat">Logic Bug</span>
  </span>
</a>

</div>

<h2 class="section-header">Explore by Topic</h2>

<div class="nav-pills">
  <a class="nav-pill" href="attack-surfaces/">Attack Surfaces</a>
  <a class="nav-pill" href="vuln-classes/">Vulnerability Classes</a>
  <a class="nav-pill" href="primitives/">Primitives</a>
  <a class="nav-pill" href="mitigations/">Mitigations</a>
  <a class="nav-pill" href="case-studies/">Case Studies (28 CVEs)</a>
  <a class="nav-pill" href="tooling/">Tooling</a>
</div>

## At a Glance

| | |
|---|---|
| **28** CVE case studies | **16** unique drivers |
| **12** exploited in the wild | **2** remotely exploitable |
| **9** driver type categories | **46** technique pages |
| **66** AutoPiff detection rules | Automated collector monitors 6+ feeds |
