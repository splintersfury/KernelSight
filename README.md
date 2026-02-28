# KernelSight — Windows Kernel Driver Exploitation Knowledge Base

[![GitHub Pages](https://img.shields.io/badge/Browse-Knowledge%20Base-blue)](https://splintersfury.github.io/KernelSight/)
[![CVEs](https://img.shields.io/badge/CVEs-134-red)](https://splintersfury.github.io/KernelSight/case-studies/)
[![Drivers](https://img.shields.io/badge/Drivers-62-orange)](https://splintersfury.github.io/KernelSight/driver-types/)
[![ITW](https://img.shields.io/badge/Exploited%20ITW-52-critical)](https://splintersfury.github.io/KernelSight/guides/corpus-analytics/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

A structured knowledge base for **Windows kernel driver exploitation** -- covering vulnerability classes, exploitation primitives, BYOVD campaigns, exploit chain patterns, and kernel mitigations. Every entry is grounded in real CVEs with driver names, vulnerable/fixed builds, and patch analysis.

**[Browse the Knowledge Base →](https://splintersfury.github.io/KernelSight/)**

---

## Corpus

| Metric | Count |
|--------|-------|
| CVE case studies | **134** |
| Unique drivers analysed | **62** |
| Exploited in the wild | **52** |
| Remotely exploitable | **2** |
| BYOVD drivers | **41** |
| Driver type categories | **12** |
| Exploitation technique pages | **57** |
| AutoPiff detection rules | **80+** |

## What's Inside

### The Exploitation Pipeline

KernelSight is organized as a pipeline from driver identification through privilege escalation:

**[Driver Types](https://splintersfury.github.io/KernelSight/driver-types/)** → **[Attack Surfaces](https://splintersfury.github.io/KernelSight/attack-surfaces/)** → **[Vulnerability Classes](https://splintersfury.github.io/KernelSight/vuln-classes/)** → **[Exploitation Primitives](https://splintersfury.github.io/KernelSight/primitives/)** → **[Case Studies](https://splintersfury.github.io/KernelSight/case-studies/)**

With **[Mitigations](https://splintersfury.github.io/KernelSight/mitigations/)** cross-cutting every stage.

### Driver Types (12 Categories)

| Driver Type | Example Drivers | CVEs | Key Pattern |
|---|---|---|---|
| **File System** | ntfs.sys, fastfat.sys, refs.sys | 7 | VHD mount gives unprivileged access to on-disk parsing |
| **Minifilters** | cldflt.sys | 8 | Reparse data and cloud file callbacks |
| **Log / Transaction** | clfs.sys | 12 | Most exploited single driver -- on-disk metadata corruption |
| **Network Stack** | tcpip.sys, afd.sys, http.sys | 13 | Includes 2 remotely exploitable bugs (IPv6 RCE, HTTP RCE) |
| **Kernel Streaming** | ks.sys, mskssrv.sys, ksthunk.sys | 12 | IOCTL handlers, MDL mapping, type confusion |
| **Win32k** | win32k.sys, win32kbase.sys, win32kfull.sys | 12 | Callback reentrancy, window object races |
| **Core Kernel** | ntoskrnl.exe | 9 | Token races, secure-mode bypasses, highest impact |
| **Security / Policy** | appid.sys, ci.dll | 2 | Missing IOCTL access checks |
| **Storage / Caching** | csc.sys, storvsp.sys | 2 | Logic bugs, PreviousMode manipulation |
| **Vendor Utility** | RTCore64.sys, DBUtil_2_3.sys | 15+ | Physical memory mapping, MSR access -- BYOVD weapons |
| **Performance & GPU** | dxgkrnl.sys, dwmcore.dll | 8+ | DMA, shared memory, kernel streaming |
| **Third-Party Security** | Truesight.sys, amsdk.sys | 5+ | EDR bypass, process termination primitives |

### Guides

- **[Why Kernel Drivers?](https://splintersfury.github.io/KernelSight/guides/why-kernel-drivers/)** -- what hardware enforces, what only Ring 0 can do, user-mode alternatives
- **[Anatomy of a Secure Driver](https://splintersfury.github.io/KernelSight/guides/secure-driver-anatomy/)** -- the 6 anti-patterns behind most kernel driver CVEs
- **[Corpus Analytics](https://splintersfury.github.io/KernelSight/guides/corpus-analytics/)** -- visual breakdown of 134 CVEs by driver, year, vulnerability class
- **[Exploit Chain Patterns](https://splintersfury.github.io/KernelSight/guides/exploit-chain-patterns/)** -- the 5 recurring exploit chain shapes
- **[Patch Patterns](https://splintersfury.github.io/KernelSight/guides/patch-patterns/)** -- what Microsoft's fixes look like for each bug class
- **[Mitigation Timeline](https://splintersfury.github.io/KernelSight/guides/mitigation-timeline/)** -- when each kernel defence landed

### Deep Dives

- **[CLFS Deep-Dive](https://splintersfury.github.io/KernelSight/case-studies/clfs-deep-dive/)** -- 12 CVEs, 3 exploited in the wild
- **[AFD Deep-Dive](https://splintersfury.github.io/KernelSight/case-studies/afd-deep-dive/)** -- 13 CVEs, socket teardown races
- **[Win32k Deep-Dive](https://splintersfury.github.io/KernelSight/case-studies/win32k-deep-dive/)** -- 12 CVEs, callback reentrancy
- **[NTFS Deep-Dive](https://splintersfury.github.io/KernelSight/case-studies/ntfs-deep-dive/)** -- 7 CVEs, crafted VHD exploitation

### Additional Sections

- **[Attack Surfaces](https://splintersfury.github.io/KernelSight/attack-surfaces/)** (9) -- IOCTL handlers, filesystem IRPs, NDIS/network, ALPC, shared memory, WMI/ETW
- **[Vulnerability Classes](https://splintersfury.github.io/KernelSight/vuln-classes/)** (10) -- buffer overflow, UAF, type confusion, TOCTOU, race conditions, integer overflow
- **[Exploitation Primitives](https://splintersfury.github.io/KernelSight/primitives/)** (19) -- arbitrary R/W families + exploitation building blocks (pool spray, I/O Ring, WNF, token swap, PreviousMode)
- **[Mitigations](https://splintersfury.github.io/KernelSight/mitigations/)** (9) -- SMEP/SMAP, kCFG/kCET, VBS/HVCI, KDP, pool hardening, KASLR
- **[BYOVD](https://splintersfury.github.io/KernelSight/reference/byovd/)** -- Bring Your Own Vulnerable Driver attack pattern
- **[Tooling](https://splintersfury.github.io/KernelSight/tooling/)** -- static analysis, fuzzing, debugging, patch diffing, AutoPiff integration

## Quick Start

### Browse Online

Visit **[splintersfury.github.io/KernelSight](https://splintersfury.github.io/KernelSight/)** -- no setup required.

### Serve Locally

```bash
git clone https://github.com/splintersfury/KernelSight.git
cd KernelSight
pip install mkdocs-material
mkdocs serve
# Open http://localhost:8000
```

## Related Projects

- **[AutoPiff](https://github.com/splintersfury/AutoPiff)** -- Automated Windows kernel driver patch diffing pipeline that feeds into KernelSight's case studies and detection rules
- **[LOLDrivers](https://www.loldrivers.io/)** -- Community-maintained catalogue of vulnerable and malicious drivers

## Contributing

Contributions welcome -- whether adding a case study, documenting a new technique, or improving existing entries.

1. Use the templates in `templates/` as a starting point
2. Follow the schema in `index/techniques.yaml`
3. Cross-reference CVEs to techniques, techniques to mitigations
4. Open a PR

## License

MIT
