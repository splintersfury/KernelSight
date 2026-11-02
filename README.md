# KernelSight

[![GitHub Pages](https://img.shields.io/badge/Browse-Knowledge%20Base-blue)](https://splintersfury.github.io/KernelSight/)
[![CVEs](https://img.shields.io/badge/CVEs-157-red)](https://splintersfury.github.io/KernelSight/case-studies/)
[![Drivers](https://img.shields.io/badge/Drivers-64-orange)](https://splintersfury.github.io/KernelSight/driver-types/)
[![ITW](https://img.shields.io/badge/Exploited%20ITW-58-critical)](https://splintersfury.github.io/KernelSight/guides/corpus-analytics/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

The exploitation pipeline for Windows kernel drivers, from attack surface to privilege escalation. Every entry is grounded in real CVEs with driver names, vulnerable/fixed builds, patch analysis, and detection rules.

**[Browse the Knowledge Base →](https://splintersfury.github.io/KernelSight/)**

---

## What is KernelSight?

KernelSight is an interactive knowledge base that maps how Windows kernel drivers get exploited. It tracks 157 CVEs across 64 drivers, organized as a pipeline that mirrors how exploitation actually works: identify a driver, find its attack surface, classify the bug, convert it into a primitive, and escalate to SYSTEM.

The landing page is an interactive threat intelligence dashboard with a driver-by-vuln-class heat matrix, searchable CVE explorer, and export functionality. The knowledge base behind it contains 279 pages of narrative-driven technical content covering vulnerability classes, exploitation primitives, kernel mitigations, and real-world case studies.

## Corpus

| Metric | Count |
|--------|-------|
| CVE case studies | **157** |
| Unique drivers analysed | **64** |
| Exploited in the wild | **58** |
| Remotely exploitable | **2** |
| BYOVD drivers | **41** |
| Driver type categories | **12** |
| Exploitation technique pages | **57** |
| AutoPiff detection rules | **80+** |
| LOLDrivers analysed | **1,775** |

## The Exploitation Pipeline

KernelSight is organized as a pipeline from driver identification through privilege escalation:

**[Driver Types](https://splintersfury.github.io/KernelSight/driver-types/)** → **[Attack Surfaces](https://splintersfury.github.io/KernelSight/attack-surfaces/)** → **[Vulnerability Classes](https://splintersfury.github.io/KernelSight/vuln-classes/)** → **[Exploitation Primitives](https://splintersfury.github.io/KernelSight/primitives/)** → **[Case Studies](https://splintersfury.github.io/KernelSight/case-studies/)**

The navigation groups these five as **Means**: how kernel access is obtained. **Targets** holds the other half of the thesis: for every enumerated Windows defense, a maintained inventory of what a kernel primitive does and does not defeat against it, each verdict dated and marked tested, cited, or inferred. The **[Bypass Matrix](https://splintersfury.github.io/KernelSight/bypasses/)** re-evaluates every registered inventory against one platform selector, and **[Developer Highlights](https://splintersfury.github.io/KernelSight/notable-exploits/)** profile exploit developers by the chains they compose rather than the bugs they find.

### Driver Types (12 Categories)

| Driver Type | Example Drivers | CVEs | Key Pattern |
|---|---|---|---|
| **File System** | ntfs.sys, fastfat.sys | 7 | VHD mount gives unprivileged access to on-disk parsing |
| **Minifilters** | cldflt.sys | 8 | Reparse data and cloud file callbacks |
| **Log / Transaction** | clfs.sys | 15 | Most exploited single driver, on-disk metadata corruption |
| **Network Stack** | tcpip.sys, afd.sys, http.sys | 13 | Includes 2 remotely exploitable bugs (IPv6 RCE, HTTP RCE) |
| **Kernel Streaming** | ks.sys, mskssrv.sys, ksthunk.sys | 14 | IOCTL handlers, MDL mapping, type confusion |
| **Win32k** | win32k.sys, win32kbase.sys, win32kfull.sys | 12 | Callback reentrancy, window object races |
| **Core Kernel** | ntoskrnl.exe | 13 | Token races, secure-mode bypasses, highest impact |
| **Security / Policy** | appid.sys, ci.dll | 2 | Missing IOCTL access checks |
| **Storage / Caching** | csc.sys, storvsp.sys | 2 | Logic bugs, PreviousMode manipulation |
| **Vendor Utility** | RTCore64.sys, DBUtil_2_3.sys | 15+ | Physical memory mapping, MSR access, BYOVD weapons |
| **Performance & GPU** | dxgkrnl.sys, dwmcore.dll | 8+ | DMA, shared memory, kernel streaming |
| **Third-Party Security** | Truesight.sys, amsdk.sys | 5+ | EDR bypass, process termination primitives |

### Guides

- **[Why Kernel Drivers?](https://splintersfury.github.io/KernelSight/guides/why-kernel-drivers/)** -- what hardware enforces, what only Ring 0 can do, user-mode alternatives
- **[Anatomy of a Secure Driver](https://splintersfury.github.io/KernelSight/guides/secure-driver-anatomy/)** -- the 6 anti-patterns behind most kernel driver CVEs
- **[Corpus Analytics](https://splintersfury.github.io/KernelSight/guides/corpus-analytics/)** -- visual breakdown of 157 CVEs by driver, year, vulnerability class
- **[Exploit Chain Patterns](https://splintersfury.github.io/KernelSight/guides/exploit-chain-patterns/)** -- the 5 recurring exploit chain shapes
- **[Patch Patterns](https://splintersfury.github.io/KernelSight/guides/patch-patterns/)** -- what Microsoft's fixes look like for each bug class
- **[Mitigation Timeline](https://splintersfury.github.io/KernelSight/guides/mitigation-timeline/)** -- when each kernel defence landed

### Deep Dives

- **[CLFS Deep-Dive](https://splintersfury.github.io/KernelSight/case-studies/clfs-deep-dive/)** -- 15 CVEs, the most exploited Windows kernel attack surface
- **[AFD Deep-Dive](https://splintersfury.github.io/KernelSight/case-studies/afd-deep-dive/)** -- 13 CVEs, socket teardown races and Lazarus Group campaigns
- **[Win32k Deep-Dive](https://splintersfury.github.io/KernelSight/case-studies/win32k-deep-dive/)** -- 12 CVEs, callback reentrancy and the evolution of exploitation
- **[NTFS Deep-Dive](https://splintersfury.github.io/KernelSight/case-studies/ntfs-deep-dive/)** -- 7 CVEs, crafted VHD exploitation

### Additional Sections

- **[Dashboard](https://splintersfury.github.io/KernelSight/)** -- interactive threat matrix, searchable CVE explorer, CSV/JSON export
- **[Attack Surfaces](https://splintersfury.github.io/KernelSight/attack-surfaces/)** (9) -- IOCTL handlers, filesystem IRPs, NDIS/network, ALPC, shared memory, WMI/ETW
- **[Vulnerability Classes](https://splintersfury.github.io/KernelSight/vuln-classes/)** (10) -- buffer overflow, UAF, type confusion, TOCTOU, race conditions, integer overflow
- **[Exploitation Primitives](https://splintersfury.github.io/KernelSight/primitives/)** (19) -- arbitrary R/W families + exploitation building blocks
- **[Bypass Matrix](https://splintersfury.github.io/KernelSight/bypasses/)** -- every registered bypass inventory evaluated against one platform selector, machine-readable export included
- **[Mitigations / Targets](https://splintersfury.github.io/KernelSight/mitigations/)** -- 30 defenses on the roster across kernel and user layer, 18 with a reviewed bypass inventory
- **[Developer Highlights](https://splintersfury.github.io/KernelSight/notable-exploits/)** -- exploit-developer profiles organized by chain, not by bug
- **[BYOVD](https://splintersfury.github.io/KernelSight/reference/byovd/)** -- Bring Your Own Vulnerable Driver attack pattern
- **[Tooling](https://splintersfury.github.io/KernelSight/tooling/)** -- static analysis, fuzzing, debugging, patch diffing, AutoPiff integration
- **[LOLDrivers Analysis](https://splintersfury.github.io/KernelSight/reference/loldrivers-analysis/)** -- 1,775 drivers analysed with automated Ghidra decompilation

## Quick Start

### Browse Online

Visit **[splintersfury.github.io/KernelSight](https://splintersfury.github.io/KernelSight/)** -- no setup required.

### Serve Locally

```bash
git clone https://github.com/splintersfury/KernelSight.git
cd KernelSight
pip install mkdocs-material pyyaml pytest
python scripts/build_dashboard_data.py    # dashboard data
python scripts/build_hero_curve.py        # homepage hardening curve
python scripts/build_bypass_export.py     # machine-readable bypass registry
python scripts/build_page_dates.py        # per-page dates from git history
mkdocs serve                              # open http://localhost:8000
python -m pytest tests/ -q                # corpus consistency checks
```

### Project Structure

```
KernelSight/
├── docs/                    # MkDocs source (279 markdown pages)
│   ├── index.md             # Dashboard landing page (custom template)
│   ├── overview.md          # Pipeline overview page
│   ├── driver-types/        # 12 driver categories
│   ├── attack-surfaces/     # 9 attack vectors
│   ├── vuln-classes/        # 10 vulnerability classes
│   ├── primitives/          # 19 exploitation techniques
│   ├── case-studies/        # 157 CVE case studies + 4 deep dives
│   ├── notable-exploits/    # exploit-developer profiles, organized by chain
│   ├── mitigations/         # defense pages with bypass inventories
│   ├── bypasses/            # aggregate bypass matrix
│   ├── guides/              # 6 synthesis essays
│   ├── tooling/             # 5 tool guides
│   ├── reference/           # BYOVD, LOLDrivers, KDU, resources
│   ├── overrides/           # Custom dashboard HTML template
│   └── assets/              # Dashboard JS, data JSON
├── index/                   # YAML data indices
│   ├── cve_index.yaml       # 157 CVE definitions
│   ├── driver_index.yaml    # Driver metadata
│   ├── defenses.yaml        # Defense roster (30 entries, kernel and user layer)
│   ├── techniques.yaml      # Technique registry
│   └── autopiff_rule_map.yaml
├── collector/               # Automated CVE data collector (Docker)
├── scripts/                 # Build scripts
└── mkdocs.yml               # Site configuration
```

## Related Projects

- **[AutoPiff](https://github.com/splintersfury/AutoPiff)** -- Automated Windows kernel driver patch diffing pipeline that feeds into KernelSight's case studies and detection rules
- **[LOLDrivers](https://www.loldrivers.io/)** -- Community-maintained catalogue of vulnerable and malicious drivers

## Contributing

Contributions welcome, whether adding a case study, documenting a new technique, or improving existing entries.

The [MSRC watch](.github/workflows/watch-msrc.yml) scans every Patch Tuesday and opens a monthly triage issue listing each new kernel-driver CVE the corpus does not yet cover, exploited-in-the-wild first. Pick an unchecked entry from the latest one as a ready-made first contribution.

1. Use the templates in `templates/` as a starting point
2. Follow the schema in `index/techniques.yaml`
3. Cross-reference CVEs to techniques, techniques to mitigations
4. Run `python scripts/build_dashboard_data.py` to regenerate dashboard data
5. Open a PR

## License

MIT
