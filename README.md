# KernelSight

A structured, living knowledge base cataloging **Windows kernel driver exploitation techniques**, attack surfaces, and arbitrary R/W primitives — each grounded in real CVEs with specific driver names, versions, and builds.

**[Browse the Knowledge Base](https://splintersfury.github.io/KernelSight/)**

---

## Why KernelSight?

Windows kernel exploitation knowledge is scattered across blog posts, conference talks, and GitHub repos. KernelSight organizes it into a single, browsable reference structured around what matters most: **what type of driver are you looking at, and what bugs does it have?**

Every technique links back to real CVEs with:
- Exact vulnerable and patched build numbers
- Driver filenames and affected functions
- Writeup and PoC references
- Automated detection rules from [AutoPiff](https://github.com/splintersfury/AutoPiff)

## What's Inside

### Driver Types (Primary Organization)

The knowledge base is organized by **Windows kernel driver type** — because vulnerability patterns cluster by driver architecture:

| Driver Type | Drivers | CVEs | Key Insight |
|---|---|---|---|
| **File System** | ntfs.sys, fastfat.sys | 2 | VHD mount gives unprivileged access to on-disk parsing |
| **Minifilters** | cldflt.sys | 2 | Reparse data is the recurring attack vector |
| **Log / Transaction** | clfs.sys | 4 | Most exploited single driver — 3 ITW, complex metadata format |
| **Network Stack** | tcpip.sys, afd.sys, http.sys | 5 | Includes 2 remotely exploitable bugs (IPv6 RCE, HTTP RCE) |
| **Kernel Streaming** | ks.sys, mskssrv.sys, ksthunk.sys | 6 | Most productive research target — IOCTL, MDL, type confusion |
| **Win32k** | win32k.sys, win32kbase.sys, win32kfull.sys | 3 | ~1200 syscall handlers, historically most exploited subsystem |
| **Core Kernel** | ntoskrnl.exe | 4 | Security subsystem races, VBS bypass, highest impact |
| **Security / Policy** | appid.sys | 1 | Lazarus Group ITW — admin-to-kernel via missing IOCTL access check |
| **Storage / Caching** | csc.sys | 1 | Logic bug → PreviousMode manipulation → SYSTEM |

### Additional Sections

- **Attack Surfaces** (9) — IOCTL handlers, filesystem IRPs, NDIS/network, PnP/Power, WDF, registry callbacks, ALPC, shared memory, WMI/ETW
- **Vulnerability Classes** (10) — Buffer overflows, integer overflows, type confusion, TOCTOU/double-fetch, use-after-free, race conditions, uninitialized memory, arbitrary R/W, null deref, logic bugs
- **Exploitation Primitives** (19) — 10 arbitrary R/W primitive families (direct IOCTL, pool overflow, MDL mapping, write-what-where, PTE manipulation, ...) + 9 exploitation techniques (pool spray, I/O Ring, WNF, token swap, PreviousMode, ...)
- **Mitigations** (8) — SMEP/SMAP, kCFG/kCET, VBS/HVCI, KDP, pool hardening, Secure Pool, ACG, KASLR
- **Case Studies** (28) — Real CVEs with driver names, vulnerable/fixed builds, root cause, exploitation details, and patch analysis
- **Tooling** — Static analysis, fuzzing, debugging, and AutoPiff integration guides

### YAML Indexes (Machine-Readable)

All data is also available as structured YAML for programmatic use:

- `index/techniques.yaml` — 46 technique entries with slugs, tags, CVE cross-refs
- `index/cve_index.yaml` — 28 CVEs with build numbers, references, AutoPiff data
- `index/driver_index.yaml` — 16 drivers grouped by CVE
- `index/autopiff_rule_map.yaml` — 66 AutoPiff rule IDs mapped to techniques

## Stats

| Metric | Count |
|--------|-------|
| CVE case studies | 28 |
| Unique drivers | 16 |
| Exploited in the wild | 12 |
| Remotely exploitable | 2 |
| Driver type categories | 9 |
| Technique pages | 46 |
| AutoPiff detection rules | 66 |
| Exploitation primitive families | 19 |

## Automated Collector

KernelSight includes a **Docker-based intelligence collector** that continuously monitors security feeds and proposes additions to the knowledge base via GitHub PRs:

| Source | What It Monitors |
|--------|-----------------|
| **MSRC Security Update Guide** | New kernel driver CVEs from Microsoft |
| **Google Project Zero** | Windows kernel research, 0-day root cause analyses |
| **GitHub PoC repos** | CVE-tagged exploit repositories with 2+ stars |
| **Security blogs** | Synacktiv, STAR Labs, SSD Disclosure, Exodus Intelligence, ZDI, SafeBreach |
| **NVD** | CVE metadata enrichment (CVSS scores, CWE IDs, affected products) |

The collector:
1. Scrapes all configured sources on a 6-hour schedule
2. Extracts CVE IDs, driver names, and technique indicators
3. Classifies findings against the technique taxonomy
4. Deduplicates against existing entries (Redis-backed)
5. Opens a GitHub PR with proposed additions (new case studies, updated references, technique cross-refs)

## Quick Start

### Browse Online

Visit **[splintersfury.github.io/KernelSight](https://splintersfury.github.io/KernelSight/)** — no setup required.

### Serve Locally

```bash
git clone https://github.com/splintersfury/KernelSight.git
cd KernelSight
pip install mkdocs-material
mkdocs serve
# Open http://localhost:8000
```

### Run the Collector

```bash
# Set your GitHub token
export GITHUB_TOKEN=ghp_...

# Run with Docker Compose
docker compose up -d

# Or dry-run to preview without creating PRs
cd collector
pip install -r requirements.txt
python collector.py --dry-run
```

### Bootstrap from AutoPiff

If you have [AutoPiff](https://github.com/splintersfury/AutoPiff) cloned alongside this repo:

```bash
python scripts/bootstrap_from_autopiff.py
```

This regenerates case study stubs and YAML indexes from AutoPiff's CVE validation corpus.

## Repository Structure

```
KernelSight/
├── docs/                       # mkdocs site content
│   ├── driver-types/           #   9 driver type pages (primary navigation)
│   ├── attack-surfaces/        #   9 attack surface entries
│   ├── vuln-classes/           #   10 vulnerability class entries
│   ├── primitives/             #   19 primitives (10 arb R/W + 9 exploitation)
│   │   ├── arw/                #     Arbitrary R/W primitive families
│   │   └── exploitation/       #     Exploitation technique families
│   ├── mitigations/            #   8 mitigation entries
│   ├── case-studies/           #   28 CVE case studies
│   └── tooling/                #   Tool and integration guides
│
├── index/                      # YAML indexes (machine-readable)
│   ├── techniques.yaml         #   Master technique registry (46 entries)
│   ├── cve_index.yaml          #   All CVEs with metadata
│   ├── driver_index.yaml       #   Per-driver CVE list
│   └── autopiff_rule_map.yaml  #   AutoPiff rule → technique mapping
│
├── collector/                  # Automated intel collector (Docker service)
│   ├── collector.py            #   Main service entry point
│   ├── analyzer.py             #   Content classifier
│   ├── pr_manager.py           #   GitHub PR creation
│   ├── sources/                #   Per-source scrapers (MSRC, P0, GitHub, blogs, NVD)
│   ├── config.yaml             #   Source URLs, keywords, schedule
│   ├── Dockerfile              #   Python 3.12 + gh CLI
│   └── tests/                  #   Analyzer unit tests
│
├── scripts/
│   └── bootstrap_from_autopiff.py  # Generate indexes from AutoPiff corpus
│
├── templates/                  # Reference templates for contributions
│   ├── technique.md
│   └── case-study.md
│
├── mkdocs.yml                  # Material for MkDocs configuration
└── docker-compose.yml          # Collector + Redis services
```

## Contributing

Contributions welcome — whether it's filling in a case study stub, adding a new technique, or improving the collector.

1. **Add content**: Use the templates in `templates/` as a starting point
2. **Follow the schema**: See `index/techniques.yaml` for the technique entry format
3. **Cross-reference**: Link CVEs to techniques, techniques to mitigations
4. **Collector PRs**: The collector will also propose additions — review and merge as appropriate

## Related Projects

- **[AutoPiff](https://github.com/splintersfury/AutoPiff)** — Automated Windows kernel driver patch diffing pipeline that feeds into KernelSight's case studies and detection rules

## License

MIT
