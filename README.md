# KernelSight

A structured, living knowledge base cataloging Windows kernel driver exploitation techniques, attack surfaces, and arbitrary R/W primitives — each grounded in real CVEs with specific driver names, versions, and builds.

## What's Inside

- **Attack Surfaces** — IOCTL handlers, filesystem IRPs, NDIS/network, PnP/Power, WDF, registry callbacks, ALPC, shared memory, WMI/ETW
- **Vulnerability Classes** — Buffer overflows, integer overflows, type confusion, TOCTOU/double-fetch, use-after-free, race conditions, uninitialized memory, arbitrary R/W, null deref, logic bugs
- **Primitives** — 10 arbitrary R/W primitive families + 9 exploitation primitive families
- **Mitigations** — SMEP/SMAP, kCFG/kCET, VBS/HVCI, KDP, pool hardening, Secure Pool, ACG, KASLR
- **Case Studies** — 28+ real CVEs with driver names, vulnerable/fixed builds, writeup links, and PoC references
- **Tooling** — Static analysis, fuzzing, debugging, and AutoPiff integration guides

## Automated Collector

KernelSight includes an automated intelligence collector that continuously monitors security feeds for new Windows kernel driver vulnerabilities and exploitation research:

- **MSRC Security Update Guide** — New kernel driver CVEs
- **Google Project Zero** — Windows kernel research and 0-day RCAs
- **GitHub PoC repos** — CVE-tagged exploit repositories
- **Security blogs** — Synacktiv, STAR Labs, SSD Disclosure, Exodus Intelligence
- **NVD** — CVE metadata enrichment (CVSS, CWE, affected products)

The collector analyzes new findings, classifies them into the knowledge base taxonomy, and opens GitHub PRs with proposed additions.

## Quick Start

### Browse the Knowledge Base

```bash
pip install mkdocs-material
mkdocs serve
```

Then open http://localhost:8000.

### Run the Collector

```bash
docker compose up -d kernelsight-collector
```

Or dry-run to preview without creating PRs:

```bash
cd collector
python collector.py --dry-run
```

### Bootstrap from AutoPiff

If you have the AutoPiff project alongside this repo:

```bash
python scripts/bootstrap_from_autopiff.py
```

This generates case study stubs and YAML indexes from AutoPiff's CVE validation corpus.

## Repository Structure

```
index/              YAML indexes (machine-readable)
docs/               mkdocs content
  attack-surfaces/  9 attack surface entries
  vuln-classes/     10 vulnerability class entries
  primitives/       19 primitive entries (10 arb R/W + 9 exploitation)
  mitigations/      8 mitigation entries
  case-studies/     28+ CVE case studies
  tooling/          Tool and integration guides
templates/          Reference templates for contributions
scripts/            Utility scripts
collector/          Automated intel collector service
```

## Contributing

1. Use the templates in `templates/` as a starting point
2. Follow the existing YAML schema in `index/techniques.yaml`
3. Link CVEs to techniques using the cross-reference fields
4. The collector will also propose additions via PR — review and merge as appropriate

## License

MIT
