---
description: "Guides for Windows kernel driver security -- secure driver anatomy, corpus analytics, exploit chain patterns, patch patterns, and mitigation timelines."
---

# Guides

These guides synthesize patterns from the KernelSight corpus into analysis that cuts across individual CVEs and vulnerability classes. Where case studies examine specific bugs and mitigation pages describe individual defenses, the guides look at the broader picture: what recurring shapes appear across exploit chains, where vulnerabilities cluster by driver and year, how Microsoft's patches follow predictable templates, and how each new mitigation shifted the techniques that attackers use.

The six guides approach the same body of data from different angles.

[Why Kernel Drivers?](why-kernel-drivers.md) begins at the hardware level, explaining why Ring 0 code exists, what only the kernel can do, and where Microsoft is trying to push functionality to user mode. It grounds the entire knowledge base in the architectural reality that creates the attack surface.

[Anatomy of a Secure Driver](secure-driver-anatomy.md) distills the corpus into six anti-patterns that account for the vast majority of kernel driver vulnerabilities. Each anti-pattern includes the specific coding mistake, real CVE examples, and the fix. This is the closest thing to a checklist for driver developers and auditors.

[Corpus Analytics](corpus-analytics.md) presents a visual breakdown of 147 CVEs across 64 drivers, showing where vulnerabilities cluster by driver family, year, vulnerability class, and exploitation status. The data reveals which drivers generate the most bugs and which bug types are most likely to be exploited in the wild.

[Exploit Chain Patterns](exploit-chain-patterns.md) identifies the five recurring chain shapes that turn a kernel bug into SYSTEM. From file format corruption through pool spray to token swap, these archetypes describe how real-world exploits navigate the defense-in-depth stack.

[Patch Patterns](patch-patterns.md) catalogs the seven most common fix shapes that Microsoft applies across Patch Tuesday. Recognizing these patterns in a binary diff lets a researcher classify the underlying vulnerability before any public writeup exists.

[Mitigation Timeline](mitigation-timeline.md) maps each kernel defense to the year it shipped and the specific technique shift it caused. The timeline shows how each new mitigation redirected attackers from one approach to the next, tracing the path from trivial ret2user to the data-only strategies that dominate today.
