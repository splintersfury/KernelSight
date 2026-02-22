# Mitigations

Windows kernel security mitigations that defend against driver exploitation.

## Categories

| Mitigation | Description | Bypass Difficulty |
|-----------|-------------|-------------------|
| [SMEP / SMAP](smep-smap.md) | Supervisor mode execution/access prevention | Medium |
| [kCFG / kCET](kcfg-kcet.md) | Kernel control flow integrity | High |
| [VBS / HVCI](vbs-hvci.md) | Virtualization-based code integrity | Very High |
| [KDP](kdp.md) | Kernel Data Protection | Very High |
| [Pool Hardening](pool-hardening.md) | Segment heap, pool cookies, NX pool | Medium |
| [Secure Pool](secure-pool.md) | VBS-protected pool allocations | Very High |
| [ACG](acg.md) | Arbitrary Code Guard | High |
| [KASLR](kaslr.md) | Kernel address space randomization | Low-Medium |
