# SMEP / SMAP

Supervisor Mode Execution Prevention (SMEP) and Supervisor Mode Access Prevention (SMAP) prevent the kernel from executing code in or accessing user-mode pages.

## Description

- **SMEP** (CR4 bit 20): Faults if kernel tries to execute code from user-mode page
- **SMAP** (CR4 bit 21): Faults if kernel tries to read/write user-mode page without explicit `STAC`/`CLAC`

## Bypass Techniques

- PTE manipulation to remap user page as kernel page
- ROP/JOP chains that stay within kernel code
- Data-only attacks that don't require code execution
- CR4 overwrite (mitigated by VBS/HVCI)
