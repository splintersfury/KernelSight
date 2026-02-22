# Secure Pool

VBS-protected secure pool for sensitive kernel allocations, isolated from VTL 0 corruption.

## Description

Secure Pool allocations live in VTL 1-protected memory, making them immune to VTL 0 kernel exploits. Used for high-value security data structures.
