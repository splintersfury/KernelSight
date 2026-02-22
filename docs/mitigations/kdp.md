# Kernel Data Protection (KDP)

VBS-backed read-only protection for critical kernel data structures.

## Description

KDP uses the hypervisor to mark specific kernel data pages as read-only, preventing even kernel-mode code from modifying them. Drivers can use `MmProtectDriverSection` to protect their own data.

## Protected Data

- Security-critical global variables
- Driver configuration data
- CI (Code Integrity) policy data
