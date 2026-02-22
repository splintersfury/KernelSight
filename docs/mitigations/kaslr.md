# KASLR

Kernel Address Space Layout Randomization — randomizes kernel base address and pool addresses.

## Description

KASLR randomizes the load address of the kernel image, drivers, and pool regions on each boot. Attackers need an info leak to determine kernel addresses before exploitation.

## Bypass Techniques

- **NtQuerySystemInformation**: Leaks module base addresses (requires Medium IL)
- **Uninitialized memory**: Stack/pool leaks revealing kernel pointers
- **KUSER_SHARED_DATA timing**: Side-channel attacks
- **Pool pointer leaks**: Info disclosure vulnerabilities

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2023-32019](../case-studies/CVE-2023-32019.md) | `ntoskrnl.exe` | Kernel heap memory leak |
| [CVE-2024-38256](../case-studies/CVE-2024-38256.md) | `win32k.sys` | Uninitialized memory leak |

## AutoPiff Detection

- `buffer_zeroing_before_copy_added`
- `stack_variable_initialization_added`
- `kernel_pointer_scrubbing_added`
