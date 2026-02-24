# File System Drivers

File system drivers implement on-disk format parsing and file I/O for specific file systems. They process raw disk structures and must handle malformed or malicious media.

## Architecture

- **Driver model**: WDM, loaded by the I/O Manager on volume mount
- **IRP dispatch**: IRP_MJ_CREATE, IRP_MJ_READ, IRP_MJ_WRITE, IRP_MJ_SET_INFORMATION, IRP_MJ_QUERY_INFORMATION
- **Key data**: On-disk metadata (MFT records for NTFS, FAT entries for FAT32), directory structures, bitmap allocations
- **Privilege**: Typically triggered by mounting a removable volume (USB, VHD) — local physical access or VHD attachment

## Attack Surface

- **On-disk structure parsing**: MFT records (NTFS), FAT bitmap/cluster tables (fastfat.sys), extent trees
- **Size calculations**: Cluster counts, allocation sizes, bitmap lengths — prime targets for integer overflow
- **Metadata validation**: Trusting on-disk offsets and lengths without bounds checking
- **VHD/VHDX mount**: User-mode can mount crafted virtual disks that trigger file system parsing

## Common Vulnerability Patterns

| Pattern | Description | AutoPiff Rules |
|---------|-------------|----------------|
| Integer overflow in size calc | Cluster count or allocation size overflows a 32-bit value | `alloc_size_overflow_check_added`, `safe_size_math_helper_added` |
| Heap overflow from MFT parse | Untrusted MFT record length used as memcpy size | `added_len_check_before_memcpy`, `added_struct_size_validation` |
| Missing bounds on bitmap | FAT bitmap allocation trusts on-disk cluster count | `added_index_bounds_check` |

## CVEs

| CVE | Driver | Description | Class |
|-----|--------|-------------|-------|
| [CVE-2025-24993](../case-studies/CVE-2025-24993.md) | `ntfs.sys` | MFT metadata heap buffer overflow via crafted VHD | Buffer Overflow |
| [CVE-2025-24985](../case-studies/CVE-2025-24985.md) | `fastfat.sys` | Cluster count overflow in FAT bitmap allocation | Integer Overflow |

## Key Drivers

### ntfs.sys
- **Role**: NTFS file system driver
- **Attack vector**: Crafted VHD/VHDX mount, removable media
- **Key structures**: MFT records (`FILE_RECORD_SEGMENT_HEADER`), attribute lists, index entries

### fastfat.sys
- **Role**: FAT12/16/32 file system driver
- **Attack vector**: Crafted USB drive or FAT-formatted VHD
- **Key structures**: FAT table entries, cluster bitmap, directory entries

## Research Notes

VHD mounting is available to standard users on Windows 10/11, so file system parsing bugs are reachable without admin privileges. Both CVE-2025-24985 and CVE-2025-24993 were exploited in the wild.
