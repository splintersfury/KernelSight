# Driver Types

Windows kernel drivers are categorized by their role and the kernel subsystem they interact with. Each driver type has distinct attack surfaces, IRP handling patterns, and vulnerability profiles.

## Categories

| Driver Type | Examples | CVEs in Corpus | Key Attack Surface |
|---|---|---|---|
| [File System Drivers](filesystem.md) | ntfs.sys, fastfat.sys | 2 | On-disk structure parsing, IRP dispatch |
| [File System Minifilters](minifilter.md) | cldflt.sys | 2 | Pre/post-operation callbacks, reparse data |
| [Log / Transaction Drivers](log-transaction.md) | clfs.sys | 4 | Metadata parsing, base log manipulation |
| [Network Stack](network-stack.md) | tcpip.sys, afd.sys, http.sys | 5 | Packet parsing, socket operations, protocol handling |
| [Kernel Streaming](kernel-streaming.md) | ks.sys, mskssrv.sys, ksthunk.sys | 5 | IOCTL dispatch, WOW64 thunking, MDL operations |
| [Win32k Subsystem](win32k.md) | win32k.sys, win32kbase.sys, win32kfull.sys | 3 | Syscall handlers, GDI objects, window management |
| [Core Kernel](core-kernel.md) | ntoskrnl.exe | 4 | Syscall handlers, security subsystem, VBS |
| [Security / Policy Drivers](security-policy.md) | appid.sys | 1 | IOCTL access control, policy enforcement |
| [Storage / Caching Drivers](storage-caching.md) | csc.sys | 1 | IOCTL handlers, file caching |

## Driver Type vs. Vulnerability Class Heatmap

| Driver Type | Buffer Overflow | Integer Overflow | Type Confusion | Race Condition | UAF | Info Disclosure | Logic Bug |
|---|---|---|---|---|---|---|---|
| File System | ■■ | ■ | | | | | |
| Minifilter | ■■ | | | | | | |
| Log / Transaction | ■■■■ | | | | | | |
| Network Stack | ■ | ■■ | | | ■ | | |
| Kernel Streaming | | ■ | ■ | | ■ | | |
| Win32k | | | ■ | | ■ | ■ | |
| Core Kernel | | | | ■■ | | ■ | ■ |
| Security / Policy | | | | | | | ■ |
| Storage / Caching | | | | | | | ■ |
