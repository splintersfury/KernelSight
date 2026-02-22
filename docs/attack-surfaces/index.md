# Attack Surfaces

Windows kernel drivers expose multiple attack surfaces depending on their type and the IRP/callback interfaces they implement.

## Categories

| Surface | Description | Key Drivers |
|---------|-------------|-------------|
| [IOCTL Handlers](ioctl-handlers.md) | Device I/O control dispatch | appid.sys, ks.sys, csc.sys |
| [Filesystem IRPs](filesystem-irps.md) | File system and minifilter operations | cldflt.sys, ntfs.sys, fastfat.sys |
| [NDIS / Network](ndis-network.md) | Network packet and OID handling | tcpip.sys |
| [PnP & Power](pnp-power.md) | Plug and Play and power transitions | All PnP drivers |
| [WDF / KMDF](wdf.md) | WDF-managed driver framework | KMDF drivers |
| [Registry Callbacks](registry-callbacks.md) | Registry filtering callbacks | Minifilter/security drivers |
| [ALPC](alpc.md) | Advanced Local Procedure Call | System services |
| [Shared Memory](shared-memory.md) | Kernel-user shared memory regions | mskssrv.sys, ksthunk.sys |
| [WMI / ETW](wmi-etw.md) | WMI and ETW interfaces | Instrumented drivers |
