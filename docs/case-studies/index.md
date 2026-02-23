# Case Studies

<div class="ks-pipeline-pos">
  Driver Type &rarr; Attack Surface &rarr; Vuln Class &rarr; Primitive &rarr; <span class="ks-active">Case Study</span>
</div>

Case studies are where the pipeline comes together. Each entry walks through a real CVE from root cause through exploitation to patch — connecting the driver type, attack surface, vulnerability class, and primitives used into a complete chain. The corpus covers 52 CVEs across 39 unique drivers, with 29 exploited in the wild — including 21 third-party BYOVD driver case studies.

## CVE Index

| CVE | Driver | Class | ITW | Build (Vuln → Fix) |
|-----|--------|-------|-----|---------------------|
| [CVE-2025-29824](CVE-2025-29824.md) | `clfs.sys` | Use-After-Free / Logic Bug | Yes | `10.0.26100.3476` → `10.0.26100.3775` |
| [CVE-2025-24993](CVE-2025-24993.md) | `ntfs.sys` | Buffer Overflow / Bounds Check | Yes | `10.0.22621.4830` → `10.0.22621.4890` |
| [CVE-2025-24985](CVE-2025-24985.md) | `fastfat.sys` | Integer Overflow | Yes | `10.0.22621.4830` → `10.0.22621.5037` |
| [CVE-2025-21333](CVE-2025-21333.md) | `vsp.sys` | Buffer Overflow | Yes | `10.0.26100.2605` → `10.0.26100.2894` |
| [CVE-2024-49138](CVE-2024-49138.md) | `clfs.sys` | Buffer Overflow / Bounds Check | Yes | `10.0.22621.4541` → `10.0.22621.4601` |
| [CVE-2024-49114](CVE-2024-49114.md) | `cldflt.sys` | Buffer Overflow | No | `10.0.22621.4460` → `10.0.22621.4602` |
| [CVE-2024-38256](CVE-2024-38256.md) | `win32k.sys` | Information Disclosure | No | `10.0.22621.3958` → `10.0.22621.4169` |
| [CVE-2024-38238](CVE-2024-38238.md) | `ksthunk.sys` | MDL Handling | No | `10.0.22621.4036` → `10.0.22621.4169` |
| [CVE-2024-38193](CVE-2024-38193.md) | `afd.sys` | Use-After-Free / Lifetime | Yes | `10.0.22621.3672` → `10.0.22621.4036` |
| [CVE-2024-38106](CVE-2024-38106.md) | `ntoskrnl.exe` | Race Condition / TOCTOU | Yes | `10.0.22621.3958` → `10.0.22621.4169` |
| [CVE-2024-38063](CVE-2024-38063.md) | `tcpip.sys` | Integer Overflow | No | `10.0.22621.3958` → `10.0.22621.4036` |
| [CVE-2024-38054](CVE-2024-38054.md) | `ksthunk.sys` | IOCTL Hardening | No | `10.0.22621.3733` → `10.0.22621.3880` |
| [CVE-2024-35250](CVE-2024-35250.md) | `ks.sys` | IOCTL Hardening | Yes | `10.0.22621.3672` → `10.0.22621.3733` |
| [CVE-2024-30089](CVE-2024-30089.md) | `mskssrv.sys` | Use-After-Free / Lifetime | No | `10.0.22621.2506` → `10.0.22621.3733` |
| [CVE-2024-30088](CVE-2024-30088.md) | `ntoskrnl.exe` | Race Condition / TOCTOU | Yes | `10.0.22621.3672` → `10.0.22621.3733` |
| [CVE-2024-30085](CVE-2024-30085.md) | `cldflt.sys` | Buffer Overflow / Bounds Check | No | `10.0.22621.3672` → `10.0.22621.3733` |
| [CVE-2024-26229](CVE-2024-26229.md) | `csc.sys` | Authorization / Access Check | No | `10.0.22621.1` → `10.0.22621.3447` |
| [CVE-2024-21338](CVE-2024-21338.md) | `appid.sys` | IOCTL Hardening | Yes | `10.0.22621.2506` → `10.0.22621.3155` |
| [CVE-2024-21302](CVE-2024-21302.md) | `ntoskrnl.exe` | State Hardening | No | `10.0.22621.3958` → `10.0.22621.4169` |
| [CVE-2023-36802](CVE-2023-36802.md) | `mskssrv.sys` | Type Confusion | Yes | `10.0.22621.1848` → `10.0.22621.2283` |
| [CVE-2023-36424](CVE-2023-36424.md) | `clfs.sys` | Pool Hardening | No | `10.0.22621.2506` → `10.0.22621.2715` |
| [CVE-2023-36036](CVE-2023-36036.md) | `cldflt.sys` | Buffer Overflow / Bounds Check | Yes | `10.0.22621.2506` → `10.0.22621.2715` |
| [CVE-2023-32019](CVE-2023-32019.md) | `ntoskrnl.exe` | Information Disclosure | No | `10.0.22621.1702` → `10.0.22621.1848` |
| [CVE-2023-29360](CVE-2023-29360.md) | `mskssrv.sys` | MDL Handling | No | `10.0.22621.1702` → `10.0.22621.1848` |
| [CVE-2023-29336](CVE-2023-29336.md) | `win32kfull.sys` | Object Management | Yes | `10.0.22621.1555` → `10.0.22621.1635` |
| [CVE-2023-28252](CVE-2023-28252.md) | `clfs.sys` | Buffer Overflow / Bounds Check | Yes | `10.0.22621.1265` → `10.0.22621.1555` |
| [CVE-2023-28218](CVE-2023-28218.md) | `afd.sys` | Integer Overflow | No | `10.0.22621.1344` → `10.0.22621.1555` |
| [CVE-2023-21768](CVE-2023-21768.md) | `afd.sys` | User Boundary Validation | No | `10.0.22621.608` → `10.0.22621.1105` |
| [CVE-2022-37969](CVE-2022-37969.md) | `clfs.sys` | Buffer Overflow / Bounds Check | Yes | `10.0.22621.1` → `10.0.22621.521` |
| [CVE-2022-21907](CVE-2022-21907.md) | `http.sys` | String Handling | No | `10.0.22621.1` → `10.0.22621.382` |
| [CVE-2022-21882](CVE-2022-21882.md) | `win32kbase.sys` | Type Confusion | Yes | `10.0.22621.1` → `10.0.22621.382` |

## Third-Party Drivers

### Vendor Utility Drivers

| CVE / ID | Driver | Vendor | Class | ITW | Status |
|----------|--------|--------|-------|-----|--------|
| [CVE-2021-21551](CVE-2021-21551.md) | `DBUtil_2_3.sys` | Dell | Arbitrary R/W | Yes | Blocklisted |
| [CVE-2019-16098](CVE-2019-16098.md) | `RTCore64.sys` | MSI | Arbitrary R/W | Yes | Blocklisted |
| [CVE-2018-19320](CVE-2018-19320.md) | `gdrv.sys` | Gigabyte | Arbitrary R/W | Yes | Blocklisted |
| [CVE-2015-2291](CVE-2015-2291.md) | `iqvw64e.sys` | Intel | Arbitrary R/W | Yes | Blocklisted |
| [CVE-2020-15368](CVE-2020-15368.md) | `HW.sys` | Marvin Test | Arbitrary R/W | Yes | Blocklisted |
| [CVE-2022-3699](CVE-2022-3699.md) | `LenovoDiagnosticsDriver.sys` | Lenovo | Arbitrary R/W | Yes | Blocklisted |
| [CVE-2019-18845](CVE-2019-18845.md) | Viper RGB driver | Patriot | Arbitrary R/W | No | Withdrawn |
| [CVE-2019-8372](CVE-2019-8372.md) | LG LSB driver | LG | Arbitrary Write | No | Withdrawn |
| [CVE-2023-41444](CVE-2023-41444.md) | `iREC.sys` | iREC | Arbitrary R/W | No | Still loadable |
| [CVE-2025-45737](CVE-2025-45737.md) | `NeacController.sys` | NEAC | Arbitrary R/W | No | Still loadable |
| [ATSZIO64.sys](ATSZIO64-sys.md) | `ATSZIO64.sys` | ASUS | Arbitrary R/W | Yes | Blocklisted |
| [AsIO3.sys](AsIO3-sys.md) | `AsIO3.sys` | ASRock/ASUS | Arbitrary R/W | Yes | Blocklisted |

### Performance & GPU Drivers

| CVE / ID | Driver | Vendor | Class | ITW | Status |
|----------|--------|--------|-------|-----|--------|
| [CVE-2020-12928](CVE-2020-12928.md) | `AMDRyzenMasterDriver.sys` | AMD | Arbitrary R/W | No | Patched |
| [CVE-2023-20598](CVE-2023-20598.md) | AMD chipset driver | AMD | Info Disclosure | No | Patched |
| [CVE-2025-7771](CVE-2025-7771.md) | `ThrottleStop.sys` | ThrottleStop | MSR Write | Yes | Blocklisted |
| [NVDrv](NVDrv.md) | `nvlddmkm.sys` | NVIDIA | GPU Memory R/W | No | Still loadable |

### Anti-Cheat & Security Product Drivers

| CVE / ID | Driver | Vendor | Class | ITW | Status |
|----------|--------|--------|-------|-----|--------|
| [Capcom.sys](Capcom-sys.md) | `Capcom.sys` | Capcom | Ring-0 Code Exec | Yes | Withdrawn / Blocklisted |
| [echo_driver.sys](echo-driver-sys.md) | `echo_driver.sys` | Echo AC | Callback Manipulation | No | Still loadable |
| [viragt64.sys](viragt64-sys.md) | `viragt64.sys` | TG Soft | Process Termination | Yes | Blocklisted |
| [Truesight.sys](Truesight-sys.md) | `Truesight.sys` | Adlice | EDR Bypass | Yes | Blocklisted |
| [amsdk.sys](amsdk-sys.md) | `amsdk.sys` | WatchDog | Process Termination | Yes | Blocklisted |

## By Driver

### `afd.sys`

- [CVE-2023-21768](CVE-2023-21768.md) — AFD WinSock — missing ProbeForWrite allows kernel write-what-where via IO ring
- [CVE-2023-28218](CVE-2023-28218.md) — AFD WinSock — integer overflow in AfdCopyCMSGBuffer allows EoP
- [CVE-2024-38193](CVE-2024-38193.md) — AFD — use-after-free race on Registered I/O buffers allows EoP

### `appid.sys`

- [CVE-2024-21338](CVE-2024-21338.md) — AppLocker — IOCTL 0x22A018 missing access control allows kernel code execution

### `cldflt.sys`

- [CVE-2023-36036](CVE-2023-36036.md) — Cloud Files Mini Filter — heap overflow via crafted reparse data
- [CVE-2024-30085](CVE-2024-30085.md) — Cloud Files Mini Filter — missing size check before memcpy leads to heap overflow
- [CVE-2024-49114](CVE-2024-49114.md) — Cloud Files Mini-Filter — elevation of privilege via buffer overflow

### `clfs.sys`

- [CVE-2022-37969](CVE-2022-37969.md) — Common Log File System — SignaturesOffset OOB write via corrupted cbSymbolZone
- [CVE-2023-28252](CVE-2023-28252.md) — Common Log File System — OOB write via corrupted base log offset
- [CVE-2023-36424](CVE-2023-36424.md) — Common Log File System — pool overflow from unvalidated reparse data
- [CVE-2024-49138](CVE-2024-49138.md) — Common Log File System — heap overflow in LoadContainerQ allows EoP
- [CVE-2025-29824](CVE-2025-29824.md) — Common Log File System — elevation of privilege via log file metadata corruption

### `csc.sys`

- [CVE-2024-26229](CVE-2024-26229.md) — Client-Side Caching — missing access check allows EoP

### `fastfat.sys`

- [CVE-2025-24985](CVE-2025-24985.md) — FAT File System — cluster count overflow in FAT bitmap allocation allows RCE

### `http.sys`

- [CVE-2022-21907](CVE-2022-21907.md) — HTTP Protocol Stack — uninitialized tracker struct via crafted HTTP headers allows RCE

### `ks.sys`

- [CVE-2024-35250](CVE-2024-35250.md) — Kernel Streaming — untrusted pointer dereference in IOCTL dispatch allows EoP

### `ksthunk.sys`

- [CVE-2024-38054](CVE-2024-38054.md) — Kernel Streaming WOW64 Thunk — integer overflow in KSSTREAM_HEADER thunking allows EoP
- [CVE-2024-38238](CVE-2024-38238.md) — Kernel Streaming WOW64 Thunk — MmMapLockedPages without MmProbeAndLockPages in frame handling

### `mskssrv.sys`

- [CVE-2023-29360](CVE-2023-29360.md) — Kernel Streaming Server — MmProbeAndLockPages called with KernelMode on user MDL
- [CVE-2023-36802](CVE-2023-36802.md) — Kernel Streaming Server — FsContextReg/FsStreamReg object type confusion leads to EoP
- [CVE-2024-30089](CVE-2024-30089.md) — Kernel Streaming Server — ref-count logic error causes use-after-free EoP

### `ntfs.sys`

- [CVE-2025-24993](CVE-2025-24993.md) — NTFS — MFT metadata heap buffer overflow via crafted VHD allows RCE

### `ntoskrnl.exe`

- [CVE-2023-32019](CVE-2023-32019.md) — NT Kernel — kernel heap memory leak to user process via thread info query
- [CVE-2024-21302](CVE-2024-21302.md) — NT Kernel — secure kernel version downgrade bypass via unvalidated version state
- [CVE-2024-30088](CVE-2024-30088.md) — NT Kernel — TOCTOU race in AuthzBasepCopyoutInternalSecurityAttributes
- [CVE-2024-38106](CVE-2024-38106.md) — NT Kernel — missing lock around VslpEnterIumSecureMode causes race condition EoP

### `vsp.sys`

- [CVE-2025-21333](CVE-2025-21333.md) — Hyper-V Virtual Service Provider — heap-based buffer overflow

### `tcpip.sys`

- [CVE-2024-38063](CVE-2024-38063.md) — TCP/IP stack — integer underflow in IPv6 packet reassembly allows RCE

### `win32k.sys`

- [CVE-2024-38256](CVE-2024-38256.md) — Win32k — uninitialized resource usage leaks kernel memory to user mode

### `win32kbase.sys`

- [CVE-2022-21882](CVE-2022-21882.md) — Win32k — ConsoleWindow flag misinterprets WndExtra causing type confusion EoP

### `win32kfull.sys`

- [CVE-2023-29336](CVE-2023-29336.md) — Win32k — use-after-free from unlocked nested menu object allows EoP

### `DBUtil_2_3.sys`

- [CVE-2021-21551](CVE-2021-21551.md) — Dell BIOS utility — arbitrary R/W via IOCTL

### `RTCore64.sys`

- [CVE-2019-16098](CVE-2019-16098.md) — MSI Afterburner — physical mem R/W, MSR, I/O port

### `gdrv.sys`

- [CVE-2018-19320](CVE-2018-19320.md) — Gigabyte — arbitrary kernel R/W, MSR access

### `iqvw64e.sys`

- [CVE-2015-2291](CVE-2015-2291.md) — Intel Ethernet diagnostics — arbitrary R/W via IOCTL

### `HW.sys`

- [CVE-2020-15368](CVE-2020-15368.md) — Marvin Test — physical memory R/W

### `LenovoDiagnosticsDriver.sys`

- [CVE-2022-3699](CVE-2022-3699.md) — Lenovo Diagnostics — arbitrary R/W

### Viper RGB driver

- [CVE-2019-18845](CVE-2019-18845.md) — Patriot — physical memory R/W

### LG LSB driver

- [CVE-2019-8372](CVE-2019-8372.md) — LG — arbitrary write

### `iREC.sys`

- [CVE-2023-41444](CVE-2023-41444.md) — iREC — arbitrary R/W

### `NeacController.sys`

- [CVE-2025-45737](CVE-2025-45737.md) — NEAC — arbitrary R/W

### `ATSZIO64.sys`

- [ATSZIO64.sys](ATSZIO64-sys.md) — ASUS — physical memory R/W

### `AsIO3.sys`

- [AsIO3.sys](AsIO3-sys.md) — ASRock/ASUS — physical mem R/W, SMM

### `AMDRyzenMasterDriver.sys`

- [CVE-2020-12928](CVE-2020-12928.md) — AMD Ryzen Master — arbitrary R/W via IOCTL

### AMD chipset driver

- [CVE-2023-20598](CVE-2023-20598.md) — AMD — info disclosure / MMIO

### `ThrottleStop.sys`

- [CVE-2025-7771](CVE-2025-7771.md) — ThrottleStop — MSR write / AV killer

### `nvlddmkm.sys`

- [NVDrv](NVDrv.md) — NVIDIA — GPU memory R/W

### `Capcom.sys`

- [Capcom.sys](Capcom-sys.md) — Capcom — ring-0 code exec, SMEP bypass

### `echo_driver.sys`

- [echo_driver.sys](echo-driver-sys.md) — Echo AC — kernel callback manipulation

### `viragt64.sys`

- [viragt64.sys](viragt64-sys.md) — TG Soft — process termination

### `Truesight.sys`

- [Truesight.sys](Truesight-sys.md) — Adlice RogueKiller — EDR bypass

### `amsdk.sys`

- [amsdk.sys](amsdk-sys.md) — WatchDog — process termination

## By Exploitation Status

### Exploited in the Wild

- [CVE-2022-21882](CVE-2022-21882.md) — `win32kbase.sys` — Win32k — ConsoleWindow flag misinterprets WndExtra causing type confusion EoP
- [CVE-2022-37969](CVE-2022-37969.md) — `clfs.sys` — Common Log File System — SignaturesOffset OOB write via corrupted cbSymbolZone
- [CVE-2023-28252](CVE-2023-28252.md) — `clfs.sys` — Common Log File System — OOB write via corrupted base log offset
- [CVE-2023-29336](CVE-2023-29336.md) — `win32kfull.sys` — Win32k — use-after-free from unlocked nested menu object allows EoP
- [CVE-2023-36036](CVE-2023-36036.md) — `cldflt.sys` — Cloud Files Mini Filter — heap overflow via crafted reparse data
- [CVE-2023-36802](CVE-2023-36802.md) — `mskssrv.sys` — Kernel Streaming Server — FsContextReg/FsStreamReg object type confusion leads to EoP
- [CVE-2024-21338](CVE-2024-21338.md) — `appid.sys` — AppLocker — IOCTL 0x22A018 missing access control allows kernel code execution
- [CVE-2024-30088](CVE-2024-30088.md) — `ntoskrnl.exe` — NT Kernel — TOCTOU race in AuthzBasepCopyoutInternalSecurityAttributes
- [CVE-2024-35250](CVE-2024-35250.md) — `ks.sys` — Kernel Streaming — untrusted pointer dereference in IOCTL dispatch allows EoP
- [CVE-2024-38106](CVE-2024-38106.md) — `ntoskrnl.exe` — NT Kernel — missing lock around VslpEnterIumSecureMode causes race condition EoP
- [CVE-2024-38193](CVE-2024-38193.md) — `afd.sys` — AFD — use-after-free race on Registered I/O buffers allows EoP
- [CVE-2024-49138](CVE-2024-49138.md) — `clfs.sys` — Common Log File System — heap overflow in LoadContainerQ allows EoP
- [CVE-2025-24985](CVE-2025-24985.md) — `fastfat.sys` — FAT File System — cluster count overflow in FAT bitmap allocation allows RCE
- [CVE-2025-21333](CVE-2025-21333.md) — `vsp.sys` — Hyper-V Virtual Service Provider — heap-based buffer overflow
- [CVE-2025-24993](CVE-2025-24993.md) — `ntfs.sys` — NTFS — MFT metadata heap buffer overflow via crafted VHD allows RCE
- [CVE-2025-29824](CVE-2025-29824.md) — `clfs.sys` — Common Log File System — elevation of privilege via log file metadata corruption
- [CVE-2021-21551](CVE-2021-21551.md) — `DBUtil_2_3.sys` — Dell — arbitrary R/W via IOCTL
- [CVE-2019-16098](CVE-2019-16098.md) — `RTCore64.sys` — MSI — physical mem R/W, MSR, I/O port
- [CVE-2018-19320](CVE-2018-19320.md) — `gdrv.sys` — Gigabyte — arbitrary kernel R/W, MSR access
- [CVE-2015-2291](CVE-2015-2291.md) — `iqvw64e.sys` — Intel — arbitrary R/W via IOCTL
- [CVE-2020-15368](CVE-2020-15368.md) — `HW.sys` — Marvin Test — physical memory R/W
- [CVE-2022-3699](CVE-2022-3699.md) — `LenovoDiagnosticsDriver.sys` — Lenovo — arbitrary R/W
- [ATSZIO64.sys](ATSZIO64-sys.md) — `ATSZIO64.sys` — ASUS — physical memory R/W
- [AsIO3.sys](AsIO3-sys.md) — `AsIO3.sys` — ASRock/ASUS — physical mem R/W, SMM
- [CVE-2025-7771](CVE-2025-7771.md) — `ThrottleStop.sys` — ThrottleStop — MSR write / AV killer
- [Capcom.sys](Capcom-sys.md) — `Capcom.sys` — Capcom — ring-0 code exec, SMEP bypass
- [viragt64.sys](viragt64-sys.md) — `viragt64.sys` — TG Soft — process termination (Kasseika ransomware)
- [Truesight.sys](Truesight-sys.md) — `Truesight.sys` — Adlice — EDR bypass
- [amsdk.sys](amsdk-sys.md) — `amsdk.sys` — WatchDog — process termination (Silver Fox APT)
