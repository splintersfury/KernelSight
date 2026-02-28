# Case Studies

<div class="ks-pipeline-pos">
  Driver Type &rarr; Attack Surface &rarr; Vuln Class &rarr; Primitive &rarr; <span class="ks-active">Case Study</span>
</div>

Case studies are where the pipeline comes together. Each entry walks through a real CVE from root cause through exploitation to patch — connecting the driver type, attack surface, vulnerability class, and primitives used into a complete chain. The corpus covers 134 CVEs across 62 unique drivers, with 52 exploited in the wild — including 41 third-party BYOVD driver case studies.

## CVE Index

| CVE | Driver | Class | ITW | Build (Vuln → Fix) |
|-----|--------|-------|-----|---------------------|
| [CVE-2026-21519](CVE-2026-21519.md) | `dwmcore.dll` | Type Confusion | Yes | |
| [CVE-2026-21533](CVE-2026-21533.md) | Remote Desktop Services | Elevation of Privilege | Yes | |
| [CVE-2026-21253](CVE-2026-21253.md) | `msfs.sys` | Use-After-Free | No | |
| [CVE-2026-21231](CVE-2026-21231.md) | `ntoskrnl.exe` | Race Condition | Yes | |
| [CVE-2026-20922](CVE-2026-20922.md) | `ntfs.sys` | Buffer Overflow (Heap) | No | |
| [CVE-2026-20876](CVE-2026-20876.md) | VBS Enclave | Buffer Overflow (Heap) | No | |
| [CVE-2026-20857](CVE-2026-20857.md) | `cldflt.sys` | Elevation of Privilege | No | |
| [CVE-2026-20842](CVE-2026-20842.md) | `dwmcore.dll` | Elevation of Privilege | No | |
| [CVE-2026-20840](CVE-2026-20840.md) | `ntfs.sys` | Buffer Overflow (Heap) | No | |
| [CVE-2026-20822](CVE-2026-20822.md) | `win32kfull.sys` | Use-After-Free | No | |
| [CVE-2026-20820](CVE-2026-20820.md) | `clfs.sys` | Buffer Overflow (Heap) | No | |
| [CVE-2026-20814](CVE-2026-20814.md) | `dxgkrnl.sys` | Elevation of Privilege | No | |
| [CVE-2026-2636](CVE-2026-2636.md) | `clfs.sys` | Denial of Service | No | |
| [CVE-2025-62221](CVE-2025-62221.md) | `cldflt.sys` | Use-After-Free | Yes | |
| [CVE-2025-64680](CVE-2025-64680.md) | `dwmcore.dll` | Buffer Overflow (Heap) | No | |
| [CVE-2025-64673](CVE-2025-64673.md) | `storvsp.sys` | Elevation of Privilege | No | |
| [CVE-2025-62470](CVE-2025-62470.md) | `clfs.sys` | Buffer Overflow (Heap) | No | |
| [CVE-2025-62458](CVE-2025-62458.md) | `win32k.sys` | Elevation of Privilege | No | |
| [CVE-2025-62457](CVE-2025-62457.md) | `cldflt.sys` | Out-of-Bounds Read | No | |
| [CVE-2025-62454](CVE-2025-62454.md) | `cldflt.sys` | Elevation of Privilege | No | |
| [CVE-2025-62217](CVE-2025-62217.md) | `afd.sys` | Elevation of Privilege | No | |
| [CVE-2025-62213](CVE-2025-62213.md) | `afd.sys` | Use-After-Free | No | |
| [CVE-2025-62215](CVE-2025-62215.md) | `ntoskrnl.exe` | Race Condition / Double-Free | Yes | |
| [CVE-2025-60719](CVE-2025-60719.md) | `afd.sys` | Use-After-Free / Race Condition | No | |
| [CVE-2025-60709](CVE-2025-60709.md) | `clfs.sys` | Out-of-Bounds Read | No | |
| [CVE-2025-59254](CVE-2025-59254.md) | `dwmcore.dll` | Elevation of Privilege | No | |
| [CVE-2025-59230](CVE-2025-59230.md) | `rasman.sys` | Elevation of Privilege | Yes | |
| [CVE-2025-58722](CVE-2025-58722.md) | `dwmcore.dll` | Elevation of Privilege | No | |
| [CVE-2025-55681](CVE-2025-55681.md) | `dwmcore.dll` | Out-of-Bounds Access | No | |
| [CVE-2025-55680](CVE-2025-55680.md) | `cldflt.sys` | Race Condition / TOCTOU | No | |
| [CVE-2025-55228](CVE-2025-55228.md) | `win32k.sys` | Race Condition | No | |
| [CVE-2025-54916](CVE-2025-54916.md) | `ntfs.sys` | Buffer Overflow (Stack) | No | |
| [CVE-2025-54110](CVE-2025-54110.md) | `ntoskrnl.exe` | Integer Overflow | No | |
| [CVE-2025-53804](CVE-2025-53804.md) | `ntoskrnl.exe` | Information Disclosure | No | |
| [CVE-2025-53803](CVE-2025-53803.md) | `ntoskrnl.exe` | Information Disclosure | No | |
| [CVE-2025-53718](CVE-2025-53718.md) | `afd.sys` | Use-After-Free | No | |
| [CVE-2025-53149](CVE-2025-53149.md) | `ksthunk.sys` | Buffer Overflow (Heap) | No | |
| [CVE-2025-53147](CVE-2025-53147.md) | `afd.sys` | Use-After-Free | No | |
| [CVE-2025-49762](CVE-2025-49762.md) | `afd.sys` | Race Condition | No | |
| [CVE-2025-49733](CVE-2025-49733.md) | `win32k.sys` | Use-After-Free | No | |
| [CVE-2025-49675](CVE-2025-49675.md) | `ksthunk.sys` | Use-After-Free | No | |
| [CVE-2025-49667](CVE-2025-49667.md) | `win32k.sys` | Double Free | No | |
| [CVE-2025-49661](CVE-2025-49661.md) | `afd.sys` | Untrusted Pointer Dereference | No | |
| [CVE-2025-47982](CVE-2025-47982.md) | `storvsp.sys` | Improper Input Validation | No | |
| [CVE-2025-32722](CVE-2025-32722.md) | `storport.sys` | Information Disclosure | No | |
| [CVE-2025-32713](CVE-2025-32713.md) | `clfs.sys` | Buffer Overflow (Heap) | No | |
| [CVE-2025-32709](CVE-2025-32709.md) | `afd.sys` | Use-After-Free | Yes | |
| [CVE-2025-32706](CVE-2025-32706.md) | `clfs.sys` | Buffer Overflow (Heap) | Yes | |
| [CVE-2025-32701](CVE-2025-32701.md) | `clfs.sys` | Use-After-Free | Yes | |
| [CVE-2025-30400](CVE-2025-30400.md) | `dwmcore.dll` | Use-After-Free | Yes | |
| [CVE-2025-29829](CVE-2025-29829.md) | Trusted Runtime Interface | Information Disclosure | No | |
| [CVE-2025-29824](CVE-2025-29824.md) | `clfs.sys` | Use-After-Free / Logic Bug | Yes | `10.0.26100.3476` → `10.0.26100.3775` |
| [CVE-2025-27732](CVE-2025-27732.md) | `win32k.sys` | Improper Memory Locking | No | |
| [CVE-2025-24993](CVE-2025-24993.md) | `ntfs.sys` | Buffer Overflow / Bounds Check | Yes | `10.0.22621.4830` → `10.0.22621.4890` |
| [CVE-2025-24992](CVE-2025-24992.md) | `ntfs.sys` | Information Disclosure | No | |
| [CVE-2025-24991](CVE-2025-24991.md) | `ntfs.sys` | Information Disclosure (OOB Read) | Yes | |
| [CVE-2025-24985](CVE-2025-24985.md) | `fastfat.sys` | Integer Overflow | Yes | `10.0.22621.4830` → `10.0.22621.5037` |
| [CVE-2025-24984](CVE-2025-24984.md) | `ntfs.sys` | Information Disclosure | Yes | |
| [CVE-2025-24983](CVE-2025-24983.md) | `win32k.sys` | Use-After-Free / Race Condition | Yes | |
| [CVE-2025-24990](CVE-2025-24990.md) | `ltmdm64.sys` | Untrusted Pointer Dereference | Yes | |
| [CVE-2025-24066](CVE-2025-24066.md) | `ks.sys` | Buffer Overflow (Heap) | No | |
| [CVE-2025-24067](CVE-2025-24067.md) | `mskssrv.sys` | Buffer Overflow (Heap) | No | |
| [CVE-2025-24063](CVE-2025-24063.md) | `ks.sys` | Buffer Overflow (Heap) | No | |
| [CVE-2025-24058](CVE-2025-24058.md) | `dwmcore.dll` | Improper Input Validation | No | |
| [CVE-2025-24052](CVE-2025-24052.md) | `ltmdm64.sys` | Buffer Overflow (Stack) | No | |
| [CVE-2025-24044](CVE-2025-24044.md) | `win32k.sys` | Use-After-Free | No | |
| [CVE-2025-24046](CVE-2025-24046.md) | `ks.sys` | Double Free | No | |
| [CVE-2025-21418](CVE-2025-21418.md) | `afd.sys` | Buffer Overflow (Heap) | Yes | |
| [CVE-2025-21367](CVE-2025-21367.md) | `win32k.sys` | Race Condition | No | |
| [CVE-2025-21334](CVE-2025-21334.md) | `vkrnlintvsp.sys` | Use-After-Free | Yes | |
| [CVE-2025-21335](CVE-2025-21335.md) | `vkrnlintvsp.sys` | Use-After-Free | Yes | |
| [CVE-2025-21333](CVE-2025-21333.md) | `vsp.sys` | Buffer Overflow | Yes | `10.0.26100.2605` → `10.0.26100.2894` |
| [CVE-2024-55414](CVE-2024-55414.md) | `smserl64.sys` | Physical Memory Mapping | No | |
| [CVE-2024-49138](CVE-2024-49138.md) | `clfs.sys` | Buffer Overflow / Bounds Check | Yes | `10.0.22621.4541` → `10.0.22621.4601` |
| [CVE-2024-49114](CVE-2024-49114.md) | `cldflt.sys` | Buffer Overflow | No | `10.0.22621.4460` → `10.0.22621.4602` |
| [CVE-2024-38256](CVE-2024-38256.md) | `win32k.sys` | Information Disclosure | No | `10.0.22621.3958` → `10.0.22621.4169` |
| [CVE-2024-38238](CVE-2024-38238.md) | `ksthunk.sys` | MDL Handling | No | `10.0.22621.4036` → `10.0.22621.4169` |
| [CVE-2026-21241](CVE-2026-21241.md) | `afd.sys` | Use-After-Free / Race Condition | No | |
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
| [CVE-2023-31096](CVE-2023-31096.md) | `agrsm64.sys` | Buffer Overflow (Stack) | No | |
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
| [CVE-2025-1533](CVE-2025-1533.md) | `AsIO3.sys` | ASUS | Stack Overflow | No | Blocklisted |
| [CVE-2025-3464](CVE-2025-3464.md) | `AsIO3.sys` | ASUS | Auth Bypass / Arb Decrement | No | Blocklisted |
| [AsIO3.sys](AsIO3-sys.md) | `AsIO3.sys` | ASRock/ASUS | Arbitrary R/W | Yes | Blocklisted |
| [CVE-2023-1048](CVE-2023-1048.md) | `WinRing0x64.sys` | OpenLibSys / TechPowerUp / Razer / many | MSR Write / Phys Mem R/W | Yes | Blocklisted |
| [CVE-2023-1676](CVE-2023-1676.md) | `mydrivers64.sys` | DriverGenius | MSR Write / Phys Mem R/W | No | Still loadable |
| [CVE-2025-0285](CVE-2025-0285.md) | `BioNTdrv.sys` | Paragon | Arb Memory Mapping | No | Blocklisted |
| [CVE-2025-0286](CVE-2025-0286.md) | `BioNTdrv.sys` | Paragon | Arb Kernel Write | No | Blocklisted |
| [CVE-2025-0287](CVE-2025-0287.md) | `BioNTdrv.sys` | Paragon | Null Pointer Deref | No | Blocklisted |
| [CVE-2025-0288](CVE-2025-0288.md) | `BioNTdrv.sys` | Paragon | Arb Kernel Write | No | Blocklisted |
| [CVE-2025-0289](CVE-2025-0289.md) | `BioNTdrv.sys` | Paragon | Arb Kernel Write | Yes | Blocklisted |
| [CVE-2025-8061](CVE-2025-8061.md) | `LnvMSRIO.sys` | Lenovo | MSR R/W / Phys Mem R/W | No | Patched |

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
| [CVE-2025-68947](CVE-2025-68947.md) | `NSecKrnl.sys` | NsecSoft | Process Termination | Yes | Under active abuse |
| [CVE-2025-61156](CVE-2025-61156.md) | `TfSysMon.sys` | ThreatFire | Process Termination | Yes | Under active abuse |
| [CVE-2025-52915](CVE-2025-52915.md) | `K7RKScan.sys` | K7 Computing | Process Termination | No | Still loadable |
| [CVE-2025-1055](CVE-2025-1055.md) | `K7RKScan.sys` | K7 Computing | Elevation of Privilege | No | Still loadable |
| [CVE-2025-70795](CVE-2025-70795.md) | `STProcessMonitor.sys` | Safetica | Process Termination | No | Still loadable |
| [CVE-2025-11156](CVE-2025-11156.md) | `epdlpdrv.sys` | Netskope | Null Pointer Deref / DoS | No | Patched |
| [CVE-2025-5942](CVE-2025-5942.md) | `epdlpdrv.sys` | Netskope | Heap Overflow / DoS | No | Patched |
| [CVE-2024-11616](CVE-2024-11616.md) | `epdlpdrv.sys` | Netskope | Double-Fetch (TOCTOU) | No | Patched |
| [CVE-2024-51324](CVE-2024-51324.md) | `BdApiUtil.sys` | Baidu | Process Termination | Yes | Still loadable |
| [EnPortv.sys](EnPortv-sys.md) | `EnPortv.sys` | Guidance/OpenText | Process Termination | Yes | Revoked cert, still loads |

## By Driver

### `afd.sys`

- [CVE-2023-21768](CVE-2023-21768.md) — AFD WinSock — missing ProbeForWrite allows kernel write-what-where via IO ring
- [CVE-2023-28218](CVE-2023-28218.md) — AFD WinSock — integer overflow in AfdCopyCMSGBuffer allows EoP
- [CVE-2024-38193](CVE-2024-38193.md) — AFD — use-after-free race on Registered I/O buffers allows EoP
- [CVE-2025-21418](CVE-2025-21418.md) — AFD — heap-based buffer overflow allows SYSTEM escalation
- [CVE-2025-32709](CVE-2025-32709.md) — AFD — use-after-free after socket closure allows SYSTEM escalation
- [CVE-2025-49661](CVE-2025-49661.md) — AFD — untrusted pointer dereference allows EoP
- [CVE-2025-49762](CVE-2025-49762.md) — AFD — race condition allows EoP
- [CVE-2025-53147](CVE-2025-53147.md) — AFD — use-after-free allows EoP
- [CVE-2025-53718](CVE-2025-53718.md) — AFD — use-after-free allows EoP
- [CVE-2025-60719](CVE-2025-60719.md) — AFD — use-after-free from race between socket unbind and concurrent operations
- [CVE-2025-62213](CVE-2025-62213.md) — AFD — use-after-free allows EoP
- [CVE-2025-62217](CVE-2025-62217.md) — AFD — elevation of privilege
- [CVE-2026-21241](CVE-2026-21241.md) — AFD — race condition in AfdNotifyPostEvents spinlock release causes use-after-free EoP

### `appid.sys`

- [CVE-2024-21338](CVE-2024-21338.md) — AppLocker — IOCTL 0x22A018 missing access control allows kernel code execution

### `cldflt.sys`

- [CVE-2023-36036](CVE-2023-36036.md) — Cloud Files Mini Filter — heap overflow via crafted reparse data
- [CVE-2024-30085](CVE-2024-30085.md) — Cloud Files Mini Filter — missing size check before memcpy leads to heap overflow
- [CVE-2024-49114](CVE-2024-49114.md) — Cloud Files Mini-Filter — elevation of privilege via buffer overflow
- [CVE-2025-55680](CVE-2025-55680.md) — Cloud Files Mini Filter — race condition / TOCTOU allows EoP
- [CVE-2025-62221](CVE-2025-62221.md) — Cloud Files Mini Filter — use-after-free allows SYSTEM escalation
- [CVE-2025-62454](CVE-2025-62454.md) — Cloud Files Mini Filter — elevation of privilege
- [CVE-2025-62457](CVE-2025-62457.md) — Cloud Files Mini Filter — out-of-bounds read
- [CVE-2026-20857](CVE-2026-20857.md) — Cloud Files Mini Filter — elevation of privilege

### `clfs.sys`

- [CVE-2022-37969](CVE-2022-37969.md) — Common Log File System — SignaturesOffset OOB write via corrupted cbSymbolZone
- [CVE-2023-28252](CVE-2023-28252.md) — Common Log File System — OOB write via corrupted base log offset
- [CVE-2023-36424](CVE-2023-36424.md) — Common Log File System — pool overflow from unvalidated reparse data
- [CVE-2024-49138](CVE-2024-49138.md) — Common Log File System — heap overflow in LoadContainerQ allows EoP
- [CVE-2025-29824](CVE-2025-29824.md) — Common Log File System — elevation of privilege via log file metadata corruption
- [CVE-2025-32701](CVE-2025-32701.md) — Common Log File System — use-after-free in log stream object allows SYSTEM escalation
- [CVE-2025-32706](CVE-2025-32706.md) — Common Log File System — heap buffer overflow from missing input validation
- [CVE-2025-32713](CVE-2025-32713.md) — Common Log File System — heap buffer overflow allows EoP
- [CVE-2025-60709](CVE-2025-60709.md) — Common Log File System — out-of-bounds read
- [CVE-2025-62470](CVE-2025-62470.md) — Common Log File System — heap buffer overflow allows EoP
- [CVE-2026-20820](CVE-2026-20820.md) — Common Log File System — heap buffer overflow allows EoP
- [CVE-2026-2636](CVE-2026-2636.md) — Common Log File System — denial of service

### `csc.sys`

- [CVE-2024-26229](CVE-2024-26229.md) — Client-Side Caching — missing access check allows EoP

### `dwmcore.dll`

- [CVE-2025-24058](CVE-2025-24058.md) — Desktop Window Manager — improper input validation allows EoP
- [CVE-2025-30400](CVE-2025-30400.md) — Desktop Window Manager — use-after-free in composition surface handling allows SYSTEM escalation
- [CVE-2025-55681](CVE-2025-55681.md) — Desktop Window Manager — out-of-bounds access allows EoP
- [CVE-2025-58722](CVE-2025-58722.md) — Desktop Window Manager — elevation of privilege
- [CVE-2025-59254](CVE-2025-59254.md) — Desktop Window Manager — elevation of privilege
- [CVE-2025-64680](CVE-2025-64680.md) — Desktop Window Manager — heap buffer overflow allows EoP
- [CVE-2026-20842](CVE-2026-20842.md) — Desktop Window Manager — elevation of privilege
- [CVE-2026-21519](CVE-2026-21519.md) — Desktop Window Manager — type confusion allows SYSTEM escalation

### `fastfat.sys`

- [CVE-2025-24985](CVE-2025-24985.md) — FAT File System — cluster count overflow in FAT bitmap allocation allows RCE

### `http.sys`

- [CVE-2022-21907](CVE-2022-21907.md) — HTTP Protocol Stack — uninitialized tracker struct via crafted HTTP headers allows RCE

### `ks.sys`

- [CVE-2024-35250](CVE-2024-35250.md) — Kernel Streaming — untrusted pointer dereference in IOCTL dispatch allows EoP
- [CVE-2025-24046](CVE-2025-24046.md) — Kernel Streaming — double free in filter object handling
- [CVE-2025-24063](CVE-2025-24063.md) — Kernel Streaming — heap-based buffer overflow allows EoP
- [CVE-2025-24066](CVE-2025-24066.md) — Kernel Streaming — heap-based buffer overflow allows EoP

### `ksthunk.sys`

- [CVE-2024-38054](CVE-2024-38054.md) — Kernel Streaming WOW64 Thunk — integer overflow in KSSTREAM_HEADER thunking allows EoP
- [CVE-2024-38238](CVE-2024-38238.md) — Kernel Streaming WOW64 Thunk — MmMapLockedPages without MmProbeAndLockPages in frame handling
- [CVE-2025-49675](CVE-2025-49675.md) — Kernel Streaming WOW64 Thunk — use-after-free allows EoP
- [CVE-2025-53149](CVE-2025-53149.md) — Kernel Streaming WOW64 Thunk — heap-based buffer overflow

### `mskssrv.sys`

- [CVE-2023-29360](CVE-2023-29360.md) — Kernel Streaming Server — MmProbeAndLockPages called with KernelMode on user MDL
- [CVE-2023-36802](CVE-2023-36802.md) — Kernel Streaming Server — FsContextReg/FsStreamReg object type confusion leads to EoP
- [CVE-2024-30089](CVE-2024-30089.md) — Kernel Streaming Server — ref-count logic error causes use-after-free EoP
- [CVE-2025-24067](CVE-2025-24067.md) — Kernel Streaming Server — heap-based buffer overflow allows EoP

### `ntfs.sys`

- [CVE-2025-24984](CVE-2025-24984.md) — NTFS — information disclosure
- [CVE-2025-24991](CVE-2025-24991.md) — NTFS — information disclosure via out-of-bounds read
- [CVE-2025-24992](CVE-2025-24992.md) — NTFS — information disclosure
- [CVE-2025-24993](CVE-2025-24993.md) — NTFS — MFT metadata heap buffer overflow via crafted VHD allows RCE
- [CVE-2025-54916](CVE-2025-54916.md) — NTFS — stack buffer overflow allows EoP
- [CVE-2026-20840](CVE-2026-20840.md) — NTFS — heap buffer overflow allows EoP
- [CVE-2026-20922](CVE-2026-20922.md) — NTFS — heap buffer overflow allows EoP

### `ntoskrnl.exe`

- [CVE-2023-32019](CVE-2023-32019.md) — NT Kernel — kernel heap memory leak to user process via thread info query
- [CVE-2024-21302](CVE-2024-21302.md) — NT Kernel — secure kernel version downgrade bypass via unvalidated version state
- [CVE-2024-30088](CVE-2024-30088.md) — NT Kernel — TOCTOU race in AuthzBasepCopyoutInternalSecurityAttributes
- [CVE-2024-38106](CVE-2024-38106.md) — NT Kernel — missing lock around VslpEnterIumSecureMode causes race condition EoP
- [CVE-2025-53803](CVE-2025-53803.md) — NT Kernel — information disclosure
- [CVE-2025-53804](CVE-2025-53804.md) — NT Kernel — information disclosure
- [CVE-2025-54110](CVE-2025-54110.md) — NT Kernel — integer overflow allows EoP
- [CVE-2025-62215](CVE-2025-62215.md) — NT Kernel — race condition / double-free allows SYSTEM escalation
- [CVE-2026-21231](CVE-2026-21231.md) — NT Kernel — race condition allows SYSTEM escalation

### `vsp.sys`

- [CVE-2025-21333](CVE-2025-21333.md) — Hyper-V Virtual Service Provider — heap-based buffer overflow

### `vkrnlintvsp.sys`

- [CVE-2025-21334](CVE-2025-21334.md) — Hyper-V VSP Integration — use-after-free allows SYSTEM escalation
- [CVE-2025-21335](CVE-2025-21335.md) — Hyper-V VSP Integration — use-after-free allows SYSTEM escalation

### `tcpip.sys`

- [CVE-2024-38063](CVE-2024-38063.md) — TCP/IP stack — integer underflow in IPv6 packet reassembly allows RCE

### `win32k.sys`

- [CVE-2024-38256](CVE-2024-38256.md) — Win32k — uninitialized resource usage leaks kernel memory to user mode
- [CVE-2025-21367](CVE-2025-21367.md) — Win32k — race condition allows EoP
- [CVE-2025-24044](CVE-2025-24044.md) — Win32k — use-after-free allows EoP
- [CVE-2025-24983](CVE-2025-24983.md) — Win32k — use-after-free / race condition allows SYSTEM escalation
- [CVE-2025-27732](CVE-2025-27732.md) — Win32k — improper memory locking allows EoP
- [CVE-2025-49667](CVE-2025-49667.md) — Win32k — double free allows SYSTEM escalation
- [CVE-2025-49733](CVE-2025-49733.md) — Win32k — use-after-free allows EoP
- [CVE-2025-55228](CVE-2025-55228.md) — Win32k — race condition allows EoP
- [CVE-2025-62458](CVE-2025-62458.md) — Win32k — elevation of privilege

### `win32kbase.sys`

- [CVE-2022-21882](CVE-2022-21882.md) — Win32k — ConsoleWindow flag misinterprets WndExtra causing type confusion EoP

### `win32kfull.sys`

- [CVE-2023-29336](CVE-2023-29336.md) — Win32k — use-after-free from unlocked nested menu object allows EoP
- [CVE-2026-20822](CVE-2026-20822.md) — Win32k — use-after-free allows EoP

### `rasman.sys`

- [CVE-2025-59230](CVE-2025-59230.md) — RAS Manager — elevation of privilege

### Remote Desktop Services

- [CVE-2026-21533](CVE-2026-21533.md) — Remote Desktop Services — elevation of privilege

### `storvsp.sys`

- [CVE-2025-47982](CVE-2025-47982.md) — Storage VSP — improper input validation allows EoP
- [CVE-2025-64673](CVE-2025-64673.md) — Storage VSP — elevation of privilege

### `storport.sys`

- [CVE-2025-32722](CVE-2025-32722.md) — Storage Port — information disclosure

### `dxgkrnl.sys`

- [CVE-2026-20814](CVE-2026-20814.md) — DirectX Graphics Kernel — elevation of privilege

### `msfs.sys`

- [CVE-2026-21253](CVE-2026-21253.md) — Mailslot File System — use-after-free allows EoP

### VBS Enclave

- [CVE-2026-20876](CVE-2026-20876.md) — VBS Enclave — heap buffer overflow allows EoP

### Trusted Runtime Interface

- [CVE-2025-29829](CVE-2025-29829.md) — Trusted Runtime Interface — information disclosure

### `agrsm64.sys`

- [CVE-2023-31096](CVE-2023-31096.md) — Broadcom/Archer — stack buffer overflow allows EoP

### `smserl64.sys`

- [CVE-2024-55414](CVE-2024-55414.md) — SMS Modem — physical memory mapping allows EoP

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

- [CVE-2025-1533](CVE-2025-1533.md) — ASUS — stack overflow in Win32PathToNtPath (MAX_PATH assumption)
- [CVE-2025-3464](CVE-2025-3464.md) — ASUS — auth bypass via hardlink, ObfDereferenceObject decrement-by-one, PreviousMode flip, token theft
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

### `WinRing0x64.sys`

- [CVE-2023-1048](CVE-2023-1048.md) — OpenLibSys — MSR write, physical memory R/W, I/O port access

### `mydrivers64.sys`

- [CVE-2023-1676](CVE-2023-1676.md) — DriverGenius — MSR write (0x9C402088), physical memory R/W (0x9C406104/0x9C40A108)

### `BioNTdrv.sys`

- [CVE-2025-0285](CVE-2025-0285.md) — Paragon — arbitrary memory mapping via IOCTL
- [CVE-2025-0286](CVE-2025-0286.md) — Paragon — arbitrary kernel write via IOCTL
- [CVE-2025-0287](CVE-2025-0287.md) — Paragon — null pointer dereference via IOCTL
- [CVE-2025-0288](CVE-2025-0288.md) — Paragon — arbitrary kernel write via IOCTL
- [CVE-2025-0289](CVE-2025-0289.md) — Paragon — arbitrary kernel write via IOCTL

### `LnvMSRIO.sys`

- [CVE-2025-8061](CVE-2025-8061.md) — Lenovo — MSR R/W and physical memory R/W via IOCTL

### `NSecKrnl.sys`

- [CVE-2025-68947](CVE-2025-68947.md) — NsecSoft — process termination abused for EDR bypass

### `K7RKScan.sys`

- [CVE-2025-1055](CVE-2025-1055.md) — K7 Computing — elevation of privilege
- [CVE-2025-52915](CVE-2025-52915.md) — K7 Computing — process termination primitive

### `BdApiUtil.sys`

- [CVE-2024-51324](CVE-2024-51324.md) — Baidu — process termination abused for AV/EDR bypass

### `EnPortv.sys`

- [EnPortv.sys](EnPortv-sys.md) — Guidance/OpenText — process termination primitive

### `ltmdm64.sys`

- [CVE-2025-24052](CVE-2025-24052.md) — LiteManager — stack buffer overflow allows EoP
- [CVE-2025-24990](CVE-2025-24990.md) — LiteManager — untrusted pointer dereference allows SYSTEM escalation

### `TfSysMon.sys`

- [CVE-2025-61156](CVE-2025-61156.md) — ThreatFire — process termination abused for EDR bypass

### `STProcessMonitor.sys`

- [CVE-2025-70795](CVE-2025-70795.md) — Safetica — process termination

### `epdlpdrv.sys`

- [CVE-2024-11616](CVE-2024-11616.md) — Netskope Endpoint DLP — double-fetch heap overflow
- [CVE-2025-5942](CVE-2025-5942.md) — Netskope Endpoint DLP — heap overflow / DoS
- [CVE-2025-11156](CVE-2025-11156.md) — Netskope Endpoint DLP — null pointer dereference / DoS

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
- [CVE-2025-24984](CVE-2025-24984.md) — `ntfs.sys` — NTFS — information disclosure
- [CVE-2025-24991](CVE-2025-24991.md) — `ntfs.sys` — NTFS — information disclosure via out-of-bounds read
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
- [CVE-2023-1048](CVE-2023-1048.md) — `WinRing0x64.sys` — OpenLibSys — MSR write and physical memory R/W
- [CVE-2025-21334](CVE-2025-21334.md) — `vkrnlintvsp.sys` — Hyper-V VSP Integration — use-after-free allows SYSTEM
- [CVE-2025-21335](CVE-2025-21335.md) — `vkrnlintvsp.sys` — Hyper-V VSP Integration — use-after-free allows SYSTEM
- [CVE-2025-21418](CVE-2025-21418.md) — `afd.sys` — AFD — heap-based buffer overflow allows SYSTEM escalation
- [CVE-2025-24983](CVE-2025-24983.md) — `win32k.sys` — Win32k — use-after-free / race condition allows SYSTEM
- [CVE-2025-24990](CVE-2025-24990.md) — `ltmdm64.sys` — LiteManager — untrusted pointer dereference allows SYSTEM
- [CVE-2025-30400](CVE-2025-30400.md) — `dwmcore.dll` — DWM — use-after-free in composition surface allows SYSTEM
- [CVE-2025-32701](CVE-2025-32701.md) — `clfs.sys` — CLFS — use-after-free in log stream object allows SYSTEM
- [CVE-2025-32706](CVE-2025-32706.md) — `clfs.sys` — CLFS — heap buffer overflow allows SYSTEM
- [CVE-2025-32709](CVE-2025-32709.md) — `afd.sys` — AFD — use-after-free after socket closure allows SYSTEM
- [CVE-2025-59230](CVE-2025-59230.md) — `rasman.sys` — RAS Manager — elevation of privilege
- [CVE-2025-62215](CVE-2025-62215.md) — `ntoskrnl.exe` — NT Kernel — race condition / double-free allows SYSTEM
- [CVE-2025-62221](CVE-2025-62221.md) — `cldflt.sys` — Cloud Files Mini Filter — use-after-free allows SYSTEM
- [CVE-2026-21231](CVE-2026-21231.md) — `ntoskrnl.exe` — NT Kernel — race condition allows SYSTEM
- [CVE-2026-21519](CVE-2026-21519.md) — `dwmcore.dll` — DWM — type confusion allows SYSTEM
- [CVE-2026-21533](CVE-2026-21533.md) — Remote Desktop Services — elevation of privilege
- [CVE-2025-0289](CVE-2025-0289.md) — `BioNTdrv.sys` — Paragon — arbitrary kernel write
- [CVE-2025-68947](CVE-2025-68947.md) — `NSecKrnl.sys` — NsecSoft — process termination / EDR bypass
- [CVE-2025-61156](CVE-2025-61156.md) — `TfSysMon.sys` — ThreatFire — process termination / EDR bypass
- [CVE-2024-51324](CVE-2024-51324.md) — `BdApiUtil.sys` — Baidu — process termination / AV bypass
- [EnPortv.sys](EnPortv-sys.md) — `EnPortv.sys` — Guidance/OpenText — process termination
