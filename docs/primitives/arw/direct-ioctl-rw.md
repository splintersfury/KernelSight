# Direct IOCTL Read/Write

In most kernel exploitation scenarios, an attacker needs to find a memory corruption vulnerability, trigger it under carefully controlled conditions, groom the pool layout, and chain multiple primitives to achieve kernel read/write. But some drivers skip all of that work by simply handing it over. A signed driver that exposes IOCTLs for reading and writing arbitrary physical or virtual memory gives any process with a handle to the device direct, unconstrained access to kernel memory. No bug hunting required. No exploit chain needed. Just open the device, send the IOCTL, and read or write whatever you want.

This is the primitive behind BYOVD (Bring Your Own Vulnerable Driver) attacks, which have become one of the most common kernel exploitation techniques in the threat landscape. Rather than exploiting a bug in a driver already present on the target system, the attacker loads a legitimately signed driver that was designed with overly permissive IOCTLs and uses it as a ready-made kernel R/W tool. The driver is not "vulnerable" in the traditional sense of having a memory safety bug. It is working exactly as designed. The vulnerability is the design itself.

## Why these drivers exist

The drivers that expose direct memory IOCTLs were almost always written for legitimate purposes. Hardware diagnostics tools need to read physical memory to inspect device registers. BIOS update utilities need to write to specific physical addresses to flash firmware. Overclocking software needs MSR (Model-Specific Register) access to adjust CPU parameters. Performance monitoring tools need to read hardware counters mapped into physical address space.

The problem is that these drivers typically implement their memory access IOCTLs without restricting which addresses can be read or written, and without limiting which processes can open the device. A diagnostics driver that can read any physical address for debugging can also read the `_EPROCESS` token of any process. A BIOS utility that can write to firmware addresses can also write to kernel code pages. The IOCTL does not know or care about the caller's intent.

## How the primitive works

The exploitation flow is remarkably simple compared to other kernel R/W techniques. The attacker loads the vulnerable driver (or finds it already present on the system), opens a handle to the device object it creates, and sends IOCTL requests with the target address and data. The driver performs the memory operation in kernel mode and returns the result.

For physical memory read/write, drivers typically use `MmMapIoSpace` to map a physical address range into kernel virtual address space, perform the read or write, and then unmap it. For virtual memory access, drivers may use direct pointer dereference or APIs like `MmCopyVirtualMemory`. MSR access uses `__readmsr` and `__writemsr` intrinsics. I/O port access uses `__inbyte`/`__outbyte` and related functions.

The critical distinction from other primitives is that no corruption or memory safety violation is involved. The driver is performing a legitimate kernel operation on behalf of the caller. The security boundary failure is in the access control: the driver does not verify that the caller should be allowed to perform the operation, or that the target address is within an acceptable range.

## The BYOVD attack model

In a BYOVD attack, the attacker brings the vulnerable driver as part of their tooling. The attack proceeds in stages. First, the attacker drops the driver binary to disk. Since the driver is legitimately signed by a trusted publisher (Microsoft WHQL, or a valid EV certificate), Windows allows it to load. Second, the attacker creates a service for the driver and starts it, or uses `NtLoadDriver` to load it directly. Third, the attacker opens a handle to the device. Fourth, they use the IOCTLs to read kernel memory (for information leaks, KASLR bypass, or process enumeration) and write kernel memory (for token manipulation, callback removal, or driver signature enforcement bypass).

The Lazarus Group's use of a Dell BIOS utility driver ([CVE-2021-21551](../../case-studies/CVE-2021-21551.md)) exemplifies this pattern. The `DBUtil_2_3.sys` driver exposed five separate IOCTLs that collectively provided full kernel read/write capability. The driver was signed by Dell and trusted by Windows. Lazarus used it to disable EDR products by removing kernel notification callbacks, then deployed their rootkit with detection mechanisms neutralized.

Microsoft's Vulnerable Driver Blocklist attempts to address BYOVD by maintaining a list of known vulnerable driver hashes that Windows will refuse to load. However, the blocklist is not exhaustive, new vulnerable drivers are discovered regularly, and the blocklist updates lag behind discovery. Organizations running older Windows versions or with the blocklist disabled remain exposed.

## Access control failures

The root cause in these drivers is almost always one of three access control failures. The most common is a missing device ACL: the driver creates its device object with default permissions that allow any authenticated user to open a handle. The second is a missing caller validation: the driver does not check whether the calling process has the privileges needed for the operation. The third is a missing address validation: the driver accepts any address from the caller without checking whether it falls within an acceptable range (such as the driver's own device memory region).

A well-designed hardware access driver would restrict its device ACL to administrators, validate that requested addresses fall within the specific hardware regions the driver manages, and potentially require a specific privilege like `SeLoadDriverPrivilege` before performing operations. The vulnerable drivers in the CVE table below implement none of these checks.

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2024-21338](../../case-studies/CVE-2024-21338.md) | `appid.sys` | IOCTL 0x22A018 missing access control |
| [CVE-2021-21551](../../case-studies/CVE-2021-21551.md) | `DBUtil_2_3.sys` | Dell BIOS utility -- 5 IOCTLs for kernel R/W |
| [CVE-2019-16098](../../case-studies/CVE-2019-16098.md) | `RTCore64.sys` | MSI Afterburner -- physical mem, MSR, I/O port |
| [CVE-2018-19320](../../case-studies/CVE-2018-19320.md) | `gdrv.sys` | Gigabyte -- kernel R/W and MSR access |
| [CVE-2015-2291](../../case-studies/CVE-2015-2291.md) | `iqvw64e.sys` | Intel -- physical and virtual memory R/W |
| [CVE-2020-15368](../../case-studies/CVE-2020-15368.md) | `HW.sys` | Marvin Test -- physical memory via MmMapIoSpace |

These CVEs share a common pattern that AutoPiff detects: patches add input size validation, device ACL hardening, or entirely new IOCTL handler logic that restricts previously unrestricted operations. When a patch introduces `IoCreateDeviceSecure` where `IoCreateDevice` was used before, or adds `ProbeForRead`/`ProbeForWrite` calls to an IOCTL handler that previously accepted raw pointers, AutoPiff flags the change as a security-relevant modification to the driver's access boundary.

## AutoPiff Detection

- `ioctl_input_size_validation_added`
- `device_acl_hardening`
- `new_ioctl_handler`

## Relationship to other primitives

Direct IOCTL R/W is unique among the primitives in this section because it provides immediate, full kernel read/write without any intermediate steps. Every other arbitrary R/W primitive requires exploiting a vulnerability first and typically chains through [pool spray](../exploitation/pool-spray-feng-shui.md), information leaks, and multiple corruption steps before achieving stable R/W. Direct IOCTL access skips the entire chain.

This makes BYOVD drivers particularly dangerous for [token swapping](../exploitation/token-swapping.md) attacks: with direct R/W already in hand, the attacker can immediately locate the SYSTEM process token and overwrite the current process token in a single operation. The same applies to [PTE manipulation](pte-manipulation.md) for code execution, or [ACL/SD manipulation](../exploitation/acl-sd-manipulation.md) for access boundary bypass. The simplicity of the primitive is precisely what makes it so widely used by threat actors, even when more sophisticated techniques exist.

Some of the drivers listed above also overlap with the [DMA/MMIO](dma-mmio.md) primitive, since their physical memory access is implemented through `MmMapIoSpace`. The distinction is in the attack model: DMA/MMIO as a primitive category covers cases where the driver's memory mapping is exploitable through a bug, while direct IOCTL R/W covers cases where the mapping is the intended functionality, exposed without adequate access control.
