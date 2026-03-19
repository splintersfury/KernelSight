# Registry-Based Primitives

When kernel drivers read configuration from the registry, they typically allocate a buffer, call `ZwQueryValueKey` to fill it with the registry value data, and then use that data to configure internal behavior. The registry is a trusted data source in many drivers' threat models: it is assumed that only administrators can modify the relevant keys, and that the data conforms to expected formats and sizes. But these assumptions can be wrong. Some registry keys are writable by non-administrative users. Some drivers read values without validating their length against the destination buffer. And in BYOVD scenarios, an attacker with administrator access may want to inject data into kernel memory through registry values precisely because it avoids the more monitored IOCTL path.

Registry-based primitives are less common than direct IOCTL or pool-based techniques, but they appear in specific contexts where a driver's initialization or configuration path trusts registry data. The primitive works by setting a registry value to attacker-controlled content before the driver reads it, causing the driver to load that content into a kernel buffer where it influences execution, overflows an adjacent allocation, or populates fields that are later used as pointers or sizes.

## How the primitive works

The typical vulnerability pattern involves a driver that reads a REG_BINARY or REG_SZ value from the registry into a fixed-size kernel buffer without checking that the value's length fits. If the attacker can write a value larger than the buffer, the excess data overflows into adjacent kernel memory. This is functionally equivalent to a [pool overflow](pool-overflow.md), but the overflow data comes from the registry rather than from an IOCTL input buffer.

A subtler variant involves type confusion. The driver expects a REG_DWORD (4 bytes) but the attacker writes a REG_BINARY of arbitrary length to the same value name. If the driver does not check the value type before reading, it may interpret the oversized data incorrectly, leading to buffer overflows or pointer corruption.

Configuration injection is another pattern. Some drivers use registry values to set internal parameters like buffer sizes, timeout values, or feature flags. If a non-privileged user can modify these values, they can influence the driver's behavior in security-relevant ways: setting a buffer size to zero to trigger a division-by-zero, setting a timeout to force a race condition window, or enabling debug features that expose additional attack surface.

## When registry-based primitives matter

Registry-based primitives are most relevant in two scenarios. The first is when a driver reads from a registry key that is writable by non-administrative users. This can occur when the driver's installer sets overly permissive ACLs on its configuration key, when the driver reads from an HKCU location (which is always user-writable), or when a Group Policy or software deployment tool sets permissive ACLs on an HKLM subkey.

The second scenario is in BYOVD or post-compromise situations where the attacker already has administrator access and wants to inject data into the kernel through a channel that is less likely to trigger EDR alerts than IOCTL calls. Registry writes are routine system operations that generate less suspicion than direct device I/O, and the driver's registry read happens during initialization, which may be before EDR hooks are fully established.

## Defenses and detection

The fix for registry-based buffer overflows is straightforward: validate the length of the registry value before copying it into the kernel buffer. The fix for type confusion is to check the value type returned by `ZwQueryValueKey` before interpreting the data. The fix for configuration injection is to harden the ACLs on the driver's registry keys to restrict writes to administrators or SYSTEM only.

AutoPiff detects registry-related patches primarily through the `registry_access_mask_hardened` rule, which fires when a patch changes the access mask or ACL on a registry key from a permissive setting to a restrictive one. This catches the most common fix pattern for registry-based privilege escalation.

## AutoPiff Detection

- `registry_access_mask_hardened`

## See Also

- [Pool Overflow](pool-overflow.md) -- the related primitive when registry data overflows a kernel buffer
- [Direct IOCTL R/W](direct-ioctl-rw.md) -- the more common data injection path through device I/O
- [DMA / MMIO](dma-mmio.md) -- another hardware-adjacent data injection primitive
