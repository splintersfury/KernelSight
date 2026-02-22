# Registry-Based Primitives

Using registry key values to pass controlled data into kernel memory for exploitation.

## Description

Some drivers read configuration from registry keys into kernel buffers without proper validation. By controlling registry values, an attacker can inject data into kernel memory.

## AutoPiff Detection

- `registry_access_mask_hardened`
