# Write-What-Where

Classic write-what-where condition — controlled address and controlled value write.

## Description

A write-what-where primitive allows writing an attacker-controlled value to an attacker-controlled kernel address. This is the most powerful single-operation primitive and can directly modify any kernel data structure.

## Common Sources

- Missing `ProbeForWrite` on user-supplied pointer
- Buffer overflow with controlled offset and value
- CLFS base log offset corruption

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [CVE-2023-21768](../../case-studies/CVE-2023-21768.md) | `afd.sys` | Missing ProbeForWrite allows kernel write |
| [CVE-2023-28252](../../case-studies/CVE-2023-28252.md) | `clfs.sys` | OOB write via corrupted base log offset |

## AutoPiff Detection

- `probe_for_read_or_write_added`
- `added_bounds_check_on_offset`
- `method_neither_probe_added`
