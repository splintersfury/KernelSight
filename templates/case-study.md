# {{ CVE-ID }}

> {{ One-line description of the vulnerability }}

<!-- Uncomment if exploited in the wild:
!!! danger "Exploited in the Wild"
    This vulnerability was exploited in the wild before or shortly after patching.
-->

## Summary

| Field | Value |
|-------|-------|
| **Driver** | `{{ driver.sys }}` |
| **Vulnerability Class** | {{ e.g., Buffer Overflow, Type Confusion }} |
| **Vulnerable Build** | `{{ 10.0.xxxxx.xxxx }}` ({{ KB number }}) |
| **Fixed Build** | `{{ 10.0.xxxxx.xxxx }}` ({{ KB number }}) |
| **Exploited ITW** | {{ Yes / No }} |
| **CVSS** | {{ Score if available }} |

## Affected Functions

- `{{ FunctionName1 }}`
- `{{ FunctionName2 }}`

## Root Cause

{{ Detailed explanation of the vulnerability root cause.
   Include specific field names, structure offsets, and code paths. }}

### Vulnerable Code Path

```
{{ Call chain leading to the vulnerability }}
DriverEntry → DispatchDeviceControl → VulnerableHandler → BuggyMemcpy
```

## Exploitation

{{ How the vulnerability is exploited:
   - What primitive does it provide? (arb R/W, type confusion, etc.)
   - What exploitation technique is used? (pool spray, token swap, etc.)
   - What is the end result? (EoP to SYSTEM, RCE, etc.) }}

### Exploitation Primitive

{{ e.g., Pool overflow → adjacent object corruption → arbitrary R/W }}

### Post-Exploitation

{{ e.g., Token swapping to gain SYSTEM privileges }}

## Patch Analysis

{{ What changed between the vulnerable and fixed builds:
   - Specific code changes (new checks, new locks, API replacements)
   - AutoPiff detection rules that match }}

### AutoPiff Detection

- `{{ rule_id }}` — {{ What was detected }}

## Timeline

| Date | Event |
|------|-------|
| {{ YYYY-MM-DD }} | {{ Vulnerability reported }} |
| {{ YYYY-MM-DD }} | {{ Patch released }} |
| {{ YYYY-MM-DD }} | {{ Public writeup/PoC }} |

## References

- [MSRC Advisory]({{ msrc_url }})
- [Writeup]({{ writeup_url }})
- [PoC]({{ poc_url }})
