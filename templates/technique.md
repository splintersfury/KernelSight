# {{ Title }}

<!-- Replace {{ placeholders }} with actual content -->

{{ Brief one-line description }}

## Description

{{ Detailed description of the technique, vulnerability class, or attack surface.
   Include relevant Windows internals context. }}

## Patterns

<!-- List specific code patterns, API misuse, or design flaws -->

- {{ Pattern 1 }}
- {{ Pattern 2 }}

## Example

<!-- Optional: pseudocode or simplified code showing the vulnerability pattern -->

```c
// Vulnerable pattern
void VulnerableFunction(PVOID UserBuffer, ULONG UserSize) {
    PVOID KernelBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, FIXED_SIZE, 'Tag1');
    // BUG: No size check — UserSize may exceed FIXED_SIZE
    RtlCopyMemory(KernelBuffer, UserBuffer, UserSize);
}
```

```c
// Fixed pattern
void FixedFunction(PVOID UserBuffer, ULONG UserSize) {
    if (UserSize > FIXED_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    PVOID KernelBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, FIXED_SIZE, 'Tag1');
    RtlCopyMemory(KernelBuffer, UserBuffer, UserSize);
}
```

## Related CVEs

| CVE | Driver | Description |
|-----|--------|-------------|
| [{{ CVE-ID }}](../case-studies/{{ CVE-ID }}.md) | `{{ driver.sys }}` | {{ Brief description }} |

## AutoPiff Detection

<!-- List relevant AutoPiff rule_ids that detect this technique -->

- `{{ rule_id_1 }}` — {{ What the rule detects }}
- `{{ rule_id_2 }}` — {{ What the rule detects }}

## Mitigations

<!-- What defenses exist against this technique -->

- {{ Mitigation 1 }}
- {{ Mitigation 2 }}

## References

- {{ Links to documentation, research papers, blog posts }}
