# Third-Party Security Drivers

Anti-virus, EDR, anti-rootkit, and anti-cheat kernel modules — abused for process termination, callback manipulation, and code execution.

!!! note "Distinct from Security / Policy Drivers"
    This category covers **third-party** security product kernel drivers (AV, EDR, anti-cheat). For Microsoft's built-in security enforcement drivers (appid.sys, ci.sys), see [Security / Policy Drivers](security-policy.md).

## Architecture

- **Driver model**: WDM or minifilter, typically with kernel callback registrations
- **Key drivers**: `Capcom.sys` (Capcom), `echo_driver.sys` (Echo AC), `viragt64.sys` (TG Soft), `Truesight.sys` (RogueKiller), `amsdk.sys` (WatchDog)
- **Interface**: Kernel callbacks (PsSetCreateProcessNotifyRoutine, ObRegisterCallbacks), IOCTL for management, direct kernel function invocation
- **Privilege**: Run with full kernel privileges; designed to monitor and control system behavior

## Attack Surface

- **Kernel callback registration**: Security drivers register callbacks for process/thread creation, object access, and image load. Attackers abuse these to manipulate or remove callbacks.
- **IOCTL process control**: IOCTLs that can terminate processes, modify process memory, or query process information — intended for security management but abusable
- **Code execution primitives**: Some drivers (Capcom.sys) intentionally disable SMEP and execute user-supplied function pointers in ring 0
- **Callback removal**: Drivers that expose IOCTLs to enumerate and remove kernel notification callbacks, blinding EDR products
- **Handle manipulation**: Opening handles to protected processes with full access rights, bypassing object callback protections

## Common Vulnerability Patterns

| Pattern | Description | AutoPiff Rules |
|---------|-------------|----------------|
| Ring-0 code execution | Driver executes user-supplied function pointer in kernel mode | `direct_arw_ioctl_detected` |
| Process termination | IOCTL terminates arbitrary processes by PID | `privilege_check_added` |
| Callback manipulation | Enumerates and zeros kernel notification callbacks | `access_mode_enforcement_added` |
| EDR bypass | Removes or disables security product hooks and callbacks | `authorization_validation_added` |
| Handle elevation | Opens handles to protected processes bypassing PPL | `handle_force_access_check_added` |

## CVEs

| CVE | Driver | Description | Class | ITW |
|-----|--------|-------------|-------|-----|
| [Capcom.sys](../case-studies/Capcom-sys.md) | `Capcom.sys` | Capcom anti-cheat — ring-0 code exec, SMEP bypass | Logic Bug | Yes |
| [echo_driver.sys](../case-studies/echo-driver-sys.md) | `echo_driver.sys` | Echo AC — kernel callback manipulation | Logic Bug | No |
| [viragt64.sys](../case-studies/viragt64-sys.md) | `viragt64.sys` | TG Soft VirIT — process termination via IOCTL | Logic Bug | Yes |
| [Truesight.sys](../case-studies/Truesight-sys.md) | `Truesight.sys` | RogueKiller — EDR bypass | Logic Bug | Yes |
| [amsdk.sys](../case-studies/amsdk-sys.md) | `amsdk.sys` | WatchDog — process termination | Logic Bug | Yes |

## Key Drivers

### Capcom.sys (Capcom)
- **Role**: Anti-cheat protection driver for Capcom game titles
- **Attack vector**: Disables SMEP and jumps to a user-mode function pointer in ring 0
- **Note**: tandasat and FuzzySecurity documented the exploitation; one of the most famous BYOVD examples. The driver was designed to execute user code in kernel mode for anti-cheat checks.

### echo_driver.sys (Echo AC)
- **Role**: Echo anti-cheat kernel driver
- **Attack vector**: IOCTL allows enumerating and removing kernel notification callbacks
- **Note**: kite03 GitHub PoC demonstrates callback removal to blind EDR products

### viragt64.sys (TG Soft VirIT)
- **Role**: TG Soft VirIT antivirus kernel driver
- **Attack vector**: IOCTL allows terminating arbitrary processes by PID
- **Note**: Trend Micro documented abuse by Kasseika ransomware to terminate AV/EDR processes before encryption

### Truesight.sys (RogueKiller)
- **Role**: Adlice RogueKiller anti-rootkit kernel driver
- **Attack vector**: IOCTLs expose process handle duplication and termination capabilities
- **Note**: Check Point Research 2025 documented abuse for EDR bypass; driver's anti-rootkit capabilities repurposed against defenders

### amsdk.sys (WatchDog)
- **Role**: WatchDog Development security product kernel driver
- **Attack vector**: Process termination IOCTL with insufficient access control
- **Note**: Check Point documented Silver Fox APT using this driver to terminate security products

## Research Notes

Third-party security drivers are designed to interact with security-sensitive kernel objects (process callbacks, object callbacks, image load notifications), and their legitimate functionality (process termination, callback management) is exactly what attackers need for EDR evasion. The "vulnerability" is often insufficient access control on IOCTLs, not a memory corruption bug. Anti-cheat drivers like Capcom.sys are the extreme case: intentional ring-0 code execution from user mode. PPL bypass is a key capability, as these drivers can often open handles to protected processes. Attackers increasingly target AV vendor drivers to kill security products before deploying malware.
