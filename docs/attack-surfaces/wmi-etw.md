# WMI / ETW

WMI provider interfaces and ETW trace session management in kernel drivers provide additional attack surface through data buffer handling.

## Attack Surface Overview

- **Entry points**: `IoWMIRegistrationControl`, WMI query/set callbacks, ETW provider routines
- **Key risk**: WMI data block buffer handling, ETW session object management

## Common Vulnerability Patterns

- Missing size validation in WMI data block handlers
- ETW session object lifetime issues
- WMI method parameter buffer overflows

## AutoPiff Detection

*No specific WMI/ETW rules currently — general bounds_check and ioctl_hardening rules may apply.*
