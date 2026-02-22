# NULL Pointer Dereference

NULL pointer dereference vulnerabilities in kernel context.

## Description

NULL pointer dereferences in kernel drivers cause bugchecks (BSOD). On modern Windows (post-Windows 8), the zero page is not mappable from user mode, making these primarily DoS issues. However, on older systems or with certain configurations, they could be exploitable.

## Patterns

- Missing NULL check after pool allocation
- Missing NULL check on `MmGetSystemAddressForMdlSafe` return
- Dereferencing optional IRP fields without validation

## AutoPiff Detection

- `pool_allocation_null_check_added` — NULL check after pool allocation
- `mdl_null_check_added` — NULL check on Irp->MdlAddress
- `mdl_safe_mapping_replacement` — MmGetSystemAddressForMdl replaced with Safe variant
