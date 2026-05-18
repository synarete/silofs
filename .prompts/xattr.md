# Extended Attribute Implementation Audit

## Overview

This document defines the audit procedure for the extended attribute
(xattr) implementation in `silofs`. Attributes are stored in dedicated
"xanodes" (extended attribute nodes) when they do not fit within the
inode. The system manages standard Linux namespaces (user, system,
security, trusted) and enforces size limits and access controls. The
implementation uses a custom entry-based storage format within nodes,
requiring strict 8-byte alignment and manual space management.

## Objective

Identify bugs, security vulnerabilities, or deviations from Linux
xattr semantics. Focus on buffer management, pointer arithmetic within
the `xe_data` region, alignment logic, and the transition between
"create" and "replace" operations.

## Review Checklist

### 1. Pointer Arithmetic and Alignment

- Verify that `xe_aligned_size` and `xe_calc_nents` correctly enforce
  8-byte alignment to prevent unaligned access on strict
  architectures.
- Audit `xe_view_of` and `xe_value` calculations. Ensure that the
  offset logic between name and value does not lead to out-of-bounds
  reads or writes within the `silofs_xentry_view` buffer.

### 2. Linux/FUSE API Compliance

- Ensure `getxattr` correctly handles size-only queries (where the
  buffer pointer is NULL or size is 0).
- Verify that `XATTR_CREATE` and `XATTR_REPLACE` flags are strictly
  enforced:
  - `XATTR_CREATE` must fail if the attribute already exists.
  - `XATTR_REPLACE` must fail if the attribute does not exist.
- Check that `removexattr` follows the special return code behavior
  for POSIX ACLs as defined in `is_posix_acl_name`.

### 3. Namespace and Prefix Validation

- Review `xac_check_xattr_name` and `search_prefix`. Ensure that
  disabled prefixes (like `gnu.*`) are rejected and that ACL prefixes
  are gated by the `SILOFS_F_ALLOWXACL` environment flag.
- Verify that name length checks against `SILOFS_NAME_MAX` and
  `NAME_MAX` are consistent with the rest of the VFS layer.

### 4. Space Management and Corruption

- Audit `xe_squeeze` and `xan_remove`. Ensure that `memmove`
  parameters correctly shift subsequent entries and that the "tip" of
  the node is properly zeroed to prevent data leakage or corruption.
- Verify the robustness of `xe_verify_range`. Ensure it prevents
  infinite loops or out-of-bounds reads when processing a corrupted
  xanode.
- Check the logic in `xac_try_insert_at_nodes` for potential leaks of
  xanodes if a partial failure occurs during a multi-slot operation.

### 5. Resource Management

- Ensure `silofs_ii_incref` and `silofs_ii_decref` are balanced in
  all top-level entry points (`silofs_do_getxattr`,
  `silofs_do_setxattr`, etc.).
- Verify that `xac_stage_xanode` and its variants properly handle
  reference counting for both the inode and the staged vnodes.

## Input Files

- `lib/fs/xattr.c` (primary implementation)
- `include/silofs/ondisk.h` (on-disk structures:
  `silofs_xattr_node`)
- `lib/fs/inode.c` (inode interaction context)

## Required Output

Provide findings grouped by category:

- **ABI/Semantics**: Violations of standard Linux xattr behavior.
- **Memory Safety**: Buffer overflows, unaligned access, or invalid
  pointers.
- **Logic Errors**: Incorrect state transitions or space accounting.
- **Fix**: Minimal code snippet or diff sufficient to correct the
  issue.
