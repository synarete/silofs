# Symbolic Link Implementation Audit

## Overview

This document defines the audit procedure for the symbolic link
implementation in `silofs`. Symlinks are implemented in
`lib/fs/symlink.c`. Symlink values are split between the inode's
"head" (`SILOFS_SYMLNK_HEAD_MAX`) and up to two external "parts"
stored in `symval` nodes (`SILOFS_SYMLNK_PART_MAX`). The system uses
a descriptor-based approach to partition the link target string during
creation and reconstruct it during `readlink`.

## Objective

Identify bugs, logic errors, or resource leaks. Focus on the splitting
logic in `symval_desc_setup`, external node management
(spawn/bind/drop), proper error propagation, and inode reference
counting.

## Review Checklist

### 1. String Partitioning and Reconstruction

- Verify `symval_desc_setup` correctly handles various lengths:
  - Empty strings or strings fitting entirely in the head.
  - Strings requiring exactly one or two external parts.
  - Strings exceeding `SILOFS_SYMLNK_MAX` (should return
    `ENAMETOOLONG`).
- Audit `sylc_extern_symval` and its helpers. Ensure
  `silofs_bytebuf_append` calls are safe and that the total
  reconstructed length matches the length stored in the inode.

### 2. Error Propagation

- Check all internal helpers (prefixed with `sylc_`) for ignored
  return codes. Specifically, ensure that failures in
  `sylc_assign_symval` or `sylc_stage_symval` are propagated to the
  FUSE entry points.
- Verify that partial failures during symlink creation do not leave
  the filesystem in an inconsistent state (e.g., orphaned `symval`
  nodes).

### 3. Node and Block Management

- Review `sylc_drop_symval`. Ensure it attempts to remove all
  associated external parts even if one removal fails, or document the
  cleanup policy.
- Verify `sylc_update_iblocks_by` correctly accounts for the metadata
  blocks consumed by `symval` nodes to ensure accurate `stat`
  reporting.
- Audit the use of `SILOFS_STG_COW` vs `SILOFS_STG_CUR` staging modes
  to ensure data consistency during modifications.

### 4. Resource Management (Reference Counting)

- Ensure `silofs_ii_incref` and `silofs_ii_decref` are balanced in
  `silofs_do_readlink`, `silofs_bind_symval`, and
  `silofs_drop_symlink`.
- Verify that `sylc_stage_symval` correctly manages the lifetime of
  the staged vnodes.

### 5. Metadata Integrity

- Audit `symv_verify_parent` and `symv_verify_length`. Ensure they
  effectively detect corruption in `symval` nodes during staging.
- Check that `sylc_update_post_symlink` correctly sets `IA_SIZE` and
  triggers `CTIME`/`MTIME` updates.

## Input Files

- `lib/fs/symlink.c` (primary implementation)
- `include/silofs/ondisk.h` (on-disk structure:
  `silofs_symlnk_value`)
- `lib/fs/inode.c` (inode interaction context)

## Required Output

Provide findings grouped by category:

- **ABI/Semantics**: Violations of standard Linux symlink behavior.
- **Memory Safety**: Buffer management or pointer arithmetic issues.
- **Logic Errors**: Incorrect state transitions or failed error
  propagation.
- **Fix**: Minimal code snippet or diff sufficient to correct the
  issue.
