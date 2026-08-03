# Symbolic Link Implementation Audit (v2)

## Overview

This document defines the audit procedure for the symbolic link
implementation in `silofs` after the refactoring described below.
Symlinks are implemented in `lib/silofs/fs/symlink.c`. The link
target value is split into two parts:

- **Head**: stored inline in the inode's `silofs_inode_lnk.l_head`
  field, up to `SILOFS_SYMVAL_HEAD_MAX` (480) bytes.
- **Tail**: when the value exceeds `SILOFS_SYMVAL_HEAD_MAX`, the
  remainder is stored in a single external `silofs_symval_node`,
  whose logical address is kept in `silofs_inode_lnk.l_tail`.

The maximum symlink length is `SILOFS_SYMLNK_MAX` (= `PATH_MAX` =
4096). The tail node holds up to `SILOFS_SYMVAL_TAIL_MAX` (4000)
bytes, which is sufficient for the worst case (4096 - 480 = 3616).

The context struct `silofs_symlnk_ctx` (prefix `slc_`) carries the
task context, the owning inode, the symlink value, and the staging
mode. All public entry points are `silofs_do_readlink`,
`silofs_bind_symval`, and `silofs_drop_symlink`.

## Objective

Identify bugs, logic errors, or resource leaks introduced or exposed
by the refactoring. Focus on the head/tail split logic, tail node
lifecycle (spawn/bind/drop), error propagation, and the integrity
validation performed during staging.

## Review Checklist

### 1. Head/Tail Split and Reconstruction

- Verify `split_symval` correctly partitions the value for all
  lengths: fits entirely in head, exactly at the boundary, and
  requires a tail.
- Audit `slc_extern_symval_head` and `slc_extern_symval_tail`.
  Confirm that `append_symval` detects truncation (returns
  `-SILOFS_ERANGE`) and that the total reconstructed length equals
  `lnk_value_length`.
- Check `slc_symval_head_length`: it uses `silofs_min(symval_len,
  SILOFS_SYMVAL_HEAD_MAX)`. Verify this is consistent with what
  `split_symval` stores during `slc_assign_symval_head`.

### 2. Error Handling in slc_drop_symval_tail

- `lnk_get_symval_tail` returns `0` (tail present) or
  `-SILOFS_ENOENT` (no tail). The guard condition must be
  `if (err == 0)`, not `if (err != -SILOFS_ENOENT)`. The latter
  silently swallows unexpected errors and calls
  `slc_remove_symval_at` with an uninitialized stack `laddr` if
  `lnk_get_symval_tail` ever returns a third error code.
- Verify that `laddr` is zero-initialised (or that the guard
  condition is tight enough to make uninitialised use impossible).

### 3. Integrity Recheck (slc_do_recheck_symval)

- The recheck is only reachable when `slc_has_symval_tail` is true,
  i.e. `value_len > SILOFS_SYMVAL_HEAD_MAX`. Confirm that the first
  sub-condition `(value_len <= head_max)` is therefore dead code and
  cannot mask a real corruption scenario (inode with non-null tail
  laddr but `value_len <= HEAD_MAX`).
- Verify the formula `head_max + tail_len == value_len` is correct
  given that the head always stores exactly `SILOFS_SYMVAL_HEAD_MAX`
  bytes when a tail exists.
- Check that `svn_verify_length` in `silofs_verify_symval_node`
  rejects `tail_len == 0` and `tail_len > SILOFS_SYMVAL_TAIL_MAX`,
  consistent with the recheck.

### 4. Tail Node Lifecycle

- Audit `slc_create_symval`: verify `svi_setup_by` writes the
  correct parent inode number and length into the on-disk node
  before `slc_add_svi_to_predq` queues it.
- Verify `slc_bind_tail_symval` correctly handles the `svi == NULL`
  case (no tail) by calling `lnk_reset_symval_tail`, and the
  non-NULL case by storing the laddr and updating iblock counts.
- Confirm `slc_update_iblocks_by` is called exactly once per tail
  node creation and not called during drop.

### 5. Error Propagation

- Check all `slc_` helpers for ignored return codes. Ensure failures
  in `slc_assign_symval` and `slc_extern_symval` are propagated to
  the public entry points.
- Verify that a failure partway through `slc_assign_symval` (e.g.
  tail spawn succeeds but a later step fails) does not leave an
  orphaned `symval` node in the repository.

### 6. iattr Update

- `symval_length` casts `symval->len` (`size_t`) to `ssize_t`.
  Confirm the return type is appropriate for assignment to
  `ia_size` and that no sign confusion can occur.
- Verify `slc_update_post_symlink` sets both `SILOFS_IATTR_SIZE`
  and `SILOFS_IATTR_MCTIME` flags.

### 7. Reference Counting

- Ensure `silofs_ii_incref` / `silofs_ii_decref` are balanced in
  `silofs_do_readlink`, `slc_symlink`, and `silofs_drop_symlink`
  on all code paths including error returns.

## Input Files

- `lib/silofs/fs/symlink.c` (primary implementation)
- `include/silofs/ondisk.h` (on-disk structures:
  `silofs_symval_node`, `silofs_inode_lnk`)
- `lib/silofs/fs/inode.c` (inode interaction context)
- `lib/silofs/infra/bytebuf.c` (bytebuf append semantics)

## Required Output

Provide findings grouped by category:

- **ABI/Semantics**: Violations of standard Linux symlink behavior.
- **Memory Safety**: Buffer management or pointer arithmetic issues.
- **Logic Errors**: Incorrect state transitions or failed error
  propagation.
- **Fix**: Minimal code snippet or diff sufficient to correct the
  issue.
