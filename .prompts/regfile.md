# Regular File Implementation Audit

## Overview

This document defines the audit procedure for the regular file
implementation and virtual hierarchy in `silofs`. Regular files use a
tiered virtual addressing hierarchy split into three main components:

- **Head1**: Small file optimization using 4 slots of 1KB data blocks.
- **Head2**: Medium file optimization using 15 slots of 4KB data
  blocks.
- **Tree**: A radix-tree-like structure for large files using 64KB
  leaves.

The logic in `lib/fs/file.c` manages transitions between these tiers,
handles Copy-on-Write (CoW) via `SILOFS_STG_COW`, and implements
complex VFS operations like `fallocate`, `copy_file_range`, and
`fiemap`.

## Objective

Identify bugs, logic errors, and concurrency issues in file mapping,
data consistency, and tiered addressing. Focus on offset-to-slot
calculations, tree navigation, and the safety of the
sharing/unsharing mechanisms.

## Review Checklist

### 1. Hierarchy and Offset Mathematics

- Audit offset-to-slot and offset-to-height functions:
  `off_to_head1_slot`, `off_to_head2_slot`, `off_to_leaf_slot`, and
  `off_to_tree_height`.
- Verify `ftn_span_by_height` and `ftn_calc_range`. Ensure that
  integer overflows or bit-shift errors do not lead to incorrect tree
  indexing.
- Check `off_clamp` and `off_is_partial` logic across different
  `vtype` boundaries.

### 2. Read/Write and CoW Path

- Analyze `filc_write_data` and its interaction with
  `filc_require_mut_vaddr`. Ensure the CoW transition is atomic with
  respect to metadata updates.
- Review `filc_unshare_leaf_by`. Verify that when a 64KB leaf is
  shared, the unsharing process correctly claims new space and rebinds
  the parent node.
- Check reference counting in `fli_pre_io` and `fli_post_io`,
  especially under `SILOFS_F_ASYNCWR`.

### 3. Sparse Files and Fallocate

- Audit `filc_fallocate_op`. Verify that `FALLOC_FL_PUNCH_HOLE` and
  `FALLOC_FL_ZERO_RANGE` correctly discard data via
  `filc_discard_data`.
- Review `filc_discard_partial_by`. Ensure that partial block zeroing
  does not accidentally truncate or corrupt adjacent data in the same
  leaf.
- Verify `filc_check_fl_mode` for compliance with Linux fallocate
  semantics.

### 4. Copy Range and Data Sharing

- Analyze `filc_copy_range_iter`. This is high-complexity: check the
  logic for sharing leaves between files versus performing a full
  memory copy.
- Verify `filc_check_copy_range` for overlap detection within the
  same inode to prevent data corruption.
- Ensure `filc_set_copy_range_start` correctly aligns both source and
  destination to the next data segment via `SEEK_DATA`.

### 5. Fiemap and Seek

- Audit `filc_emit_fiemap_ext`. Ensure reported logical and physical
  offsets match the virtual hierarchy.
- Review `filc_lseek_data` and `filc_lseek_hole`. Verify they
  correctly traverse the hierarchy to find the next data/hole boundary
  and handle the end-of-file (`isz`) correctly.

### 6. Metadata Consistency

- Check `filc_update_post_io`. Ensure `IA_SIZE`, `IA_SPAN`, and
  `IA_BLOCKS` are updated correctly for every operation type (Read,
  Write, Trunc, etc.).
- Verify `filc_update_kill_suidgid` logic to ensure security bits are
  stripped on modifying writes per POSIX requirements.

## Input Files

- `lib/fs/file.c`
- `include/silofs/ondisk.h`

## Required Output

Provide findings grouped by category:

- **Critical Logic**: Offset math errors, tree corruption, or CoW
  failures.
- **ABI Compliance**: Deviations from standard Linux/FUSE I/O
  semantics.
- **Consistency/Race**: Metadata desync or racy reference counts.
- **Fix**: Minimal code snippet or diff sufficient to correct the
  issue.
