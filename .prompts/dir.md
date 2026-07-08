# Directory Hash-Tree Audit

## Overview

This document defines the audit procedure for the directory hash-tree
implementation in `silofs`. Directories are not simple linear lists;
they are trees of `dtree_node` objects. Navigation is based on name
hashes, with a maximum depth of 4. Inside each node, directory entries
(`silofs_dir_entry`) and their filenames are stored in a shared
union-based buffer (`dn_data`), where entries grow forward and names
grow backward.

## Objective

Identify bugs, logic errors, or safety issues in the directory tree
management. Focus on tree indexing calculations, buffer safety within
nodes, hash collision handling, and `readdir` offset consistency.

## Review Checklist

### 1. Tree Indexing and Navigation

- Verify the logic in `dtn_index_to_parent`, `dtn_index_to_child_ord`,
  and `hash_to_child_dtn_index`. Ensure the 1-based indexing for tree
  nodes is handled consistently and prevents out-of-bounds fanout
  access.
- Check `dtn_index_depth` for potential infinite loops if a corrupted
  index is provided.
- Audit the recursive `dirc_discard_recursively` logic to ensure no
  orphaned nodes are left during a directory drop.

### 2. Buffer Safety and Entry Management

- Analyze `dtn_insert` and `dtn_remove`. Verify that the space check
  in `dtn_may_insert` correctly accounts for both the fixed-size entry
  and the variable-length name without overlapping the two in
  `dn_data`.
- Check the "punch and fixup" logic in `dtn_remove`. Moving names and
  updating `name_pos` for existing entries is high-risk; verify that
  `memmove` or `memcpy` logic is correct for overlapping regions.
- Audit `dtn_verify_names` and `dtn_verify_des` for robustness against
  filesystem corruption (e.g., names containing `/` or null bytes).

### 3. Readdir and Cookies

- Verify `encode_doffset` and `decode_doffset`. The directory offset
  (cookie) must be stable. Ensure that `make_doffset` and the 2-bit
  shifting logic correctly distinguishes between meta-entries (`.`,
  `..`) and actual tree entries.
- Audit `dirc_iterate_node` and its use of `dtn_scan`. Ensure that if
  the tree structure changes between `readdir` calls, the iterator can
  safely resume or terminate.

### 4. Consistency and Atomicity

- Check the coordination between `dir_ndents` (stored in the inode)
  and the actual number of active entries in the tree.
- Verify `dirc_update_isizeblocks`. Silofs represents directory size
  based on the last node index; confirm this calculation is correct.
- Ensure `SILOFS_STG_COW` is used correctly during modifications to
  maintain consistency if the task is interrupted.

### 5. Resource Management

- Ensure `dni_incref` and `dni_decref` are balanced across all
  navigation loops (e.g., in `dirc_do_lookup_by_tree`).
- Check that `silofs_ii_incref/decref` are correctly balanced in the
  top-level entry points like `silofs_add_dentry` and
  `silofs_do_readdir`.

## Input Files

- `lib/silofs/fs/dir.c` (primary implementation)
- `include/silofs/ondisk.h` (on-disk structure: `silofs_dtree_node`)
- `lib/silofs/fs/namei.c` (VFS interaction context)

## Required Output

Provide findings grouped by category:

- **Logic Errors**: Issues in tree navigation or index calculation.
- **Safety/Corruption**: Buffer overflows or failure to handle bad
  disk data.
- **Resource Leaks**: Unbalanced reference counts or orphaned blocks.
- **Fix**: Minimal code snippet or diff sufficient to correct the
  issue.

**Note**: Directory entries grow from index 0 upwards, while names
grow from the end of the 7616-byte buffer downwards. Collision of the
two pointers is the primary constraint.
