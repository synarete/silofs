# Directory Hash-Tree Audit (Round 2)

## Overview

Silofs directories use a **hash-tree** stored as a forest of
`silofs_dtree_node` objects (`SILOFS_DTREE_NODE_SIZE` = 8192 bytes).
Each node is identified by a 0-based integer index. The tree has a
fixed fanout of 64 (`SILOFS_DTREE_NODE_NCHILDS`) and a maximum depth
of 4 (`SILOFS_DIR_TREE_DEPTH_MAX`), giving a maximum node index of
17 043 520 (`SILOFS_DIR_TREE_INDEX_MAX`).

### Index Arithmetic

Node indices are 0-based. Index `UINT32_MAX` is the null sentinel
(`SILOFS_DIR_TREE_INDEX_NULL`); index 0 is the root
(`SILOFS_DIR_TREE_INDEX_ROOT`). The parent/child relationships are:

```
parent(idx) = (idx - 1) / FANOUT          [root has no parent]
child(parent, ord) = parent * FANOUT + ord + 1
child_ord(idx)     = (idx - 1) % FANOUT
```

The depth of a node is computed by walking up to the root via
`dtn_index_to_parent`. The hash of a name selects the child ordinal
at each level: `ord = (hash >> (SHIFT * (depth - 1))) % FANOUT`,
where `SHIFT = 6`. Depth 1 uses bits 5:0, depth 2 uses bits 11:6,
depth 3 uses bits 17:12, depth 4 uses bits 23:18.

### Per-Node Buffer Layout

Each node's `dn_data` field is a 7616-byte union:

```
union silofs_dtree_data {
    struct silofs_dir_entry de[476];   /* entries, grow upward  */
    uint8_t                 nb[7616];  /* names,   grow downward */
};
```

`de[]` entries occupy bytes 0..`nde*16 - 1` (each entry is 16 bytes).
Names are packed from the top downward: the first name inserted ends
at byte 7615; subsequent names are prepended. `dn_nnb` tracks total
name bytes; `dn_nde` is the high-water mark of the entry array.

The **space invariant** is: `nde * 16 + nnb + 16 + nlen <= 7616`.
A non-active (tombstone) entry slot may be reused, saving 16 bytes.

Each `silofs_dir_entry` stores:
- `de_ino` (8 bytes): target inode number.
- `de_name_hash_dt` (4 bytes): low 24 bits = hash, high 8 bits = dtype.
- `de_name_len` (2 bytes): name length in bytes.
- `de_name_pos` (2 bytes): byte offset of the name within `nb[]`.

### Name Removal (Punch and Fixup)

Removing an entry at `name_pos` P with length L:

1. `dtn_punch_name_at`: `memmove` the names in `[names_beg, P)` up
   by L bytes (toward higher addresses), closing the gap.
2. `dtn_sub_nnb`: decrement `nnb` by L.
3. `de_deactivate`: zero out the entry (ino=0, len=0, pos=0).
4. `dtn_remove_fixup`: for every *active* entry with `name_pos < P`,
   add L to its stored `name_pos` (they were shifted up by L).

The parameter called `nb_moved` in `dtn_remove_fixup` is the removed
name's length L, **not** the memmove byte count (`P - names_beg`).

### Readdir Offset Encoding

Directory offsets (cookies) encode both the node index and the slot:

```
doffset = ((dtn_index << 13) | slot) << 2 | 2
```

`DTREE_OFF_SHIFT = 13` matches `DTREE_NODE_SIZE = 8192 = 1 << 13`.
The `| 2` tag distinguishes tree entries from dot (0) and dotdot (1).
Valid doffsets are spaced **4 apart** within a node. After emitting
an entry at doffset D, the code advances `pos` by 1 (to D+1), which
falls between two valid doffsets; `dtn_scan`'s `>= pos` check then
correctly skips to the next slot.

### Known Issues from Prior Audit

The following issues were identified in the first audit pass and
should be verified as fixed or still present:

1. **`dtn_index_depth` no early-exit**: the loop has no depth cap;
   add `if (++depth > DTREE_DEPTH_MAX) return depth` as a guard.

2. **Unprotected `child_dti` in traversal loops**: in
   `dirc_do_lookup_by_tree` and `dirc_do_add_to_tree`, after
   `dti = child_dti` the new `dti` has no `incref`. The staging
   helpers protect the parent during I/O, but the child is
   unprotected between loop iterations.

3. **`rd_ctx->pos += 1` fragility**: the +1 advance relies on
   doffsets being spaced 4 apart. Should be `pos = off + 4`.

4. **Stale `last_index`**: `dirin_update_last_index` decrements
   `last_index` by 1 on removal; in a sparse tree this can point to
   a non-existent node. Safe in practice (ENOENT is handled), but
   causes unnecessary I/O probes.

5. **`dtn_remove_fixup` parameter name**: `nb_moved` means the
   removed name's length, not the memmove byte count. Rename to
   `name_len` for clarity.

6. **`dtn_verify_names` / `dtn_verify_des` not cross-validated**:
   a corrupted `nnb` smaller than the true total shifts `names_beg`
   into a name. Add a cross-check: sum `de_name_len` over active
   entries and compare against `nnb`.

## Objective

Verify whether the issues above have been fixed. Identify any new
bugs introduced by those fixes or by other recent changes. Focus on
the buffer safety of the punch/fixup path, reference counting in
tree traversal, and readdir cookie stability.

## Review Checklist

### 1. Tree Indexing and Navigation

- Confirm `dtn_index_depth` has an early-exit guard at `DEPTH_MAX`.
- Re-verify `dtn_index_to_parent` and `child_dtn_index_of` round-trip
  for root (0), first child (1), last depth-1 child (64), first
  depth-2 child (65), and `INDEX_MAX` (17 043 520).
- Confirm `dtn_index_isvalid` accepts 0 and rejects `UINT32_MAX`.
- Check `hash_to_child_ord`: depth argument must be `parent_depth+1`,
  ranging 1..4; verify no off-by-one.

### 2. Buffer Safety and Entry Management

- Re-audit `dtn_may_insert`: confirm the nonactive-slot edge case
  correctly subtracts `sizeof(de)` from `nwant`.
- Re-audit `dtn_punch_name_at` + `dtn_remove_fixup`: trace a removal
  of a middle name and verify all `name_pos` values are updated.
- Confirm `dtn_remove` captures `name_pos`/`name_len` before any
  mutation of `de`.

### 3. Reference Counting

- Verify `dirc_do_lookup_by_tree` and `dirc_do_add_to_tree` now
  incref/decref `dti` correctly across loop iterations.
- Confirm `dirc_discard_childs_of` holds `dti_incref` on the parent
  for the full child-iteration loop.

### 4. Readdir and Cookies

- Confirm `dirc_iterate_node` advances `pos` by 4 (or equivalent)
  rather than 1.
- Verify `dtn_scan` correctly handles a `pos` that encodes a
  different node index than the current node (should return nullptr).
- Check `dirc_do_iterate_tree_nodes` handles ENOENT from
  `dirc_stage_node_by_index` without leaking the loop counter.

### 5. Verification Robustness

- Check whether `dtn_verify_des` and `dtn_verify_names` now
  cross-validate `nnb` against the sum of active `de_name_len`.
- Verify `dtn_verify_counts` catches `nde > NENTS` and
  `nnb > NBSIZE` before any pointer arithmetic.

## Input Files

- `lib/silofs/fs/dir.c` (primary implementation)
- `include/silofs/ondisk.h` (on-disk structures)

## Required Output

Provide findings grouped by category:

- **Fixed**: Issues from the prior audit that are now resolved.
- **Regressed**: Prior issues still present or made worse.
- **New**: Bugs not present in the prior audit.
- **Fix**: Minimal code snippet or diff sufficient to correct each
  issue.
