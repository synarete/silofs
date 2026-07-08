# Intrusive AVL Tree Audit

## Overview

This document defines the audit procedure for the intrusive AVL tree
implementation in `lib/base/avl.c`. The tree is used for ordered
metadata indexing. It uses a "head" sentinel node where:

- `head.parent` points to the actual root.
- `head.left` points to the leftmost (minimum) node.
- `head.right` points to the rightmost (maximum) node.

The tree maintains balance factors of -1, 0, or 1.

### Comparator Contract

The `keycmp(a, b)` function registered via `silofs_avl_init` uses a
**reversed sign convention** — the opposite of `qsort`/`strcmp`:

- Returns **> 0** when `a < b`.
- Returns **0** when `a == b`.
- Returns **< 0** when `a > b`.

This is equivalent to a standard comparator with its two arguments
swapped. Every internal helper is written against this contract:

- `avl_less_than(x, k)` returns `keycmp(key(x), k) > 0`, which
  correctly means `key(x) < k`.
- `avl_compare(x, y)` returns a value whose sign encodes
  `key(x) < key(y)` as positive, so `cmp > 0` in the search loops
  means "go right" (toward larger keys), which is correct.

Before flagging any comparison as inverted, verify the sign against
this contract. A comparison that looks backwards under standard
semantics is likely correct here.

## Objective

Identify logical errors in the balancing algorithm, pointer corruption
in rotation and relinking, and edge-case failures in range searches.
Focus on the mathematical correctness of the AVL properties.

## Review Checklist

### 1. Rotation Logic and Balance Factors

- Audit the four rotation types: `avl_rotate_left`, `avl_rotate_right`,
  `avl_rotate_left_right`, and `avl_rotate_right_left`.
- Verify that balance factors are updated correctly post-rotation.
- Compare `bst_rotate_*` (structural) against `avl_rotate_*`
  (balance-aware) to ensure they don't desynchronize the tree height.

### 2. Insertion and Deletion Fixups

- Review `avl_insert_fixup`. Ensure it correctly terminates when the
  tree is rebalanced or the root is reached.
- Review `avl_delete_fixup`. Pay special attention to the case where
  the sibling node has a balance of 0, which is a classic AVL pitfall.
- Analyze `avl_delete` node swapping logic. Ensure that when a node
  with two children is deleted, its successor is correctly spliced out
  and replaces the target node without breaking `parent` pointers.

### 3. Intrusive Sentinel (Head) Management

- Verify that `avl_leftmost_p` and `avl_rightmost_p` are updated
  correctly during every insert and delete operation.
- Check `avl_post_insert_fixup` and `avl_remove_rebalance`. Ensure
  they don't leave dangling pointers in the `head` node when the tree
  is emptied or the min/max elements change.
- Verify that leftmost/rightmost are updated **before**
  `avl_insert_fixup` completes, as rotations may change node
  relationships.

### 4. Search and Range Operations

- Audit `avl_lower_bound` and `avl_upper_bound`. Ensure the
  "greater than" vs "greater or equal" logic strictly follows C++
  `std::map` semantics.
- Review `avl_equal_range`. Check for efficiency and correctness in
  trees with non-unique keys.
- Verify `bst_successor` and `bst_predecessor` handle the transition
  through the root and the sentinel node correctly.

### 5. Memory Safety and API

- Audit `avl_node_verify`. Check if the magic value and balance factor
  assertions are sufficient to detect corruption.
- Review `avl_unlinkall`. Ensure it transforms the tree into a linear
  list using the `right` pointer without losing nodes.
- Check `avl_node_unconst`. Verify the union-based cast does not
  violate strict aliasing rules.

### 6. Unit Test Coverage

- Review `test/utests/ut_avl.c`. Verify that it tests:
  - Basic CRUD (Insert, Find, Remove).
  - Range operations (Lower/Upper bound).
  - Large random sets to stress balancing.
  - Duplicate key handling (Unique vs Non-unique).

## Input Files

- `lib/silofs/infra/avl.c`
- `lib/silofs/infra/avl.h`
- `test/utests/ut_avl.c`

## Required Output

Provide findings grouped by category:

- **Critical Logic**: Violations of AVL balance properties or pointer
  leaks.
- **Edge Cases**: Failures during root deletion or empty tree
  operations.
- **Comparator Issues**: Mismatches between implementation and the
  contract.
- **Fix**: Minimal code snippet or diff to resolve the issue.
