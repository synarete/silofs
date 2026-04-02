# Role: Senior Systems Programmer (Data Structures & Algorithms Specialist)
**Task:** Deep-dive audit of the intrusive AVL tree implementation.

## 1. System Overview
Silofs uses an intrusive AVL tree (`lib/base/avl.c`) for ordered metadata
indexing. The implementation uses a "head" sentinel node where:
- `head.parent` points to the actual root.
- `head.left` points to the leftmost (minimum) node.
- `head.right` points to the rightmost (maximum) node.
The tree maintains balance factors of -1, 0, or 1.

### Comparator Contract (CRITICAL — read before auditing any comparison)
The `keycmp(a, b)` function registered via `silofs_avl_init` uses a
**reversed sign convention** — the opposite of `qsort`/`strcmp`:
- returns **> 0** when `a < b`
- returns **0** when `a == b`
- returns **< 0** when `a > b`

This is equivalent to a standard comparator with its two arguments swapped.
Every internal helper is written against this contract:
- `avl_less_than(x, k)` returns `keycmp(key(x), k) > 0`, which correctly
  means `key(x) < k`.
- `avl_compare(x, y)` returns a value whose sign encodes `key(x) < key(y)`
  as positive, so `cmp > 0` in the search loops means "go right" (toward
  larger keys), which is correct.
- `avl_insert_leaf_at` must use `avl_compare(x, *leftmost) > 0` (not `< 0`)
  to detect a new minimum, because positive means `key(x) < key(*leftmost)`.

Before flagging any comparison as inverted, verify the sign against this
contract. A comparison that looks backwards under `qsort` semantics is
likely correct here, and vice versa.

## 2. Objective
Identify logical errors in the balancing algorithm, pointer corruption in
rotation/relinking, and edge-case failures in range searches. Focus on the
mathematical correctness of the AVL properties.

## 3. Review Checklist

### 3.1 Rotation Logic and Balance Factors
- **Before auditing any `cmp > 0` / `cmp < 0` branch: re-read the
  Comparator Contract in Section 1 and confirm the sign interpretation
  against it. Do not assume `qsort` semantics.**
- Audit the four rotation types: `avl_rotate_left`, `avl_rotate_right`,
  `avl_rotate_left_right`, and `avl_rotate_right_left`.
- Verify that balance factors are updated correctly post-rotation.
- Compare `bst_rotate_*` (structural) against `avl_rotate_*` (balance-aware)
  to ensure they don't desynchronize the tree height.

### 3.2 Insertion and Deletion Fixups
- Review `avl_insert_fixup`. Ensure it correctly terminates when the tree
  is rebalanced or the root is reached.
- Review `avl_delete_fixup`. This is high-complexity: verify the case
  where `y->balance == 0` during a delete rotation, which is a classic
  AVL implementation pitfall.
- Analyze `avl_delete` node swapping logic. Ensure that when a node with
  two children is deleted, its successor is correctly spliced out and
  replaces the target node without breaking the `parent` pointers.

### 3.3 Intrusive Sentinel (Head) Management
- Verify that `avl_leftmost_p` and `avl_rightmost_p` are updated correctly
  during every insert and delete operation.
- Check `avl_post_insert_fixup` and `avl_remove_rebalance`. Ensure they
  don't leave dangling pointers in the `head` node when the tree is
  emptied or the min/max elements change.
- When auditing leftmost/rightmost update logic, apply the Comparator
  Contract: `avl_compare(new, current) > 0` means `key(new) < key(current)`
  (new minimum), and `< 0` means `key(new) > key(current)` (new maximum).
- Verify that leftmost/rightmost are updated **before** `avl_insert_fixup`
  is called, since rotations inside fixup invalidate parent-pointer walks
  that `bst_predecessor`/`bst_successor` rely on.

### 3.4 Search and Range Operations
- Audit `avl_lower_bound` and `avl_upper_bound`. Ensure the "greater than"
  vs "greater or equal" logic strictly follows C++ `std::map` semantics.
- Review `avl_equal_range`. Check for efficiency and correctness in trees
  with non-unique keys (if allowed).
- Verify `bst_successor` and `bst_predecessor` handle the transition
  through the root and the sentinel node correctly.

### 3.5 Memory Safety and Magic Checks
- Audit `avl_node_verify`. Check if the magic value and balance factor
  assertions are sufficient to detect heap corruption.
- Review `avl_unlinkall`. Ensure it correctly transforms the tree into a
  linear list without losing nodes or creating cycles.

### 3.6 Reentrancy and Concurrency
- While this is a base library, check for global state.
- Ensure `avl_node_unconst` (the union-based cast) does not violate
  strict aliasing rules on target compilers.

### 3.7 Unit Test Coverage and Usage Patterns
- Review `test/utests/ut_avl.c` to understand how the AVL tree functions are
  exercised. Verify that critical logic paths, edge cases (e.g., empty tree,
  single node, root operations), and balance factor updates are adequately
  covered by the unit tests.

## 4. Input Files
- `lib/base/avl.c`
- `lib/include/silofs/base/avl.h`
- `test/utests/ut_avl.c`

## 5. Required Output
Provide findings grouped by category:
- **Critical Logic:** Violations of AVL balance properties or pointer leaks.
- **Edge Cases:** Failures during root deletion, empty tree operations,
  or single-node trees.
- **Performance:** Suboptimal traversal or excessive rotations.
- **Fix:** Minimal code snippet or diff to resolve the issue.

---
*Note: The implementation uses 1-based balance logic where balance =
height(right) - height(left). Verify this sign convention is consistent
across all fixup functions.*

*Note: The `keycmp` comparator uses a reversed sign convention (positive
when `a < b`). Verify every comparison site in `avl.c` against this
contract before concluding a sign is wrong. Past audits have produced
false-positive findings by assuming `qsort` semantics here.*
