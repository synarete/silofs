# Role: Senior Systems Programmer (Data Structures Specialist)
**Task:** Audit the intrusive double linked-list and sized queue in `silofs`.

## 1. System Overview
Silofs uses a circular intrusive double linked-list (`silofs_list_head`) as
its fundamental container. It also provides a sized wrapper (`silofs_listq`)
for queue operations where O(1) size retrieval is required. The design
follows the Linux kernel's `list_head` pattern where an empty list is
represented by a sentinel node pointing to itself.

## 2. Objective
Identify logical errors in pointer manipulation, inconsistencies in size
tracking, and improper handling of edge cases (e.g., popping from empty
lists). Focus on the safety of the `inline` helpers and the correctness
of the `listq` wrappers.

## 3. Review Checklist

### 3.1 Pointer Integrity and Circularity
- Verify `silofs_list_head_init` correctly establishes the circular
  invariant (`lh->next = lh->prev = lh`).
- Audit `silofs_list_head_insert` and `silofs_list_head_remove`. Ensure
  all four pointer updates (new node's next/prev and neighbors' next/prev)
  are performed in the correct order to avoid data loss.
- Verify that `silofs_list_head_remove` resets the removed node to a
  valid empty state (pointing to itself) to prevent double-removals from
  corrupting the original list.

### 3.2 Sized Queue Consistency
- Review all `silofs_listq` operations (`push`, `pop`, `remove`).
- **Critical:** Ensure that for every operation that modifies the list
  structure, the `lsq->sz` counter is incremented or decremented
  accordingly.
- Verify that `silofs_listq_pop_front/back` handles the empty case
  gracefully by checking `sz > 0` before attempting to remove or
  decrement.

### 3.3 Boundary Conditions and Nullability
- Audit `silofs_list_pop_front/back`. Check that they return `nullptr`
  (or the project's equivalent) when the list is empty, rather than
  returning the sentinel node itself.
- Review `silofs_listq_next/prev`. Verify they correctly detect the
  sentinel node (`&lsq->ls`) and return `nullptr` when the end of the
  list is reached, preventing callers from accidentally iterating into
  the head structure.
- Ensure `silofs_list_head_fini` sets pointers to `nullptr`. Verify that
  no code paths attempt to use a "finished" node without re-initialization.

### 3.4 Initialization and Cleanup
- Verify `silofs_list_head_initn` and `silofs_listq_initn`. Ensure they
  correctly initialize every element in an array without off-by-one errors.
- Check the symmetry between `init` and `fini` functions to ensure
  consistent lifecycle management.

### 3.5 API Usage and Safety
- Evaluate the `const` correctness of "read-only" operations like
  `silofs_list_isempty`, `silofs_list_front`, and `silofs_listq_size`.
- Check for potential "magic number" or pointer arithmetic issues in
  the list implementation.

## 4. Input Files
- `lib/base/list.c`
- `lib/include/silofs/base/list.h`

## 5. Required Output
Provide findings grouped by category:
- **Logic Errors:** Pointer corruption, circularity breaks, or incorrect
  terminations.
- **Consistency:** Mismatches between list state and the `sz` counter.
- **Safety:** Null pointer dereferences or exposure of sentinel nodes to
  the caller.
- **Fix:** Minimal code snippet or diff sufficient to correct the issue.

---
*Note: The implementation uses `nullptr` which is a C23/C++ keyword. Ensure
the project's headers/compiler flags support this, or check if it should
be `NULL`.*

*Note: Intrusive lists rely on `container_of` style macros for actual
data access. While not in `list.c`, verify the `list_head` is always
accessible and that removing a node doesn't leave the parent structure
in an invalid state if it's being used by other threads (though this
library itself is non-locking).*
