# Role: Senior Systems Programmer (Memory Allocator Specialist)
**Task:** Deep-dive code audit of `lib/silofs/infra/qalloc.c`.

## 1. System Overview
`qalloc` is a custom userspace slab allocator backed by `memfd_create` and
`mmap`. It manages memory in 64KB "pages" (`QALLOC_PAGE_SIZE`).
- **Large allocations:** Served directly from the page pool (`qpool`).
- **Small allocations:** Served from size-specific slabs backed by pages.
- **Release:** Uses `fallocate(FALLOC_FL_PUNCH_HOLE)` to return unused
  physical memory to the OS without unmapping virtual memory.

## 2. Objective
Focus strictly on the implementation details of `qalloc.c`. Identify race
conditions, lock ordering violations, pointer arithmetic errors, and
potential heap corruption bugs.

## 3. Review Checklist

### 3.1 Concurrency and Locking
- **Lock Ordering:** The code acquires `slab->mutex` then `qpool->mutex`
  (e.g., `slab_alloc` -> `slab_require_space` -> `qpool_alloc`). Verify
  this hierarchy is strictly respected and never inverted.
- **Granularity:** Are critical sections too broad?
- **Atomics:** Review `silofs_atomic_sc_*` usage for statistics.

### 3.2 Pointer Arithmetic and Bounds
- Audit `qpool_ptr_to_off`, `qpool_ptr_to_pgn`, and `qpool_slab_seg_of`.
- Verify cast safety between `void*`, `char*`, and struct pointers.
- Ensure `qpool_isinrange` is checked before every pointer dereference in
  the free path (`qalloc_free`).

### 3.3 Slab Management (Expand/Shrink)
- Review `slab_expand`: usage of `qpg->seg[]` array and initialization of
  free list links.
- Review `slab_shrink`: logic for detecting when a page is fully empty
  and returning it to the `qpool`.
- Verify `slab_check_seg`: ensure it correctly identifies if a pointer
  belongs to a specific slab to prevent type confusion.

### 3.4 Backing Store & Hole Punching
- Analyze `qpool_punch_hole_at`. Verify offset/length calculations for
  `fallocate`.
- Check the heuristic in `qpool_may_punch_hole_at` (alignment vs threshold).
- Verify `memfd` lifecycle management in `qpool_init`/`fini`.

### 3.5 Robustness and Performance
- **Error Handling:** `qpool_punch_hole_at` panics on failure. Should it
  degrade gracefully (log warning, leak physical backing)?
- **Free List Search:** The `free_pgs` list is scanned linearly (O(N)).
  Propose a data structure upgrade (RB-Tree or Buddy System).
- **False Sharing:** Check if `qal->slabs[]` array elements align with cache
  lines to prevent false sharing on `slab->mutex`.

## 4. Input Files
- `lib/silofs/infra/qalloc.c`
- `lib/silofs/infra/qalloc.h`

## 5. Required Output
Provide findings grouped by category:
- **Critical Safety:** Memory corruption, deadlocks, integer overflows.
- **Logic Bugs:** Incorrect state transitions, resource leaks.
- **Performance:** Algorithmic bottlenecks and cache/lock contention.
- **Fix:** Minimal code snippet or diff to resolve the issue.
