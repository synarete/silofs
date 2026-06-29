# Custom Slab Allocator Audit

## Overview

This document defines the audit procedure for the custom userspace
slab allocator in `lib/infra/qalloc.c`. The allocator is backed by
`memfd_create` and `mmap`, and manages memory in 64KB "pages"
(`QALLOC_PAGE_SIZE`):

- **Large allocations**: Served directly from the page pool (`qpool`).
- **Small allocations**: Served from size-specific slabs backed by
  pages.
- **Release**: Uses `fallocate(FALLOC_FL_PUNCH_HOLE)` to return unused
  physical memory to the OS without unmapping virtual memory.

## Objective

Focus strictly on the implementation details of `qalloc.c`. Identify
race conditions, lock ordering violations, pointer arithmetic errors,
and potential heap corruption bugs.

## Review Checklist

### 1. Concurrency and Locking

- **Lock Ordering**: The code acquires `slab->mutex` then
  `qpool->mutex` (e.g., `slab_alloc` → `slab_require_space` →
  `qpool_alloc`). Verify this hierarchy is strictly respected and
  never inverted.
- **Granularity**: Are critical sections too broad?
- **Atomics**: Review `silofs_atomic_sc_*` usage for statistics.

### 2. Pointer Arithmetic and Bounds

- Audit `qpool_ptr_to_off`, `qpool_ptr_to_pgn`, and
  `qpool_slab_seg_of`.
- Verify cast safety between `void*`, `char*`, and struct pointers.
- Ensure `qpool_isinrange` is checked before every pointer dereference
  in the free path (`qalloc_free`).

### 3. Slab Management (Expand/Shrink)

- Review `slab_expand`: usage of `qpg->seg[]` array and
  initialization of free list links.
- Review `slab_shrink`: logic for detecting when a page is fully empty
  and returning it to the `qpool`.
- Verify `slab_check_seg`: ensure it correctly identifies if a pointer
  belongs to a specific slab to prevent type confusion.

### 4. Backing Store and Hole Punching

- Analyze `qpool_punch_hole_at`. Verify offset/length calculations for
  `fallocate`.
- Check the heuristic in `qpool_may_punch_hole_at` (alignment vs
  threshold).
- Verify `memfd` lifecycle management in `qpool_init`/`fini`.

### 5. Robustness and Performance

- **Error Handling**: `qpool_punch_hole_at` panics on failure. Should
  it degrade gracefully (log warning, leak physical backing)?
- **Free List Search**: The `free_pgs` list is scanned linearly
  (O(N)). Propose a data structure upgrade (RB-Tree or Buddy System).
- **False Sharing**: Check if `qal->slabs[]` array elements align with
  cache lines to prevent false sharing on `slab->mutex`.

## Input Files

- `lib/silofs/base/qalloc.c`
- `lib/silofs/base/qalloc.h`

## Required Output

Provide findings grouped by category:

- **Critical Safety**: Memory corruption, deadlocks, integer
  overflows.
- **Logic Bugs**: Incorrect state transitions, resource leaks.
- **Performance**: Algorithmic bottlenecks and cache/lock contention.
- **Fix**: Minimal code snippet or diff to resolve the issue.
