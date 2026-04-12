# Role: Senior Systems Programmer (String & Memory Utility Specialist)
**Task:** Audit the core string, buffer, and view utilities in `silofs`.

## 1. System Overview
Silofs uses a suite of string utilities divided into core character
manipulation (`strchr.c`), dynamic buffers (`strbuf.c`), non-owning
string views (`strview.c`), search/spanning tools (`strspan.c`), and
ASCII-specific helpers (`ascii.c`).

Key features include:
- Manual handling of overlapping memory during insertion/replacement.
- Length-explicit operations to avoid NUL-termination vulnerabilities.
- Stack-buffered chunking for memory-constrained overlap handling.
- Non-owning views to minimize redundant allocations.

## 2. Objective
Identify logical errors in buffer manipulation, off-by-one errors in length
calculations, and potential stack safety issues. Focus on the correctness
of overlap detection, the efficiency of search algorithms, and the safety
of the "with-overlap" vs "no-overlap" codepaths.

## 3. Review Checklist

### 3.1 Overlap Detection and Memory Safety
- Audit `silofs_str_overlaps`. Verify that the pointer arithmetic using
  `uintptr_t` correctly identifies intersections between two regions.
- Review `str_insert_with_overlap`. It uses a 512-byte stack buffer.
  Check if strings larger than 512 bytes are handled correctly via the
  looping mechanism (verify source pointer updates).
- Audit `strbuf.c` for growth logic. Ensure that capacity increases
  handle integer overflow and that the original buffer is not leaked
  on `realloc` failure.

### 3.2 Search and Comparison Logic
- Audit `silofs_str_find` and `silofs_str_rfind`. Check the loop bounds
  and pointer increments for off-by-one errors, especially when the
  "needle" is at the very beginning or end of the "haystack".
- Review `silofs_str_ncompare`. Ensure the three-way comparison logic
  correctly handles mismatched lengths (`n1 != n2`).
- Verify that prefix/suffix matching (`common_prefix`, `common_suffix`)
  properly handles empty inputs or zero-length constraints.
- Review `strspan.c` for correct bitmask or lookup-table usage when
  calculating spans of character sets.

### 3.3 Buffer Manipulation (Insert/Replace)
- Analyze `silofs_str_insert` and `silofs_str_replace`. Verify that the
  destination buffer size (`sz`) is never exceeded and that truncation
  logic correctly accounts for existing data (`n1` or `len`).
- Check `silofs_str_reverse` for boundary conditions (length 0 or 1).

### 3.4 String Views and Lifetime
- Audit `strview.c`. Ensure that views do not attempt to null-terminate
  the underlying data (as they are non-owning).
- Verify that functions accepting views check for `length == 0` and
  do not dereference the view's data pointer in such cases.

### 3.4 API Robustness and Standards
- Check handling of `nullptr` (C23) in public entry points.
- Review the `ctype` wrappers (e.g., `silofs_chr_isalnum`). Standard
  `isalnum` and friends expect an `int` (unsigned char or EOF). Verify
  that the `char` to `int` promotion is handled safely.
- Verify the consistency of null-termination. Since many of these
  functions are length-based, ensure `silofs_str_terminate` is used by
  callers or within the library where null-terminated strings are expected.

### 3.5 Efficiency
- Look for "Schlemiel the Painter" patterns (e.g., repeated `strlen` or
  redundant overlap checks).
- Evaluate the performance of `silofs_str_find`. For very large strings,
  consider if the current $O(N \cdot M)$ implementation is acceptable for
  filesystem metadata use cases.

## 4. Input Files
- `lib/str/ascii.c`
- `lib/str/strbuf.c`
- `lib/str/strchr.c`
- `lib/str/strspan.c`
- `lib/str/strview.c`
- `lib/include/silofs/str/ascii.h`
- `lib/include/silofs/str/strbuf.h`
- `lib/include/silofs/str/strchr.h`
- `lib/include/silofs/str/strspan.h`
- `lib/include/silofs/str/strview.h`

## 5. Required Output
Provide findings grouped by category:
- **Memory Safety:** Potential overflows, invalid pointer math, or
  stack safety issues.
- **Logic Errors:** Incorrect search results, off-by-one errors, or
  flawed truncation logic.
- **Performance:** Redundant scans or inefficient algorithms.
- **Fix:** Minimal code snippet or diff sufficient to correct the issue.

---
*Note: The implementation uses `nullptr`. Ensure compatibility with the*
*configured C standard (C23).*
