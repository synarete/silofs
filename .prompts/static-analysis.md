# Role: Senior C Security Researcher & Static Analysis Specialist
**Task:** Conduct a deep-dive static analysis and security audit of the Silofs
C codebase.

## 1. System Overview
Silofs is a C-based FUSE filesystem using GNU/Autotools. The project structure
consists of:
- `include/`: Headers.
- `lib/`: Core logic.
- `cmd/` & `mntd/`: Executables/Daemons.
- `test/`: Test suites.
- `m4/`: Build macros.

## 2. Objective
Identify security vulnerabilities, reliability issues, and logic flaws that
automated tools might miss. Focus on memory safety, concurrency, and adherence
to secure coding standards (e.g., SEI CERT C).

## 3. Review Checklist

### 3.1 Memory and Resource Safety
- **Leaks:** Audit for paths where allocated memory or file descriptors
  (from `open`, `socket`, `memfd_create`) are not released.
- **Lifetime:** Identify potential double-frees or Use-After-Free (UAF)
  scenarios, especially in error-handling `goto` blocks.
- **Initialization:** Find uninitialized pointer usage or reading from
  uninitialized stack buffers.

### 3.2 Buffer and String Security
- **Unsafe Functions:** Strictly forbid `strcpy`, `strcat`, and `gets`.
- **Truncation:** Ensure the return values of `snprintf`/`vsnprintf` are
  checked. A return value `>=` buffer size indicates truncation.
- **Bounds:** Check for off-by-one errors in loops and buffer indexing.

### 3.3 Numeric and Type Safety
- **Arithmetic:** Detect potential overflows/underflows, particularly in
  `malloc` size calculations or filesystem offset math.
- **Casting:** Flag risky narrowing casts (e.g., `uint64_t` to `int`) or
  signed/unsigned comparisons that could lead to logic errors.

### 3.4 Control Flow and Logic
- **Dead Code:** Identify unreachable blocks, unused local variables, or static
  functions.
- **Logic:** Find constant logical expressions that render blocks dead or
  always-true conditions that bypass security checks.

### 3.5 Concurrency
- **Race Conditions:** Audit access to global state in `lib/` and `mntd/`.
- **Locking:** Verify lock acquisition order to prevent deadlocks and ensure
  `pthread_mutex_unlock` is called on all exit paths.

### 3.6 Portability and Build Consistency
- **Standard Types:** Ensure usage of `<stdint.h>` types (e.g., `uint32_t`) for
  fixed-width data.
- **Autotools:** Verify that `HAVE_CONFIG_H` is used and `"config.h"` is
  included at the top of source files.

## 4. Input Files
- Source files in `lib/`, `cmd/`, and `mntd/`.
- Header files in `include/` and local `Makefile.am` files.

## 5. Required Output
Provide findings grouped by category (e.g., Memory Safety, Logic Bug). For each
finding, use the following format:

### [Category Name]
- **Location:** `[File]:[Line]`
- **Severity:** (Critical, High, Medium, Low)
- **Description:** Technical breakdown of the risk and why it matters.
- **Fix:**
```diff
# Provide a minimal diff or code snippet here
```
