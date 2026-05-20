# C Undefined Behavior Audit

## Overview

This document defines the audit procedure for identifying and
mitigating undefined behavior (UB) in the `silofs` C codebase,
primarily focusing on the `lib` directory. Undefined behavior
can lead to crashes, security vulnerabilities, or incorrect
program execution that may vary across compilers, optimization
levels, and platforms.

## Objective

Identify instances of undefined behavior, categorize their
potential impact, and suggest concrete fixes to ensure the
robustness, portability, and security of the `silofs` library.
The audit aims to eliminate non-deterministic program behavior
and improve code quality.

## Review Checklist

### 1. Memory Access Violations

- **Out-of-bounds Access**: Audit array and buffer indexing.
  Verify that all accesses are within allocated bounds.
  Check for off-by-one errors in loops and pointer arithmetic.
- **Use-after-free**: Ensure that memory is not accessed after
  it has been freed. Track object lifetimes carefully,
  especially in complex data structures.
- **Double-free**: Verify that memory is freed exactly once.
  Check for multiple `free()` calls on the same pointer.
- **Uninitialized Reads**: Audit local and dynamically
  allocated variables. Ensure all variables are initialized
  before their values are read.
- **Invalid Pointer Dereference**: Check for dereferencing
  `NULL` pointers or pointers to invalid memory regions.

### 2. Integer Overflows and Underflows

- **Signed Integer Overflow**: Audit arithmetic operations
  (addition, subtraction, multiplication) on signed integers.
  Ensure results do not exceed `INT_MAX` or fall below `INT_MIN`.
- **Shift Operations**: Verify that shift counts are non-negative
  and less than the width of the promoted operand. Check for
  left-shifting a negative value or shifting into the sign bit.
- **Division by Zero / Remainder by Zero**: Audit all division
  and modulo operations. Ensure the divisor is never zero.
- **Integer Conversion Issues**: Check for implicit conversions
  between signed and unsigned types, or between different
  integer widths, that might lead to unexpected value changes.

### 3. Pointer Arithmetic and Comparisons

- **Invalid Pointer Arithmetic**: Audit pointer arithmetic
  operations. Ensure pointers only point to elements within
  the same array object or one past the end.
- **Comparing Unrelated Pointers**: Verify that comparisons
  (e.g., `<`, `>`, `<=`, `>=`) are only performed between
  pointers to elements of the same array object.
- **Pointer to Integer Conversion**: Check for conversions
  between pointers and integers that are not explicitly
  defined by the standard (e.g., `uintptr_t`).

### 4. Type Conversions and Strict Aliasing

- **Strict Aliasing Violations**: Audit type-punning through
  pointers of incompatible types. Ensure that data is accessed
  only through pointers of its effective type or compatible
  types (e.g., `char*`).
- **Incorrect Type Casts**: Verify that explicit casts are
  correct and do not lead to misinterpretation of data.
  Pay attention to casts involving function pointers.

### 5. Concurrency Issues (Data Races)

- **Unprotected Shared Data**: Identify shared variables
  accessed by multiple threads without proper synchronization
  (e.g., mutexes, atomic operations). This can lead to data
  races and non-deterministic results.
  (Note: `list.c` is non-locking; check other modules.)

### 6. Function Calls and Control Flow

- **Invalid Function Arguments**: Audit function calls to ensure
  arguments match the expected types and constraints (e.g.,
  non-`NULL` pointers where required).
- **Reaching End of Non-void Function**: Verify that all
  non-void functions have a `return` statement on every
  possible execution path.
- **Infinite Loops**: Identify loops that may not terminate
  under certain conditions.

## Input Files

- `lib/` (all C source files within the library directory)

## Required Output

Provide findings grouped by category:

- **Memory**: Out-of-bounds, use-after-free, double-free,
  uninitialized reads, invalid dereferences.
- **Integer**: Overflows, underflows, shift issues, division by
  zero, conversion problems.
- **Pointer**: Invalid arithmetic, unrelated comparisons,
  improper conversions.
- **Type**: Strict aliasing, incorrect casts.
- **Concurrency**: Data races on shared memory.
- **Other**: Invalid function arguments, control flow issues.

Each finding should include:

- **Location**: Function name and file path.
- **Description**: What is the undefined behavior and why it is
  problematic.
- **Fix**: Minimal code snippet or diff sufficient to correct
  the issue.

**Note**: Leverage compiler warnings (e.g., `-Wall -Wextra
-Werror -fsanitize=undefined`) and static analysis tools
(e.g., Clang Static Analyzer, Coverity) during the audit.