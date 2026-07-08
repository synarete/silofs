# Fatal Error and Assertion Infrastructure Audit

## Overview

This document defines the audit procedure for the fatal-error and
assertion infrastructure in `silofs`. The system is responsible for
providing meaningful diagnostic information (backtraces, source
locations, and error messages) before terminating the process. It
integrates with `libunwind` for stack unwinding and leverages
`addr2line` for symbol resolution.

## Objective

Identify bugs, memory safety issues, and logical errors in the error
reporting, stack unwinding, and assertion macros. Focus on buffer
overflows, incorrect state management, and thread-safety of the panic
mechanism.

## Review Checklist

### 1. Stack Unwinding and Backtraces

- Audit `silofs_backtrace_calls`. Verify the loop bounds (80 steps)
  and the logic for skipping initial frames (step < 2).
- Review `backtrace_addrs_to_str`. Ensure that the manual buffer
  pointer arithmetic (`buf + len`) and size calculations (`bsz - len`)
  do not lead to out-of-bounds writes.
- Verify that `unw_get_proc_name` failures are handled gracefully
  without leaving uninitialized data in the symbol buffer.

### 2. Buffer Management and String Formatting

- Analyze `fmtmsg` and `silofs_panicf`. Both use fixed-size stack
  buffers. Evaluate if this is sufficient and ensure `vsnprintf`
  return values are handled if truncation occurs.
- Check for `va_list` reuse violations. Ensure `va_end` is called
  correctly in all formatting paths.
- Verify the usage of `silofs_attr_printf` to ensure the compiler
  validates format strings against arguments.

### 3. Assertion Logic and Comparisons

- Audit the `silofs_expect_*` suite. Ensure that `intmax_t` is used
  consistently for comparisons to avoid signed/unsigned mismatch bugs.
- Review `silofs_expect_eqs_` (string comparison) and
  `silofs_expect_eqm_` (memory comparison). Verify that `nullptr`
  inputs are handled or explicitly guarded.
- Check `find_first_not_eq` for off-by-one errors when identifying
  the mismatch position in memory buffers.

### 4. Fatal Flow and Global State

- Analyze `silofs_panicked` and the `SILOFS_PANIC_WAIT` logic. Ensure
  the busy-wait loop is intentional and check if it interacts poorly
  with signals or multi-threaded scenarios.
- Audit `silofs_backtrace_enabled`. Since this is a global static
  boolean, check for race conditions where multiple threads might
  trigger a panic simultaneously, potentially corrupting logs or the
  backtrace.
- Verify `errno` preservation. Ensure `errno` is captured immediately
  in `silofs_panicf` before other system calls (like `silofs_logf`)
  potentially overwrite it.

### 5. API and Portability

- Review usage of `program_invocation_name`. Verify its availability
  on target platforms (GNU extension) or check for proper guards.
- Ensure `silofs_attr_noreturn` is correctly applied to all functions
  that terminate the process to aid compiler flow analysis.

## Input Files

- `lib/silofs/infra/panic.c`
- `include/silofs/panic.h`

## Required Output

Provide findings grouped by category:

- **Critical Logic**: Buffer overflows, pointer corruption, or
  incorrect assertion logic.
- **Safety/Concurrency**: Issues with global state or signal safety.
- **Diagnostics**: Failures in backtrace generation or symbol
  reporting.
- **Fix**: Minimal code snippet or diff to resolve the issue.
