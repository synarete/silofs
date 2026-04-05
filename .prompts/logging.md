# Role: Senior Systems Programmer (Logging & Observability Specialist)
**Task:** Audit the logging infrastructure in `silofs`.

## 1. System Overview
Silofs uses a centralized logging facility implemented in `lib/base/logging.c`.
The system supports dual output (stdout and syslog), level-based filtering
following RFC-5424, and metadata enrichment (timestamps, file/line info).
It uses a global parameter structure (`silofs_log_params`) to control
behavior across the entire process.

## 2. Objective
Identify bugs, logical errors, and API inconsistencies. Focus on thread
safety regarding global state, potential buffer overflows in string
formatting, and correctness of the RFC-5424 level mapping.

## 3. Review Checklist

### 3.1 Thread Safety and Global State
- Verify the safety of `silofs_global_log_params`. Since it is a static
  pointer modified by `silofs_set_global_log_params`, check for race
  conditions if the parameters are updated during active logging.
- Audit the use of `flockfile`/`funlockfile` in `log_to_stdout`. Ensure
  interleaved logs from multiple threads are prevented.
- Confirm that `localtime_r` is used correctly to ensure thread-safe
  timestamp generation.

### 3.2 Buffer Management and Formatting
- Review `silofs_logf` and its 512-byte internal buffer. Check if the
  truncation logic (using `vsnprintf`) is robust and handles the return
  value correctly.
- Verify the `silofs_attr_printf` macro usage in the header to ensure
  the compiler validates format strings at call sites.
- Audit `log_timestamp`. Ensure the 40-byte buffer is sufficient for the
  strftime format and that it handles empty returns gracefully.

### 3.3 RFC-5424 and Syslog Integration
- Audit `syslog_level` and `silofs_log_level_by_rfc5424`. Verify that
  the mapping between internal levels, RFC-5424 strings/integers, and
  standard `<syslog.h>` constants is consistent and logical.
- Check for missing levels (e.g., `EMERG`, `ALERT`, `NOTICE`) and how
  they are aliased or handled.

### 3.4 Logic and Verbosity
- Analyze `log_ctrl_flags_by`. Verify the behavior of `SILOFS_LOGF_VERBOSE`
  and ensure it correctly overrides flags for error-level messages.
- Review `errno` preservation. Ensure `saved_errno` is restored correctly
  so that logging doesn't interfere with the caller's error handling.
- Check the `basename_of` implementation for edge cases like trailing
  slashes or empty paths.

### 3.5 API Consistency and Conventions
- Evaluate the convenience macros (`silofs_log_info`, etc.). Ensure
  consistent parameter ordering and that they correctly pass `__FILE__`
  and `__LINE__`.
- Check for "magic numbers" or hardcoded defaults that should be
  defined as constants.
- Review the `silofs_log_meta_banner` logic for potential buffer
  overflows in `make_version_banner`.

## 4. Input Files
- `lib/base/logging.c`
- `include/silofs/logging.h`

## 5. Required Output
Provide findings grouped by category:
- **Critical Logic:** Thread-safety issues, buffer overflows, or
  incorrect level filtering.
- **Consistency:** Deviations from project naming conventions or
  non-uniform API patterns.
- **Maintenance:** Suggestions for improving performance (e.g.,
  avoiding `vsnprintf` when logging is disabled).
- **Fix:** Minimal code snippet or diff to resolve the issue.

---
*Note: The internal buffer size is 512 bytes. If log messages exceed this,
they are truncated. Evaluate if this is sufficient for a filesystem
daemon or if dynamic allocation/stack-based scaling is preferred.*

*Note: Ensure `program_invocation_short_name` usage is portable or
correctly guarded for the target build environments.*
