# Role: Senior Linux Systems Programmer (Signal Safety Specialist)
**Task:** Audit signal handling in the `silofs` command-line frontend.

## 1. System Overview
The `cmd/cmd_signals.c` module registers signal handlers for the `silofs`
daemon and CLI tools. The daemon (`silofs mount`) runs as a long-lived
FUSE process that must respond to `SIGINT`, `SIGTERM`, and other signals
by gracefully unmounting the filesystem and releasing locks. Signal
handlers execute in an asynchronous context and must obey strict POSIX
async-signal-safety rules to avoid deadlock, heap corruption, or
undefined behaviour.

## 2. Objective
Identify violations of async-signal-safety in all signal handlers.
Ensure that handlers use only async-signal-safe operations (per POSIX
`signal-safety(7)`), avoid re-entrancy hazards, and correctly propagate
halt requests to the main loop without calling `exit()`, `raise()`, or
non-reentrant logging functions.

## 3. Review Checklist

### 3.1 Async-Signal-Safety Violations
- **Forbidden Functions:** Verify that no handler calls `exit()`,
  `malloc()`, `free()`, `printf()`, `fprintf()`, `fflush()`, `syslog()`,
  or any logging wrapper that uses stdio or heap allocation. These are
  **not** async-signal-safe and cause undefined behaviour if the signal
  interrupts the same function.
- **Allowed Operations:** Handlers may only write to `volatile
  sig_atomic_t` variables, call `_exit()` or `_Exit()`, use `write()`
  to a pre-opened fd, or call other explicitly async-signal-safe
  functions listed in POSIX `signal-safety(7)`.
- **Re-entrancy:** Check for `raise()` or `kill(getpid(), ...)` calls
  that re-trigger another signal handler. If the second handler is not
  async-signal-safe, this creates a nested violation.

### 3.2 Exit Handlers and Cleanup
- **`exit()` vs `_exit()`:** Fatal signal handlers (e.g., `SIGSEGV`,
  `SIGBUS`, `SIGABRT`) must call `_exit()` or `_Exit()`, **not**
  `exit()`. The latter runs `atexit` handlers, which may perform
  complex I/O (flock release, file unlink, env destroy) and are not
  async-signal-safe.
- **`atexit` Handlers:** Verify that `atexit` handlers registered by
  sub-commands (e.g., `cmd_mount_atexit`) do not assume they are called
  from a normal exit path. If a fatal signal arrives, the handler may
  run in a corrupted state. Consider using `on_exit()` with a status
  flag to distinguish normal vs signal-driven exits, or avoid complex
  cleanup in `atexit` entirely.

### 3.3 Signal Disposition and Masking
- **`SIGPIPE`:** Verify that `SIGPIPE` is set to `SIG_IGN` (not a
  terminating handler). Broken pipes (e.g., `silofs lsmnt | head -1`)
  should return `EPIPE` from `write()`, not terminate the process.
- **`SIGHUP`:** If `SIGHUP` is used for "reload config" or "re-wake",
  ensure its handler is async-signal-safe. If it only logs, consider
  `SIG_IGN` or a flag-based approach.
- **Signal Masks:** Check that the daemon does not block signals
  indefinitely. If `sigprocmask()` or `pthread_sigmask()` is used,
  ensure critical signals (`SIGTERM`, `SIGINT`) remain unblocked.

### 3.4 Graceful Shutdown Mechanism
- **Flag-Based Halt:** The recommended pattern is:
  ```c
  static volatile sig_atomic_t g_halt_signal = 0;
  static void sigaction_halt_handler(int signum) {
      g_halt_signal = signum;
      if (callback_hook != nullptr)
          callback_hook(signum);  /* must also be async-signal-safe */
  }
  ```
  The main loop polls `g_halt_signal` and calls `silofs_halt_fs()` from
  a safe context. Verify this pattern is followed.
- **Callback Hooks:** If `silofs_signal_callback_hook` is set (e.g., by
  `cmd_mount`), verify that the callback itself is async-signal-safe.
  For example, `silofs_halt_fs()` must only set internal flags, not
  call `pthread_cancel()` or other complex operations.

### 3.5 Logging from Signal Handlers
- **Forbidden:** `silofs_log_info()`, `silofs_log_debug()`,
  `silofs_log_crit()` are **not** async-signal-safe. They likely use
  `vsnprintf()`, `fprintf()`, or `syslog()`, all of which are forbidden.
- **Allowed Alternative:** Use `write(STDERR_FILENO, msg, len)` with a
  static message buffer if logging is absolutely necessary. Better: log
  nothing from the handler and let the main loop log after detecting
  the flag.

### 3.6 Backtrace and Debugging
- **`silofs_backtrace()`:** Verify that this function (if called from
  signal handlers) uses only async-signal-safe primitives. Most
  backtrace implementations (`backtrace()`, `backtrace_symbols()`) use
  `malloc()` and are **not** safe. If used, it must be via
  `backtrace_symbols_fd()` or a custom safe implementation.

## 4. Input Files
- `cmd/cmd_signals.c`
- `cmd/cmd_mount.c` (for `cmd_mount_halt_by_signal` callback)
- `cmd/cmd.h` (for `cmd_global_params` and signal flag definitions)

## 5. Required Output
Provide findings grouped by severity:
- **Critical:** Calls to `exit()`, `malloc()`, `free()`, `printf()`,
  `syslog()`, or other non-async-signal-safe functions from handlers.
- **High:** Use of `raise()` or `kill()` that re-enters a non-safe
  handler.
- **Medium:** Missing flag-based halt mechanism; reliance on `atexit`
  cleanup in signal context.
- **Fix:** Minimal code diff showing the safe replacement (e.g., replace
  `exit()` with `_exit()`, remove logging calls, add `volatile
  sig_atomic_t` flag).

## 6. Reference
- POSIX `signal-safety(7)`: List of async-signal-safe functions.
- Key safe functions: `_exit()`, `_Exit()`, `write()`, `sigaction()`,
  `sigprocmask()`, `kill()`, `getpid()`, `pause()`, `sigsuspend()`.
- Key **unsafe** functions: `exit()`, `malloc()`, `free()`, `printf()`,
  `fprintf()`, `fflush()`, `syslog()`, `openlog()`, `pthread_*` (except
  `pthread_sigmask`), `backtrace_symbols()`.

---
*Note: The existing TODO-0057 suggests migrating to `signalfd(2)`, which*
*would eliminate most async-signal-safety concerns by handling signals in*
*the main event loop. Until that migration is complete, all handlers must*
*strictly obey async-signal-safety rules.*
