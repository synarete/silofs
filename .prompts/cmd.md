# Command-Line Interface and Process Lifecycle Audit

## Overview

This document defines the audit procedure for the command-line
interface and process management in `silofs`. The `cmd` directory
implements the `silofs` multi-command frontend. It bridges
user-provided arguments to the internal filesystem library. Key
responsibilities include process daemonization for `mount`, signal
handling for graceful exits, and uniform error reporting across
different sub-commands like `mkfs`, `fork`, and `lsmnt`. `silofs`
runs as a strictly unprivileged process; it offloads privileged
`mount(2)` and `umount(2)` syscalls to the `silofs-mountd` daemon
via a UNIX domain socket.

## Objective

Identify bugs in process lifecycle management, credential handling,
and command-line parsing. Focus on ensuring that sub-commands behave
consistently, handle errors gracefully without leaking resources, and
follow Linux conventions for daemons and CLI tools.

## Review Checklist

### 1. Process Lifecycle and Daemonization

- Audit the daemonization logic (e.g., `fork`, `setsid`,
  `chdir("/")`). Ensure standard streams (stdin/out/err) are correctly
  redirected to `/dev/null` or log files to prevent hanging the parent
  shell.
- Verify PID file management. Check for race conditions where multiple
  instances might attempt to use the same mount point or PID file.
- Review `atexit` or `on_exit` handlers. Ensure they don't perform
  unsafe operations (like complex I/O) in a signal-driven exit context.

### 2. Signal Handling and Shutdown

- Audit signal masks and handlers. Ensure `SIGINT` and `SIGTERM`
  trigger a graceful unmount and cleanup of the FUSE session.
- Verify that the daemon handles `SIGHUP` or other signals
  appropriately without unexpected termination or state corruption.
- Check for "zombie" process prevention if the CLI forks children for
  auxiliary tasks.

### 3. CLI Argument Parsing and Validation

- Review `getopt_long` implementations. Ensure that unknown options
  are handled and that mandatory arguments (like repo paths) are
  validated before the process performs any side effects.
- Audit path sanitization. Ensure paths provided via CLI are resolved
  correctly (absolute vs relative) before being passed to `lib/fs`.
- Check for consistent use of units (e.g., `--size=100G`) and ensure
  the parsing logic is overflow-safe.
- Ensure mandatory positional arguments are validated for existence
  and proper format immediately after the parsing loop.

### 4. Pattern Consistency

- **Naming Conventions**: Verify that all sub-commands follow the
  `cmd_<subcmd>_...` naming pattern for internal helpers and provide a
  `cmd_execute_<subcmd>` entry point.
- **Help Layout**: Check that help strings follow a uniform structure:
  command usage line, a blank line, and an "options:" section with
  consistent indentation (e.g., matching the style in `cmd_tune.c`).
- **Context Management**: Ensure each sub-command utilizes a private
  context struct (`struct cmd_<subcmd>_ctx`) passed as a pointer to
  helpers, avoiding reliance on disparate global variables.
- **Lifecycle Logic**: Confirm every command uses the
  `cmd_<subcmd>_start` pattern to register its `atexit` cleanup
  handler via a static context pointer.

### 5. Error Reporting and Security

- Ensure that all sub-commands use the global logging facility
  consistently.
- Verify exit codes. Failures should return non-zero values that
  reflect the nature of the error (e.g., `ENOENT`, `EACCES`).
- Check that sensitive information (like passwords entered via `mkfs`
  or `mount`) is wiped from memory after use and not leaked in logs.

### 6. Integration with lib/ and FUSE

- Analyze the "glue" code that initializes the FUSE session. Verify
  correct handling of mount options passed to the kernel.
- Audit the interaction with `silofs-mountd`. Ensure that the
  unprivileged CLI process correctly identifies itself and passes the
  required credentials and paths to the daemon via the RPC interface.
- Ensure that the CLI correctly checks for existing mounts or locks
  before initiating operations that modify the repository.

## Input Files

- `cmd/`
- `lib/include/silofs/cmd.h` (if applicable)

## Required Output

Provide findings grouped by category:

- **Process Logic**: Errors in forking, daemonization, or signal
  safety.
- **CLI/UX Consistency**: Deviations in argument handling or exit
  codes.
- **Security**: Improper credential handling or path traversal risks.
- **Fix**: Minimal code snippet or diff sufficient to correct the
  issue.

**Note**: Focus on the transition from `main()` to the core loop. The
internal filesystem logic is covered by other audits; here, the focus
is the environment and process state.

**Note**: Verify that `umask` is set explicitly when creating new
repository files to ensure the configured security model is enforced.
