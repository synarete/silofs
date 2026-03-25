# Role: Senior Linux Systems Programmer (Daemon & IPC Specialist)
**Task:** Audit the `silofs-mountd` daemon and its RPC interface.

## 1. System Overview
Silofs operates as an unprivileged user process but requires `mount(2)`
capability. To bridge this, an auxiliary systemd service (`silofs-mountd`)
runs with `CAP_SYS_ADMIN`. The client (`silofs mount`) communicates with
the daemon via a UNIX domain socket. The daemon verifies the request against
an allowlist (`/etc/silofs/mountd.conf`) and performs the mount.

## 2. Objective
Identify security vulnerabilities and logical bugs in the privilege separation
mechanism. Focus on:
- **Privilege Escalation:** Can a user trick the daemon into mounting on an
  arbitrary directory?
- **Protocol Safety:** Robustness of the binary RPC protocol against malformed
  inputs.
- **Resource Management:** FD leaks, socket state handling, and zombie
  processes.

## 3. Review Checklist

### 3.1 Credential Verification
- Verify usage of `SO_PEERCRED` to identify the connecting process.
- Ensure the daemon enforces that the requestor owns the mount point or meets
  configured policy requirements.

### 3.2 Path Validation and Sanitization
- Analyze how paths received over the socket are validated.
- Check for TOCTOU (Time-of-Check Time-of-Use) races where the mount point
  might change between check and mount.
- Ensure path traversal protection (e.g., `..`) is robust.

### 3.3 RPC Protocol Logic
- Review `lib/mnt` serialization/deserialization.
- Check for buffer overflows or integer overflows in message parsing.
- Verify handling of partial writes/reads on the non-blocking socket.

### 3.4 Mount Operation
- Audit the arguments passed to `mount(2)`.
- Verify the handling of the file descriptor transfer (passing the `/dev/fuse`
  fd back to the client).

### 3.5 Daemon Robustness
- Check signal handling and event loop logic in `mntd`.
- Verify error paths ensure proper cleanup of pending connections.

## 4. Input Files
- `mntd/`
- `incluse/silofs/mntsvc.h`
- `lib/mnt/`
- `lib/include/silofs/mnt/`

## 5. Required Output
Provide findings grouped by category:
- **Security:** Privilege escalation, path traversal, permission bypass.
- **Stability:** Crashes, hangs, resource leaks.
- **Logic:** Protocol errors, incorrect state transitions.
- **Fix:** Minimal code snippet or diff to resolve the issue.
