# Mount Daemon and RPC Interface Audit

## Overview

This document defines the audit procedure for the `silofs-mountd`
daemon and its RPC interface. Silofs operates as an unprivileged user
process but requires `mount(2)` capability. To bridge this, an
auxiliary systemd service (`silofs-mountd`) runs with
`CAP_SYS_ADMIN`. The client (`silofs mount`) communicates with the
daemon via a UNIX domain socket. The daemon verifies the request
against an allowlist (`/etc/silofs/mountd.conf`) and performs the
mount.

## Objective

Identify security vulnerabilities and logical bugs in the privilege
separation mechanism. Focus on:

- **Privilege Escalation**: Can a user trick the daemon into mounting
  on an arbitrary directory?
- **Protocol Safety**: Robustness of the binary RPC protocol against
  malformed inputs.
- **Resource Management**: FD leaks, socket state handling, and zombie
  processes.
- **Systemd Integration**: Verification of service hardening, resource
  limits, and security descriptors in the unit file.

## Review Checklist

### 1. Credential Verification

- Verify usage of `SO_PEERCRED` to identify the connecting process.
- Ensure the daemon enforces that the requestor owns the mount point
  or meets configured policy requirements.

### 2. Path Validation and Sanitization

- Analyze how paths received over the socket are validated.
- Check for TOCTOU (Time-of-Check Time-of-Use) races where the mount
  point might change between check and mount.
- Ensure path traversal protection (e.g., `..`) is robust.

### 3. RPC Protocol Logic

- Review `lib/mnt` serialization/deserialization.
- Check for buffer overflows or integer overflows in message parsing.
- Verify handling of partial writes/reads on the non-blocking socket.

### 4. Mount Operation

- Audit the arguments passed to `mount(2)`.
- Verify the handling of the file descriptor transfer (passing the
  `/dev/fuse` fd back to the client).

### 5. Daemon Robustness

- Check signal handling and event loop logic in `mntd`.
- Verify error paths ensure proper cleanup of pending connections.

### 6. Systemd Service Hardening

- Review `silofs-mountd.service.in` for the Principle of Least
  Privilege.
- **Capabilities**: Evaluate `CapabilityBoundingSet`. Is
  `CAP_SYS_ADMIN` strictly necessary for the entire lifecycle, or can
  it be dropped?
- **Sandboxing**: Check why directives like `ProtectSystem`,
  `ProtectKernelTunables`, and `PrivateTmp` are commented out. Assess
  the risk of leaving these disabled.
- **Resource Limits**: Verify if `LimitNPROC=1` and `TasksMax=1` are
  too restrictive. If the daemon forks or uses a thread pool, these
  settings will prevent it from functioning.
- **Device Access**: Ensure `DeviceAllow` correctly limits access to
  only `/dev/fuse`, `/dev/null`, and `/dev/urandom`.
- **Filesystem Access**: Verify `UMask=0777`. This is extremely
  restrictive; ensure it doesn't interfere with socket creation or
  logging.

## Input Files

- `mntd/`
- `include/silofs/mntsvc.h`
- `lib/mnt/`
- `lib/include/silofs/mnt/`
- `mntd/systemd/silofs-mountd.service.in`

## Required Output

Provide findings grouped by category:

- **Security**: Privilege escalation, path traversal, permission
  bypass.
- **Stability**: Crashes, hangs, resource leaks.
- **Logic**: Protocol errors, incorrect state transitions.
- **Fix**: Minimal code snippet or diff to resolve the issue.
