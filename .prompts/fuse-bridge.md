# Custom FUSE Kernel Bridge Audit

## Overview

This document defines the audit procedure for the custom FUSE kernel
bridge implementation in `silofs`. Silofs bypasses the standard
`libfuse` user-space library and instead implements a direct FUSE
bridge to interact with the Linux kernel via `/dev/fuse`. The ABI
definitions are found in `fuse_abi.h`.

The implementation uses two I/O modes:

- **Buffer-copy mode**: `read(2)` from `/dev/fuse` into a per-thread
  buffer.
- **Splice mode**: `splice(2)` from `/dev/fuse` into a per-thread
  pipe, then `splice(2)` or `vmsplice(2)` out to the destination fd
  or iovec.

Each worker thread owns a `silofs_fuseq_sub` with its own input buffer
(`fqs_inb`), output buffer (`fqs_outb`), and optional pipe
(`fqs_pipe`). Global session state lives in `silofs_fuseq` and is
shared across threads.

## Objective

Identify bugs, logical errors, or inconsistencies with the Linux
Kernel FUSE ABI. Focus on raw protocol parsing, request
deserialization, response serialization, the splice I/O path, and
shared session state.

## Review Checklist

### 1. FUSE_INIT and Capability Negotiation

- Verify that **both** `fuse_init_in.flags` and
  `fuse_init_in.flags2` are read. Capabilities above bit 31 (e.g.,
  `FUSE_SECURITY_CTX` = bit 32, `FUSE_PASSTHROUGH` = bit 37) live in
  `flags2` and are silently lost if only `flags` is consumed.
- Verify that **both** `fuse_init_out.flags` and
  `fuse_init_out.flags2` are populated in the reply. Sending only
  `flags` when the negotiated minor is ≥ 36 (`FUSE_INIT_EXT`) is an
  ABI violation.
- Verify that the internal capability bitmasks (`kern_cap`,
  `want_cap`) are 64-bit wide. A 32-bit field silently truncates any
  capability flag ≥ bit 32.
- Verify that version negotiation follows the spec: if the kernel
  sends a lower minor version, userspace must clamp to it and
  continue, not hard-reject. Check that the "version mismatch" warning
  path does not fire for a valid downward negotiation (kernel minor <
  userspace minor).
- Verify that handlers which dispatch on `kern_proto_minor` at runtime
  (e.g., `do_setxattr` switching between `fuse_setxattr1_in` and
  `fuse_setxattr_in` at minor 33/34) remain correct if the negotiated
  minor is lower than the compiled-in `FUSE_KERNEL_MINOR_VERSION`.

### 2. No-Reply Opcodes and Dispatch Table

- `FUSE_FORGET` and `FUSE_BATCH_FORGET` must never send a reply.
  Verify their handlers return without calling any reply function.
- `FUSE_INTERRUPT` must never send a reply. Verify the dispatch table
  registers a real handler (not `nullptr`) that returns without
  calling any reply function. A `nullptr` entry causes the dispatcher
  to return `-ENOSYS` and send an error reply — an ABI violation that
  will confuse the kernel's interrupt tracking.
- Verify that the `FUSE_INTERRUPT` handler sets a per-request
  interrupt flag on the matching in-flight operation, and that every
  reply path checks this flag before sending its normal reply.
- Verify that the lock acquired inside `fqs_interrupt_op` is not the
  same lock held by the operation being interrupted (deadlock risk for
  any future implementation of the interrupt body).

### 3. Extension Headers (Protocol 7.38+)

- `fuse_in_header.total_extlen` signals trailing extension data
  appended after the fixed argument struct: security contexts
  (`fuse_secctx_header` + `fuse_secctx`) and supplementary groups
  (`fuse_supp_groups`). Verify this field is read and the extension
  region is either parsed or explicitly skipped before the payload is
  accessed, so extension bytes are not misinterpreted as filename or
  data payload.

### 4. Splice I/O Path

- Verify `SPLICE_F_NONBLOCK` is set when splicing from `/dev/fuse`
  into the pipe. Without it, requesting more bytes than the kernel has
  queued causes `splice(2)` to block indefinitely, hanging the worker
  thread.
- Verify the pipe is fully drained (pending bytes == 0) before each
  new request splice. A non-zero `pend` at entry means a previous
  message's residue is still in the pipe and will be prepended to the
  new message.
- Verify that after the initial splice, the number of bytes copied
  from the pipe into the in-buffer is driven by
  `fuse_in_header.len`, not by a hardcoded struct size. Using
  `sizeof(fuse_write_in)` as the copy length is correct only for
  `FUSE_WRITE`; for any other opcode with a larger fixed header it
  will under-copy, leaving residue in the pipe.

### 5. Buffer-Copy Write Path

- Verify that the data payload pointer for `FUSE_WRITE` in
  buffer-copy mode is computed as:
  ```c
  (uint8_t*)in + sizeof(fuse_in_header) + sizeof(fuse_write_in)
  ```
  not as an offset from the outer wrapper struct. The two are
  equivalent only if the wrapper struct has no padding between the
  header and the arg. Confirm this with a `STATICASSERT` or
  `offsetof` check.

### 6. Error Serialization

- `fuse_out_header.error` must be a negative errno in
  `[-EMAXERRNO, -1]`. Verify that every internal error code is
  remapped before being written to the header, and that the remap
  function provably never returns 0 (which the kernel interprets as
  success with no payload).
- Verify that error replies always send exactly
  `sizeof(fuse_out_header)` bytes with no payload. In particular,
  check that `FUSE_IOCTL` error replies do not accidentally include an
  output buffer — the ioctl reply helper takes both a result and a
  buffer pointer; verify the error path passes `NULL`/0 for the
  buffer.

### 7. Shared State and Memory Ordering

- `fq_active`, `fq_got_init`, and `fq_reply_init_ok` are plain
  `bool`/`int` fields written by one thread and read by others without
  locks. Verify these are accessed with C11 `_Atomic` or
  `__atomic_*` builtins with at least
  `memory_order_acquire`/`release` semantics, especially on
  architectures with weak memory ordering (ARM, RISC-V).
- `fq_curr_opers.sz` is read outside `fq_op_lock` in the hot path
  (`fuseq_has_live_opers`). Verify this is either made atomic or that
  the racy read is explicitly documented as a safe hint.

### 8. Resource Management

- Verify that `fqs_renew_bufs` does not leak the old output buffer
  when the new input buffer allocation succeeds but the new output
  buffer allocation fails. The old `fqs_outb` must be freed before
  returning the error.

## Input Files

- `lib/silofs/fuseq.h` (internal header)
- `lib/silofs/fuse/fqtypes.c` (internal types checker)
- `lib/silofs/fuse/fqtypes.h` (internal types header)
- `lib/silofs/fuse/fuseq.c` (implementation)
- `lib/silofs/fuse/fuse_abi.h` (kernel interface)

## Required Output

Provide findings grouped by category, each entry containing:

- **Severity**: Critical / High / Medium / Low
- **Location**: Function name and file
- **Description**: What is wrong and why it violates the ABI or is
  unsafe
- **Fix**: Minimal code snippet or diff sufficient to correct the
  issue

Categories:

- **ABI Violations**
- **Logic Errors**
- **Concurrency Bugs**
- **Buffer / Splice Safety**
- **Resource Management**
