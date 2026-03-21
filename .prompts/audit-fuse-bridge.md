# Role: Senior Systems Engineer (FUSE Specialist)
**Task:** Audit the custom FUSE kernel bridge implementation in `silofs`.

## 1. System Overview
Silofs bypasses the standard `libfuse` user-space library. Instead, it
implements a direct FUSE bridge to interact with the Linux kernel via
`/dev/fuse`. This optimizes performance and allows tight integration with
the internal threading model. The ABI definitions are found in `fuse_abi.h`.

## 2. Objective
Identify bugs, logical errors, or inconsistencies with the Linux Kernel
FUSE ABI. Focus on the raw protocol parsing, request deserialization, and
response serialization.

## 3. Review Checklist
Analyze the code under `lib/silofs/fuse/` for:
- **ABI Compliance:** Correct use of structs from `fuse_abi.h`, especially
  regarding padding and alignment on 64-bit systems.
- **Protocol Logic:** Correct handling of `FUSE_INIT`, version negotiation,
  and opcode dispatching.
- **Concurrency:** Race conditions when assigning unique request IDs or
  handling FUSE interrupts (`FUSE_INTERRUPT`).
- **Buffer Safety:** Correct handling of `read`/`write` buffers,
  `iovec` logic, and potential overflows in variable-length messages.
- **Error Handling:** Ensuring correct `errno` codes are returned to the
  kernel in `fuse_out_header`.

## 4. Input Files
- `lib/silofs/fuse/fuse_abi.h` (Kernel Interface)
- `lib/silofs/fuse/*.c` (Implementation)
- `lib/silofs/fuse/*.h` (Internal headers)

## 5. Required Output
Please provide the analysis in the following format:
- **ABI Violations:** Mismatches between kernel expectations and user-space
  structs.
- **Logic Errors:** Improper state management (e.g., session lifecycle).
- **Concurrency Bugs:** Potential races in request/reply loop.
- **Code Fixes:** Specific diffs or snippets to fix identified issues.