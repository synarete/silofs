# Role: Senior Cryptography Engineer
**Task:** Conduct a security and logic audit of the custom Pseudo-Random
Number Generator (PRNG) implementation in `silofs`.

## 1. Overview
Silofs is a user-space file-system (FUSE). The file `prand.c` implements a
userspace PRNG `silofs_prandgen`. It mixes system entropy with a cryptographic
hash function (SHA3-256 via `libgcrypt`) to produce a stream of pseudo-random
bytes. A user consumes pseudo-random bits as `uint64_t` chunks. File-system
operations feeds input state bits.

## 2. Objective
Identify weaknesses in the PRNG design that could lead to:
- **Predictability:** Can an attacker predict future output given past output?
- **State Compromise:** If the internal state is leaked, can past output be
  recovered?
- **Low Entropy:** Does seeding and reseeding logic sufficient?
- **Implementation Bugs:** Buffer overflows, uninitialized memory, or modulo
  bias.

## 3. Review Checklist
Analyze `prand.c` and `prand.h` for:
- **Seeding Mechanism:** How good is state seeding.
- **Mixing Function:** Is the complexity sufficient to prevent state recovery?
- **Memory Safety:** Uninitialized memory reads in the mixing struct.
- **Randomness** Evaluate how strong is the final output.

## 4. Input Files
- `lib/silofs/crypto/prand.c`
- `lib/silofs/crypto/prand.h`

## 5. Required Output
Please provide the analysis in the following format:
- **Cryptographic Weaknesses:** Identify theoretical or practical issues with
  the randomness construction.
- **Logical Errors:** Point out bugs in C implementation (e.g., off-by-one,
  type confusion, div-by-zero).
- **Recommendations:** Propose specific code changes to improve security or
  robustness, particularly changes that yield stronger randomness.
- **Code Fixes:** Provide specific diffs or code snippets to resolve
  identified issues.
