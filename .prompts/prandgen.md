# Pseudo-Random Number Generator Security Audit

## Overview

This document defines the audit procedure for the custom
Pseudo-Random Number Generator (PRNG) implementation in `silofs`.
The file `prand.c` implements a userspace PRNG `silofs_prandgen`. It
mixes system entropy with a cryptographic hash function (SHA3-256 via
`libgcrypt`) to produce a stream of pseudo-random bytes. A user
consumes pseudo-random bits as `uint64_t` chunks. File-system
operations feed input state bits.

## Objective

Identify weaknesses in the PRNG design that could lead to:

- **Predictability**: Can an attacker predict future output given past
  output?
- **State Compromise**: If the internal state is leaked, can past
  output be recovered?
- **Low Entropy**: Is the seeding and reseeding logic sufficient?
- **Implementation Bugs**: Buffer overflows, uninitialized memory, or
  modulo bias.

## Review Checklist

### 1. Seeding Mechanism

- Evaluate how well the initial state is seeded from system entropy.
- Check whether reseeding is triggered at appropriate intervals or
  events.

### 2. Mixing Function

- Assess whether the complexity of the mixing function is sufficient
  to prevent state recovery.

### 3. Memory Safety

- Check for uninitialized memory reads in the mixing struct.

### 4. Randomness Quality

- Evaluate how strong the final output is relative to the input
  entropy and mixing steps.

## Input Files

- `lib/silofs/crypt/prand.c`
- `include/silofs/` (no dedicated header; crypto interfaces via `crypt.h`)

## Required Output

Provide findings grouped by category:

- **Cryptographic Weaknesses**: Identify theoretical or practical
  issues with the randomness construction.
- **Logical Errors**: Point out bugs in the C implementation (e.g.,
  off-by-one, type confusion, div-by-zero).
- **Recommendations**: Propose specific code changes to improve
  security or robustness, particularly changes that yield stronger
  randomness.
- **Code Fixes**: Provide specific diffs or code snippets to resolve
  identified issues.
