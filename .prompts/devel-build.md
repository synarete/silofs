# Developer Build Wrapper Audit

## Overview

This document defines the audit procedure for the developer build
wrapper `devel.mk`. The project uses GNU Autotools as the authoritative
build system. `devel.mk` is a convenience wrapper used by developers
to drive the build process, enforce strict warnings, configure
sanitizers, and manage build artifacts (RPM/Deb).

## Objective

Ensure the build wrapper provides a robust development environment:

- **Hardening**: Verify that `CFLAGS` enforce high security standards
  (stack protection, PIE, FORTIFY_SOURCE).
- **Correctness**: Check logic for bootstrapping, configuration, and
  recursive make invocations.
- **Maintainability**: Ensure variable overrides (`D`, `O`, `V`) work
  as intended without side effects.

## Review Checklist

### 1. Compiler Flags

- Are important hardening flags missing?
- Are any flags deprecated or superseded?

### 2. Make Logic

- Check target dependencies (e.g., `configure` vs `bootstrap`) and
  phony targets.

### 3. Tooling Integration

- Review clang-tidy (`tidy`), clang-analyzer (`scan`), and compilation
  database (`compdb`) targets.

### 4. Portability

- Check logic distinguishing `gcc` vs `clang`.

## Input Files

- `devel.mk`

## Required Output

Provide findings grouped by category:

- **Hardening Gaps**: Specific flags missing from OpenSSF
  recommendations or compiler hardening guides.
- **Logic Flaws**: Potential race conditions, dependency errors, or
  inefficient make patterns.
- **Improvements**: Suggestions to streamline the wrapper or improve
  developer experience.
- **Code Fixes**: Provide specific diffs or code snippets to resolve
  identified issues.
