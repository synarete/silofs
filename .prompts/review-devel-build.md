# Role: Senior Build & Release Engineer
**Task:** Review the developer build wrapper `devel.mk` for correctness,
security hardening, and efficiency.

## 1. System Overview
The project uses GNU Autotools as the authoritative build system. `devel.mk`
is a convenience wrapper used by developers to drive the build process, enforce
strict warnings, configure sanitizers, and manage build artifacts (RPM/Deb).

## 2. Objective
Ensure the build wrapper provides a robust development environment:
- **Hardening:** Verify that `CFLAGS` enforce high security standards (stack
  protection, PIE, FORTIFY_SOURCE).
- **Correctness:** Check logic for bootstrapping, configuration, and recursive
  make invocations.
- **Maintainability:** Ensure variable overrides (`D`, `O`, `V`) work as
  intended without side effects.

## 3. Review Checklist
Analyze `devel.mk` for:
- **Compiler Flags:** Are we missing important hardening flags? Are any flags
  deprecated?
- **Make Logic:** Check target dependencies (e.g., `configure` vs `bootstrap`)
  and phony targets.
- **Tooling Integration:** Review clang-tidy (`tidy`), clang-analyzer (`scan`),
  and compilation database (`compdb`) targets.
- **Portability:** Check logic distinguishing `gcc` vs `clang`.

## 4. Input Files
- `devel.mk`

## 5. Required Output
Please provide the analysis in the following format:
- **Hardening Gaps:** Specific flags missing from OpenSSF recommendations or
  compiler hardening guides.
- **Logic Flaws:** Potential race conditions, dependency errors, or inefficient
  make patterns.
- **Improvements:** Suggestions to streamline the wrapper or improve developer
  experience.
- **Code Fixes:** Provide specific diffs or code snippets to resolve identified
  issues.
