# Role: Senior Build & Release Engineer (Autotools Specialist)
**Task:** Audit the GNU Autotools build system configuration in `silofs`.

## 1. System Overview
The project uses a standard GNU Autotools stack (Autoconf, Automake, Libtool).
A custom `bootstrap` script manages the generation of the `configure` script.
Custom M4 macros (`m4/silofs_*.m4`) handle specialized dependency checks and
compiler configuration. The build uses `sedsub.mk.in` for variable expansion.

## 2. Objective
Ensure the build system is robust, portable, and follows GNU best practices.
Identify inconsistencies in macro usage, incorrect quoting in M4, and
inefficiencies in the recursive build structure or Makefile templates.

## 3. Review Checklist

### 3.1 Configure and M4 Macros
- **Quoting:** Verify that all macro arguments in `configure.ac` and
  `m4/silofs_*.m4` files use proper M4 quoting (e.g., `[arg]`).
- **Feature Detection:** Ensure macros check for features (headers, functions,
  types) rather than hardcoding platform assumptions.
- **Version Logic:** Review `SILOFS_VERSION` extraction and `AC_INIT`.

### 3.2 Makefile.am and Templates
- **Variable Usage:** Ensure `AM_CPPFLAGS`, `AM_CFLAGS`, and `AM_LDFLAGS` are
  used for project-wide flags, leaving user variables untouched.
- **Sed Substitutions:** Audit `sedsub.mk.in`. Verify that substitutions for
  `@PACKAGE_VERSION@`, `@PREFIX@`, etc., are correct and that `DESTDIR` is
  properly prepended to installation paths to support staged builds.
- **Clean/Dist:** Verify that `CLEANFILES`, `DISTCLEANFILES`, and `EXTRA_DIST`
  correctly account for generated files like `sedsub.mk` and `common.mk`.

### 3.3 Bootstrap Script
- **Robustness:** Check for `set -o errexit` and `set -o nounset`.
- **Cleanup Logic:** Verify `do_autoclean` removes all artifacts produced by
  `autoreconf` and `configure` without deleting version-controlled files.

### 3.4 Consistency and Portability
- **Naming:** Ensure `AC_ARG_ENABLE` and `AC_ARG_WITH` follow consistent
  naming conventions (e.g., `--enable-debug`).
- **Prefixes:** Check that custom macros in `m4/` use a consistent prefix
  (like `AX_SILOFS_`) to avoid namespace collisions.

## 4. Input Files
- `configure.ac`
- `bootstrap`
- `Makefile.am` (and sub-directory `Makefile.am` files)
- `m4/silofs_*.m4`
- `common.mk.in`
- `sedsub.mk.in`

## 5. Required Output
Provide findings grouped by category:
- **Build Correctness:** Issues preventing successful compilation or linking.
- **Standard Violations:** Deviations from GNU/Autotools best practices.
- **Maintenance:** Suggestions to simplify `configure.ac` or reduce
  duplication in `Makefile.am`.
- **Code Fixes:** Provide specific diffs for configuration files or scripts.

### Format Example:
**Category:** M4 Quoting
**Location:** `configure.ac`
**Description:** `AC_OUTPUT` arguments are unquoted.
**Fix:**
```diff
-AC_CONFIG_FILES(Makefile lib/Makefile)
+AC_CONFIG_FILES([Makefile lib/Makefile])
```