# Bash Completion Script Syntax Audit

## Overview

This document defines the audit procedure for the bash completion
script at `cmd/completions/silofs`. The script is sourced by the shell
to provide tab-completion for the `silofs` multi-command CLI. This
audit focuses on **bash correctness bugs** — ensuring the script is
syntactically and behaviourally correct as a bash completion,
independent of the specific `silofs` command logic.

## Objective

Verify that the completion script follows best practices for bash
completions, handles edge cases (like spaces in filenames), and
correctly uses the `bash-completion` utility functions.

## Review Checklist

### 1. Bash Completion Correctness

- **Guard clause**: Verify the `[ -z "$BASH_VERSION" ] && return` guard
  is present and placed before any bash-specific syntax.
- **`_init_completion`**: Confirm the script calls `_init_completion`
  (from `bash-completion`) before using `$cur`, `$prev`, `$words`, and
  `$cword`. These variables are undefined without it.
- **`compgen` quoting**: Check that all `compgen -W "..."` calls quote
  the word list and `-- "$cur"` correctly to handle special characters
  and empty `$cur`.
- **`mapfile` usage**: Verify `mapfile -t COMPREPLY < <(...)` is used
  instead of `COMPREPLY=($(compgen ...))` to avoid word-splitting on
  filenames with spaces.
- **`compopt -o nospace`**: Confirm it is applied only when the single
  completion ends with `=`, and that `compopt +o nospace` is called
  before `_filedir` to reset state left by a previous option match.
- **`_filedir` dependency**: `_filedir` is provided by
  `bash-completion` and is not a standard bash builtin. Verify the
  script does not call it unconditionally without checking
  availability, or that the `_init_completion` guard already implies
  it.
- **`complete` registration**: Confirm the final `complete` call uses
  `-F _silofs_completions silofs` and that the option flags
  (`-o filenames`, `-o bashdefault`, `-o default`) are appropriate.
  `-o filenames` triggers filename post-processing (trailing `/` on
  directories).

## Input Files

- `cmd/completions/silofs` (the completion script under review)

## Required Output

Provide findings for **Bash Correctness**: issues with the script's
behaviour as a bash completion, independent of `silofs` semantics.
Include the line number and a minimal fix.

**Note**: Use the standard bash-completion package as the reference
for behavior.
