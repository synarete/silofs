# Role: Senior Linux Systems Programmer (Shell & CLI Consistency Specialist)
**Task:** Audit the bash completion script for the `silofs` command.

## 1. System Overview
`cmd/completions/silofs` is a bash completion script sourced by the
shell to provide tab-completion for the `silofs` multi-command CLI.
It must accurately reflect the sub-commands and options implemented in
the C sources under `cmd/`. The canonical sub-command list is defined
in `cmd/cmd_main.c` (`g_cmd_info[]`). Each sub-command's accepted
options are defined in its `cmd_optdesc ods[]` table inside the
corresponding `cmd/cmd_<subcmd>.c` file.

Two classes of bugs are possible:
1. **Bash correctness bugs** — the script is syntactically or
   behaviourally wrong as a bash completion (wrong `compopt` usage,
   missing `_init_completion`, unsafe variable expansion, etc.).
2. **Consistency bugs** — the script offers completions that do not
   match the actual C implementation (missing options, stale options
   that were removed, wrong argument types, missing sub-commands).

## 2. Objective
Verify that the completion script is both a correct bash completion
and a faithful mirror of the C implementation. Every discrepancy
between the script and the `cmd_optdesc` tables is a bug that causes
either missing completions (user frustration) or ghost completions
(user confusion).

## 3. Review Checklist

### 3.1 Bash Completion Correctness
- **Guard clause:** Verify the `[ -z "$BASH_VERSION" ] && return` guard
  is present and placed before any bash-specific syntax.
- **`_init_completion`:** Confirm the script calls `_init_completion`
  (from `bash-completion`) before using `$cur`, `$prev`, `$words`, and
  `$cword`. These variables are undefined without it.
- **`compgen` quoting:** Check that all `compgen -W "..."` calls quote
  the word list and `-- "$cur"` correctly to handle special characters
  and empty `$cur`.
- **`mapfile` usage:** Verify `mapfile -t COMPREPLY < <(...)` is used
  instead of `COMPREPLY=($(compgen ...))` to avoid word-splitting on
  filenames with spaces.
- **`compopt -o nospace`:** Confirm it is applied only when the single
  completion ends with `=`, and that `compopt +o nospace` is called
  before `_filedir` to reset state left by a previous option match.
- **`_filedir` dependency:** `_filedir` is provided by `bash-completion`
  and is not a standard bash builtin. Verify the script does not call
  it unconditionally without checking availability, or that the
  `_init_completion` guard already implies it.
- **`complete` registration:** Confirm the final `complete` call uses
  `-F _silofs_completions silofs` and that the option flags
  (`-o filenames`, `-o bashdefault`, `-o default`) are appropriate.
  `-o filenames` triggers filename post-processing (trailing `/` on
  dirs); verify this is intentional for all sub-commands.

### 3.2 Sub-Command List Consistency
Cross-check the sub-commands listed in `_silofs_main` and dispatched
in `_silofs_subcmd` against the canonical list in `cmd/cmd_main.c`
(`g_cmd_info[]`):

| Sub-command  | In `g_cmd_info` | In `_silofs_main` | Handler in script |
|--------------|:--------------:|:-----------------:|:-----------------:|
| `init`       | yes            | ?                 | ?                 |
| `mkfs`       | yes            | ?                 | ?                 |
| `mount`      | yes            | ?                 | ?                 |
| `umount`     | yes            | ?                 | ?                 |
| `lsmnt`      | yes            | ?                 | ?                 |
| `show`       | yes            | ?                 | ?                 |
| `clone`      | yes            | ?                 | ?                 |
| `sync`       | yes            | ?                 | ?                 |
| `tune`       | yes            | ?                 | ?                 |
| `rmfs`       | yes            | ?                 | ?                 |
| `prune`      | yes            | ?                 | ?                 |
| `fsck`       | yes            | ?                 | ?                 |
| `view`       | yes            | ?                 | ?                 |
| `preserve`   | yes            | ?                 | ?                 |

Check for:
- Sub-commands present in `g_cmd_info` but absent from `_silofs_main`.
- Sub-commands present in `_silofs_main` but absent from `g_cmd_info`
  (stale/renamed commands).
- Sub-commands dispatched in `_silofs_subcmd` that have no handler
  function defined (would silently call an undefined function).
- Handler functions defined in the script but not dispatched in
  `_silofs_subcmd`.

### 3.3 Per-Sub-Command Option Consistency
For each sub-command, compare the options listed in the completion
handler against the `cmd_optdesc ods[]` table in the corresponding
C source. Both the long form (`--foo`) and short form (`-f`) must
match. Options that take an argument must use `--foo=` (with trailing
`=`) in the completion; options that are flags must not.

Key sources per sub-command:
- `init`:     `cmd/cmd_init.c`
- `mkfs`:     `cmd/cmd_mkfs.c`
- `mount`:    `cmd/cmd_mount.c`
- `umount`:   `cmd/cmd_umount.c`
- `lsmnt`:    `cmd/cmd_lsmnt.c`
- `show`:     `cmd/cmd_show.c`
- `clone`:    `cmd/cmd_clone.c`
- `sync`:     `cmd/cmd_sync.c`
- `tune`:     `cmd/cmd_tune.c`
- `rmfs`:     `cmd/cmd_rmfs.c`
- `prune`:    `cmd/cmd_prune.c`
- `fsck`:     `cmd/cmd_fsck.c`
- `view`:     `cmd/cmd_view.c`
- `preserve`: `cmd/cmd_preserve.c`

For each sub-command report:
- **Missing options:** present in `ods[]` but absent from the script.
- **Ghost options:** present in the script but absent from `ods[]`.
- **Wrong argument type:** option takes an argument in C (`has_arg=1`)
  but is listed without `=` in the script, or vice versa.

### 3.4 Argument Type Completions
Beyond options, verify that the positional argument completion
(the `else` branch in each handler) uses the correct completion type:

- Sub-commands that take a `<repodir/fsname>` path (a regular file
  inside a repo directory) should use `_silofs_complete_file`, not
  `_silofs_complete_dir`.
- Sub-commands that take a `<mountpoint>` or `<repodir>` (a directory)
  should use `_silofs_complete_dir`.
- Sub-commands that take either (e.g., `show <pathname>`) may use the
  generic `_silofs_complete_filedir`.
- Check `lsmnt` specifically: it takes no positional argument, so the
  `else` branch should not offer file/dir completions at all.

### 3.5 `show` Sub-Command Completions
`show` takes a mandatory sub-command word before the pathname. Verify
that the sub-command list in `_silofs_show` matches the values in
`cmd_show_subcommands[]` in `cmd/cmd_show.c`:
`version`, `repo`, `boot`, `proc`, `spstats`, `statx`.

Also verify that after the sub-command word is typed, the script
transitions to completing the `<pathname>` argument (i.e., it handles
`$cword -eq 2` vs `$cword -ge 3` correctly, or delegates to
`_silofs_complete_filedir` at the right word position).

### 3.6 Global Options
Verify that `_silofs_main` offers `-v`/`--version` and `-h`/`--help`
as the only top-level options, matching the `cmd_parse_global_args()`
logic in `cmd/cmd_main.c`.

## 4. Input Files
- `cmd/completions/silofs` (the completion script under review)
- `cmd/cmd_main.c` (canonical sub-command list: `g_cmd_info[]`)
- `cmd/cmd_<subcmd>.c` for each sub-command (option tables: `ods[]`)
- `cmd/cmd_show.c` (`cmd_show_subcommands[]` array)

## 5. Required Output
Provide findings in two groups:

**Bash Correctness:** Issues with the script's behaviour as a bash
completion, independent of `silofs` semantics. Include the line number
and a minimal fix.

**Consistency with C:** A table of discrepancies between the script
and the C implementation, with one row per affected sub-command:

| Sub-command | Issue type        | Script value | C value | Fix |
|-------------|-------------------|--------------|---------|-----|
| ...         | missing option    | —            | `--foo` | add `--foo` |
| ...         | ghost option      | `--bar`      | —       | remove |
| ...         | wrong arg type    | `--baz`      | `--baz=`| add `=` |
| ...         | wrong completion  | `_complete_dir` | `_complete_file` | change |

---
*Note: Treat the C `cmd_optdesc ods[]` tables as the ground truth.*
*The completion script must follow the implementation, not the other*
*way around. Do not suggest changes to the C sources in this audit.*
