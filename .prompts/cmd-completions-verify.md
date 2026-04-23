# Role: Senior Linux Systems Programmer (CLI & C Integration Specialist)
**Task:** Audit the `silofs` bash completion script for consistency with the C implementation.

## 1. System Overview
`cmd/completions/silofs` provides tab-completion for the `silofs`
multi-command CLI. It must accurately reflect the sub-commands and
options implemented in the C sources under `cmd/`.
- The canonical sub-command list is defined in `cmd/cmd_main.c` (`g_cmd_info[]`).
- Each sub-command's accepted options are defined in its `cmd_optdesc ods[]`
  table inside the corresponding `cmd/cmd_<subcmd>.c` file.

This audit focuses on **Consistency bugs** — ensuring the script mirrors
the actual C implementation.

## 2. Objective
Verify that every discrepancy between the script and the `cmd_optdesc`
tables is identified. Discrepancies cause either missing completions
(user frustration) or ghost completions (user confusion).

## 3. Review Checklist

### 3.1 Sub-Command List Consistency
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
- Sub-commands present in `_silofs_main` but absent from `g_cmd_info`.
- Missing or orphaned handler functions.

### 3.2 Per-Sub-Command Option Consistency
For each sub-command, compare options in the completion handler against
the `cmd_optdesc ods[]` table in the corresponding C source. Both long
form (`--foo`) and short form (`-f`) must match. Options with arguments
(`has_arg=1`) must use `--foo=` in the script.

Sources: `cmd/cmd_init.c`, `cmd/cmd_mkfs.c`, `cmd/cmd_mount.c`, etc.

### 3.3 Argument Type Completions
Verify positional argument completion (the `else` branch in handlers):
- `<repodir/fsname>` (file in repo) -> `_silofs_complete_file`.
- `<mountpoint>` or `<repodir>` (directory) -> `_silofs_complete_dir`.
- Mixed usage -> `_silofs_complete_filedir`.
- `lsmnt` should offer no positional arguments.

### 3.4 `show` Sub-Command Completions
Verify sub-commands in `_silofs_show` match `cmd_show_subcommands[]` in
`cmd/cmd_show.c`: `version`, `repo`, `boot`, `proc`, `spstats`, `statx`.

### 3.5 Global Options
Verify `_silofs_main` offers `-v`/`--version` and `-h`/`--help` as the
only top-level options, matching `cmd_parse_global_args()` in `cmd/cmd_main.c`.

## 4. Input Files
- `cmd/completions/silofs` (the completion script)
- `cmd/cmd_main.c` (canonical sub-command list)
- `cmd/cmd_<subcmd>.c` for each sub-command (option tables)
- `cmd/cmd_show.c` (`cmd_show_subcommands[]` array)

## 5. Required Output
Provide a table of discrepancies between the script and the C implementation:

| Sub-command | Issue type        | Script value | C value | Fix |
|-------------|-------------------|--------------|---------|-----|
| ...         | missing option    | —            | `--foo` | add `--foo` |
| ...         | ghost option      | `--bar`      | —       | remove |
| ...         | wrong arg type    | `--baz`      | `--baz=`| add `=` |
| ...         | wrong completion  | `_complete_dir` | `_complete_file` | change |

---
*Note: Treat the C `cmd_optdesc ods[]` tables as the ground truth.*
*The completion script must follow the implementation, not the other*
*way around.*