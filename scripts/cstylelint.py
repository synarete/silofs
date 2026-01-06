#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

#
# cstylelint.py: C-style checker utility for silofs
#
# Copyright (C) 2026 Shachar Sharon
#
# Silofs is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Silofs is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#

import collections
import curses.ascii
import re
import sys
import typing
from pathlib import Path

# Globals:
TOKENLEN_MAX = 40
LINELEN_MAX = 79
BLOCKSIZE_MAX = 104
TAB_WIDTH = 8
LINECNT_MAX = 8000
EMPTYLINES_MAX = 6
C_HDR_EXT = ".h"
C_SRC_EXT = ".c"
C_HEADERS = [
    "assert.h",
    "float.h",
    "math.h",
    "stdatomic.h",
    "stdlib.h",
    "time.h",
    "complex.h",
    "inttypes.h",
    "setjmp.h",
    "stdbool.h",
    "stdnoreturn.h",
    "uchar.h",
    "ctype.h",
    "iso646.h",
    "signal.h",
    "stddef.h",
    "string.h",
    "wchar.h",
    "errno.h",
    "limits.h",
    "stdalign.h",
    "stdint.h",
    "tgmath.h",
    "wctype.h",
    "fenv.h",
    "locale.h",
    "stdarg.h",
    "stdio.h",
    "threads.h",
]

SYS_HEADERS = [
    "errno.h",
    "signal.h",
    "unistd.h",
    "fcntl.h",
    "poll.h",
    "prctl.h",
    "pthread.h",
    "sys/types.h",
    "sys/stat.h",
    "sys/statvfs.h",
    "sys/time.h",
    "sys/select.h",
    "sys/wait.h",
    "sys/xattr.h",
]

INSECURE_FUNCS = [
    "getdents",
    "sprintf",
    "scalbf",
    "gets",
    "getpw",
    "gets",
    "mkstemp",
    "mktemp",
    "rand",
    "strcpy",
    "vfork",
]

NON_REENTRANT_FUNCS = [
    "crypt",
    "encrypt",
    "getgrgid",
    "getgrnam",
    "getlogin",
    "getpwnam",
    "getpwuid",
    "asctime",
    "ctime",
    "gmtime",
    "localtime",
    "getdate",
    "rand",
    "random",
    "readdir",
    "strtok",
    "ttyname",
    "hcreate",
    "hdestroy",
    "hsearch",
    "getmntent",
]

WRAPPER_FUNCS = [
    "assert",
    "bzero",
    "usleep",
]

DEPRECATED_FUNCS = [
    "bzero",
    "pvalloc",
    "gets",
]

COMPILER_PRIVATE = [
    "__builtin_",
    "__asm",
    "__sync",
    "__file__",
    "__line__",
    "__func__",
    "__inline__",
    "__has_attribute",
    "__attribute__",
    "__extension__",
    "__typeof__",
    "__clang__",
    "__const__",
    "__aligned__",
    "__packed__",
    "__pure__",
    "__nonnull__",
    "__noreturn__",
    "__unused__",
    "__fallthrough__",
    "__cplusplus",
    "__has_feature",
    "__thread",
    "__FILE__",
    "__LINE__",
    "__TIME__",
    "__DATE__",
    "__COUNTER__",
    "__OPTIMIZE__",
    "__VA_ARGS__",
    "__BYTE_ORDER",
    "__WORDSIZE",
    "__GNUC__",
    "__GNUC_MINOR__",
    "__GNUC_PATCHLEVEL__",
    "__USE_GNU",
    "__INTEL_COMPILER",
    "__i386__",
    "_Static_assert",
    "_Bool",
    "__SIZEOF_INT128__",
    "__SIZEOF_FLOAT128__",
    "__int128_t",
    "__uint128_t",
    "__restrict__",
    "__restrict",
    "__RESTRICT",
    "__EXTENSIONS__",
    "__ATOMIC_RELAXED",
    "__ATOMIC_SEQ_CST",
    "__atomic_load_n",
    "__atomic_store_n",
    "__atomic_add_fetch",
    "__atomic_sub_fetch",
    "__format__",
    "__printf__",
]

SYS_PRIVATE = [
    "__GLIBC__",
    "__GLIBC_MINOR__",
    "__STDC__",
    "__LITTLE_ENDIAN",
    "__BIG_ENDIAN",
    "__u8",
    "__u16",
    "__u32",
    "__u64",
    "__s8",
    "__s16",
    "__s32",
    "__s64",
    "__le16",
    "__le32",
    "__le64",
    "__be16",
    "__be32",
    "__be64",
    "__rlimit_resource_t",
    "__KERNEL__",
]

CSOURCE_EXCLUDE = [
    "extern",
    "new",
    "delete",
    "private",
    "protected",
    "public",
    "using",
    "namespace",
    "cplusplus",
    "_cast",
    "try",
    "throw",
    "catch",
    "mutable",
    "friend",
    "template",
    "virtual",
    "operator",
    "setjmp",
    "longjmp",
]

MAP_TO_C23 = {
    "NULL": "nullptr",
    "TRUE": "true",
    "FALSE": "false",
}

LIBS_PREFIX = [
    "ZSTD_",
    "LZ4_",
]

RESERVED_TOKENS = [
    "+-",
    "-+",
    "''",
    "~~",
    "!!",
    "??",
    "---",
    "+++",
    "&&&",
    "***",
    "<<<",
    ">>>",
    "___",
    "===",
    "\\\\",
    "////",
    "(((((",
    ")))))",
]

RE_FUNC_DECL = re.compile(r"""\w+ \w+\(.*\);$""")
RE_SIZEOF_ADDRESS = re.compile(r"""\bsizeof\s*\(\s*\&""")
RE_SUSPICIOUS_SEMICOLON = re.compile(r"""\bif\s*\(.*\)\s*;""")

# . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .


def _is_hdr_file(path: Path) -> bool:
    return path.is_file() and path.suffix == C_HDR_EXT


def _is_src_file(path: Path) -> bool:
    return path.is_file() and path.suffix == C_SRC_EXT


def _is_cfile(path: Path) -> bool:
    return path.exists() and (_is_hdr_file(path) or _is_src_file(path))


def _read_cfile(path: Path) -> str:
    """Read input C source file, line-by-line."""
    output = ""
    with path.open("r", encoding="UTF-8") as fh:
        for line in fh:
            output = output + line
    return output


def _reparse_cfile(txt: str) -> str:
    """Traverse C source file and white-out comments and strings."""
    (in_mlc, in_slc, in_str, pps) = (False, False, False, False)
    (next_ch, prev_ch) = (" ", " ")
    out = ""
    for ch in txt:
        if prev_ch == "\n":
            pps = ch == "#"
        next_ch = ch
        if in_str:
            if ch == '"' and prev_ch != "\\":
                in_str = False
            elif not pps:
                next_ch = " "
        elif in_slc:
            if ch == "\n":
                in_slc = False
            else:
                next_ch = " "
        elif in_mlc:
            if prev_ch == "*" and ch == "/":
                in_mlc = False
            elif not (ch == "\n" or ch == "*"):
                next_ch = " "
        else:
            if ch == '"' and prev_ch != "\\":
                in_str = True
                in_mlc = in_slc = False
            elif ch == "/" and prev_ch == "/":
                in_slc = True
                in_mlc = in_str = False
            elif ch == "*" and prev_ch == "/":
                in_mlc = True
                in_slc = in_str = False
        out += next_ch
        prev_ch = ch
    return out


# . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .


class SourceLine:
    """
    Representation of single C source line.

    A triplet of source file-path, text line and line-number.
    """

    def __init__(self, path: Path, txt: str, lno: int) -> None:
        self.path = path
        self.line = txt
        self.lnum = lno
        self.toks = self._tokenize()

    def _tokenize(self) -> list[str]:
        """Converts delimiters to spaces and splits line into tokens."""
        wline = str(self.line)
        for c in " { * } [ ] ( ) ; : . ".split():
            wline = wline.replace(c, " ")
        return wline.split()


class SourceFile:
    """
    Representation of single C source file.
    """

    def __init__(self, path: Path, text: str) -> None:
        self.path = path
        self.text = text
        self.lines = self._text_to_lines()

    def _text_to_lines(self) -> list[SourceLine]:
        src_lines: list[SourceLine] = []
        lno = 0
        for line in self.text.split("\n"):
            lno += 1
            src_lines.append(SourceLine(self.path, line, lno))
        return src_lines


class LintEnv:
    """Lint context object for accumulating checkers state."""

    def __init__(self) -> None:
        self.wordir = Path.cwd()
        self.progname = Path(sys.argv[0]).name
        self.err_count: int = 0

    def lerror(self, sl: SourceLine, msg: str) -> None:
        rpath = self._rpath(sl.path)
        self._error(f"{rpath}:{sl.lnum}: ", msg)

    def ferror(self, sf: SourceFile, msg: str) -> None:
        rpath = self._rpath(sf.path)
        self._error(f"{rpath}: ", msg)

    def _error(self, meta: str, msg: str) -> None:
        print(f"{self.progname}: {meta}{msg}")
        self.err_count = self.err_count + 1

    def _rpath(self, path: Path) -> Path:
        rpath = path.relative_to(self.wordir)
        return rpath if str(rpath) != "" else path


# . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .


def check_line_length(env: LintEnv, sl: SourceLine) -> None:
    """Require source-line to be up to 80 chars long."""
    sline = sl.line.replace("\t", " " * TAB_WIDTH).rstrip("\n")
    line_len = len(sline)
    if line_len > LINELEN_MAX:
        env.lerror(sl, f"Long-line len={line_len}")


def check_ascii_printable(env: LintEnv, sl: SourceLine) -> None:
    """Require all characters to be are ASCII-printable."""
    for c in sl.line.strip():
        if not curses.ascii.isprint(c) and (c != "\t"):
            ord_c = ord(c)
            env.lerror(sl, f"Non-ASCII-printable ord={ord_c}")


def check_only_indent_tabs(env: LintEnv, sl: SourceLine) -> None:
    """Require TABS only for indentation."""
    pos = max(sl.line.find("\t"), sl.line.find("\v"))
    if pos > 0:
        env.lerror(sl, f"Tab-character at {pos}")


def check_no_multi_semicolon(env: LintEnv, sl: SourceLine) -> None:
    """Do not allow multiple semi-colons."""
    pos = sl.line.rfind(";;")
    if pos >= 0:
        env.lerror(sl, f"Multiple semi-colon at {pos}")


def check_no_long_tokens(env: LintEnv, sl: SourceLine) -> None:
    """Do not allow loooooong tokens."""
    for tok in sl.toks:
        if len(tok) > TOKENLEN_MAX:
            env.lerror(sl, f"Long token: {tok}")


def check_no_suspicious_semicolon(env: LintEnv, sl: SourceLine) -> None:
    """Require no semicolon at the end of if, unless it is do-while."""
    line = sl.line.strip()
    do_while = (line.find("do ") >= 0) and (line.find(" while") > 0)
    if do_while:
        return  # special case: do-while loop
    susp_semicolon = re.search(RE_SUSPICIOUS_SEMICOLON, line)
    if susp_semicolon is not None:
        env.lerror(sl, "Suspicious semicolon")


def check_no_relative_include(env: LintEnv, sl: SourceLine) -> None:
    """Require include directive to be without relative path."""
    (i, j) = (sl.line.find("#include"), sl.line.find("../"))
    if (i >= 0) and (j > 0):
        env.lerror(sl, "Relative include directive")


def check_no_sizeof_address(env: LintEnv, sl: SourceLine) -> None:
    """Forbid the sizeof(&) syntax."""
    if re.search(RE_SIZEOF_ADDRESS, sl.line) is not None:
        env.lerror(sl, "Avoid sizeof(& ")


def check_struct_union_name(env: LintEnv, sl: SourceLine) -> None:
    """Require names of struct/union to be all lower-case."""
    check = False
    for tok in sl.toks:
        if check and not tok.islower():
            env.lerror(sl, f"Non-valid-name {tok}")
        check = tok in ("struct", "union")


def check_c23_keywords(env: LintEnv, sl: SourceLine) -> None:
    """Require usage of C23 keywords."""
    for tok in sl.toks:
        c23_tok = MAP_TO_C23.get(tok, "")
        if len(c23_tok) > 0:
            env.lerror(sl, f"Need to change to C23: '{tok} --> {c23_tok}'")


def _is_private_name(tok: str) -> bool:
    """Return True if a token is in compiler/system private names."""
    for p in COMPILER_PRIVATE + SYS_PRIVATE:
        if tok.startswith(p):
            return True
    return False


def _is_lib_name(tok: str) -> bool:
    """Return True if a token is from know libraries."""
    for p in LIBS_PREFIX:
        if tok.startswith(p):
            return True
    return False


def _is_mixed_case_token(tok: str) -> bool:
    (has_lower, has_upper) = (False, False)
    for c in tok:
        if c.islower():
            has_lower = True
        if c.isupper():
            has_upper = True
    return has_lower and has_upper


def _has_mixed_case(tok: str) -> bool:
    """Check if a token consists of mixed upper/lower characters.

    Returns True when a token a mixed case; if it is a combination of two or
    more sub-tokens (e.g., system defines such as SYS_gettid), check each
    sub-token.
    """
    for t in tok.split("_"):
        if _is_mixed_case_token(t):
            return True
    return False


def check_no_mixed_case(env: LintEnv, sl: SourceLine) -> None:
    """Require function/struct/union/variable names to have same case."""
    names = []
    for tok in sl.toks:
        for t in tok.split("_"):
            if (len(t) > 0) and t.isalnum() and t[0].isalpha():
                names.append((t, tok))
    for name, tok in names:
        if _is_private_name(tok) or _is_lib_name(tok):
            continue
        if _has_mixed_case(tok):
            env.lerror(sl, f"Mixed-case '{tok}'")


def check_underscore_prefix(env: LintEnv, sl: SourceLine) -> None:
    """Reserve double-underscore prefix for compiler/system."""
    for tok in sl.toks:
        if _is_private_name(tok) or _is_lib_name(tok):
            continue
        if tok.startswith("__"):
            env.lerror(sl, f"Not a compiler/system built-in {tok}")


def _using_function(line: str, fn: str) -> bool:
    """Check if function call exists in line."""
    fn_prefix = " " + fn
    return fn_prefix + "(" in line or fn_prefix + " (" in line


def check_no_insecure_functions(env: LintEnv, sl: SourceLine) -> None:
    """Do not use insecure/unsafe functions."""
    for fn in INSECURE_FUNCS:
        if fn in sl.toks and _using_function(sl.line, fn):
            env.lerror(sl, f"Insecure-function: '{fn}'")


def check_no_non_reentrant_func(env: LintEnv, sl: SourceLine) -> None:
    """Do not allow usage of non-reentrant functions."""
    for fn in NON_REENTRANT_FUNCS:
        if fn in sl.toks and _using_function(sl.line, fn):
            env.lerror(sl, f"Non-reentrant {fn} (prefer: {fn}_r)")


def check_no_deprecated_functions(env: LintEnv, sl: SourceLine) -> None:
    """Do not allow usage of deprecated functions."""
    for fn in DEPRECATED_FUNCS:
        if fn in sl.toks and _using_function(sl.line, fn):
            env.lerror(sl, f"Deprecated-function: '{fn}'")


def check_using_wrapper_functions(env: LintEnv, sl: SourceLine) -> None:
    """Prefer usage of wrapper functions."""
    for fn in WRAPPER_FUNCS:
        if fn in sl.toks and _using_function(sl.line, fn):
            env.lerror(sl, f"Prefer wrapper function: '{fn}'")


def check_no_reserved_tokens(env: LintEnv, sl: SourceLine) -> None:
    """Check that there is no usage of confusing reserved tokens."""
    for rtok in RESERVED_TOKENS:
        (i, j) = (sl.line.find(" " + rtok), sl.line.find(rtok + " "))
        if (i >= 0) or (j >= 0):
            env.lerror(sl, f"Avoid using '{rtok}'")


def check_no_excluded_keyword(env: LintEnv, sl: SourceLine) -> None:
    """Do not allow using specific C/C++ keywords in C files."""
    for ex in CSOURCE_EXCLUDE:
        word = " " + ex.strip(".-+%~><?^*")
        if word in sl.toks:
            env.lerror(sl, f"Avoid using '{word}' in C files")


def check_no_static_inline(env: LintEnv, sl: SourceLine) -> None:
    """Do not use using 'static inline' function within C source.

    Avoid using 'static inline' in C source file: modern compilers are very
    smart, let it make the decision for us.
    """
    if "static inline " in sl.line:
        env.lerror(sl, "Avoid using 'static inline' in C source file")


def check_std_includes(env: LintEnv, sl: SourceLine) -> None:
    """Require standard include-headers to be with angle brackets."""
    std_headers = C_HEADERS + SYS_HEADERS
    spln = sl.line.strip().split()
    if len(spln) == 2 and spln[0].startswith("#include"):
        inc = spln[1]
        hdr = inc.strip('"<>')
        if hdr in std_headers and inc.startswith('"'):
            env.lerror(sl, f"Malformed include: '{hdr}'")


def check_includes_suffix(env: LintEnv, sl: SourceLine) -> None:
    """Prevent non-headers includes."""
    spln = sl.line.strip().split()
    if len(spln) == 2 and spln[0].startswith("#include"):
        inc = spln[1]
        hdr = inc.strip('"<>')
        if not hdr.endswith(".h"):
            env.lerror(sl, f"Wrong header suffix: '{inc}'")


def check_source_line(env: LintEnv, sl: SourceLine) -> None:
    """Run source-line checkers."""
    check_line_length(env, sl)
    check_ascii_printable(env, sl)
    check_only_indent_tabs(env, sl)
    check_no_multi_semicolon(env, sl)
    check_no_long_tokens(env, sl)
    check_no_suspicious_semicolon(env, sl)
    check_no_relative_include(env, sl)
    check_no_sizeof_address(env, sl)
    check_struct_union_name(env, sl)
    check_c23_keywords(env, sl)
    check_no_mixed_case(env, sl)
    check_underscore_prefix(env, sl)
    check_no_insecure_functions(env, sl)
    check_no_non_reentrant_func(env, sl)
    check_no_deprecated_functions(env, sl)
    check_using_wrapper_functions(env, sl)
    check_no_reserved_tokens(env, sl)
    check_std_includes(env, sl)
    check_includes_suffix(env, sl)
    if _is_src_file(sl.path):
        check_no_excluded_keyword(env, sl)
        check_no_static_inline(env, sl)


# . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .


def check_lines_style(env: LintEnv, sf: SourceFile) -> None:
    """Perform line-by-line checks."""
    for sl in sf.lines:
        check_source_line(env, sl)


def check_file_lines_cnt(env: LintEnv, sf: SourceFile) -> None:
    """Check number of lines does not exceeds upper limit."""
    lncnt = len(sf.lines)
    if lncnt > LINECNT_MAX:
        env.ferror(sf, f"Too-many source lines: {lncnt}")


def check_block_size(env: LintEnv, sf: SourceFile) -> None:
    """Require sane block-sizes within { and }."""
    deque: typing.Deque[int] = collections.deque()
    for ln in sf.lines:
        for c in ln.line:
            if c == "{":
                deque.append(ln.lnum)
            if c == "}":
                try:
                    no0 = deque.pop()
                    dif = ln.lnum - no0
                    if dif > BLOCKSIZE_MAX:
                        env.lerror(ln, f"Block-overflow: {dif}")
                except IndexError:
                    env.ferror(sf, "Block-error")


def _starts_with_pp(line: str, ppt: str) -> bool:
    """Check if line starts with pre-processing token."""
    s = line.lstrip("#").strip()
    t = ppt.lstrip("#").strip()
    return s.startswith(t)


def _has_pps_token_name(line: str, ppt: str, name: str) -> bool:
    return _starts_with_pp(line, ppt) and name in line


def check_pps_guards(env: LintEnv, sf: SourceFile) -> None:
    """Require pre-processing guards to match header filename."""
    name = sf.path.name
    guard = name.upper().replace(".", "_").replace("-", "_")
    guard = "_" + guard + "_"
    guard_define_cnt = 0
    guard_ifndef_cnt = 0
    for sl in sf.lines:
        if _has_pps_token_name(sl.line, "define", guard):
            guard_define_cnt += 1
        if _has_pps_token_name(sl.line, "ifndef", guard):
            guard_ifndef_cnt += 1
    if (guard_define_cnt != 1) or (guard_ifndef_cnt != 1):
        env.ferror(sf, f"Pre-processing guard (use: {guard})")


def check_nodup_includes(env: LintEnv, sf: SourceFile) -> None:
    """Check for (no) duplicated includes."""
    includes: typing.Dict[str, int] = {}
    for sl in sf.lines:
        line = sl.line
        if not line.strip().startswith("#include "):
            continue
        lsp = line.split()
        if len(lsp) != 2:
            env.lerror(sl, "Bad include")
            continue
        inc = lsp[1].strip('"<>')
        cnt = includes[inc] = includes.get(inc, 0) + 1
        if cnt > 1:
            env.lerror(sl, f"Duplicated include '{inc}'")


def check_consecutive_empty_lines(env: LintEnv, sf: SourceFile) -> None:
    """Limit the number of consecutive empty lines."""
    cnt = 0
    for sl in sf.lines:
        if len(sl.line.strip()) != 0:
            cnt = 0
            continue
        cnt += 1
        if cnt >= EMPTYLINES_MAX:
            env.lerror(sl, "Too many empty lines")


def check_enum_def(env: LintEnv, sf: SourceFile) -> None:
    """Require enum-names to be all upper-case + underscores."""
    enum_lines: list[SourceLine] = []
    in_enum_def = False
    for sl in sf.lines:
        ln = sl.line.strip()
        if in_enum_def:
            enum_lines.append(sl)
        elif ln.startswith("enum ") and ("{" in ln):
            in_enum_def = True
        if ("}" in ln) or (";" in ln):
            in_enum_def = False
    for sl in enum_lines:
        ln = sl.line.strip()
        toks = ln.strip("{[()]} \t\r\v\n").split()
        if len(toks):
            tok = toks[0].strip("=;:")
            if len(tok) and tok.isalnum() and not tok.isupper():
                env.lerror(sl, f"Illegal enum-name {tok}")


def check_close_braces(env: LintEnv, sf: SourceFile) -> None:
    """Require zero empty lines before close-braces."""
    empty_line = False
    for sl in sf.lines:
        ln = sl.line.strip()
        if len(ln) == 0:
            empty_line = True
        if ln == "}" and empty_line:
            env.lerror(sl, "Closing brace after empty line")
        if len(ln) != 0:
            empty_line = False


def check_source_file(env: LintEnv, sf: SourceFile) -> None:
    """Perform whole-file checks."""
    check_lines_style(env, sf)
    check_file_lines_cnt(env, sf)
    check_nodup_includes(env, sf)
    check_consecutive_empty_lines(env, sf)
    check_enum_def(env, sf)
    check_close_braces(env, sf)
    if _is_src_file(sf.path):
        check_block_size(env, sf)
    if _is_hdr_file(sf.path):
        check_pps_guards(env, sf)


# . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .


def _read_source_file(path: Path) -> SourceFile:
    txt = _reparse_cfile(_read_cfile(path))
    return SourceFile(path, txt)


def _check_cstyle(env: LintEnv, src_path_list: list[Path]) -> None:
    for src_path in src_path_list:
        check_source_file(env, _read_source_file(src_path))


def _resolve_cfiles(sources: list[str]) -> list[Path]:
    return [Path(src) for src in sources if _is_cfile(Path(src))]


def main() -> None:
    """Run various C-style checks on input source files."""
    env = LintEnv()
    _check_cstyle(env, _resolve_cfiles(sys.argv[1:]))
    sys.exit(0 if (env.err_count == 0) else 1)


if __name__ == "__main__":
    main()
