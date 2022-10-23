#!/usr/bin/env python3
#
# checkcstyle -- Style-checker for C-source files
#
# Copyright (C) 2015-2022 Shachar Sharon
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
#

import sys
import os
import re
import stat
import collections
import curses.ascii

# Globals:
PROGNAME = os.path.basename(sys.argv[0])
TOKENLEN_MAX = 40
LINELEN_MAX = 79
BLOCKSIZE_MAX = 90
TAB_WIDTH = 8
LINECNT_MAX = 8000
EMPTYLINES_MAX = 6
C_HEADERS = """
    assert.h
    float.h
    math.h
    stdatomic.h
    stdlib.h
    time.h
    complex.h
    inttypes.h
    setjmp.h
    stdbool.h
    stdnoreturn.h
    uchar.h
    ctype.h
    iso646.h
    signal.h
    stddef.h
    string.h
    wchar.h
    errno.h
    limits.h
    stdalign.h
    stdint.h
    tgmath.h
    wctype.h
    fenv.h
    locale.h
    stdarg.h
    stdio.h
    threads.h
    """
SYS_HEADERS = """
    errno.h
    signal.h
    unistd.h
    fcntl.h
    poll.h
    prctl.h
    pthread.h
    sys/types.h
    sys/stat.h
    sys/time.h
    sys/select.h
    """

INSECURE_FUNCS = """
    getdents
    sprintf
    scalbf
    gets
    getpw
    gets
    mkstemp
    mktemp
    rand
    strcpy
    vfork
    """

NON_REENTRANT_FUNCS = """
    crypt
    encrypt
    getgrgid
    getgrnam
    getlogin
    getpwnam
    getpwuid
    asctime
    ctime
    gmtime
    localtime
    getdate
    rand
    random
    readdir
    strtok
    ttyname
    hcreate
    hdestroy
    hsearch
    getmntent
    """

WRAPPER_FUNCS = """
    assert
    bzero
    usleep
    """

DEPRECATED_FUNCS = """
    bzero
    pvalloc
    gets
    """

COMPILER_PRIVATE = """
    __builtin_
    __asm
    __sync
    __file__
    __line__
    __func__
    __inline__
    __attribute__
    __extension__
    __typeof__
    __clang__
    __aligned__
    __packed__
    __pure__
    __nonnull__
    __noreturn__
    __unused__
    __cplusplus
    __has_feature
    __thread
    __FILE__
    __LINE__
    __TIME__
    __DATE__
    __COUNTER__
    __OPTIMIZE__
    __VA_ARGS__
    __BYTE_ORDER
    __WORDSIZE
    __GNUC__
    __GNUC_MINOR__
    __GNUC_PATCHLEVEL__
    __USE_GNU
    __INTEL_COMPILER
    __i386__
    _Static_assert
    _Bool
    __SIZEOF_INT128__
    __SIZEOF_FLOAT128__
    __int128_t
    __uint128_t
    __restrict__
    __restrict
    __RESTRICT
    __EXTENSIONS__
    __ATOMIC_RELAXED
    __atomic_load_n
    __atomic_store_n
    __atomic_add_fetch
    __atomic_sub_fetch
    """

SYS_PRIVATE = """
    __GLIBC__ __GLIBC_MINOR__
    __STDC__
    __LITTLE_ENDIAN
    __BIG_ENDIAN
    __u8 __u16 __u32 __u64
    __s8 __s16 __s32 __s64
    __le16 __le32 __le64
    __be16 __be32 __be64
    __rlimit_resource_t
    __KERNEL__
    """

CSOURCE_EXCLUDE = """
    extern
    new
    delete
    private
    protected
    public
    using
    namespace
    cplusplus
    _cast
    try
    throw
    catch
    mutable
    friend
    template
    virtual
    operator
    setjmp
    longjmp
    """

LIBS_PREFIX = """
    ZSTD_
    LZ4_
    """

RESERVED_TOKENS = """
    +-
    -+
    ''
    ~~
    !!
    ??
    ---
    +++
    &&&
    ***
    <<<
    >>>
    ___
    ===
    \\\\
    ////
    (((((
    )))))
    """

RE_FUNC_DECL = re.compile(r"""\w+ \w+\(.*\);$""")
RE_SIZEOF_ADDRESS = re.compile(r"""\bsizeof\s*\(\s*\&""")
RE_SUSPICIOUS_SEMICOLON = re.compile(r"""\bif\s*\(.*\)\s*;""")

# . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

# Common helpers:


def getext(pname: str) -> str:
    return str(os.path.splitext(pname)[1])


def iscfile(path: str) -> bool:
    ext = getext(path)
    return ext == ".c"


def ishfile(path: str) -> bool:
    ext = getext(path)
    return len(ext) and getext(path) in (".h", ".hpp", ".hxx")


# . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .


class FileStripper:
    """
    Utility class to help simplify source-file analyzing

    Replaces strings-content with white-spaces and replaces block-comments with
    white-spaces + holds a list of tuples: (line-number, stripped-line)
    """
    def __init__(self, txt: str) -> str:
        self.txt = self.strip_source(txt)
        self.xlines = self.lines_nums(self.txt.split("\n"))

    def get(self) -> (str, list):
        return (self.txt, self.xlines)

    @staticmethod
    def lines_nums(lines: list) -> list:
        """Generators of (line-number, line) tuples list"""
        return list(zip(list(range(1, len(lines) + 1)), lines))

    @staticmethod
    def strip_source(txt: str) -> str:
        """Replace block-comments and strings' data with white-spaces"""
        no_strings_txt = FileStripper.whiteout_strings(txt)
        stripped_txt = FileStripper.whiteout_comments(no_strings_txt)
        return stripped_txt

    @staticmethod
    def whiteout_lstrings(line: str) -> str:
        """Replace strings-in-line with white-spaces"""
        wline = ""
        instr = False
        inctl = False
        for c in line:
            if instr:
                if c == "\\":
                    inctl = not inctl
                elif c == '"':
                    if inctl:
                        wline = wline + " "
                    else:
                        instr = False
                        inctl = False
                    wline = wline + '"'
                else:
                    wline = wline + " "
            elif c == '"':
                instr = True
                inctl = False
                wline = wline + '"'
            else:
                wline = wline + c
        return wline

    @staticmethod
    def whiteout_strings(txt: str) -> str:
        """Replace strings with white-spaces"""
        rlines = txt.split("\n")
        wlines = []
        for line in rlines:
            if not line.lstrip().startswith("#"):
                line = FileStripper.whiteout_lstrings(line)
            wlines.append(line)
        return "\n".join(wlines)

    @staticmethod
    def whiteout_dcomment(txt: str) -> str:
        """Replace comments data with white-spaces"""
        out = ""
        for c in txt:
            if c != "\n":
                c = " "
            out = out + c
        return out

    @staticmethod
    def whiteout_comments(txt: str) -> str:
        """Replace block-comments with white-spaces"""

        beg = "/*"
        end = "*/"
        dat = txt
        out = []
        while True:
            indx = dat.find(beg)
            if indx < 0:
                out.append(dat)
                break
            out.append(dat[:indx])
            dat = dat[indx:]
            indx = dat.find(end)
            if indx < 0:
                out.append(dat)
                break
            com = dat[:indx + len(end)]
            out.append(FileStripper.whiteout_dcomment(com))
            dat = dat[indx + len(end):]
        return "".join(out)


# . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .


class Checker:
    """Utility base-class for checker objects"""
    def __init__(self) -> None:
        self.msgs = []

    def info(self, msg, lnum=0) -> None:
        self.msgs.append((lnum, msg))

    def error(self, msg, lnum=0) -> None:
        self.info("[ERROR] " + msg, lnum)

    def warn(self, msg, lnum=0) -> None:
        self.info(msg, lnum)

    @staticmethod
    def _has_mixed_case(tok: str) -> bool:
        """Returns True if a token consists of mixed upper/lower characters
        If a token is a combination of two or more sub-tokens (e.g., system
        defines such as SYS_gettid), check each sub-token.
        """
        (has_lower, has_upper) = (False, False)
        if "_" in tok:
            for t in tok.split("_"):
                if Checker._has_mixed_case(t):
                    return True
        else:
            for c in tok:
                if c.islower():
                    has_lower = True
                if c.isupper():
                    has_upper = True
        return has_lower and has_upper

    @staticmethod
    def _is_private_name(tok: str) -> bool:
        """Return True if a token is in compiler/system private names"""
        compiler_private = COMPILER_PRIVATE.split()
        sys_private = SYS_PRIVATE.split()
        for p in compiler_private:
            if tok.startswith(p):
                return True
        for p in sys_private:
            if tok.startswith(p):
                return True
        return False

    @staticmethod
    def _is_lib_name(tok: str) -> bool:
        """Return True if a token is from know libs"""
        libs_prefix = LIBS_PREFIX.split()
        for p in libs_prefix:
            if tok.startswith(p):
                return True
        return False

    @staticmethod
    def _using_function(line: str, fn: str) -> bool:
        """Checks if function call exists in line"""
        fn_prefix = " " + fn
        return fn_prefix + "(" in line or fn_prefix + " (" in line

    @staticmethod
    def _starts_with_pp(line: str, ppt: str) -> bool:
        """Checks if line starts with pre-processing token"""
        s = line.lstrip("#").strip()
        t = ppt.lstrip("#").strip()
        return s.startswith(t)


# . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .


class LineChecker(Checker):
    """Context-object for single source-line analyzing"""
    def __init__(self, lnum: int, line: str, ish: bool) -> None:
        super(LineChecker, self).__init__()
        self.lnum = lnum
        self.line = line
        self.toks = self._tokenize(line)
        self.ish = ish

    @staticmethod
    def _tokenize(line: str) -> list:
        """Converts delimiters to spaces and splits line into tokens"""
        wline = str(line)
        for c in " { * } [ ] ( ) ; : . ".split():
            wline = wline.replace(c, " ")
        return wline.split()

    def info(self, msg, lnum=0) -> None:
        if lnum == 0:
            lnum = self.lnum
        Checker.info(self, msg, self.lnum)

    def check(self) -> list:
        """Run line-checkers"""
        self.check_line_length()
        self.check_no_cxx_comments()
        self.check_ascii_printable()
        self.check_only_indent_tabs()
        self.check_no_multi_semicolon()
        self.check_no_long_tokens()
        self.check_no_suspicious_semicolon()
        self.check_no_relative_include()
        self.check_no_sizeof_address()
        self.check_struct_union_name()
        self.check_no_mixed_case()
        self.check_underscore_prefix()
        self.check_no_insecure_functions()
        self.check_no_non_reentrant_func()
        self.check_no_deprecated_functions()
        self.check_using_wrapper_functions()
        self.check_no_reserved_tokens()
        self.check_no_excluded_keyword()
        self.check_no_static_inline()
        return self.msgs

    def check_line_length(self) -> None:
        """Source-code lines should not be more then 80 chars long. Map TABs to
        4 white space characters.
        """
        line_len = len(self.line.replace("\t", " " * TAB_WIDTH).rstrip("\n"))
        if line_len > LINELEN_MAX:
            self.error("Long-line len={0}".format(line_len))

    def check_no_cxx_comments(self) -> None:
        """Avoid C++ style comments (be as portable as possible)"""
        line = self.line
        if line.strip().startswith("//") or line.find(" //") >= 0:
            self.warn("C++ comment")

    def check_ascii_printable(self) -> None:
        """All characters should be ASCII-printable"""
        for c in self.line.strip():
            if not curses.ascii.isprint(c) and (c != "\t"):
                self.error("Non-ASCII-printable ord={0}".format(ord(c)))

    def check_only_indent_tabs(self) -> None:
        """Source line should have no tabs, except for indent"""
        line = self.line.lstrip()
        tcol = max(line.rfind("\t"), line.rfind("\v"))
        if tcol > 0:
            line = self.line
            tcol = max(line.rfind("\t"), line.rfind("\v"))
            self.warn("Tab-character at pos={0}".format(tcol))

    def check_no_multi_semicolon(self) -> None:
        """Should not have multiple ;;"""
        line = self.line.rstrip()
        i = line.rfind(";;")
        if i >= 0:
            self.warn("Multiple semi-colon")

    def check_no_long_tokens(self) -> None:
        """Avoid having loooooong tokens"""
        for tok in self.toks:
            if len(tok) > TOKENLEN_MAX:
                self.error("Long token: {0}".format(tok))

    def check_no_suspicious_semicolon(self) -> None:
        """Avoid having semicolon at the end of if, unless it is do-while"""
        line = self.line.strip()
        do_while = (line.find("do ") >= 0) and (line.find(" while") > 0)
        if not do_while:
            susp_semicolon = re.search(RE_SUSPICIOUS_SEMICOLON, line)
            if susp_semicolon is not None:
                self.warn("Suspicious semicolon")

    def check_no_relative_include(self) -> None:
        """Should not have relative includes"""
        line = self.line.strip()
        (i, j) = (line.find("#include"), line.find("../"))
        if (i == 0) and (j > 0):
            self.error("Relative path in: {0}".format(line))

    def check_no_sizeof_address(self) -> None:
        """Avoid using sizeof(&)"""
        if re.search(RE_SIZEOF_ADDRESS, self.line) is not None:
            self.error("Avoid sizeof(& ")

    def check_struct_union_name(self) -> None:
        """Names of struct/union should be all lower"""
        check = False
        for tok in self.toks:
            if check and not tok.islower():
                self.error("Non-valid-name {0}".format(tok))
            check = (tok == "struct") or (tok == "union")

    def check_no_mixed_case(self) -> None:
        """Names of function/struct/union/variable must be have same case"""
        names = []
        for tok in self.toks:
            for t in tok.split("_"):
                if (len(t) > 0) and t.isalnum() and t[0].isalpha():
                    names.append((t, tok))
        for name, tok in names:
            if (self._has_mixed_case(name) and not self._is_private_name(tok)
                    and not self._is_lib_name(tok)):
                self.warn("Mixed-case: '{0}'".format(name))

    def check_underscore_prefix(self) -> None:
        """Double-underscore prefix should be reserved for compiler/system"""
        for tok in self.toks:
            if (len(tok) > 2) and tok.startswith("__"):
                if not self._is_private_name(tok):
                    self.warn("Not a compiler/system built-in {0}".format(tok))

    def check_no_insecure_functions(self) -> None:
        """Avoid insecure/unsafe functions"""
        insecure_funcs = INSECURE_FUNCS.split()
        for fn in insecure_funcs:
            if fn in self.toks and self._using_function(self.line, fn):
                self.warn("Insecure-function: '{0}'".format(fn))

    def check_no_deprecated_functions(self) -> None:
        """Avoid deprecated functions"""
        deprecated_funcs = DEPRECATED_FUNCS.split()
        for fn in deprecated_funcs:
            if fn in self.toks and self._using_function(self.line, fn):
                self.warn("Deprecated-function: '{0}'".format(fn))

    def check_no_non_reentrant_func(self) -> None:
        """Avoid non-reentrant functions"""
        non_reentrant_funcs = NON_REENTRANT_FUNCS.split()
        for fn in non_reentrant_funcs:
            if fn in self.toks and self._using_function(self.line, fn):
                self.warn("Non-reentrant {0} (use: {0}_r)".format(fn))

    def check_using_wrapper_functions(self) -> None:
        """Prefer wrapper functions"""
        wrapper_funcs = WRAPPER_FUNCS.split()
        for fn in wrapper_funcs:
            if fn in self.toks and self._using_function(self.line, fn):
                self.info("Prefer wrapper function: '{0}'".format(fn))

    def check_no_reserved_tokens(self) -> None:
        """Avoid using reserved tokens which may confuse"""
        reserved_tokens = RESERVED_TOKENS.split()
        line = self.line
        for rt in reserved_tokens:
            tok1 = " " + rt
            tok2 = rt + " "
            if tok1 in line or tok2 in line:
                self.warn("Avoid using '{0}'".format(rt))

    def check_no_excluded_keyword(self) -> None:
        """Avoid using some (C/C++) keywords in C files"""
        if self.ish:
            return
        csource_exclude = CSOURCE_EXCLUDE.split()
        for ex in csource_exclude:
            word = " " + ex.strip(".-+%~><?^*")
            if word in self.toks:
                self.warn("Avoid using '{0}' in C files".format(word))

    def check_no_static_inline(self) -> None:
        """Avoid using 'static inline ' function declaration within C source
        file; Let the compiler be wise for us.
        """
        if self.ish:
            return
        if "static inline " in self.line:
            self.warn("Avoid using 'static inline' in C source file")


# . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .


class FileChecker(Checker):
    """Context-context for entire source-file analyzing"""
    @staticmethod
    def create(path: str):
        with open(path, "r") as inf:
            dat = inf.read()
            ish = ishfile(path)
            chk = FileChecker(path, dat, ish)
        return chk

    def __init__(self, path: str, dat: str, ish: bool) -> None:
        super(FileChecker, self).__init__()
        self.path = path
        self.dat = dat
        self.ish = ish
        self.txt, self.xlines = FileStripper(dat).get()

    def check(self) -> list:
        """Run checkers"""
        self.check_line_style()
        self.check_file_lines_cnt()
        self.check_block_size()
        self.check_pps_guards()
        self.check_nodup_includes()
        self.check_std_includes()
        # self.check_includes_order() # TODO: revisit this check
        self.check_includes_suffix()
        self.check_enum_def()
        self.check_empty_lines()
        self.check_close_braces()
        # self.check_lspace_between_func_decl()
        return self.msgs

    def check_line_style(self) -> None:
        for lnum, line in self.xlines:
            self.msgs += LineChecker(lnum, line, self.ish).check()

    def check_file_lines_cnt(self) -> None:
        """Check limit number of lines per file"""
        lncnt = len(self.xlines)
        if lncnt > LINECNT_MAX:
            self.error("Too-many source lines: {0}".format(lncnt))

    def check_block_size(self) -> None:
        """Check block-sizes within { and } is not larger then BLOCKSIZE_MAX"""
        if self.ish:
            return  # Ignore this check for headers
        deque = collections.deque()
        for (no, ln) in self.xlines:
            for c in ln:
                if c == "{":
                    deque.append(no)
                if c == "}":
                    dif = 0
                    try:
                        no0 = deque.pop()
                        dif = no - no0
                    except IndexError:
                        self.error("Block-error")
                    if dif > BLOCKSIZE_MAX:
                        self.error("Block-overflow: {0}".format(dif), lnum=no0)

    def check_pps_guards(self) -> None:
        """Check pre-processing guards match filename for .h files"""
        if not self.ish:
            return
        name = os.path.split(self.path)[1]
        guard = name.upper().replace(".", "_").replace("-", "_") + "_"
        ls1 = [(no, ln) for (no, ln) in self.xlines
               if self._starts_with_pp(ln, "define")]
        ls2 = [(no, ln) for (no, ln) in self.xlines
               if self._starts_with_pp(ln, "ifndef")]
        count1 = len([ln for (no, ln) in ls1 if guard in ln])
        count2 = len([ln for (no, ln) in ls2 if guard in ln])
        if (count1 != count2) or (count1 != 1):
            self.warn("Pre-processing guard (use: {0})".format(guard))

    def check_lspace_between_func_decl(self) -> None:
        """Ensure at least single blank line between two functions
        declarations"""
        decl = 0
        for (no, ln) in self.xlines:
            if re.match(RE_FUNC_DECL, ln) is not None:
                decl = decl + 1
            else:
                decl = 0
            if decl >= 2:
                self.warn("No space between functions declarations", no)

    def check_nodup_includes(self) -> None:
        """Ensure no duplicated includes, have right order"""
        includes = {}
        for (no, ln) in self.xlines:
            if ln.strip().startswith("#include"):
                inc = ln.split()[1]
                inc = inc.strip('"<>')
                if inc not in includes:
                    includes[inc] = [(no, ln)]
                else:
                    includes[inc].append((no, ln))
        for i in includes.keys():
            inc_i = includes[i]
            if len(inc_i) > 1:
                (no, ln) = inc_i[1]
                self.warn("Multi include '{0}'".format(i), no)

    def check_std_includes(self) -> None:
        """STD headers include must be with <>"""
        std_headers = (C_HEADERS + SYS_HEADERS).split()
        for (no, ln) in self.xlines:
            if ln.strip().startswith("#include"):
                inc = ln.split()[1]
                hdr = inc.strip('"<>')
                if hdr in std_headers and inc.startswith('"'):
                    self.warn("Malformed include: '{0}'".format(hdr), no)

    def check_includes_order(self) -> None:
        """Ensure system includes come first"""
        sys_includes = True
        for no, ln in self.xlines:
            if ln.strip().startswith("#include"):
                inc = ln.split()[1]
                if inc.startswith('"') and not "config" in inc:
                    sys_includes = False
                elif inc.startswith("<") and not sys_includes:
                    self.warn(
                        "Wrong include order: "
                        "'#include {0}'".format(inc), no)

    def check_includes_suffix(self) -> None:
        """Should not have non-headers includes"""
        for no, ln in self.xlines:
            if ln.strip().startswith("#include"):
                inc = ln.split()[1]
                inc = inc.strip('<">')
                if not inc.endswith(".h"):
                    self.error("Wrong header suffix: '{0}'".format(inc), no)

    def check_enum_def(self) -> None:
        """Enum-names should be all upper-case + underscores"""
        enum_lines = []
        in_enum_def = False
        for (no, ln) in self.xlines:
            if in_enum_def:
                enum_lines.append((no, ln))
            elif ln.startswith("enum ") and ("{" in ln):
                in_enum_def = True
            if ("}" in ln) or (";" in ln):
                in_enum_def = False
        for (no, ln) in enum_lines:
            toks = ln.strip("{[()]} \t\r\v\n").split()
            if len(toks):
                t = toks[0].strip("=;:")
                if len(t) and t.isalnum() and not t.isupper():
                    self.error("Illegal enum-name {0}".format(t), lnum=no)

    def check_empty_lines(self) -> None:
        """Limit the number of consecutive empty lines"""
        cnt = 0
        lnum = 0
        limit = EMPTYLINES_MAX
        for line in self.dat.split("\n"):
            lnum += 1
            if len(line.strip()) == 0:
                cnt += 1
            else:
                cnt = 0
            if cnt == limit:
                self.error("Too many empty lines", lnum)

    def check_close_braces(self) -> None:
        """Avoid empty lines before close-braces"""
        empty_line = False
        lnum = 0
        for line in self.dat.split("\n"):
            lnum += 1
            sln = line.strip()
            if len(sln) == 0:
                empty_line = True
            if sln == "}" and empty_line:
                self.warn("Closing brace after empty line", lnum)
            if len(sln) != 0:
                empty_line = False


# . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .


def report(path, lnum, msg) -> None:
    s = ""
    if path:
        s = s + os.path.relpath(path)
    if lnum:
        s = s + ":" + str(lnum)
    if PROGNAME:
        s = str(PROGNAME) + ": " + s
    print(s + ": " + msg)


def isreg(path: str) -> bool:
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except (NameError, OSError):
        pass


def checkcstyle(files: list) -> int:
    """Check C-style for input C files"""
    num_reports = 0
    for path in files:
        if isreg(path) and (iscfile(path) or ishfile(path)):
            for lnum, msg in FileChecker.create(path).check():
                report(path, lnum, msg)
                num_reports += 1
    return num_reports


def listfiles(path: str) -> list:
    """Recursive listing for C source/header files"""
    files = []
    for ff in os.listdir(path):
        if str(ff) == "." or str(ff) == "..":
            continue
        pf = os.path.abspath(os.path.join(path, ff))
        if os.path.isdir(pf):
            files = files + listfiles(pf)
        else:
            files.append(pf)
    return files


def resolvesources(sources: list) -> list:
    files = []
    if len(sources) == 0:
        files = listfiles(os.getcwd())
    else:
        for src in sources:
            if os.path.isdir(src):
                files = files + listfiles(src)
            else:
                files.append(src)
    return list(set(files))


def settitle(title: str) -> None:
    try:
        import setproctitle

        setproctitle.setproctitle(title)
    except ImportError:
        pass


def main() -> None:
    settitle(PROGNAME)
    num_reports = checkcstyle(resolvesources(sys.argv[1:]))
    if num_reports > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
