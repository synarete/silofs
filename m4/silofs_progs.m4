AC_DEFUN([AX_SILOFS_NEED_PROGS],
[
  AC_PROG_CC
  AC_PROG_CPP
  AC_PROG_CXX
  AC_PROG_INSTALL
  AC_PROG_MKDIR_P
  AC_PROG_LN_S
  AC_PROG_SED
  AC_PROG_RANLIB
  AC_PROG_GREP
  AC_PROG_MAKE_SET
])

AC_DEFUN([AX_SILOFS_WANT_PROGS],
[
  AC_PATH_PROG(RST2MAN, rst2man)
  AS_IF([test -x "$RST2MAN"],
    [
      AM_CONDITIONAL([HAVE_RST2MAN], true)
    ],
    [
      AC_MSG_WARN([Unable to build MANs without docutils])
      AM_CONDITIONAL([HAVE_RST2MAN], false)
    ])

  AC_PATH_PROG(RST2HTML, rst2html)
  AS_IF([test -x "$RST2HTML"],
    [
      AM_CONDITIONAL([HAVE_RST2HTML], true)
    ],
    [
      AC_MSG_WARN([Unable to build HTMLs without docutils])
      AM_CONDITIONAL([HAVE_RST2HTML], false)
    ])
])

AC_DEFUN([AX_SILOFS_WANT_CC],
[
  AX_COMPILER_VENDOR
  dnl AX_CFLAGS_WARN_ALL
])


