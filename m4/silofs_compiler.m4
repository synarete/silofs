AC_DEFUN([AX_SILOFS_NEED_COMPILER],
[
  AC_PROG_CC
  AC_PROG_CC_C_O
  AC_PROG_CPP
  AC_PROG_LN_S
  AC_PROG_RANLIB
  AX_PROG_CC_FOR_BUILD
])

AC_DEFUN([AX_SILOFS_WANT_COMPILER_OPTS],
[
  AC_C_BIGENDIAN
  AX_C___ATTRIBUTE__
  AX_COMPILER_VENDOR
  AX_COMPILER_FLAGS
  AX_CFLAGS_WARN_ALL
])

AC_DEFUN([AX_SILOFS_WANT_STD_C23],
[
  AX_CHECK_COMPILE_FLAG([-std=c23], [CFLAGS="$CFLAGS -std=c23"],
  [
  # Fallback: Check for the experimental C2x flag (for GCC 13 and earlier)
  AX_CHECK_COMPILE_FLAG([-std=c2x], [CFLAGS="$CFLAGS -std=c2x"])
  ])
])

AC_DEFUN([AX_SILOFS_WANT_C23_CONSTEXPR],
[
  AC_CACHE_CHECK([for C23 constexpr support],
    [ac_cv_c_constexpr],
    [
      AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([
        [constexpr int x = 10;]], [return x;])],
        [ac_cv_c_constexpr=yes], [ac_cv_c_constexpr=no])
    ])

  if test "x$ac_cv_c_constexpr" = "xno"; then
    AC_DEFINE([constexpr], [const],
      [Define 'constexpr' to 'const' due to missing C23 compiler support.])
  fi
])

AC_DEFUN([AX_SILOFS_WANT_C23_COMPILER],
[
  AX_SILOFS_WANT_STD_C23
  AX_SILOFS_WANT_C23_CONSTEXPR
])
