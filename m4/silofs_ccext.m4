
AC_DEFUN([AX_SILOFS_NEED_BUILTIN],
[
  AX_GCC_BUILTIN(__builtin_clz)
  AX_GCC_BUILTIN(__builtin_expect)
  AX_GCC_BUILTIN(__builtin_popcount)
  AX_GCC_BUILTIN(__builtin_popcountl)
  AX_GCC_BUILTIN(__builtin_expect)
  AX_GCC_BUILTIN(__builtin_unreachable)
])

AC_DEFUN([AX_SILOFS_NEED_ATTRIBUTE],
[
  AX_GCC_FUNC_ATTRIBUTE(noreturn)
  AX_GCC_FUNC_ATTRIBUTE(noinline)
  AX_GCC_VAR_ATTRIBUTE(aligned)
  AX_GCC_VAR_ATTRIBUTE(packed)
  AX_GCC_VAR_ATTRIBUTE(unused)
])




