AC_DEFUN([AX_SILOFS_NEED_SYSDEFS],
[
  AX_SILOFS_NEED_SYSDEF(SYS_getdents64)
  AX_SILOFS_NEED_SYSDEF(SYS_landlock_add_rule)
  AX_SILOFS_NEED_SYSDEF(SYS_landlock_create_ruleset)
  AX_SILOFS_NEED_SYSDEF(SYS_landlock_restrict_self)
])

AC_DEFUN([AX_SILOFS_NEED_SYSDEF],
[AC_CACHE_CHECK([for $1], [ax_cv_sysdef_$1_defined],
[AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM(
    [[
        #include <sys/types.h>
        #include <sys/syscall.h>
        #ifndef $1
        #error missing $1
        #endif
    ]],
    [[]])
  ],
  [ax_cv_sysdef_$1_defined=yes],
  [ax_cv_sysdef_$1_defined=no])
])
  if test $ax_cv_sysdef_$1_defined != yes; then
    AC_MSG_ERROR([Unable to find system-def $1])
  fi
])
