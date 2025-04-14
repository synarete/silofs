AC_DEFUN([AX_SILOFS_NEED_SYSDEFS],
[
  AX_SILOFS_NEED_SYSDEF(SYS_getdents64)
])

AC_DEFUN([AX_SILOFS_NEED_SYSDEF],
[AC_CACHE_CHECK([for $1 syscall def], [ax_cv_sysdef_$1_defined],
[AC_RUN_IFELSE(
  [AC_LANG_PROGRAM(
    [[
        #include <sys/types.h>
        #include <sys/syscall.h>
        #include <unistd.h>
        #include <stdlib.h>
    ]],
    [[
        int sysdef = $1;

        return (sysdef > 0) ? 0 : 1;
    ]])
  ],
  [ax_cv_sysdef_$1_defined=yes],
  [ax_cv_sysdef_$1_defined=no],
  [ax_cv_sysdef_$1_defined=no])
])
  if test $ax_cv_sysdef_$1_defined != yes; then
    AC_MSG_ERROR([Unable to find system-def $1])
  fi
])
