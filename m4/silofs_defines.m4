AC_DEFUN([AX_SILOFS_NEED_DEFINES],
[
  AX_SILOFS_NEED_POSIX_ACL_DEFINES
])

AC_DEFUN([AX_SILOFS_NEED_POSIX_ACL_DEFINES],
[AC_CACHE_CHECK([for posix ACL xattr defines], [ac_cv_ax_posix_acl_defines],
[AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM(
    [[
        #include <linux/xattr.h>
        #ifndef XATTR_NAME_POSIX_ACL_ACCESS
        #error missing XATTR_NAME_POSIX_ACL_ACCESS
        #endif
        #ifndef XATTR_NAME_POSIX_ACL_DEFAULT
        #error missing XATTR_NAME_POSIX_ACL_DEFAULT
        #endif
    ]],
    [[]])
  ],
  [ac_cv_ax_posix_acl_defines=yes],
  [ac_cv_ax_posix_acl_defines=no])
])
  if test $ac_cv_ax_posix_acl_defines != yes; then
    AC_MSG_ERROR([Unable to find POSIX ACL defines])
  fi
])
