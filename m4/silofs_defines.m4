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
        #include <string.h>
    ]],
    [[  size_t acl_access_len = strlen(XATTR_NAME_POSIX_ACL_ACCESS);
        size_t acl_default_len = strlen(XATTR_NAME_POSIX_ACL_DEFAULT);
        return (acl_access_len > 0) && (acl_default_len > 0);
    ]])
  ],
  [ac_cv_ax_posix_acl_defines=yes],
  [ac_cv_ax_posix_acl_defines=no])
])
  if test $ac_cv_ax_type_socklen_t != yes; then
    AC_MSG_ERROR([Unable to find POSIX ACL defines])
  fi
])


