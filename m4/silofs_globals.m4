
AC_DEFUN([AX_SILOFS_GLOBALS],
[
  pkg_name="$1"
  AC_SUBST(pkg_name)

  pkg_version=m4_esyscmd([./version.sh --version])
  AC_SUBST(pkg_version)

  pkg_version_major=m4_esyscmd([./version.sh --major])
  AC_SUBST(pkg_version_major)

  pkg_version_minor=m4_esyscmd([./version.sh --minor])
  AC_SUBST(pkg_version_minor)

  pkg_version_sublevel=m4_esyscmd([./version.sh --sublevel])
  AC_SUBST(pkg_version_sublevel)

  pkg_release=m4_esyscmd([./version.sh --release])
  AC_SUBST(pkg_release)

  pkg_revision=m4_esyscmd([./version.sh --revision])
  AC_SUBST(pkg_revision)

  AC_MSG_CHECKING([top-level version])
  AS_IF([test "x$PACKAGE_VERSION" = "x$pkg_version"],
    [AC_MSG_RESULT([$PACKAGE_VERSION])],
    [AC_MSG_ERROR([$PACKAGE_VERSION != $pkg_version])])
])

