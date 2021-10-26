AC_DEFUN([AX_SILOFS_WANT_SYSTEMD],
[
  dnl See 'man (7) daemon' for complete example with pkg-config
  PKG_PROG_PKG_CONFIG
  AC_ARG_WITH([systemdsystemunitdir],
    [AS_HELP_STRING([--with-systemdsystemunitdir=DIR],
      [Directory for systemd service files])],,
      [with_systemdsystemunitdir=yes])

  AS_IF([test "x$with_systemdsystemunitdir" = "xauto"], [
    pkg_config_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)

    AC_SUBST([systemdsystemunitdir], [$pkg_config_systemdsystemunitdir])
  ])

  AS_IF([test "x$with_systemdsystemunitdir" != "xno"],
    [AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])])

  AM_CONDITIONAL([HAVE_SYSTEMD], [test "x$with_systemdsystemunitdir" != "xno"])
])
