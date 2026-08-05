AC_DEFUN([AX_SILOFS_WANT_SYSTEMD],
[
  dnl See 'man (7) daemon' for complete example with pkg-config
  PKG_PROG_PKG_CONFIG
  AC_ARG_WITH([systemdsystemunitdir],
    [AS_HELP_STRING([--with-systemdsystemunitdir=DIR],
      [Directory for systemd service files])],,
      [with_systemdsystemunitdir=auto])

  AS_IF([test "x$with_systemdsystemunitdir" = "xauto"], [
    AS_IF([test -n "$PKG_CONFIG"], [
      with_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd 2>/dev/null)
    ])
    AS_IF([test -z "$with_systemdsystemunitdir"], [
      with_systemdsystemunitdir=no
    ])
  ])

  AS_IF([test "x$with_systemdsystemunitdir" != "xno"],
    [AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])])

  AM_CONDITIONAL([HAVE_SYSTEMD], [test "x$with_systemdsystemunitdir" != "xno"])
])
