AC_DEFUN([AX_SILOFS_HAVE_ARGS],
[
  AC_ARG_ENABLE([debug],
    AS_HELP_STRING([--enable-debug], [Enable debug mode]))

  AS_IF([test "x$enable_debug" = "xyes"], [AC_MSG_NOTICE([Debug mode])])

  silofs_unitests_level=1
  AC_ARG_ENABLE([unitests],
    AS_HELP_STRING([--enable-unitests], [Execute unitests upon check]),
    [case "${enableval}" in
       "0") silofs_unitests_level=0 ;;
       "1") silofs_unitests_level=1 ;;
       "2") silofs_unitests_level=2 ;;
       *) AC_MSG_ERROR([bad value ${enableval} for --enable-unitests]) ;;
     esac], [unitests="1"])

  AC_SUBST(SILOFS_UNITESTS_LEVEL, $silofs_unitests_level)
  AM_CONDITIONAL([SILOFS_RUN_UNITESTS], [test "x$unitests_level" != "x0"])
])

