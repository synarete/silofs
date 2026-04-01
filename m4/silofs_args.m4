AC_DEFUN([AX_SILOFS_HAVE_ARGS],
[
  AC_ARG_ENABLE([debug],
    AS_HELP_STRING([--enable-debug], [Enable debug mode]))

  AS_IF([test "x$enable_debug" = "xyes"], [AC_MSG_NOTICE([Debug mode])])

  silofs_utests_level=0
  AC_ARG_ENABLE([utests],
    AS_HELP_STRING([--enable-utests], [Execute unit-tests upon check]),
    [case "${enableval}" in
       "0") silofs_utests_level=0 ;;
       "1") silofs_utests_level=1 ;;
       "2") silofs_utests_level=2 ;;
       *) AC_MSG_ERROR([bad value ${enableval} for --enable-utests]) ;;
     esac], [utests="1"])

  AC_SUBST([SILOFS_UNITESTS_LEVEL], [$silofs_utests_level])
  AM_CONDITIONAL([SILOFS_RUN_UNITESTS], [test "x$silofs_utests_level" != "x0"])
])
