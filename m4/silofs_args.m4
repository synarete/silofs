AC_DEFUN([AX_SILOFS_HAVE_ARGS],
[
  AC_ARG_ENABLE([debug],
    AS_HELP_STRING([--enable-debug], [Enable debug mode]))

  AS_IF([test "x$enable_debug" = "xyes"], [AC_MSG_NOTICE([Debug mode])])

  AC_ARG_ENABLE([unitests],
    [  --enable-unitests    Execute unitests upon check],
    [case "${enableval}" in
       yes) unitests=true ;;
       no)  unitests=false ;;
       *) AC_MSG_ERROR([bad value ${enableval} for --enable-unitests]) ;;
     esac], [unitests=false])

  AM_CONDITIONAL([SILOFS_RUN_UNITESTS], [test x$unitests = xtrue])
])

