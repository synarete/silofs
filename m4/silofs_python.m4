AC_DEFUN([AX_SILOFS_WANT_PYTHON],
[
  AM_PATH_PYTHON([3.9])
  AX_PYTHON
  AX_PYTHON_MODULE([pathlib], [1])
  AX_PYTHON_MODULE([errno], [1])
  AX_PYTHON_MODULE([typing], [1])
  AX_PYTHON_MODULE([concurrent], [1])
])

AC_DEFUN([AX_SILOFS_WITH_PYTHON_SITE_PACKAGES],
[
  AC_ARG_WITH([python-site-packages],
    AS_HELP_STRING([--with-python-site-packages],
      [Install dir for silofs python module]),
      [], [with_python_site_packages="${withval}"])

  AS_IF([test "x$with_python_site_packages" != "x"], [
    pythondir="${with_python_site_packages}"
  ])
])

