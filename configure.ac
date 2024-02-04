dnl SPDX-License-Identifier: GPL-3.0-or-later
m4_define(SILOFS_VERSION, m4_esyscmd([./version.sh --version]))
AC_PREREQ([2.69])
AC_INIT([silofs],[SILOFS_VERSION],[synarete@xxxxxxxx])
AC_COPYRIGHT([Copyright (C) 2020-2024, Shachar Sharon])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([cmd/main.c])
AX_SILOFS_GLOBALS(silofs)
AX_CHECK_ENABLE_DEBUG(no, DEBUG)

AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET
AC_ARG_PROGRAM
AC_PRESERVE_HELP_ORDER
AC_USE_SYSTEM_EXTENSIONS

AM_INIT_AUTOMAKE([1.11 -Wall -Werror -Wno-portability
                  foreign silent-rules subdir-objects tar-pax])
dnl AM_MAINTAINER_MODE
AM_SILENT_RULES
AC_LANG([C])
AC_SUBST(AR_FLAGS, [cr])

dnl Package needs & wants; defined buy m4 sub-macros (order is important!)
AX_SILOFS_HAVE_ARGS
AX_SILOFS_WANT_PROGS
AX_SILOFS_WANT_CC
AX_SILOFS_NEED_CONFIG_H
AX_SILOFS_NEED_PROGS
AX_SILOFS_NEED_TYPES
AX_SILOFS_NEED_EXTRA_TYPES
AX_SILOFS_NEED_HEADERS
AX_SILOFS_NEED_LIBS
AX_SILOFS_WANT_LIBS
AX_SILOFS_NEED_FUNCS
AX_SILOFS_NEED_FUNCS2
AX_SILOFS_NEED_BUILTIN
AX_SILOFS_NEED_FUNC_ATTRIBUTE
AX_SILOFS_NEED_POSIX_ACL_DEFINES
AX_SILOFS_WANT_PYTHON
AX_SILOFS_WITH_PYTHON_SITE_PACKAGES

dnl Libtool
LT_PREREQ([2.2])
LT_INIT

dnl Generate output:
AC_CONFIG_HEADERS([include/config.h])
AC_CONFIG_FILES([common.mk])
AC_CONFIG_FILES([sedsub.mk])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([include/Makefile])
AC_CONFIG_FILES([lib/Makefile])
AC_CONFIG_FILES([cmd/Makefile])
AC_CONFIG_FILES([cmd/completions/Makefile])
AC_CONFIG_FILES([cmd/sbinutils/Makefile])
AC_CONFIG_FILES([mntd/Makefile])
AC_CONFIG_FILES([mntd/systemd/Makefile])
AC_CONFIG_FILES([tests/Makefile])
AC_CONFIG_FILES([tests/unitests/Makefile])
AC_CONFIG_FILES([tests/fftests/Makefile])
AC_CONFIG_FILES([tests/citests/Makefile])
AC_CONFIG_FILES([man/Makefile])
AC_CONFIG_FILES([docs/Makefile])
AC_CONFIG_FILES([scripts/Makefile])
AC_CONFIG_FILES([dist/Makefile])
AC_OUTPUT

AC_MSG_NOTICE([Package........: $pkg_name])
AC_MSG_NOTICE([Version........: $pkg_version])
AC_MSG_NOTICE([Release........: $pkg_release])
AC_MSG_NOTICE([Revision.......: $pkg_revision])
AC_MSG_NOTICE([Prefix.........: $prefix])
AC_MSG_NOTICE([Host...........: $host])
AC_MSG_NOTICE([Build..........: $build])
AC_MSG_NOTICE([Compiler.......: $CC])
