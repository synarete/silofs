ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
SUBDIRS = . include lib src test py man docs scripts dist cicd

EXTRA_DIST = $(NULL)
EXTRA_DIST += README.md
EXTRA_DIST += bootstrap
EXTRA_DIST += version.sh
EXTRA_DIST += cstylefmt.sh
EXTRA_DIST += VERSION
EXTRA_DIST += REVISION
EXTRA_DIST += COPYING
EXTRA_DIST += TODO
EXTRA_DIST += devel.mk
EXTRA_DIST += common.mk.in
EXTRA_DIST += sedsub.mk.in
EXTRA_DIST += build-aux/autom4te.cfg.in

BUILT_SOURCES = REVISION
CLEANFILES = REVISION

REVISION:
	@$(top_srcdir)/version.sh --revision > $@
	@echo >> $@
