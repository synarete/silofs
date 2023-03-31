ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
SUBDIRS = . include lib cmd mntd tools tests man docs scripts dist

EXTRA_DIST = $(NULL)
EXTRA_DIST += README.md
EXTRA_DIST += bootstrap
EXTRA_DIST += version.sh
EXTRA_DIST += VERSION
EXTRA_DIST += REVISION
EXTRA_DIST += COPYING
EXTRA_DIST += TODO
EXTRA_DIST += common.mk.in
EXTRA_DIST += sedsub.mk.in
EXTRA_DIST += build-aux/autom4te.cfg.in
EXTRA_DIST += devel.mk

BUILT_SOURCES = REVISION
CLEANFILES = REVISION

REVISION:
	@$(top_srcdir)/version.sh --revision > $@
	@echo >> $@







