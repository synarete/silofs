-include $(top_builddir)/common.mk
-include $(top_builddir)/sedsub.mk
SUBDIRS = archive citests .

noinst_SCRIPTS = pycheck.sh

dist_bin_SCRIPTS = $(NULL)
dist_bin_SCRIPTS += silofs-archive
dist_bin_SCRIPTS += silofs-citests

EXTRA_DIST = $(NULL)
EXTRA_DIST += pycheck.sh
EXTRA_DIST += pylintrc
EXTRA_DIST += silofs-archive.in
EXTRA_DIST += silofs-citests.in

CLEANFILES = $(NULL)
CLEANFILES += silofs-archive
CLEANFILES += silofs-citests


all-local: silofs-archive silofs-citests

silofs-%: silofs-%.in
	@echo "  SED      $@"; $(PATSUBST) "$<" > "$@" ; chmod +x "$@" ;
