-include $(top_builddir)/common.mk
-include $(top_builddir)/sedsub.mk
SUBDIRS = citests .

dist_bin_SCRIPTS = silofs-citests
noinst_SCRIPTS = pycheck.sh

EXTRA_DIST = $(NULL)
EXTRA_DIST += pycheck.sh
EXTRA_DIST += pylintrc
EXTRA_DIST += silofs-citests.in

CLEANFILES = silofs-citests

all-local: silofs-citests

silofs-citests: silofs-citests.in
	@echo "  SED      $@"; $(PATSUBST) "$<" > "$@" ; chmod +x "$@" ;

