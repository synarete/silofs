-include $(top_builddir)/common.mk
-include $(top_builddir)/sedsub.mk
SUBDIRS = citests .
EXTRA_DIST = silofs-citests.in
CLEANFILES = silofs-citests
dist_bin_SCRIPTS = silofs-citests

silofs-citests: silofs-citests.in
	@echo "  SED      $@"; $(PATSUBST) "$<" > "$@" ; chmod +x "$@" ;

