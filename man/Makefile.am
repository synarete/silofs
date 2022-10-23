-include $(top_builddir)/common.mk
-include $(top_builddir)/sedsub.mk

EXTRA_DIST = $(NULL)
EXTRA_DIST += silofs.1.rst
EXTRA_DIST += silofs-mountd.8.rst

if HAVE_RST2MAN
dist_man_MANS = $(NULL)
dist_man_MANS += silofs.1
dist_man_MANS += silofs-mountd.8
CLEANFILES = $(dist_man_MANS)

all-local: $(dist_man_MANS)

dist-local: all-local


rst2man = @RST2MAN@

%.1: %.1.rst
	@echo "  RST2MAN  $@" && $(rst2man) < $< > $@ ;

%.8: %.8.rst
	@echo "  RST2MAN  $@" && $(rst2man) < $< > $@ ;

endif


