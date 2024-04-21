-include $(top_builddir)/common.mk

EXTRA_DIST = $(NULL)
EXTRA_DIST += silofs.1.rst
EXTRA_DIST += silofs-mountd.8.rst

if HAVE_RST2MAN
_rst2man = @RST2MAN@
_rst2man_verbose = $(_rst2man_verbose_@AM_V@)
_rst2man_verbose_ = $(_rst2man_verbose_@AM_DEFAULT_V@)
_rst2man_verbose_0 = @echo "  RST2MAN  $@";
rst2man = $(_rst2man_verbose)$(_rst2man)

dist_man_MANS = $(NULL)
dist_man_MANS += silofs.1
dist_man_MANS += silofs-mountd.8
CLEANFILES = $(dist_man_MANS)

all-local: $(dist_man_MANS)

dist-local: all-local

%.1: %.1.rst
	$(rst2man) < "$<" > "$@"

%.8: %.8.rst
	$(rst2man) < "$<" > "$@"

endif


