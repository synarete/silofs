-include $(top_builddir)/sedsub.mk

EXTRA_DIST = $(NULL)
EXTRA_DIST += index.html.in
EXTRA_DIST += silofs.css
EXTRA_DIST += silofs.rst

if HAVE_RST2HTML
_rst2html = @RST2HTML@
_rst2html_verbose = $(_rst2html_verbose_@AM_V@)
_rst2html_verbose_ = $(_rst2html_verbose_@AM_DEFAULT_V@)
_rst2html_verbose_0 = @echo "  RST2HTML $@";
rst2html = $(_rst2html_verbose)$(_rst2html)

dist_doc_DATA = $(NULL)
dist_doc_DATA += index.html
dist_doc_DATA += silofs.html
CLEANFILES = $(dist_doc_DATA)

all-local: $(dist_doc_DATA)

dist-local: all-local


%.html: %.rst
	$(rst2html) --stylesheet=$(srcdir)/silofs.css < "$<" > "$@"

index.html: index.html.in
	$(silofs_sedsub) "$<" > "$@"

endif


