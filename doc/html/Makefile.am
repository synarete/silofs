-include $(top_builddir)/common.mk
-include $(top_builddir)/sedsub.mk

EXTRA_DIST = $(NULL)
EXTRA_DIST += index.html.in
EXTRA_DIST += silofs.css
EXTRA_DIST += silofs.rst

if HAVE_RST2HTML

dist_doc_DATA = index.html silofs.html
DISTCLEANFILES = $(dist_doc_DATA)

rst2html = @RST2HTML@

all-local: $(HTMLPAGES)

dist-local: all-local

%.html: %.rst
	@echo "  RST2HTML $@" && \
	  $(rst2html) --stylesheet=$(srcdir)/silofs.css < $< > $@ ;

index.html: index.html.in
	@echo "  SED      $@"; $(PATSUBST) $< > $@ ;

endif


