-include $(top_builddir)/sedsub.mk
SUBDIRS = archive qatests .

noinst_SCRIPTS = pycheck.sh

dist_bin_SCRIPTS = $(NULL)
dist_bin_SCRIPTS += silofs-archive
dist_bin_SCRIPTS += silofs-qatests

EXTRA_DIST = $(NULL)
EXTRA_DIST += pycheck.sh
EXTRA_DIST += pylintrc
EXTRA_DIST += silofs-archive.in
EXTRA_DIST += silofs-qatests.in

CLEANFILES = $(NULL)
CLEANFILES += silofs-archive
CLEANFILES += silofs-qatests


all-local: silofs-archive silofs-qatests

silofs-%: silofs-%.in
	$(silofs_sedsub) "$<" > "$@"
	$(AM_V)chmod +x "$@"
