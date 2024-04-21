-include $(top_builddir)/sedsub.mk
SUBDIRS = qatests .

noinst_SCRIPTS = pycheck.sh

dist_bin_SCRIPTS = $(NULL)
dist_bin_SCRIPTS += silofs-qatests

EXTRA_DIST = $(NULL)
EXTRA_DIST += pycheck.sh
EXTRA_DIST += pylintrc
EXTRA_DIST += silofs-qatests.in

CLEANFILES = $(NULL)
CLEANFILES += silofs-qatests


all-local: silofs-qatests

silofs-%: silofs-%.in
	$(silofs_sedsub) "$<" > "$@"
	$(AM_V)chmod +x "$@"
