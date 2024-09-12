-include $(top_builddir)/sedsub.mk

EXTRA_DIST = silofs-mountd.service.in
CLEANFILES = silofs-mountd.service

silofsmountdunitdir = $(prefix)/lib/systemd/system
silofsmountdunit_DATA = silofs-mountd.service

silofs-mountd.service: silofs-mountd.service.in
	$(silofs_sedsub) "$<" > "$@"

install-data-local: silofs-mountd.service
