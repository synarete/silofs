-include $(top_builddir)/sedsub.mk
SUBDIRS = systemd

sbin_PROGRAMS = silofs-mountd
silofs_mountd_CPPFLAGS = -I$(top_srcdir)/include
silofs_mountd_LDFLAGS = $(NULL)
silofs_mountd_LDFLAGS += $(PTHREAD_CFLAGS) $(PTHREAD_DEF)
silofs_mountd_LDFLAGS += -L$(builddir)
silofs_mountd_LDFLAGS += -L$(top_builddir)/src/lib
silofs_mountd_LDFLAGS += -static
silofs_mountd_LDADD = @LIBS@
silofs_mountd_LDADD += $(top_builddir)/src/lib/libsilofs.la
silofs_mountd_LDADD += $(PTHREAD_LIBS)
silofs_mountd_LDADD += $(LIBGCRYPT_LIBS)

silofs_mountd_SOURCES = $(NULL)
silofs_mountd_SOURCES += mntconf.c
silofs_mountd_SOURCES += mountd.c
silofs_mountd_SOURCES += mountd.h

EXTRA_DIST = mountd.conf.in
CLEANFILES = $(silofs_mountd_conf_DATA)
silofs_mountd_confdir = $(sysconfdir)/silofs
silofs_mountd_conf_DATA = mountd.conf

mountd.conf: mountd.conf.in
	$(silofs_sedsub) $< > $@ ;

install-data-local:
	$(AM_V)install -d $(DESTDIR)$(localstatedir)/run/silofs
