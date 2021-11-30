SUBDIRS = completions scripts
-include $(top_builddir)/common.mk

bin_PROGRAMS = silofs
silofs_CPPFLAGS = -I$(top_srcdir)/include
silofs_LDFLAGS = $(NULL)
silofs_LDFLAGS += $(PTHREAD_CFLAGS) $(PTHREAD_DEF)
silofs_LDFLAGS += -L$(builddir)
silofs_LDFLAGS += -L$(top_builddir)/lib
silofs_LDFLAGS += -static
silofs_LDADD = @LIBS@
silofs_LDADD += $(top_builddir)/lib/libsilofs.la
silofs_LDADD += $(PTHREAD_LIBS)
silofs_LDADD += $(LIBGCRYPT_LIBS)
silofs_SOURCES = $(NULL)
silofs_SOURCES += archive.c
silofs_SOURCES += common.c
silofs_SOURCES += fsck.c
silofs_SOURCES += getpass.c
silofs_SOURCES += lsmnt.c
silofs_SOURCES += main.c
silofs_SOURCES += mkfs.c
silofs_SOURCES += mount.c
silofs_SOURCES += prune.c
silofs_SOURCES += rconf.c
silofs_SOURCES += refs.c
silofs_SOURCES += show.c
silofs_SOURCES += signals.c
silofs_SOURCES += snap.c
silofs_SOURCES += umount.c

