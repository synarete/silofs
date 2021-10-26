-include $(top_builddir)/common.mk

libsilofsdir = $(libdir)
libsilofs_LTLIBRARIES = libsilofs.la
libsilofs_la_LDFLAGS = $(NULL)
libsilofs_la_LDFLAGS += $(PTHREAD_CFLAGS) $(PTHREAD_DEF)
libsilofs_la_LDFLAGS += -version-info 0
libsilofs_la_CPPFLAGS = $(NULL)
libsilofs_la_CPPFLAGS += -I$(top_srcdir)/include
libsilofs_la_CPPFLAGS += -DSILOFS_USE_PRIVATE=1
libsilofs_la_LIBADD = @LIBS@
libsilofs_la_LIBADD += $(PTHREAD_LIBS)
libsilofs_la_SOURCES = $(NULL)
libsilofs_la_SOURCES += address.c
libsilofs_la_SOURCES += apex.c
libsilofs_la_SOURCES += boot.c
libsilofs_la_SOURCES += cache.c
libsilofs_la_SOURCES += crypto.c
libsilofs_la_SOURCES += dir.c
libsilofs_la_SOURCES += exec.c
libsilofs_la_SOURCES += file.c
libsilofs_la_SOURCES += fuseq.c
libsilofs_la_SOURCES += guarantee.c
libsilofs_la_SOURCES += inode.c
libsilofs_la_SOURCES += itable.c
libsilofs_la_SOURCES += mntsvc.c
libsilofs_la_SOURCES += mpool.c
libsilofs_la_SOURCES += namei.c
libsilofs_la_SOURCES += nodes.c
libsilofs_la_SOURCES += opers.c
libsilofs_la_SOURCES += repo.c
libsilofs_la_SOURCES += spclaim.c
libsilofs_la_SOURCES += spmaps.c
libsilofs_la_SOURCES += spxmap.c
libsilofs_la_SOURCES += super.c
libsilofs_la_SOURCES += symlink.c
libsilofs_la_SOURCES += xattr.c
