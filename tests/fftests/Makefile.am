-include $(top_builddir)/common.mk

bin_PROGRAMS = silofs-fftests
silofs_fftests_CPPFLAGS = $(NULL)
silofs_fftests_CPPFLAGS += -I$(top_srcdir)/include
silofs_fftests_LDFLAGS = $(NULL)
silofs_fftests_LDFLAGS += -L$(top_builddir)/lib
silofs_fftests_LDFLAGS += -static
silofs_fftests_LDADD = @LIBS@
silofs_fftests_LDADD += $(top_builddir)/lib/libsilofs_infra.la
silofs_fftests_LDADD += $(PTHREAD_LIBS)
silofs_fftests_LDADD += $(LIBGCRYPT_LIBS)
silofs_fftests_SOURCES = $(NULL)
silofs_fftests_SOURCES += fftests_exec.c
silofs_fftests_SOURCES += fftests.h
silofs_fftests_SOURCES += fftests-inline.h
silofs_fftests_SOURCES += fftests_main.c
silofs_fftests_SOURCES += fftests_syscall.c
silofs_fftests_SOURCES += fftests_utility.c
silofs_fftests_SOURCES += test_access.c
silofs_fftests_SOURCES += test_boundaries.c
silofs_fftests_SOURCES += test_chmod_chown.c
silofs_fftests_SOURCES += test_copy_file_range.c
silofs_fftests_SOURCES += test_create.c
silofs_fftests_SOURCES += test_fallocate.c
silofs_fftests_SOURCES += test_fiemap.c
silofs_fftests_SOURCES += test_fifo.c
silofs_fftests_SOURCES += test_fsync.c
silofs_fftests_SOURCES += test_link.c
silofs_fftests_SOURCES += test_lseek.c
silofs_fftests_SOURCES += test_mkdir_rmdir.c
silofs_fftests_SOURCES += test_mmap_mt.c
silofs_fftests_SOURCES += test_mmap.c
silofs_fftests_SOURCES += test_namespace.c
silofs_fftests_SOURCES += test_open.c
silofs_fftests_SOURCES += test_readdir.c
silofs_fftests_SOURCES += test_rename.c
silofs_fftests_SOURCES += test_rw_basic.c
silofs_fftests_SOURCES += test_rw_large.c
silofs_fftests_SOURCES += test_rw_osync.c
silofs_fftests_SOURCES += test_rw_random.c
silofs_fftests_SOURCES += test_rw_sequential.c
silofs_fftests_SOURCES += test_rw_sparse.c
silofs_fftests_SOURCES += test_stat.c
silofs_fftests_SOURCES += test_stat_io.c
silofs_fftests_SOURCES += test_statvfs.c
silofs_fftests_SOURCES += test_symlink.c
silofs_fftests_SOURCES += test_tmpfile.c
silofs_fftests_SOURCES += test_truncate.c
silofs_fftests_SOURCES += test_truncate_file.c
silofs_fftests_SOURCES += test_unlink.c
silofs_fftests_SOURCES += test_unlinked_file.c
silofs_fftests_SOURCES += test_utimes.c
silofs_fftests_SOURCES += test_write.c
silofs_fftests_SOURCES += test_xattr.c
silofs_fftests_SOURCES += test_xstress_mt.c

