-include $(top_builddir)/common.mk

EXTRA_DIST = lsan_suppressions.txt
AM_CFLAGS = $(WARN_CFLAGS)

bin_PROGRAMS = silofs-utests
silofs_utests_CPPFLAGS = $(NULL)
silofs_utests_CPPFLAGS += -I$(top_builddir)/include
silofs_utests_CPPFLAGS += -I$(top_srcdir)/include
silofs_utests_CPPFLAGS += -I$(top_srcdir)/lib/include
silofs_utests_CPPFLAGS += -I$(top_srcdir)/lib
silofs_utests_CPPFLAGS += -DSILOFS_UNITEST=1
silofs_utests_CPPFLAGS += $(LIBGCRYPT_CFLAGS)
silofs_utests_LDFLAGS = $(NULL)
silofs_utests_LDFLAGS += $(PTHREAD_CFLAGS) $(PTHREAD_DEF)
silofs_utests_LDFLAGS += -L$(top_builddir)/lib
silofs_utests_LDFLAGS += -static
silofs_utests_LDADD = $(NULL)
silofs_utests_LDADD += @LIBS@
silofs_utests_LDADD += $(top_builddir)/lib/libsilofs.la
silofs_utests_LDADD += $(PTHREAD_LIBS)
silofs_utests_LDADD += $(LIBGCRYPT_LIBS)
silofs_utests_SOURCES = $(NULL)
silofs_utests_SOURCES += utests.h
silofs_utests_SOURCES += utests_main.c
silofs_utests_SOURCES += utests_exec.c
silofs_utests_SOURCES += utests_ops.c
silofs_utests_SOURCES += ut_avl.c
silofs_utests_SOURCES += ut_base64.c
silofs_utests_SOURCES += ut_dir_basic.c
silofs_utests_SOURCES += ut_dir_iter.c
silofs_utests_SOURCES += ut_dir_list.c
silofs_utests_SOURCES += ut_file_basic.c
silofs_utests_SOURCES += ut_file_copy_range.c
silofs_utests_SOURCES += ut_file_edges.c
silofs_utests_SOURCES += ut_file_falloc.c
silofs_utests_SOURCES += ut_file_fiemap.c
silofs_utests_SOURCES += ut_file_lseek.c
silofs_utests_SOURCES += ut_file_mthreads.c
silofs_utests_SOURCES += ut_file_random.c
silofs_utests_SOURCES += ut_file_ranges.c
silofs_utests_SOURCES += ut_file_records.c
silofs_utests_SOURCES += ut_file_rwiter.c
silofs_utests_SOURCES += ut_file_stat.c
silofs_utests_SOURCES += ut_file_trunc.c
silofs_utests_SOURCES += ut_fillfs.c
silofs_utests_SOURCES += ut_hamming.c
silofs_utests_SOURCES += ut_inspect.c
silofs_utests_SOURCES += ut_ioctl.c
silofs_utests_SOURCES += ut_namei.c
silofs_utests_SOURCES += ut_parseconf.c
silofs_utests_SOURCES += ut_qalloc.c
silofs_utests_SOURCES += ut_reload.c
silofs_utests_SOURCES += ut_rename.c
silofs_utests_SOURCES += ut_clone_basic.c
silofs_utests_SOURCES += ut_clone_io.c
silofs_utests_SOURCES += ut_statfs.c
silofs_utests_SOURCES += ut_strings.c
silofs_utests_SOURCES += ut_super.c
silofs_utests_SOURCES += ut_symlink.c
silofs_utests_SOURCES += ut_xattr.c


if SILOFS_RUN_UNITESTS
ut_check_dir := "$(builddir)/ut"

all-local:
	$(AM_V)mkdir -p $(ut_check_dir)

clean-local:
	$(AM_V)rm -rf $(ut_check_dir)

check-local: $(bin_PROGRAMS)
	$(AM_V)mkdir -p $(ut_check_dir)
	$(AM_V)rm -rf $(ut_check_dir)/*
	$(AM_V)echo "  TEST       " && \
	  $$(realpath "$^") -l $(SILOFS_UNITESTS_LEVEL) $(ut_check_dir) ;
	$(AM_V)rm -rf $(ut_check_dir)
endif
