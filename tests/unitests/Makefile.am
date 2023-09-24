-include $(top_builddir)/common.mk

bin_PROGRAMS = silofs-unitests
silofs_unitests_CPPFLAGS = $(NULL)
silofs_unitests_CPPFLAGS += -I$(top_srcdir)/include
silofs_unitests_CPPFLAGS += -DSILOFS_UNITEST=1
silofs_unitests_LDFLAGS = $(NULL)
silofs_unitests_LDFLAGS += $(PTHREAD_CFLAGS) $(PTHREAD_DEF)
silofs_unitests_LDFLAGS += -L$(top_builddir)/lib
silofs_unitests_LDFLAGS += -static
silofs_unitests_LDADD = $(NULL)
silofs_unitests_LDADD += @LIBS@
silofs_unitests_LDADD += $(top_builddir)/lib/libsilofs.la
silofs_unitests_LDADD += $(PTHREAD_LIBS)
silofs_unitests_LDADD += $(LIBGCRYPT_LIBS)
silofs_unitests_SOURCES = $(NULL)
silofs_unitests_SOURCES += unitests.h
silofs_unitests_SOURCES += unitests_main.c
silofs_unitests_SOURCES += unitests_exec.c
silofs_unitests_SOURCES += unitests_ops.c
silofs_unitests_SOURCES += ut_alloc.c
silofs_unitests_SOURCES += ut_avl.c
silofs_unitests_SOURCES += ut_base64.c
silofs_unitests_SOURCES += ut_dir_basic.c
silofs_unitests_SOURCES += ut_dir_iter.c
silofs_unitests_SOURCES += ut_dir_list.c
silofs_unitests_SOURCES += ut_file_basic.c
silofs_unitests_SOURCES += ut_file_copyrange.c
silofs_unitests_SOURCES += ut_file_edges.c
silofs_unitests_SOURCES += ut_file_falloc.c
silofs_unitests_SOURCES += ut_file_fiemap.c
silofs_unitests_SOURCES += ut_file_lseek.c
silofs_unitests_SOURCES += ut_file_mthreads.c
silofs_unitests_SOURCES += ut_file_random.c
silofs_unitests_SOURCES += ut_file_ranges.c
silofs_unitests_SOURCES += ut_file_records.c
silofs_unitests_SOURCES += ut_file_rwiter.c
silofs_unitests_SOURCES += ut_file_stat.c
silofs_unitests_SOURCES += ut_file_trunc.c
silofs_unitests_SOURCES += ut_fillfs.c
silofs_unitests_SOURCES += ut_inspect.c
silofs_unitests_SOURCES += ut_ioctl.c
silofs_unitests_SOURCES += ut_namei.c
silofs_unitests_SOURCES += ut_reload.c
silofs_unitests_SOURCES += ut_rename.c
silofs_unitests_SOURCES += ut_snap_basic.c
silofs_unitests_SOURCES += ut_snap_io.c
silofs_unitests_SOURCES += ut_statfs.c
silofs_unitests_SOURCES += ut_strings.c
silofs_unitests_SOURCES += ut_super.c
silofs_unitests_SOURCES += ut_symlink.c
silofs_unitests_SOURCES += ut_xattr.c


if SILOFS_RUN_UNITESTS
ut_check_dir := "$(builddir)/ut"

all-local:
	@mkdir -p $(ut_check_dir)

clean-local:
	@rm -rf $(ut_check_dir)

check-local: $(bin_PROGRAMS)
	@mkdir -p $(ut_check_dir)
	@echo "  TEST       " && \
	  $$(realpath "$^") -l $(SILOFS_UNITESTS_LEVEL) $(ut_check_dir) ;
	@rm -rf $(ut_check_dir)
endif


