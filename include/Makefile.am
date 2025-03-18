-include $(top_builddir)/sedsub.mk

noinst_HEADERS = $(NULL)
noinst_HEADERS += config.h
noinst_HEADERS += config-am.h
noinst_HEADERS += linux/fuse_kernel.h

nobase_include_HEADERS = $(NULL)
nobase_include_HEADERS += silofs/appexec.h
nobase_include_HEADERS += silofs/ccattr.h
nobase_include_HEADERS += silofs/consts.h
nobase_include_HEADERS += silofs/defs.h
nobase_include_HEADERS += silofs/errors.h
nobase_include_HEADERS += silofs/ioctls.h
nobase_include_HEADERS += silofs/logging.h
nobase_include_HEADERS += silofs/macros.h
nobase_include_HEADERS += silofs/memalloc.h
nobase_include_HEADERS += silofs/mntsvc.h
nobase_include_HEADERS += silofs/panic.h
nobase_include_HEADERS += silofs/random.h
nobase_include_HEADERS += silofs/silofs.h
nobase_include_HEADERS += silofs/syscall.h
nobase_include_HEADERS += silofs/thread.h
nobase_include_HEADERS += silofs/types.h
nobase_include_HEADERS += silofs/version.h


EXTRA_DIST = config-am.h.in

config-am.h: config-am.h.in
	$(silofs_sedsub) "$<" > "$@"
