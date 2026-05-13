-include $(top_builddir)/sedsub.mk

noinst_HEADERS = $(NULL)
noinst_HEADERS += silofs/config.h
noinst_HEADERS += silofs/config-am.h
noinst_HEADERS += silofs/configs.h

nobase_include_HEADERS = $(NULL)
nobase_include_HEADERS += silofs/appexec.h
nobase_include_HEADERS += silofs/api.h
nobase_include_HEADERS += silofs/ccattr.h
nobase_include_HEADERS += silofs/consts.h
nobase_include_HEADERS += silofs/errors.h
nobase_include_HEADERS += silofs/ioctls.h
nobase_include_HEADERS += silofs/logging.h
nobase_include_HEADERS += silofs/macros.h
nobase_include_HEADERS += silofs/memalloc.h
nobase_include_HEADERS += silofs/mntsvc.h
nobase_include_HEADERS += silofs/ondisk.h
nobase_include_HEADERS += silofs/panic.h
nobase_include_HEADERS += silofs/snprintf.h
nobase_include_HEADERS += silofs/syscall.h
nobase_include_HEADERS += silofs/types.h
nobase_include_HEADERS += silofs/version.h


EXTRA_DIST = silofs/config-am.h.in

silofs/config-am.h: silofs/config-am.h.in
	$(silofs_sedsub) "$<" > "$@"
