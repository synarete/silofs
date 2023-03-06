-include $(top_builddir)/common.mk
-include $(top_builddir)/sedsub.mk

nobase_include_HEADERS = $(NULL)
# infra
nobase_include_HEADERS += silofs/atomic.h
nobase_include_HEADERS += silofs/avl.h
nobase_include_HEADERS += silofs/base64.h
nobase_include_HEADERS += silofs/bytebuf.h
nobase_include_HEADERS += silofs/ccattr.h
nobase_include_HEADERS += silofs/consts.h
nobase_include_HEADERS += silofs/hash.h
nobase_include_HEADERS += silofs/iovec.h
nobase_include_HEADERS += silofs/list.h
nobase_include_HEADERS += silofs/logging.h
nobase_include_HEADERS += silofs/macros.h
nobase_include_HEADERS += silofs/panic.h
nobase_include_HEADERS += silofs/pipe.h
nobase_include_HEADERS += silofs/qalloc.h
nobase_include_HEADERS += silofs/random.h
nobase_include_HEADERS += silofs/socket.h
nobase_include_HEADERS += silofs/strings.h
nobase_include_HEADERS += silofs/syscall.h
nobase_include_HEADERS += silofs/thread.h
nobase_include_HEADERS += silofs/time.h
nobase_include_HEADERS += silofs/utility.h
nobase_include_HEADERS += silofs/version.h
nobase_include_HEADERS += silofs/infra.h
# fs
nobase_include_HEADERS += silofs/address.h
nobase_include_HEADERS += silofs/boot.h
nobase_include_HEADERS += silofs/cache.h
nobase_include_HEADERS += silofs/crypto.h
nobase_include_HEADERS += silofs/dir.h
nobase_include_HEADERS += silofs/encdec.h
nobase_include_HEADERS += silofs/errors.h
nobase_include_HEADERS += silofs/exec.h
nobase_include_HEADERS += silofs/file.h
nobase_include_HEADERS += silofs/flush.h
nobase_include_HEADERS += silofs/fuseq.h
nobase_include_HEADERS += silofs/idmap.h
nobase_include_HEADERS += silofs/inode.h
nobase_include_HEADERS += silofs/ioctls.h
nobase_include_HEADERS += silofs/mntsvc.h
nobase_include_HEADERS += silofs/namei.h
nobase_include_HEADERS += silofs/nodes.h
nobase_include_HEADERS += silofs/opers.h
nobase_include_HEADERS += silofs/repo.h
nobase_include_HEADERS += silofs/spclaim.h
nobase_include_HEADERS += silofs/spmaps.h
nobase_include_HEADERS += silofs/spxmap.h
nobase_include_HEADERS += silofs/stage.h
nobase_include_HEADERS += silofs/stats.h
nobase_include_HEADERS += silofs/super.h
nobase_include_HEADERS += silofs/symlink.h
nobase_include_HEADERS += silofs/task.h
nobase_include_HEADERS += silofs/types.h
nobase_include_HEADERS += silofs/uber.h
nobase_include_HEADERS += silofs/walk.h
nobase_include_HEADERS += silofs/xattr.h
nobase_include_HEADERS += silofs/zcmpr.h
nobase_include_HEADERS += silofs/fsdef.h
nobase_include_HEADERS += silofs/fs-private.h
nobase_include_HEADERS += silofs/fs.h

noinst_HEADERS = $(NULL)
noinst_HEADERS += config.h
noinst_HEADERS += config-am.h
noinst_HEADERS += silofs/configs.h
noinst_HEADERS += linux/fuse7.h

EXTRA_DIST = config-am.h.in

config-am.h: config-am.h.in
	@echo "  SED      $@"; $(PATSUBST) "$<" > "$@" ;

