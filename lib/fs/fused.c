/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
 *
 * Silofs is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Silofs is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/fs/types.h>
#include <silofs/fs/boot.h>
#include <silofs/fs/opers.h>
#include <silofs/fs/ioctls.h>
#include <silofs/fs/fused.h>
#include <silofs/fs/private.h>
#include <linux/fuse7.h>
#include <unistd.h>
#include <errno.h>

typedef int (*silofs_opc_fn)(struct silofs_oper_ctx *);

static const struct silofs_fs_ctx *
opc_fs_ctx(const struct silofs_oper_ctx *opc)
{
	return  &opc->opc_fsc;
}

static int opc_setattr(struct silofs_oper_ctx *opc)
{
	const struct silofs_fs_ctx *fs_ctx = opc_fs_ctx(opc);
	const struct stat *tms = &opc->opc_in.setattr.tims;
	struct stat *out_st = &opc->opc_out.setattr.st;
	loff_t size;
	mode_t mode;
	uid_t uid;
	gid_t gid;
	ino_t ino;
	int err;

	ino = opc->opc_in.setattr.ino;
	err = silofs_fs_getattr(fs_ctx, ino, out_st);
	if (!err && opc->opc_in.setattr.set_amtime_now) {
		err = silofs_fs_utimens(fs_ctx, ino, tms, out_st);
	}
	if (!err && opc->opc_in.setattr.set_mode) {
		mode = opc->opc_in.setattr.mode;
		err = silofs_fs_chmod(fs_ctx, ino, mode, tms, out_st);
	}
	if (!err && opc->opc_in.setattr.set_uid_gid) {
		uid = opc->opc_in.setattr.uid;
		gid = opc->opc_in.setattr.gid;
		err = silofs_fs_chown(fs_ctx, ino, uid, gid, tms, out_st);
	}
	if (!err && opc->opc_in.setattr.set_size) {
		size = opc->opc_in.setattr.size;
		err = silofs_fs_truncate(fs_ctx, ino, size, out_st);
	}
	if (!err && opc->opc_in.setattr.set_amctime &&
	    !opc->opc_in.setattr.set_nontime) {
		err = silofs_fs_utimens(fs_ctx, ino, tms, out_st);
	}
	return err;
}

static int opc_lookup(struct silofs_oper_ctx *opc)
{
	return silofs_fs_lookup(opc_fs_ctx(opc),
	                        opc->opc_in.lookup.parent,
	                        opc->opc_in.lookup.name,
	                        &opc->opc_out.lookup.st);
}

static int opc_forget(struct silofs_oper_ctx *opc)
{
	return silofs_fs_forget(opc_fs_ctx(opc),
	                        opc->opc_in.forget.ino,
	                        opc->opc_in.forget.nlookup);
}

static int opc_forget_one(struct silofs_oper_ctx *opc,
                          const struct fuse_forget_one *one)
{
	return silofs_fs_forget(opc_fs_ctx(opc),
	                        (ino_t)(one->nodeid), one->nlookup);
}

static int opc_batch_forget(struct silofs_oper_ctx *opc)
{
	int err;

	for (size_t i = 0; i < opc->opc_in.batch_forget.count; ++i) {
		err = opc_forget_one(opc, &opc->opc_in.batch_forget.one[i]);
		unused(err);
	}
	return 0;
}

static int opc_getattr(struct silofs_oper_ctx *opc)
{
	return silofs_fs_getattr(opc_fs_ctx(opc),
	                         opc->opc_in.getattr.ino,
	                         &opc->opc_out.getattr.st);
}

static int opc_readlink(struct silofs_oper_ctx *opc)
{
	return silofs_fs_readlink(opc_fs_ctx(opc),
	                          opc->opc_in.readlink.ino,
	                          opc->opc_in.readlink.ptr,
	                          opc->opc_in.readlink.lim,
	                          &opc->opc_out.readlink.len);
}

static int opc_symlink(struct silofs_oper_ctx *opc)
{
	return silofs_fs_symlink(opc_fs_ctx(opc),
	                         opc->opc_in.symlink.parent,
	                         opc->opc_in.symlink.name,
	                         opc->opc_in.symlink.symval,
	                         &opc->opc_out.symlink.st);
}

static int opc_mknod(struct silofs_oper_ctx *opc)
{
	return silofs_fs_mknod(opc_fs_ctx(opc),
	                       opc->opc_in.mknod.parent,
	                       opc->opc_in.mknod.name,
	                       opc->opc_in.mknod.mode,
	                       opc->opc_in.mknod.rdev,
	                       &opc->opc_out.mknod.st);
}

static int opc_mkdir(struct silofs_oper_ctx *opc)
{
	return silofs_fs_mkdir(opc_fs_ctx(opc),
	                       opc->opc_in.mkdir.parent,
	                       opc->opc_in.mkdir.name,
	                       opc->opc_in.mkdir.mode,
	                       &opc->opc_out.mkdir.st);
}

static int opc_unlink(struct silofs_oper_ctx *opc)
{
	return silofs_fs_unlink(opc_fs_ctx(opc),
	                        opc->opc_in.unlink.parent,
	                        opc->opc_in.unlink.name);
}

static int opc_rmdir(struct silofs_oper_ctx *opc)
{
	return silofs_fs_rmdir(opc_fs_ctx(opc),
	                       opc->opc_in.rmdir.parent,
	                       opc->opc_in.rmdir.name);
}

static int opc_rename(struct silofs_oper_ctx *opc)
{
	return silofs_fs_rename(opc_fs_ctx(opc),
	                        opc->opc_in.rename.parent,
	                        opc->opc_in.rename.name,
	                        opc->opc_in.rename.newparent,
	                        opc->opc_in.rename.newname,
	                        opc->opc_in.rename.flags);
}

static int opc_link(struct silofs_oper_ctx *opc)
{
	return silofs_fs_link(opc_fs_ctx(opc),
	                      opc->opc_in.link.ino,
	                      opc->opc_in.link.parent,
	                      opc->opc_in.link.name,
	                      &opc->opc_out.link.st);
}

static int opc_open(struct silofs_oper_ctx *opc)
{
	return silofs_fs_open(opc_fs_ctx(opc),
	                      opc->opc_in.open.ino,
	                      opc->opc_in.open.o_flags);
}

static int opc_statfs(struct silofs_oper_ctx *opc)
{
	return silofs_fs_statfs(opc_fs_ctx(opc),
	                        opc->opc_in.statfs.ino,
	                        &opc->opc_out.statfs.stv);
}

static int opc_release(struct silofs_oper_ctx *opc)
{
	return silofs_fs_release(opc_fs_ctx(opc),
	                         opc->opc_in.release.ino,
	                         opc->opc_in.release.o_flags,
	                         opc->opc_in.release.flush);
}

static int opc_fsync(struct silofs_oper_ctx *opc)
{
	return silofs_fs_fsync(opc_fs_ctx(opc),
	                       opc->opc_in.fsync.ino,
	                       opc->opc_in.fsync.datasync);
}

static int opc_setxattr(struct silofs_oper_ctx *opc)
{
	return silofs_fs_setxattr(opc_fs_ctx(opc),
	                          opc->opc_in.setxattr.ino,
	                          opc->opc_in.setxattr.name,
	                          opc->opc_in.setxattr.value,
	                          opc->opc_in.setxattr.size,
	                          opc->opc_in.setxattr.flags,
	                          opc->opc_in.setxattr.kill_sgid);
}

static int opc_getxattr(struct silofs_oper_ctx *opc)
{
	return silofs_fs_getxattr(opc_fs_ctx(opc),
	                          opc->opc_in.getxattr.ino,
	                          opc->opc_in.getxattr.name,
	                          opc->opc_in.getxattr.buf,
	                          opc->opc_in.getxattr.size,
	                          &opc->opc_out.getxattr.size);
}

static int opc_listxattr(struct silofs_oper_ctx *opc)
{
	return silofs_fs_listxattr(opc_fs_ctx(opc),
	                           opc->opc_in.listxattr.ino,
	                           opc->opc_in.listxattr.lxa_ctx);
}

static int opc_removexattr(struct silofs_oper_ctx *opc)
{
	return silofs_fs_removexattr(opc_fs_ctx(opc),
	                             opc->opc_in.removexattr.ino,
	                             opc->opc_in.removexattr.name);
}

static int opc_flush(struct silofs_oper_ctx *opc)
{
	return silofs_fs_flush(opc_fs_ctx(opc), opc->opc_in.flush.ino);
}

static int opc_opendir(struct silofs_oper_ctx *opc)
{
	return silofs_fs_opendir(opc_fs_ctx(opc), opc->opc_in.opendir.ino);
}

static int opc_readdir(struct silofs_oper_ctx *opc)
{
	return silofs_fs_readdir(opc_fs_ctx(opc),
	                         opc->opc_in.readdir.ino,
	                         opc->opc_in.readdir.rd_ctx);
}

static int opc_readdirplus(struct silofs_oper_ctx *opc)
{
	return silofs_fs_readdirplus(opc_fs_ctx(opc),
	                             opc->opc_in.readdir.ino,
	                             opc->opc_in.readdir.rd_ctx);
}

static int opc_releasedir(struct silofs_oper_ctx *opc)
{
	return silofs_fs_releasedir(opc_fs_ctx(opc),
	                            opc->opc_in.releasedir.ino,
	                            opc->opc_in.releasedir.o_flags);
}

static int opc_fsyncdir(struct silofs_oper_ctx *opc)
{
	return silofs_fs_fsyncdir(opc_fs_ctx(opc),
	                          opc->opc_in.fsyncdir.ino,
	                          opc->opc_in.fsyncdir.datasync);
}

static int opc_access(struct silofs_oper_ctx *opc)
{
	return silofs_fs_access(opc_fs_ctx(opc),
	                        opc->opc_in.access.ino,
	                        opc->opc_in.access.mask);
}

static int opc_create(struct silofs_oper_ctx *opc)
{
	return silofs_fs_create(opc_fs_ctx(opc),
	                        opc->opc_in.create.parent,
	                        opc->opc_in.create.name,
	                        opc->opc_in.create.o_flags,
	                        opc->opc_in.create.mode,
	                        &opc->opc_out.create.st);
}

static int opc_fallocate(struct silofs_oper_ctx *opc)
{
	return silofs_fs_fallocate(opc_fs_ctx(opc),
	                           opc->opc_in.fallocate.ino,
	                           opc->opc_in.fallocate.mode,
	                           opc->opc_in.fallocate.off,
	                           opc->opc_in.fallocate.len);
}

static int opc_lseek(struct silofs_oper_ctx *opc)
{
	return silofs_fs_lseek(opc_fs_ctx(opc),
	                       opc->opc_in.lseek.ino,
	                       opc->opc_in.lseek.off,
	                       opc->opc_in.lseek.whence,
	                       &opc->opc_out.lseek.off);
}

static int opc_copy_file_range(struct silofs_oper_ctx *opc)
{
	return silofs_fs_copy_file_range(opc_fs_ctx(opc),
	                                 opc->opc_in.copy_file_range.ino_in,
	                                 opc->opc_in.copy_file_range.off_in,
	                                 opc->opc_in.copy_file_range.ino_out,
	                                 opc->opc_in.copy_file_range.off_out,
	                                 opc->opc_in.copy_file_range.len,
	                                 opc->opc_in.copy_file_range.flags,
	                                 &opc->opc_out.copy_file_range.ncp);
}

static int opc_read_buf(struct silofs_oper_ctx *opc)
{
	return silofs_fs_read(opc_fs_ctx(opc),
	                      opc->opc_in.read.ino,
	                      opc->opc_in.read.buf,
	                      opc->opc_in.read.len,
	                      opc->opc_in.read.off,
	                      &opc->opc_out.read.nrd);
}

static int opc_read_iter(struct silofs_oper_ctx *opc)
{
	return silofs_fs_read_iter(opc_fs_ctx(opc),
	                           opc->opc_in.read.ino,
	                           opc->opc_in.read.rwi_ctx);
}

static int opc_read(struct silofs_oper_ctx *opc)
{
	return (opc->opc_in.read.rwi_ctx != NULL) ?
	       opc_read_iter(opc) : opc_read_buf(opc);
}


static int opc_write_buf(struct silofs_oper_ctx *opc)
{
	return silofs_fs_write(opc_fs_ctx(opc),
	                       opc->opc_in.write.ino,
	                       opc->opc_in.write.buf,
	                       opc->opc_in.write.len,
	                       opc->opc_in.write.off,
	                       &opc->opc_out.write.nwr);
}

static int opc_write_iter(struct silofs_oper_ctx *opc)
{
	return silofs_fs_write_iter(opc_fs_ctx(opc),
	                            opc->opc_in.write.ino,
	                            opc->opc_in.write.rwi_ctx);
}

static int opc_write(struct silofs_oper_ctx *opc)
{
	return (opc->opc_in.write.rwi_ctx != NULL) ?
	       opc_write_iter(opc) : opc_write_buf(opc);
}

static int opc_syncfs(struct silofs_oper_ctx *opc)
{
	return silofs_fs_syncfs(opc_fs_ctx(opc), opc->opc_in.syncfs.ino);
}

static int opc_ioctl_query(struct silofs_oper_ctx *opc)
{
	return silofs_fs_query(opc_fs_ctx(opc),
	                       opc->opc_in.query.ino,
	                       opc->opc_in.query.qtype,
	                       &opc->opc_out.query.qry);
}

static int opc_ioctl_clone(struct silofs_oper_ctx *opc)
{
	return silofs_fs_clone(opc_fs_ctx(opc),
	                       opc->opc_in.clone.ino,
	                       opc->opc_in.clone.flags,
	                       &opc->opc_out.clone.bsecs);
}

static int opc_ioctl(struct silofs_oper_ctx *opc)
{
	int ret;

	if (opc->opc_ioc_cmd == SILOFS_FS_IOC_QUERY) {
		ret = opc_ioctl_query(opc);
	} else if (opc->opc_ioc_cmd == SILOFS_FS_IOC_CLONE) {
		ret = opc_ioctl_clone(opc);
	} else {
		ret = -ENOSYS;
	}
	return ret;
}

static const silofs_opc_fn silofs_opc_tbl[] = {
	[FUSE_LOOKUP]           = opc_lookup,
	[FUSE_FORGET]           = opc_forget,
	[FUSE_GETATTR]          = opc_getattr,
	[FUSE_SETATTR]          = opc_setattr,
	[FUSE_READLINK]         = opc_readlink,
	[FUSE_SYMLINK]          = opc_symlink,
	[FUSE_MKNOD]            = opc_mknod,
	[FUSE_MKDIR]            = opc_mkdir,
	[FUSE_UNLINK]           = opc_unlink,
	[FUSE_RMDIR]            = opc_rmdir,
	[FUSE_RENAME]           = opc_rename,
	[FUSE_LINK]             = opc_link,
	[FUSE_OPEN]             = opc_open,
	[FUSE_READ]             = opc_read,
	[FUSE_WRITE]            = opc_write,
	[FUSE_STATFS]           = opc_statfs,
	[FUSE_RELEASE]          = opc_release,
	[FUSE_FSYNC]            = opc_fsync,
	[FUSE_SETXATTR]         = opc_setxattr,
	[FUSE_GETXATTR]         = opc_getxattr,
	[FUSE_LISTXATTR]        = opc_listxattr,
	[FUSE_REMOVEXATTR]      = opc_removexattr,
	[FUSE_FLUSH]            = opc_flush,
	[FUSE_OPENDIR]          = opc_opendir,
	[FUSE_READDIR]          = opc_readdir,
	[FUSE_RELEASEDIR]       = opc_releasedir,
	[FUSE_FSYNCDIR]         = opc_fsyncdir,
	[FUSE_ACCESS]           = opc_access,
	[FUSE_CREATE]           = opc_create,
	[FUSE_BATCH_FORGET]     = opc_batch_forget,
	[FUSE_FALLOCATE]        = opc_fallocate,
	[FUSE_READDIRPLUS]      = opc_readdirplus,
	[FUSE_RENAME2]          = opc_rename,
	[FUSE_LSEEK]            = opc_lseek,
	[FUSE_COPY_FILE_RANGE]  = opc_copy_file_range,
	[FUSE_SYNCFS]           = opc_syncfs,
	[FUSE_IOCTL]            = opc_ioctl,
};


static int opcode_of(const struct silofs_oper_ctx *opc)
{
	return opc->opc_fsc.fsc_oper.op_code;
}

static silofs_opc_fn hook_of(const struct silofs_oper_ctx *opc)
{
	const int opcode = opcode_of(opc);
	const size_t slot = (size_t)opcode;
	silofs_opc_fn hook = NULL;

	if (slot && (slot < ARRAY_SIZE(silofs_opc_tbl))) {
		hook = silofs_opc_tbl[slot];
	}
	return hook;
}

int silofs_exec_fs_oper(struct silofs_oper_ctx *opc)
{
	silofs_opc_fn hook;
	int ret;

	hook = hook_of(opc);
	if (hook != NULL) {
		ret = hook(opc);
	} else {
		ret = -ENOSYS;
	}
	return ret;
}

int silofs_operctx_init(struct silofs_oper_ctx *opc)
{
	silofs_memzero(opc, sizeof(*opc));
	return 0;
}

void silofs_operctx_fini(struct silofs_oper_ctx *opc)
{
	silofs_memffff(opc, sizeof(*opc));
}

