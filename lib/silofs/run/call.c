/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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
#include <silofs/fs.h>
#include "mbr.h"
#include "walk.h"
#include "env.h"
#include "call.h"
#include "exec.h"

static int
call_setattr(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	struct silofs_stat *out_st         = &args->out.setattr.st;
	const struct silofs_itimes *itimes = &args->in.setattr.itimes;
	const ino_t ino                    = args->in.setattr.ino;
	int err                            = 0;

	out_st->gen = 0;
	if (args->in.setattr.set_amtime_now) {
		err = silofs_exec_utimens(task, ino, itimes, out_st);
		if (err) {
			return err;
		}
	}
	if (args->in.setattr.set_mode) {
		const mode_t mode = args->in.setattr.mode;

		err = silofs_exec_chmod(task, ino, mode, itimes, out_st);
		if (err) {
			return err;
		}
	}
	if (args->in.setattr.set_uid_gid) {
		const uid_t uid         = args->in.setattr.uid;
		const gid_t gid         = args->in.setattr.gid;
		const bool kill_suidgid = args->in.setattr.kill_suidgid;

		err = silofs_exec_chown(task, ino, uid, gid, kill_suidgid,
		                        itimes, out_st);
		if (err) {
			return err;
		}
	}
	if (args->in.setattr.set_size) {
		const off_t size        = args->in.setattr.size;
		const bool kill_suidgid = args->in.setattr.kill_suidgid;

		err = silofs_exec_truncate(task, ino, size, kill_suidgid,
		                           out_st);
		if (err) {
			return err;
		}
	}
	if (args->in.setattr.set_amctime && !args->in.setattr.set_nontime) {
		err = silofs_exec_utimens(task, ino, itimes, out_st);
		if (err) {
			return err;
		}
	}

	if (!out_st->gen) {
		err = silofs_exec_getattr(task, ino, out_st);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int
call_lookup(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_lookup(task, args->in.lookup.parent,
	                          args->in.lookup.name, &args->out.lookup.st);
}

static int
call_forget(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_forget(task, args->in.forget.ino,
	                          args->in.forget.nlookup);
}

static int
call_batch_forget(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	int err;

	for (size_t i = 0; i < args->in.batch_forget.count; ++i) {
		const struct silofs_forget_in *one =
			&args->in.batch_forget.one[i];

		err = silofs_exec_forget(task, one->ino, one->nlookup);
		unused(err);
	}
	return 0;
}

static int
call_getattr(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_getattr(task, args->in.getattr.ino,
	                           &args->out.getattr.st);
}

static int
call_statx(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_statx(task, args->in.statx.ino,
	                         args->in.statx.sx_mask, &args->out.statx.st);
}

static int
call_readlink(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_readlink(task, args->in.readlink.ino,
	                            args->in.readlink.ptr,
	                            args->in.readlink.lim,
	                            &args->out.readlink.len);
}

static int
call_symlink(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_symlink(task, args->in.symlink.parent,
	                           args->in.symlink.name,
	                           args->in.symlink.symval,
	                           &args->out.symlink.st);
}

static int
call_mknod(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_mknod(task, args->in.mknod.parent,
	                         args->in.mknod.name, args->in.mknod.mode,
	                         args->in.mknod.rdev, &args->out.mknod.st);
}

static int
call_mkdir(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_mkdir(task, args->in.mkdir.parent,
	                         args->in.mkdir.name, args->in.mkdir.mode,
	                         &args->out.mkdir.st);
}

static int
call_unlink(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_unlink(task, args->in.unlink.parent,
	                          args->in.unlink.name);
}

static int
call_rmdir(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_rmdir(task, args->in.rmdir.parent,
	                         args->in.rmdir.name);
}

static int
call_rename(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_rename(task, args->in.rename.parent,
	                          args->in.rename.name,
	                          args->in.rename.newparent,
	                          args->in.rename.newname,
	                          args->in.rename.flags);
}

static int
call_link(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_link(task, args->in.link.ino, args->in.link.parent,
	                        args->in.link.name, &args->out.link.st);
}

static int
call_open(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_open(task, args->in.open.ino, args->in.open.o_flags,
	                        args->in.open.kill_suidgid);
}

static int
call_statfs(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_statfs(task, args->in.statfs.ino,
	                          &args->out.statfs.stv);
}

static int
call_release(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_release(task, args->in.release.ino,
	                           args->in.release.o_flags,
	                           args->in.release.flush);
}

static int
call_fsync(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_fsync(task, args->in.fsync.ino,
	                         args->in.fsync.datasync);
}

static int
call_setxattr(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_setxattr(
		task, args->in.setxattr.ino, args->in.setxattr.name,
		args->in.setxattr.value, args->in.setxattr.size,
		args->in.setxattr.flags, args->in.setxattr.kill_sgid);
}

static int
call_getxattr(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_getxattr(task, args->in.getxattr.ino,
	                            args->in.getxattr.name,
	                            args->in.getxattr.buf,
	                            args->in.getxattr.size,
	                            &args->out.getxattr.size);
}

static int
call_listxattr(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_listxattr(task, args->in.listxattr.ino,
	                             args->in.listxattr.lxa_ctx);
}

static int
call_removexattr(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_removexattr(task, args->in.removexattr.ino,
	                               args->in.removexattr.name);
}

static int
call_flush(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_flush(task, args->in.flush.ino,
	                         args->in.flush.ino == 0);
}

static int
call_opendir(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_opendir(task, args->in.opendir.ino,
	                           args->in.opendir.o_flags);
}

static int
call_readdir(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_readdir(task, args->in.readdir.ino,
	                           args->in.readdir.rd_ctx);
}

static int
call_readdirplus(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_readdirplus(task, args->in.readdir.ino,
	                               args->in.readdir.rd_ctx);
}

static int
call_releasedir(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_releasedir(task, args->in.releasedir.ino,
	                              args->in.releasedir.o_flags);
}

static int
call_fsyncdir(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_fsyncdir(task, args->in.fsyncdir.ino,
	                            args->in.fsyncdir.datasync);
}

static int
call_access(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_access(task, args->in.access.ino,
	                          args->in.access.mask);
}

static int
call_create(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_create(
		task, args->in.create.parent, args->in.create.name,
		args->in.create.o_flags, args->in.create.mode,
		args->in.create.kill_suidgid, &args->out.create.st);
}

static int
call_fallocate(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_fallocate(task, args->in.fallocate.ino,
	                             args->in.fallocate.mode,
	                             args->in.fallocate.off,
	                             args->in.fallocate.len);
}

static int
call_lseek(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_lseek(task, args->in.lseek.ino, args->in.lseek.off,
	                         args->in.lseek.whence, &args->out.lseek.off);
}

static int call_copy_file_range(struct silofs_task_ctx *task,
                                struct silofs_call_args *args)
{
	return silofs_exec_copy_file_range(task,
	                                   args->in.copy_file_range.ino_in,
	                                   args->in.copy_file_range.off_in,
	                                   args->in.copy_file_range.ino_out,
	                                   args->in.copy_file_range.off_out,
	                                   args->in.copy_file_range.len,
	                                   args->in.copy_file_range.flags,
	                                   &args->out.copy_file_range.ncp);
}

static int
call_read_buf(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_read(task, args->in.read.ino, args->in.read.buf,
	                        args->in.read.len, args->in.read.off,
	                        args->in.read.o_flags, &args->out.read.nrd);
}

static int
call_read_iter(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_read_iter(task, args->in.read.ino,
	                             args->in.read.o_flags,
	                             args->in.read.rwi_ctx);
}

static int
call_read(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return (args->in.read.rwi_ctx != nullptr) ?
	               call_read_iter(task, args) :
	               call_read_buf(task, args);
}

static int
call_write_buf(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_write(task, args->in.write.ino, args->in.write.buf,
	                         args->in.write.len, args->in.write.off,
	                         args->in.write.o_flags,
	                         args->in.write.kill_suidgid,
	                         &args->out.write.nwr);
}

static int
call_write_iter(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_write_iter(task, args->in.write.ino,
	                              args->in.write.o_flags,
	                              args->in.write.kill_suidgid,
	                              args->in.write.rwi_ctx);
}

static int
call_write(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return (args->in.write.rwi_ctx != nullptr) ?
	               call_write_iter(task, args) :
	               call_write_buf(task, args);
}

static int
call_syncfs(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_syncfs(task, args->in.syncfs.ino,
	                          args->in.syncfs.flags);
}

static int
call_ioctl_query(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_query(task, args->in.query.ino,
	                         args->in.query.qtype, &args->out.query.qry);
}

static int
call_ioctl_forkfs(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_forkfs(task, args->in.clone.ino,
	                          args->in.clone.flags,
	                          &args->out.clone.mbrefs);
}

static int
call_ioctl_syncfs(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	/*
	 * Currently (Linux kernel v6.3) fuse has 'fc->sync_fs = true' only for
	 * fs/fuse/virtio_fs.c code-path. Thus, implement full sync-fs via
	 * dedicated ioctl.
	 */
	return call_syncfs(task, args);
}

static int
call_ioctl_tune(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	return silofs_exec_tune(task, args->in.tune.ino,
	                        args->in.tune.iflags_want,
	                        args->in.tune.iflags_dont);
}

static int
call_ioctl(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	int ret;

	switch (args->ioc_cmd) {
	case SILOFS_IOC_QUERY:
		ret = call_ioctl_query(task, args);
		break;
	case SILOFS_IOC_FORKFS:
		ret = call_ioctl_forkfs(task, args);
		break;
	case SILOFS_IOC_SYNCFS:
		ret = call_ioctl_syncfs(task, args);
		break;
	case SILOFS_IOC_TUNE:
		ret = call_ioctl_tune(task, args);
		break;
	default:
		ret = -SILOFS_ENOSYS;
		break;
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_call_table s_call_tbl = {
	.setattr         = call_setattr,
	.lookup          = call_lookup,
	.forget          = call_forget,
	.batch_forget    = call_batch_forget,
	.getattr         = call_getattr,
	.statx           = call_statx,
	.readlink        = call_readlink,
	.symlink         = call_symlink,
	.mknod           = call_mknod,
	.mkdir           = call_mkdir,
	.unlink          = call_unlink,
	.rmdir           = call_rmdir,
	.rename          = call_rename,
	.link            = call_link,
	.open            = call_open,
	.statfs          = call_statfs,
	.release         = call_release,
	.fsync           = call_fsync,
	.setxattr        = call_setxattr,
	.getxattr        = call_getxattr,
	.listxattr       = call_listxattr,
	.removexattr     = call_removexattr,
	.flush           = call_flush,
	.opendir         = call_opendir,
	.readdir         = call_readdir,
	.readdirplus     = call_readdirplus,
	.releasedir      = call_releasedir,
	.fsyncdir        = call_fsyncdir,
	.access          = call_access,
	.create          = call_create,
	.fallocate       = call_fallocate,
	.lseek           = call_lseek,
	.copy_file_range = call_copy_file_range,
	.read            = call_read,
	.write           = call_write,
	.syncfs          = call_syncfs,
	.ioctl           = call_ioctl,
};

const struct silofs_call_table *silofs_call_hooks(void)
{
	return &s_call_tbl;
}
