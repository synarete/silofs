/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2021 Shachar Sharon
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
#include <silofs/fs/types.h>
#include <silofs/fs/address.h>
#include <silofs/fs/repo.h>
#include <silofs/fs/apex.h>
#include <silofs/fs/cache.h>
#include <silofs/fs/super.h>
#include <silofs/fs/namei.h>
#include <silofs/fs/inode.h>
#include <silofs/fs/dir.h>
#include <silofs/fs/file.h>
#include <silofs/fs/symlink.h>
#include <silofs/fs/xattr.h>
#include <silofs/fs/opers.h>
#include <silofs/fs/private.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <time.h>

#define ok_or_goto_out(err_) \
	do { if ((err_) != 0) goto out; } while (0)

#define ok_or_goto_out_ok(err_) \
	do { if ((err_) != 0) goto out_ok; } while (0)

static int op_start(struct silofs_fs_apex *apex,
                    const struct silofs_oper *op)
{
	int err;

	apex->fa_ops.op_time = op->xtime.tv_sec;
	apex->fa_ops.op_count++;

	err = silofs_apex_flush_dirty(apex, 0);
	if (!err) {
		silofs_cache_relax(apex->fa_cache, SILOFS_F_OPSTART);
	}
	return err;
}

static int op_finish(struct silofs_fs_apex *apex,
                     const struct silofs_oper *op, int err)
{
	const time_t now = time(NULL);
	const time_t beg = op->xtime.tv_sec;
	const time_t dif = now - beg;

	if ((beg < now) && (dif > 30)) {
		log_warn("slow-oper: id=%ld code=%d duration=%ld status=%d",
		         apex->fa_ops.op_count, op->opcode, dif, err);
	}
	/* TODO: maybe extra flush-relax? */
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void stat_to_itimes(const struct stat *times,
                           struct silofs_itimes *itimes)
{
	silofs_ts_copy(&itimes->atime, &times->st_atim);
	silofs_ts_copy(&itimes->mtime, &times->st_mtim);
	silofs_ts_copy(&itimes->ctime, &times->st_ctim);
	/* Birth _must_not_ be set from outside */
}

static int symval_to_str(const char *symval, struct silofs_str *str)
{
	size_t symlen;

	symlen = strnlen(symval, SILOFS_SYMLNK_MAX + 1);
	if (symlen == 0) {
		return -EINVAL;
	}
	if (symlen > SILOFS_SYMLNK_MAX) {
		return -ENAMETOOLONG;
	}
	str->str = symval;
	str->len = symlen;
	return 0;
}

static bool is_fsowner(const struct silofs_sb_info *sbi,
                       const struct silofs_ucred *ucred)
{
	return uid_eq(ucred->uid, sbi->s_owner.uid);
}

static bool has_allow_other(const struct silofs_sb_info *sbi)
{
	const unsigned long mask = SILOFS_F_ALLOWOTHER;

	return ((sbi->s_ctl_flags & mask) == mask);
}

static int op_authorize(const struct silofs_fs_apex *apex,
                        const struct silofs_oper *op)
{
	const struct silofs_ucred *ucred = &op->ucred;
	const struct silofs_sb_info *sbi = apex->fa_sbi;

	if (is_fsowner(sbi, ucred)) {
		return 0;
	}
	if (silofs_user_cap_sys_admin(ucred)) {
		return 0;
	}
	if (has_allow_other(sbi)) {
		return 0;
	}
	return -EPERM;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int stage_cacheonly_inode(const struct silofs_fs_apex *apex,
                                 ino_t ino,
                                 struct silofs_inode_info **out_ii)
{
	return silofs_stage_inode(apex->fa_sbi, ino,
	                          SILOFS_STAGE_CACHEONLY, out_ii);
}

static int stage_rdonly_inode(const struct silofs_fs_apex *apex, ino_t ino,
                              struct silofs_inode_info **out_ii)
{
	return silofs_stage_inode(apex->fa_sbi, ino,
	                          SILOFS_STAGE_RDONLY, out_ii);
}

static int stage_mutable_inode(const struct silofs_fs_apex *apex, ino_t ino,
                               struct silofs_inode_info **out_ii)
{
	return silofs_stage_inode(apex->fa_sbi, ino,
	                          SILOFS_STAGE_MUTABLE, out_ii);
}

static int stage_openable_inode(const struct silofs_fs_apex *apex, ino_t ino,
                                int o_flags, struct silofs_inode_info **out_ii)
{
	int err;

	if (o_flags & (O_RDWR | O_WRONLY | O_TRUNC | O_APPEND)) {
		err = stage_mutable_inode(apex, ino, out_ii);
	} else {
		err = stage_rdonly_inode(apex, ino, out_ii);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_fs_forget(struct silofs_fs_apex *apex,
                     const struct silofs_oper *op,
                     ino_t ino, size_t nlookup)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_cacheonly_inode(apex, ino, &ii);
	ok_or_goto_out_ok(err);

	err = silofs_do_forget(op, ii, nlookup);
	ok_or_goto_out(err);
out_ok:
	err = 0;
out:
	return op_finish(apex, op, err);
}

int silofs_fs_statfs(struct silofs_fs_apex *apex,
                     const struct silofs_oper *op,
                     ino_t ino, struct statvfs *stvfs)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_rdonly_inode(apex, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_statvfs(op, ii, stvfs);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_lookup(struct silofs_fs_apex *apex,
                     const struct silofs_oper *op, ino_t parent,
                     const char *name, struct stat *out_stat)
{
	int err;
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = NULL;
	struct silofs_inode_info *dir_ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_rdonly_inode(apex, parent, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr(dir_ii, name, &nstr);
	ok_or_goto_out(err);

	err = silofs_do_lookup(op, dir_ii, &nstr, &ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(op, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_getattr(struct silofs_fs_apex *apex,
                      const struct silofs_oper *op,
                      ino_t ino, struct stat *out_stat)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_rdonly_inode(apex, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(op, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_access(struct silofs_fs_apex *apex,
                     const struct silofs_oper *op,
                     ino_t ino, int mode)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_rdonly_inode(apex, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_access(op, ii, mode);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_mkdir(struct silofs_fs_apex *apex,
                    const struct silofs_oper *op, ino_t parent,
                    const char *name, mode_t mode, struct stat *out_stat)
{
	int err;
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = NULL;
	struct silofs_inode_info *dir_ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_mutable_inode(apex, parent, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr(dir_ii, name, &nstr);
	ok_or_goto_out(err);

	err = silofs_do_mkdir(op, dir_ii, &nstr, mode, &ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(op, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_rmdir(struct silofs_fs_apex *apex,
                    const struct silofs_oper *op,
                    ino_t parent, const char *name)
{
	int err;
	struct silofs_namestr nstr;
	struct silofs_inode_info *dir_ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_mutable_inode(apex, parent, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr(dir_ii, name, &nstr);
	ok_or_goto_out(err);

	err = silofs_do_rmdir(op, dir_ii, &nstr);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_symlink(struct silofs_fs_apex *apex,
                      const struct silofs_oper *op, ino_t parent,
                      const char *name, const char *symval,
                      struct stat *out_stat)
{
	int err;
	struct silofs_str value;
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = NULL;
	struct silofs_inode_info *dir_ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_mutable_inode(apex, parent, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr(dir_ii, name, &nstr);
	ok_or_goto_out(err);

	err = symval_to_str(symval, &value);
	ok_or_goto_out(err);

	err = silofs_do_symlink(op, dir_ii, &nstr, &value, &ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(op, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_readlink(struct silofs_fs_apex *apex,
                       const struct silofs_oper *op,
                       ino_t ino, char *ptr, size_t lim, size_t *out_len)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_rdonly_inode(apex, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_readlink(op, ii, ptr, lim, out_len);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_unlink(struct silofs_fs_apex *apex,
                     const struct silofs_oper *op,
                     ino_t parent, const char *name)
{
	int err;
	struct silofs_namestr nstr;
	struct silofs_inode_info *dir_ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_mutable_inode(apex, parent, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr(dir_ii, name, &nstr);
	ok_or_goto_out(err);

	err = silofs_do_unlink(op, dir_ii, &nstr);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_link(struct silofs_fs_apex *apex,
                   const struct silofs_oper *op, ino_t ino, ino_t parent,
                   const char *name, struct stat *out_stat)
{
	int err;
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = NULL;
	struct silofs_inode_info *dir_ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_mutable_inode(apex, parent, &dir_ii);
	ok_or_goto_out(err);

	err = stage_mutable_inode(apex, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr(dir_ii, name, &nstr);
	ok_or_goto_out(err);

	err = silofs_do_link(op, dir_ii, &nstr, ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(op, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_opendir(struct silofs_fs_apex *apex,
                      const struct silofs_oper *op, ino_t ino)
{
	int err;
	struct silofs_inode_info *dir_ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_rdonly_inode(apex, ino, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_opendir(op, dir_ii);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_releasedir(struct silofs_fs_apex *apex,
                         const struct silofs_oper *op, ino_t ino, int o_flags)
{
	int err;
	struct silofs_inode_info *dir_ii = NULL;

	unused(o_flags); /* TODO: useme */

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_rdonly_inode(apex, ino, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_releasedir(op, dir_ii);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_readdir(struct silofs_fs_apex *apex,
                      const struct silofs_oper *op, ino_t ino,
                      struct silofs_readdir_ctx *rd_ctx)
{
	int err;
	struct silofs_inode_info *dir_ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_rdonly_inode(apex, ino, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_readdir(op, dir_ii, rd_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_readdirplus(struct silofs_fs_apex *apex,
                          const struct silofs_oper *op, ino_t ino,
                          struct silofs_readdir_ctx *rd_ctx)
{
	int err;
	struct silofs_inode_info *dir_ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_rdonly_inode(apex, ino, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_readdirplus(op, dir_ii, rd_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_fsyncdir(struct silofs_fs_apex *apex,
                       const struct silofs_oper *op, ino_t ino, bool datasync)
{
	int err;
	struct silofs_inode_info *dir_ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_rdonly_inode(apex, ino, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_fsyncdir(op, dir_ii, datasync);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_chmod(struct silofs_fs_apex *apex,
                    const struct silofs_oper *op, ino_t ino, mode_t mode,
                    const struct stat *st, struct stat *out_stat)
{
	int err;
	struct silofs_itimes itimes;
	struct silofs_inode_info *ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_mutable_inode(apex, ino, &ii);
	ok_or_goto_out(err);

	stat_to_itimes(st, &itimes);
	err = silofs_do_chmod(op, ii, mode, &itimes);
	ok_or_goto_out(err);

	err = silofs_do_getattr(op, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_chown(struct silofs_fs_apex *apex,
                    const struct silofs_oper *op, ino_t ino, uid_t uid,
                    gid_t gid, const struct stat *st, struct stat *out_stat)
{
	int err;
	struct silofs_itimes itimes;
	struct silofs_inode_info *ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_mutable_inode(apex, ino, &ii);
	ok_or_goto_out(err);

	stat_to_itimes(st, &itimes);
	err = silofs_do_chown(op, ii, uid, gid, &itimes);
	ok_or_goto_out(err);

	err = silofs_do_getattr(op, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_utimens(struct silofs_fs_apex *apex,
                      const struct silofs_oper *op, ino_t ino,
                      const struct stat *times, struct stat *out_stat)
{
	int err;
	struct silofs_itimes itimes;
	struct silofs_inode_info *ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_mutable_inode(apex, ino, &ii);
	ok_or_goto_out(err);

	stat_to_itimes(times, &itimes);
	err = silofs_do_utimens(op, ii, &itimes);
	ok_or_goto_out(err);

	err = silofs_do_getattr(op, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_truncate(struct silofs_fs_apex *apex,
                       const struct silofs_oper *op,
                       ino_t ino, loff_t len, struct stat *out_stat)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_mutable_inode(apex, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_truncate(op, ii, len);
	ok_or_goto_out(err);

	err = silofs_do_getattr(op, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_create(struct silofs_fs_apex *apex,
                     const struct silofs_oper *op, ino_t parent,
                     const char *name, int o_flags, mode_t mode,
                     struct stat *out_stat)
{
	int err;
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = NULL;
	struct silofs_inode_info *dir_ii = NULL;

	unused(o_flags); /* XXX use me */

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_mutable_inode(apex, parent, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr(dir_ii, name, &nstr);
	ok_or_goto_out(err);

	err = silofs_do_create(op, dir_ii, &nstr, mode, &ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(op, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_open(struct silofs_fs_apex *apex,
                   const struct silofs_oper *op, ino_t ino, int o_flags)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_openable_inode(apex, ino, o_flags, &ii);
	ok_or_goto_out(err);

	err = silofs_do_open(op, ii, o_flags);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_mknod(struct silofs_fs_apex *apex,
                    const struct silofs_oper *op,
                    ino_t parent, const char *name, mode_t mode, dev_t rdev,
                    struct stat *out_stat)
{
	int err;
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = NULL;
	struct silofs_inode_info *dir_ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_mutable_inode(apex, parent, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr(dir_ii, name, &nstr);
	ok_or_goto_out(err);

	err = silofs_do_mknod(op, dir_ii, &nstr, mode, rdev, &ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(op, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_release(struct silofs_fs_apex *apex,
                      const struct silofs_oper *op,
                      ino_t ino, int o_flags, bool flush)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	/* TODO: useme */
	unused(flush);
	unused(o_flags);

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_rdonly_inode(apex, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_release(op, ii);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_flush(struct silofs_fs_apex *apex,
                    const struct silofs_oper *op, ino_t ino)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_mutable_inode(apex, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_flush(op, ii);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_fsync(struct silofs_fs_apex *apex,
                    const struct silofs_oper *op,
                    ino_t ino, bool datasync)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_rdonly_inode(apex, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_fsync(op, ii, datasync);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_rename(struct silofs_fs_apex *apex,
                     const struct silofs_oper *op, ino_t parent,
                     const char *name, ino_t newparent,
                     const char *newname, int flags)
{
	int err;
	struct silofs_namestr nstr;
	struct silofs_namestr newnstr;
	struct silofs_inode_info *parent_ii = NULL;
	struct silofs_inode_info *newp_ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_mutable_inode(apex, parent, &parent_ii);
	ok_or_goto_out(err);

	err = stage_mutable_inode(apex, newparent, &newp_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr(parent_ii, name, &nstr);
	ok_or_goto_out(err);

	err = silofs_make_namestr(parent_ii, newname, &newnstr);
	ok_or_goto_out(err);

	err = silofs_do_rename(op, parent_ii, &nstr, newp_ii, &newnstr, flags);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_read(struct silofs_fs_apex *apex,
                   const struct silofs_oper *op, ino_t ino, void *buf,
                   size_t len, loff_t off, size_t *out_len)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_rdonly_inode(apex, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_read(op, ii, buf, len, off, out_len);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_read_iter(struct silofs_fs_apex *apex,
                        const struct silofs_oper *op, ino_t ino,
                        struct silofs_rwiter_ctx *rwi_ctx)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_rdonly_inode(apex, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_read_iter(op, ii, rwi_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_write(struct silofs_fs_apex *apex,
                    const struct silofs_oper *op, ino_t ino,
                    const void *buf, size_t len, off_t off, size_t *out_len)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_mutable_inode(apex, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_write(op, ii, buf, len, off, out_len);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_write_iter(struct silofs_fs_apex *apex,
                         const struct silofs_oper *op, ino_t ino,
                         struct silofs_rwiter_ctx *rwi_ctx)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_mutable_inode(apex, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_write_iter(op, ii, rwi_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_rdwr_post(struct silofs_fs_apex *apex,
                        const struct silofs_oper *op, ino_t ino,
                        const struct silofs_fiovec *fiov, size_t cnt)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = stage_cacheonly_inode(apex, ino, &ii);
	/* special case: do post even if ii is NULL */

	err = silofs_do_rdwr_post(op, ii, fiov, cnt) || err;
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_fallocate(struct silofs_fs_apex *apex,
                        const struct silofs_oper *op, ino_t ino,
                        int mode, loff_t offset, loff_t length)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_mutable_inode(apex, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_fallocate(op, ii, mode, offset, length);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_lseek(struct silofs_fs_apex *apex,
                    const struct silofs_oper *op, ino_t ino,
                    loff_t off, int whence, loff_t *out_off)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_rdonly_inode(apex, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_lseek(op, ii, off, whence, out_off);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_copy_file_range(struct silofs_fs_apex *apex,
                              const struct silofs_oper *op, ino_t ino_in,
                              loff_t off_in, ino_t ino_out, loff_t off_out,
                              size_t len, int flags, size_t *out_ncp)
{
	int err;
	struct silofs_inode_info *ii_in = NULL;
	struct silofs_inode_info *ii_out = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_mutable_inode(apex, ino_in, &ii_in);
	ok_or_goto_out(err);

	err = stage_mutable_inode(apex, ino_out, &ii_out);
	ok_or_goto_out(err);

	err = silofs_do_copy_file_range(op, ii_in, ii_out, off_in,
	                                off_out, len, flags, out_ncp);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_setxattr(struct silofs_fs_apex *apex,
                       const struct silofs_oper *op, ino_t ino,
                       const char *name, const void *value,
                       size_t size, int flags, bool kill_sgid)
{
	int err;
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_mutable_inode(apex, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr(ii, name, &nstr);
	ok_or_goto_out(err);

	err = silofs_do_setxattr(op, ii, &nstr, value, size, flags, kill_sgid);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_getxattr(struct silofs_fs_apex *apex,
                       const struct silofs_oper *op, ino_t ino,
                       const char *name, void *buf, size_t size,
                       size_t *out_size)
{
	int err;
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_rdonly_inode(apex, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr(ii, name, &nstr);
	ok_or_goto_out(err);

	err = silofs_do_getxattr(op, ii, &nstr, buf, size, out_size);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_listxattr(struct silofs_fs_apex *apex,
                        const struct silofs_oper *op, ino_t ino,
                        struct silofs_listxattr_ctx *lxa_ctx)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_rdonly_inode(apex, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_listxattr(op, ii, lxa_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_removexattr(struct silofs_fs_apex *apex,
                          const struct silofs_oper *op,
                          ino_t ino, const char *name)
{
	int err;
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_mutable_inode(apex, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr(ii, name, &nstr);
	ok_or_goto_out(err);

	err = silofs_do_removexattr(op, ii, &nstr);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_statx(struct silofs_fs_apex *apex,
                    const struct silofs_oper *op, ino_t ino,
                    unsigned int request_mask, struct statx *out_stx)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_rdonly_inode(apex, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_statx(op, ii, request_mask, out_stx);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_fiemap(struct silofs_fs_apex *apex,
                     const struct silofs_oper *op,
                     ino_t ino, struct fiemap *fm)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_rdonly_inode(apex, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_fiemap(op, ii, fm);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_syncfs(struct silofs_fs_apex *apex,
                     const struct silofs_oper *op, ino_t ino)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_mutable_inode(apex, ino, &ii);
	ok_or_goto_out(err);

	err = 0; /* XXX */
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_query(struct silofs_fs_apex *apex,
                    const struct silofs_oper *op, ino_t ino,
                    struct silofs_ioc_query *out_qry)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_rdonly_inode(apex, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_query(op, ii, out_qry);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_clone(struct silofs_fs_apex *apex,
                    const struct silofs_oper *op,
                    ino_t ino, const char *name, int flags)
{
	int err;
	struct silofs_namestr nstr;
	struct silofs_inode_info *dir_ii = NULL;

	err = op_start(apex, op);
	ok_or_goto_out(err);

	err = op_authorize(apex, op);
	ok_or_goto_out(err);

	err = stage_rdonly_inode(apex, ino, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr(dir_ii, name, &nstr);
	ok_or_goto_out(err);

	err = silofs_do_clone(op, dir_ii, &nstr, flags);
	ok_or_goto_out(err);
out:
	return op_finish(apex, op, err);
}

int silofs_fs_timedout(struct silofs_fs_apex *apex, int flags)
{
	int err;

	err = silofs_apex_flush_dirty(apex, flags);
	if (err) {
		return err;
	}
	silofs_cache_relax(apex->fa_cache, flags);
	return 0;
}
