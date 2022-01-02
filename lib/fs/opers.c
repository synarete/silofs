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
#include <silofs/fs/types.h>
#include <silofs/fs/address.h>
#include <silofs/fs/boot.h>
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

#define status_ok(err_) ((err_) == 0)

#define ok_or_goto_out(err_) \
	do { if (!status_ok(err_)) goto out; } while (0)

#define ok_or_goto_out_ok(err_) \
	do { if (!status_ok(err_)) goto out_ok; } while (0)

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int op_start(const struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_fs_apex *apex = fs_ctx->fsc_apex;
	int err;

	if (unlikely(apex == NULL)) {
		return -EINVAL;
	}
	err = silofs_apex_flush_dirty(apex, 0);
	if (unlikely(err)) {
		return err;
	}
	silofs_cache_relax(apex->ap_cache, SILOFS_F_OPSTART);
	apex->ap_ops.op_time = fs_ctx->fsc_oper.op_creds.xtime.tv_sec;
	apex->ap_ops.op_count++;
	return 0;
}

static int op_finish(const struct silofs_fs_ctx *fs_ctx, int err)
{
	const time_t now = time(NULL);
	const time_t beg = fs_ctx->fsc_oper.op_creds.xtime.tv_sec;
	const time_t dif = now - beg;

	if ((beg < now) && (dif > 30)) {
		log_warn("slow-oper: id=%ld code=%d duration=%ld status=%d",
		         fs_ctx->fsc_apex->ap_ops.op_count,
		         fs_ctx->fsc_oper.op_code, dif, err);
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

static int op_authorize(const struct silofs_fs_ctx *fs_ctx)
{
	const struct silofs_ucred *ucred = &fs_ctx->fsc_oper.op_creds.ucred;
	const struct silofs_sb_info *sbi = fs_ctx->fsc_apex->ap_sbi;

	if (sbi == NULL) {
		return 0; /* case unpack */
	}
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

static int
op_stage_cacheonly_inode(const struct silofs_fs_ctx *fs_ctx,
                         ino_t ino, struct silofs_inode_info **out_ii)
{
	return silofs_stage_cached_inode(fs_ctx->fsc_apex->ap_sbi,
	                                 ino, out_ii);
}

static int op_stage_rdonly_inode(const struct silofs_fs_ctx *fs_ctx,
                                 ino_t ino, struct silofs_inode_info **out_ii)
{
	return silofs_stage_inode(fs_ctx->fsc_apex->ap_sbi,
	                          ino, SILOFS_STAGE_RDONLY, out_ii);
}

static int op_stage_mutable_inode(const struct silofs_fs_ctx *fs_ctx,
                                  ino_t ino, struct silofs_inode_info **out_ii)
{
	return silofs_stage_inode(fs_ctx->fsc_apex->ap_sbi,
	                          ino, SILOFS_STAGE_MUTABLE, out_ii);
}

static int
op_stage_openable_inode(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                        int o_flags, struct silofs_inode_info **out_ii)
{
	int err;

	if (o_flags & (O_RDWR | O_WRONLY | O_TRUNC | O_APPEND)) {
		err = op_stage_mutable_inode(fs_ctx, ino, out_ii);
	} else {
		err = op_stage_rdonly_inode(fs_ctx, ino, out_ii);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_fs_forget(const struct silofs_fs_ctx *fs_ctx,
                     ino_t ino, size_t nlookup)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_cacheonly_inode(fs_ctx, ino, &ii);
	ok_or_goto_out_ok(err);

	err = silofs_do_forget(fs_ctx, ii, nlookup);
	ok_or_goto_out(err);
out_ok:
	err = 0;
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_statfs(const struct silofs_fs_ctx *fs_ctx,
                     ino_t ino, struct statvfs *stvfs)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdonly_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_statvfs(fs_ctx, ii, stvfs);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_lookup(const struct silofs_fs_ctx *fs_ctx, ino_t parent,
                     const char *name, struct stat *out_stat)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = NULL;
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdonly_inode(fs_ctx, parent, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, dir_ii, name);
	ok_or_goto_out(err);

	err = silofs_do_lookup(fs_ctx, dir_ii, &nstr, &ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(fs_ctx, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_getattr(const struct silofs_fs_ctx *fs_ctx,
                      ino_t ino, struct stat *out_stat)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdonly_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(fs_ctx, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_access(const struct silofs_fs_ctx *fs_ctx, ino_t ino, int mode)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdonly_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_access(fs_ctx, ii, mode);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_mkdir(const struct silofs_fs_ctx *fs_ctx, ino_t parent,
                    const char *name, mode_t mode, struct stat *out_stat)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = NULL;
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mutable_inode(fs_ctx, parent, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, dir_ii, name);
	ok_or_goto_out(err);

	err = silofs_do_mkdir(fs_ctx, dir_ii, &nstr, mode, &ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(fs_ctx, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_rmdir(const struct silofs_fs_ctx *fs_ctx,
                    ino_t parent, const char *name)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mutable_inode(fs_ctx, parent, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, dir_ii, name);
	ok_or_goto_out(err);

	err = silofs_do_rmdir(fs_ctx, dir_ii, &nstr);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_symlink(const struct silofs_fs_ctx *fs_ctx, ino_t parent,
                      const char *name, const char *symval,
                      struct stat *out_stat)
{
	struct silofs_str value;
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = NULL;
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mutable_inode(fs_ctx, parent, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, dir_ii, name);
	ok_or_goto_out(err);

	err = symval_to_str(symval, &value);
	ok_or_goto_out(err);

	err = silofs_do_symlink(fs_ctx, dir_ii, &nstr, &value, &ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(fs_ctx, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_readlink(const struct silofs_fs_ctx *fs_ctx,
                       ino_t ino, char *ptr, size_t lim, size_t *out_len)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdonly_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_readlink(fs_ctx, ii, ptr, lim, out_len);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_unlink(const struct silofs_fs_ctx *fs_ctx,
                     ino_t parent, const char *name)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mutable_inode(fs_ctx, parent, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, dir_ii, name);
	ok_or_goto_out(err);

	err = silofs_do_unlink(fs_ctx, dir_ii, &nstr);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_link(const struct silofs_fs_ctx *fs_ctx, ino_t ino, ino_t parent,
                   const char *name, struct stat *out_stat)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = NULL;
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mutable_inode(fs_ctx, parent, &dir_ii);
	ok_or_goto_out(err);

	err = op_stage_mutable_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, dir_ii, name);
	ok_or_goto_out(err);

	err = silofs_do_link(fs_ctx, dir_ii, &nstr, ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(fs_ctx, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_opendir(const struct silofs_fs_ctx *fs_ctx, ino_t ino)
{
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdonly_inode(fs_ctx, ino, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_opendir(fs_ctx, dir_ii);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_releasedir(const struct silofs_fs_ctx *fs_ctx,
                         ino_t ino, int o_flags)
{
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	unused(o_flags); /* TODO: useme */

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdonly_inode(fs_ctx, ino, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_releasedir(fs_ctx, dir_ii);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_readdir(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                      struct silofs_readdir_ctx *rd_ctx)
{
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdonly_inode(fs_ctx, ino, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_readdir(fs_ctx, dir_ii, rd_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_readdirplus(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                          struct silofs_readdir_ctx *rd_ctx)
{
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdonly_inode(fs_ctx, ino, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_readdirplus(fs_ctx, dir_ii, rd_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_fsyncdir(const struct silofs_fs_ctx *fs_ctx,
                       ino_t ino, bool datasync)
{
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdonly_inode(fs_ctx, ino, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_fsyncdir(fs_ctx, dir_ii, datasync);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_chmod(const struct silofs_fs_ctx *fs_ctx, ino_t ino, mode_t mode,
                    const struct stat *st, struct stat *out_stat)
{
	struct silofs_itimes itimes;
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mutable_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	stat_to_itimes(st, &itimes);
	err = silofs_do_chmod(fs_ctx, ii, mode, &itimes);
	ok_or_goto_out(err);

	err = silofs_do_getattr(fs_ctx, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_chown(const struct silofs_fs_ctx *fs_ctx, ino_t ino, uid_t uid,
                    gid_t gid, const struct stat *st, struct stat *out_stat)
{
	struct silofs_itimes itimes;
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mutable_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	stat_to_itimes(st, &itimes);
	err = silofs_do_chown(fs_ctx, ii, uid, gid, &itimes);
	ok_or_goto_out(err);

	err = silofs_do_getattr(fs_ctx, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_utimens(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                      const struct stat *times, struct stat *out_stat)
{
	struct silofs_itimes itimes;
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mutable_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	stat_to_itimes(times, &itimes);
	err = silofs_do_utimens(fs_ctx, ii, &itimes);
	ok_or_goto_out(err);

	err = silofs_do_getattr(fs_ctx, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_truncate(const struct silofs_fs_ctx *fs_ctx,
                       ino_t ino, loff_t len, struct stat *out_stat)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mutable_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_truncate(fs_ctx, ii, len);
	ok_or_goto_out(err);

	err = silofs_do_getattr(fs_ctx, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_create(const struct silofs_fs_ctx *fs_ctx, ino_t parent,
                     const char *name, int o_flags, mode_t mode,
                     struct stat *out_stat)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = NULL;
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	unused(o_flags); /* XXX use me */

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mutable_inode(fs_ctx, parent, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, dir_ii, name);
	ok_or_goto_out(err);

	err = silofs_do_create(fs_ctx, dir_ii, &nstr, mode, &ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(fs_ctx, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_open(const struct silofs_fs_ctx *fs_ctx, ino_t ino, int o_flags)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_openable_inode(fs_ctx, ino, o_flags, &ii);
	ok_or_goto_out(err);

	err = silofs_do_open(fs_ctx, ii, o_flags);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_mknod(const struct silofs_fs_ctx *fs_ctx, ino_t parent,
                    const char *name, mode_t mode, dev_t rdev,
                    struct stat *out_stat)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = NULL;
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mutable_inode(fs_ctx, parent, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, dir_ii, name);
	ok_or_goto_out(err);

	err = silofs_do_mknod(fs_ctx, dir_ii, &nstr, mode, rdev, &ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(fs_ctx, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_release(const struct silofs_fs_ctx *fs_ctx,
                      ino_t ino, int o_flags, bool flush)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	/* TODO: useme */
	unused(flush);
	unused(o_flags);

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdonly_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_release(fs_ctx, ii);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_flush(const struct silofs_fs_ctx *fs_ctx, ino_t ino)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdonly_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_flush(fs_ctx, ii);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_fsync(const struct silofs_fs_ctx *fs_ctx,
                    ino_t ino, bool datasync)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdonly_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_fsync(fs_ctx, ii, datasync);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_rename(const struct silofs_fs_ctx *fs_ctx, ino_t parent,
                     const char *name, ino_t newparent,
                     const char *newname, int flags)
{
	struct silofs_namestr nstr;
	struct silofs_namestr newnstr;
	struct silofs_inode_info *parent_ii = NULL;
	struct silofs_inode_info *newp_ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mutable_inode(fs_ctx, parent, &parent_ii);
	ok_or_goto_out(err);

	err = op_stage_mutable_inode(fs_ctx, newparent, &newp_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, parent_ii, name);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&newnstr, parent_ii, newname);
	ok_or_goto_out(err);

	err = silofs_do_rename(fs_ctx, parent_ii, &nstr,
	                       newp_ii, &newnstr, flags);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_read(const struct silofs_fs_ctx *fs_ctx, ino_t ino, void *buf,
                   size_t len, loff_t off, size_t *out_len)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdonly_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_read(fs_ctx, ii, buf, len, off, out_len);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_read_iter(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                        struct silofs_rwiter_ctx *rwi_ctx)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdonly_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_read_iter(fs_ctx, ii, rwi_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_write(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                    const void *buf, size_t len, off_t off, size_t *out_len)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mutable_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_write(fs_ctx, ii, buf, len, off, out_len);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_write_iter(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                         struct silofs_rwiter_ctx *rwi_ctx)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mutable_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_write_iter(fs_ctx, ii, rwi_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_rdwr_post(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                        const struct silofs_fiovec *fiov, size_t cnt)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_stage_cacheonly_inode(fs_ctx, ino, &ii);
	/* special case: do post even if ii is NULL */

	err = silofs_do_rdwr_post(fs_ctx, ii, fiov, cnt) || err;
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_fallocate(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                        int mode, loff_t offset, loff_t length)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mutable_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_fallocate(fs_ctx, ii, mode, offset, length);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_lseek(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                    loff_t off, int whence, loff_t *out_off)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdonly_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_lseek(fs_ctx, ii, off, whence, out_off);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_copy_file_range(const struct silofs_fs_ctx *fs_ctx, ino_t ino_in,
                              loff_t off_in, ino_t ino_out, loff_t off_out,
                              size_t len, int flags, size_t *out_ncp)
{
	struct silofs_inode_info *ii_in = NULL;
	struct silofs_inode_info *ii_out = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mutable_inode(fs_ctx, ino_in, &ii_in);
	ok_or_goto_out(err);

	err = op_stage_mutable_inode(fs_ctx, ino_out, &ii_out);
	ok_or_goto_out(err);

	err = silofs_do_copy_file_range(fs_ctx, ii_in, ii_out, off_in,
	                                off_out, len, flags, out_ncp);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_setxattr(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                       const char *name, const void *value,
                       size_t size, int flags, bool kill_sgid)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mutable_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, ii, name);
	ok_or_goto_out(err);

	err = silofs_do_setxattr(fs_ctx, ii, &nstr,
	                         value, size, flags, kill_sgid);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_getxattr(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                       const char *name, void *buf, size_t size,
                       size_t *out_size)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdonly_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, ii, name);
	ok_or_goto_out(err);

	err = silofs_do_getxattr(fs_ctx, ii, &nstr, buf, size, out_size);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_listxattr(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                        struct silofs_listxattr_ctx *lxa_ctx)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdonly_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_listxattr(fs_ctx, ii, lxa_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_removexattr(const struct silofs_fs_ctx *fs_ctx,
                          ino_t ino, const char *name)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mutable_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, ii, name);
	ok_or_goto_out(err);

	err = silofs_do_removexattr(fs_ctx, ii, &nstr);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_statx(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                    unsigned int request_mask, struct statx *out_stx)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdonly_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_statx(fs_ctx, ii, request_mask, out_stx);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_fiemap(const struct silofs_fs_ctx *fs_ctx,
                     ino_t ino, struct fiemap *fm)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdonly_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_fiemap(fs_ctx, ii, fm);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_syncfs(const struct silofs_fs_ctx *fs_ctx, ino_t ino)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mutable_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = 0; /* XXX */
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_query(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                    struct silofs_ioc_query *out_qry)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdonly_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_query(fs_ctx, ii, out_qry);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_clone(const struct silofs_fs_ctx *fs_ctx,
                    ino_t ino, const char *name, int flags)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = silofs_make_fsnamestr(&nstr, name);
	ok_or_goto_out(err);

	err = op_stage_rdonly_inode(fs_ctx, ino, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_clone(fs_ctx, dir_ii, &nstr, flags);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_snap(const struct silofs_fs_ctx *fs_ctx,
                   ino_t ino, const char *name)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = silofs_make_fsnamestr(&nstr, name);
	ok_or_goto_out(err);

	err = op_stage_rdonly_inode(fs_ctx, ino, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_snap(fs_ctx, dir_ii, &nstr);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_unrefs(const struct silofs_fs_ctx *fs_ctx,
                     ino_t ino, const char *name)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = silofs_make_fsnamestr(&nstr, name);
	ok_or_goto_out(err);

	err = op_stage_rdonly_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_unrefs(fs_ctx, ii, &nstr);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_inspect(const struct silofs_fs_ctx *fs_ctx, ino_t ino)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdonly_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_inspect(fs_ctx, ii);
	ok_or_goto_out(err);

out:
	return op_finish(fs_ctx, err);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_fs_pack(const struct silofs_fs_ctx *fs_ctx, const char *name)
{
	struct silofs_namestr nstr;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = silofs_make_fsnamestr(&nstr, name);
	ok_or_goto_out(err);

	err = silofs_do_pack(fs_ctx, &nstr);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_timedout(struct silofs_fs_apex *apex, int flags)
{
	int err;

	err = silofs_apex_flush_dirty(apex, flags);
	if (err) {
		return err;
	}
	silofs_cache_relax(apex->ap_cache, flags);
	return 0;
}
