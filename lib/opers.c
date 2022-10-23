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
#include <silofs/fs.h>
#include <silofs/fs-private.h>
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
	struct silofs_fs_uber *uber = fs_ctx->fsc_uber;
	int err;

	if (unlikely(uber == NULL)) {
		return -EINVAL;
	}
	err = silofs_uber_flush_dirty(uber, SILOFS_DQID_ALL, 0);
	if (unlikely(err)) {
		return err;
	}
	silofs_uber_relax_caches(uber, SILOFS_F_OPSTART);
	uber->ub_ops.op_time = fs_ctx->fsc_oper.op_creds.ts.tv_sec;
	uber->ub_ops.op_count++;
	return 0;
}

static int op_finish(const struct silofs_fs_ctx *fs_ctx, int err)
{
	const time_t now = time(NULL);
	const time_t beg = fs_ctx->fsc_oper.op_creds.ts.tv_sec;
	const time_t dif = now - beg;
	const int op_code = fs_ctx->fsc_oper.op_code;

	if (op_code && (beg < now) && (dif > 30)) {
		log_warn("slow-oper: id=%ld code=%d duration=%ld status=%d",
		         fs_ctx->fsc_uber->ub_ops.op_count,
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_idsmap *
idsm_of(const struct silofs_fs_ctx *fs_ctx)
{
	return fs_ctx->fsc_uber->ub_idsm;
}

static const struct silofs_sb_info *sbi_of(const struct silofs_fs_ctx *fs_ctx)
{
	return fs_ctx->fsc_uber->ub_sbi;
}

static const struct silofs_creds *creds_of(const struct silofs_fs_ctx *fs_ctx)
{
	return &fs_ctx->fsc_oper.op_creds;
}

static struct silofs_creds *creds_of2(struct silofs_fs_ctx *fs_ctx)
{
	return &fs_ctx->fsc_oper.op_creds;
}

static bool op_is_kernel(const struct silofs_fs_ctx *fs_ctx)
{
	const struct silofs_creds *creds = creds_of(fs_ctx);

	return !creds->xcred.pid && !creds->xcred.uid && !creds->xcred.gid;
}

static bool op_is_admin(const struct silofs_fs_ctx *fs_ctx)
{
	return (sbi_of(fs_ctx) == NULL) || op_is_kernel(fs_ctx);
}

static bool op_is_fsowner(const struct silofs_fs_ctx *fs_ctx)
{
	const struct silofs_creds *creds = creds_of(fs_ctx);
	const struct silofs_sb_info *sbi = sbi_of(fs_ctx);

	return uid_eq(creds->xcred.uid, sbi->sb_owner.uid);
}

static bool op_cap_sys_admin(const struct silofs_fs_ctx *fs_ctx)
{
	const struct silofs_creds *creds = creds_of(fs_ctx);
	const struct silofs_sb_info *sbi = sbi_of(fs_ctx);
	const unsigned long mask = SILOFS_F_ALLOWADMIN;

	return ((sbi->sb_ctl_flags & mask) == mask) &&
	       silofs_user_cap_sys_admin(&creds->xcred);
}

static bool op_allow_other(const struct silofs_fs_ctx *fs_ctx)
{
	const struct silofs_sb_info *sbi = sbi_of(fs_ctx);
	const unsigned long mask = SILOFS_F_ALLOWOTHER;

	return ((sbi->sb_ctl_flags & mask) == mask);
}

static int op_authorize(const struct silofs_fs_ctx *fs_ctx)
{
	if (sbi_of(fs_ctx) == NULL) {
		return 0; /* case unpack */
	}
	if (op_is_kernel(fs_ctx)) {
		return 0; /* request by kernel */
	}
	if (op_is_fsowner(fs_ctx)) {
		return 0; /* request by file-system's owner */
	}
	if (op_cap_sys_admin(fs_ctx)) {
		return 0;  /* request by system administrator */
	}
	if (op_allow_other(fs_ctx)) {
		return 0; /* request by other users */
	}
	return -EPERM;
}

static int op_map_creds(struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_creds *creds = creds_of2(fs_ctx);
	int ret = 0;

	creds->icred.uid = creds->xcred.uid;
	creds->icred.gid = creds->xcred.gid;
	creds->icred.pid = creds->xcred.pid;
	creds->icred.umask = creds->xcred.umask;

	if (!op_is_admin(fs_ctx)) {
		ret = silofs_idsmap_map_creds(idsm_of(fs_ctx), creds);
	}
	return (ret == -ENOENT) ? -EPERM : ret;
}

static int op_map_uidgid(const struct silofs_fs_ctx *fs_ctx,
                         uid_t uid, gid_t gid, uid_t *out_uid, gid_t *out_gid)
{
	int ret;

	ret = silofs_idsmap_map_uidgid(idsm_of(fs_ctx),
	                               uid, gid, out_uid, out_gid);
	return (ret == -ENOENT) ? -EPERM : ret;
}

static int op_rmap_stat(const struct silofs_fs_ctx *fs_ctx, struct stat *st)
{
	int ret;

	ret = silofs_idsmap_rmap_stat(idsm_of(fs_ctx), st);
	return (ret == -ENOENT) ? 0 : ret;
}

static int op_rmap_statx(const struct silofs_fs_ctx *fs_ctx, struct statx *stx)
{
	int ret;

	ret = silofs_idsmap_rmap_statx(idsm_of(fs_ctx), stx);
	return (ret == -ENOENT) ? 0 : ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
op_stage_cacheonly_inode(const struct silofs_fs_ctx *fs_ctx,
                         ino_t ino, struct silofs_inode_info **out_ii)
{
	return silofs_sbi_stage_cached_ii(fs_ctx->fsc_uber->ub_sbi,
	                                  ino, out_ii);
}

static int op_stage_rdo_inode(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                              struct silofs_inode_info **out_ii)
{
	return silofs_sbi_stage_inode(fs_ctx->fsc_uber->ub_sbi,
	                              ino, SILOFS_STAGE_RO, out_ii);
}

static int op_stage_mut_inode(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                              struct silofs_inode_info **out_ii)
{
	return silofs_sbi_stage_inode(fs_ctx->fsc_uber->ub_sbi,
	                              ino, SILOFS_STAGE_RW, out_ii);
}

static int
op_stage_openable_inode(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                        int o_flags, struct silofs_inode_info **out_ii)
{
	int err;

	if (o_flags & (O_RDWR | O_WRONLY | O_TRUNC | O_APPEND)) {
		err = op_stage_mut_inode(fs_ctx, ino, out_ii);
	} else {
		err = op_stage_rdo_inode(fs_ctx, ino, out_ii);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_fs_forget(struct silofs_fs_ctx *fs_ctx, ino_t ino, size_t nlookup)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
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

int silofs_fs_statfs(struct silofs_fs_ctx *fs_ctx,
                     ino_t ino, struct statvfs *stvfs)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdo_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_statvfs(fs_ctx, ii, stvfs);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_lookup(struct silofs_fs_ctx *fs_ctx, ino_t parent,
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

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdo_inode(fs_ctx, parent, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, dir_ii, name);
	ok_or_goto_out(err);

	err = silofs_do_lookup(fs_ctx, dir_ii, &nstr, &ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(fs_ctx, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(fs_ctx, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_getattr(struct silofs_fs_ctx *fs_ctx,
                      ino_t ino, struct stat *out_stat)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdo_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(fs_ctx, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(fs_ctx, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_access(struct silofs_fs_ctx *fs_ctx, ino_t ino, int mode)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdo_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_access(fs_ctx, ii, mode);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_mkdir(struct silofs_fs_ctx *fs_ctx, ino_t parent,
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

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(fs_ctx, parent, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, dir_ii, name);
	ok_or_goto_out(err);

	err = silofs_do_mkdir(fs_ctx, dir_ii, &nstr, mode, &ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(fs_ctx, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(fs_ctx, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_rmdir(struct silofs_fs_ctx *fs_ctx,
                    ino_t parent, const char *name)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(fs_ctx, parent, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, dir_ii, name);
	ok_or_goto_out(err);

	err = silofs_do_rmdir(fs_ctx, dir_ii, &nstr);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_symlink(struct silofs_fs_ctx *fs_ctx, ino_t parent,
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

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(fs_ctx, parent, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, dir_ii, name);
	ok_or_goto_out(err);

	err = symval_to_str(symval, &value);
	ok_or_goto_out(err);

	err = silofs_do_symlink(fs_ctx, dir_ii, &nstr, &value, &ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(fs_ctx, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(fs_ctx, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_readlink(struct silofs_fs_ctx *fs_ctx, ino_t ino,
                       char *ptr, size_t lim, size_t *out_len)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdo_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_readlink(fs_ctx, ii, ptr, lim, out_len);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_unlink(struct silofs_fs_ctx *fs_ctx,
                     ino_t parent, const char *name)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(fs_ctx, parent, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, dir_ii, name);
	ok_or_goto_out(err);

	err = silofs_do_unlink(fs_ctx, dir_ii, &nstr);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_link(struct silofs_fs_ctx *fs_ctx, ino_t ino, ino_t parent,
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

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(fs_ctx, parent, &dir_ii);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, dir_ii, name);
	ok_or_goto_out(err);

	err = silofs_do_link(fs_ctx, dir_ii, &nstr, ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(fs_ctx, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(fs_ctx, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_opendir(struct silofs_fs_ctx *fs_ctx, ino_t ino)
{
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdo_inode(fs_ctx, ino, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_opendir(fs_ctx, dir_ii);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_releasedir(struct silofs_fs_ctx *fs_ctx, ino_t ino, int o_flags)
{
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	unused(o_flags); /* TODO: useme */

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdo_inode(fs_ctx, ino, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_releasedir(fs_ctx, dir_ii);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_readdir(struct silofs_fs_ctx *fs_ctx, ino_t ino,
                      struct silofs_readdir_ctx *rd_ctx)
{
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdo_inode(fs_ctx, ino, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_readdir(fs_ctx, dir_ii, rd_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

struct silofs_readdir_filter_ctx {
	struct silofs_readdir_ctx *rd_ctx_orig;
	struct silofs_fs_ctx      *fs_ctx;
	struct silofs_readdir_ctx  rd_ctx;
};

static int readdirplus_actor(struct silofs_readdir_ctx *rd_ctx,
                             const struct silofs_readdir_info *rdi)
{
	struct silofs_readdir_info rdi2;
	struct silofs_readdir_filter_ctx *rdf_ctx =
	        container_of(rd_ctx, struct silofs_readdir_filter_ctx, rd_ctx);
	int ret;

	if (rdi->attr.st_ino == 0) {
		/* case1: fast; no need to re-map attr */
		ret = rdf_ctx->rd_ctx_orig->actor(rdf_ctx->rd_ctx_orig, rdi);
	} else {
		/* case2: copy attr to local and re-map uid-gid */
		memcpy(&rdi2, rdi, sizeof(rdi2));
		op_rmap_stat(rdf_ctx->fs_ctx, &rdi2.attr);
		rdf_ctx->rd_ctx_orig->pos = rdf_ctx->rd_ctx.pos;
		ret = rdf_ctx->rd_ctx_orig->actor(rdf_ctx->rd_ctx_orig, &rdi2);
	}
	return ret;
}

int silofs_fs_readdirplus(struct silofs_fs_ctx *fs_ctx, ino_t ino,
                          struct silofs_readdir_ctx *rd_ctx)
{
	struct silofs_readdir_filter_ctx rdf_ctx = {
		.rd_ctx_orig = rd_ctx,
		.fs_ctx = fs_ctx,
		.rd_ctx.actor = readdirplus_actor,
		.rd_ctx.pos = rd_ctx->pos,
	};
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdo_inode(fs_ctx, ino, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_readdirplus(fs_ctx, dir_ii, &rdf_ctx.rd_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_fsyncdir(struct silofs_fs_ctx *fs_ctx, ino_t ino, bool datasync)
{
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdo_inode(fs_ctx, ino, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_fsyncdir(fs_ctx, dir_ii, datasync);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_chmod(struct silofs_fs_ctx *fs_ctx, ino_t ino, mode_t mode,
                    const struct stat *st, struct stat *out_stat)
{
	struct silofs_itimes itimes;
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	stat_to_itimes(st, &itimes);
	err = silofs_do_chmod(fs_ctx, ii, mode, &itimes);
	ok_or_goto_out(err);

	err = silofs_do_getattr(fs_ctx, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(fs_ctx, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_chown(struct silofs_fs_ctx *fs_ctx, ino_t ino, uid_t uid,
                    gid_t gid, const struct stat *st, struct stat *out_stat)
{
	struct silofs_itimes itimes;
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_uidgid(fs_ctx, uid, gid, &uid, &gid);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	stat_to_itimes(st, &itimes);
	err = silofs_do_chown(fs_ctx, ii, uid, gid, &itimes);
	ok_or_goto_out(err);

	err = silofs_do_getattr(fs_ctx, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(fs_ctx, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_utimens(struct silofs_fs_ctx *fs_ctx, ino_t ino,
                      const struct stat *times, struct stat *out_stat)
{
	struct silofs_itimes itimes;
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	stat_to_itimes(times, &itimes);
	err = silofs_do_utimens(fs_ctx, ii, &itimes);
	ok_or_goto_out(err);

	err = silofs_do_getattr(fs_ctx, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(fs_ctx, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_truncate(struct silofs_fs_ctx *fs_ctx,
                       ino_t ino, loff_t len, struct stat *out_stat)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_truncate(fs_ctx, ii, len);
	ok_or_goto_out(err);

	err = silofs_do_getattr(fs_ctx, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(fs_ctx, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_create(struct silofs_fs_ctx *fs_ctx, ino_t parent,
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

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(fs_ctx, parent, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, dir_ii, name);
	ok_or_goto_out(err);

	err = silofs_do_create(fs_ctx, dir_ii, &nstr, mode, &ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(fs_ctx, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(fs_ctx, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_open(struct silofs_fs_ctx *fs_ctx, ino_t ino, int o_flags)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_openable_inode(fs_ctx, ino, o_flags, &ii);
	ok_or_goto_out(err);

	err = silofs_do_open(fs_ctx, ii, o_flags);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_mknod(struct silofs_fs_ctx *fs_ctx, ino_t parent,
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

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(fs_ctx, parent, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, dir_ii, name);
	ok_or_goto_out(err);

	err = silofs_do_mknod(fs_ctx, dir_ii, &nstr, mode, rdev, &ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(fs_ctx, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(fs_ctx, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_release(struct silofs_fs_ctx *fs_ctx,
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

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdo_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_release(fs_ctx, ii);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_flush(struct silofs_fs_ctx *fs_ctx, ino_t ino)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdo_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_flush(fs_ctx, ii);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_fsync(struct silofs_fs_ctx *fs_ctx, ino_t ino, bool datasync)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdo_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_fsync(fs_ctx, ii, datasync);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_rename(struct silofs_fs_ctx *fs_ctx, ino_t parent,
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

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(fs_ctx, parent, &parent_ii);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(fs_ctx, newparent, &newp_ii);
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

int silofs_fs_read(struct silofs_fs_ctx *fs_ctx, ino_t ino, void *buf,
                   size_t len, loff_t off, size_t *out_len)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdo_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_read(fs_ctx, ii, buf, len, off, out_len);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_read_iter(struct silofs_fs_ctx *fs_ctx, ino_t ino,
                        struct silofs_rwiter_ctx *rwi_ctx)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdo_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_read_iter(fs_ctx, ii, rwi_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_write(struct silofs_fs_ctx *fs_ctx, ino_t ino,
                    const void *buf, size_t len, loff_t off, size_t *out_len)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_write(fs_ctx, ii, buf, len, off, out_len);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_write_iter(struct silofs_fs_ctx *fs_ctx, ino_t ino,
                         struct silofs_rwiter_ctx *rwi_ctx)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_write_iter(fs_ctx, ii, rwi_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_fallocate(struct silofs_fs_ctx *fs_ctx, ino_t ino,
                        int mode, loff_t offset, loff_t length)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_fallocate(fs_ctx, ii, mode, offset, length);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_lseek(struct silofs_fs_ctx *fs_ctx, ino_t ino,
                    loff_t off, int whence, loff_t *out_off)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdo_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_lseek(fs_ctx, ii, off, whence, out_off);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_copy_file_range(struct silofs_fs_ctx *fs_ctx, ino_t ino_in,
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

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(fs_ctx, ino_in, &ii_in);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(fs_ctx, ino_out, &ii_out);
	ok_or_goto_out(err);

	err = silofs_do_copy_file_range(fs_ctx, ii_in, ii_out, off_in,
	                                off_out, len, flags, out_ncp);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_setxattr(struct silofs_fs_ctx *fs_ctx, ino_t ino,
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

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, ii, name);
	ok_or_goto_out(err);

	err = silofs_do_setxattr(fs_ctx, ii, &nstr,
	                         value, size, flags, kill_sgid);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_getxattr(struct silofs_fs_ctx *fs_ctx, ino_t ino,
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

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdo_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, ii, name);
	ok_or_goto_out(err);

	err = silofs_do_getxattr(fs_ctx, ii, &nstr, buf, size, out_size);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_listxattr(struct silofs_fs_ctx *fs_ctx, ino_t ino,
                        struct silofs_listxattr_ctx *lxa_ctx)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdo_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_listxattr(fs_ctx, ii, lxa_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_removexattr(struct silofs_fs_ctx *fs_ctx,
                          ino_t ino, const char *name)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, ii, name);
	ok_or_goto_out(err);

	err = silofs_do_removexattr(fs_ctx, ii, &nstr);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_statx(struct silofs_fs_ctx *fs_ctx, ino_t ino,
                    unsigned int request_mask, struct statx *out_stx)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdo_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_statx(fs_ctx, ii, request_mask, out_stx);
	ok_or_goto_out(err);

	err = op_rmap_statx(fs_ctx, out_stx);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_fiemap(struct silofs_fs_ctx *fs_ctx,
                     ino_t ino, struct fiemap *fm)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdo_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_fiemap(fs_ctx, ii, fm);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_syncfs(struct silofs_fs_ctx *fs_ctx, ino_t ino)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_query(struct silofs_fs_ctx *fs_ctx, ino_t ino,
                    enum silofs_query_type qtype,
                    struct silofs_ioc_query *out_qry)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdo_inode(fs_ctx, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_query(fs_ctx, ii, qtype, out_qry);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_clone(struct silofs_fs_ctx *fs_ctx, ino_t ino,
                    int flags, struct silofs_bootsecs *out_bsecs)
{
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = op_stage_rdo_inode(fs_ctx, ino, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_clone(fs_ctx, dir_ii, flags, out_bsecs);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_fs_pack(struct silofs_fs_ctx *fs_ctx,
                   const struct silofs_kivam *kivam,
                   const struct silofs_bootsec *bsec_src,
                   struct silofs_bootsec *bsec_dst)
{
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = silofs_do_pack(fs_ctx, kivam, bsec_src, bsec_dst);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_unpack(struct silofs_fs_ctx *fs_ctx,
                     const struct silofs_kivam *kivam,
                     const struct silofs_bootsec *bsec_src,
                     struct silofs_bootsec *bsec_dst)
{
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = silofs_do_unpack(fs_ctx, kivam, bsec_src, bsec_dst);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_fs_rdwr_post(const struct silofs_fs_ctx *fs_ctx,
                        const struct silofs_iovec *iov, size_t cnt)
{
	return silofs_do_rdwr_post(fs_ctx, iov, cnt);
}

int silofs_fs_timedout(const struct silofs_fs_ctx *fs_ctx, int flags)
{
	struct silofs_fs_uber *uber = fs_ctx->fsc_uber;
	int err;

	err = silofs_uber_flush_dirty(uber, SILOFS_DQID_ALL, flags);
	if (err) {
		return err;
	}
	silofs_uber_relax_caches(uber, flags);
	return 0;
}

int silofs_fs_inspect(struct silofs_fs_ctx *fs_ctx)
{
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = silofs_do_inspect(fs_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}

int silofs_fs_unrefs(struct silofs_fs_ctx *fs_ctx)
{
	int err;

	err = op_start(fs_ctx);
	ok_or_goto_out(err);

	err = op_authorize(fs_ctx);
	ok_or_goto_out(err);

	err = op_map_creds(fs_ctx);
	ok_or_goto_out(err);

	err = silofs_do_unrefs(fs_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(fs_ctx, err);
}
