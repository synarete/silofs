/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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

static void op_lock_fs(const struct silofs_task *task)
{
	silofs_mutex_lock(&task->t_uber->ub_fs_lock);
}

static void op_unlock_fs(const struct silofs_task *task)
{
	silofs_mutex_unlock(&task->t_uber->ub_fs_lock);
}

static int op_start(struct silofs_task *task, ino_t ino)
{
	struct silofs_uber *uber = task->t_uber;

	op_lock_fs(task);
	uber->ub_ops.op_time = task->t_oper.op_creds.ts.tv_sec;
	uber->ub_ops.op_count++;
	silofs_unused(ino);
	return 0;
}

static int op_start1(struct silofs_task *task, ino_t ino)
{
	int ret;

	ret = op_start(task, ino);
	if (ret == 0) {
		silofs_relax_cache_by(task, SILOFS_F_OPSTART);
	}
	return ret;
}

static int op_try_flush(struct silofs_task *task, struct silofs_inode_info *ii)
{
	return silofs_flush_dirty(task, ii, SILOFS_F_OPSTART);
}

static int op_try_flush2(struct silofs_task *task,
                         struct silofs_inode_info *ii1,
                         struct silofs_inode_info *ii2)
{
	int err1;
	int err2;

	ii_incref(ii1);
	ii_incref(ii2);
	err1 = op_try_flush(task, ii1);
	err2 = op_try_flush(task, ii2);
	ii_decref(ii1);
	ii_decref(ii2);
	return err1 ? err1 : err2;
}

static void op_probe_duration(const struct silofs_task *task, int status)
{
	const time_t now = silofs_time_now();
	const time_t beg = task->t_oper.op_creds.ts.tv_sec;
	const time_t dif = now - beg;
	const uint32_t op_code = task->t_oper.op_code;

	if (op_code && (beg < now) && (dif > 30)) {
		log_warn("slow-oper: id=%ld op_code=%u duration=%ld status=%d",
		         task->t_uber->ub_ops.op_count, op_code, dif, status);
	}
}

static int op_finish(struct silofs_task *task, ino_t ino, int err)
{
	op_probe_duration(task, err);
	if (!err && task->t_apex_id) {
		silofs_relax_cache_by(task, SILOFS_F_OPFINISH);
	}
	op_unlock_fs(task);
	unused(ino);
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
		return -SILOFS_EINVAL;
	}
	if (symlen > SILOFS_SYMLNK_MAX) {
		return -SILOFS_ENAMETOOLONG;
	}
	str->str = symval;
	str->len = symlen;
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_idsmap *
idsm_of(const struct silofs_task *task)
{
	return task->t_uber->ub.idsmap;
}

static const struct silofs_sb_info *sbi_of(const struct silofs_task *task)
{
	return task_sbi(task);
}

static const struct silofs_creds *creds_of(const struct silofs_task *task)
{
	return &task->t_oper.op_creds;
}

static struct silofs_creds *creds_of2(struct silofs_task *task)
{
	return &task->t_oper.op_creds;
}

static bool op_is_kernel(const struct silofs_task *task)
{
	const struct silofs_creds *creds = creds_of(task);

	return !creds->xcred.pid && !creds->xcred.uid && !creds->xcred.gid;
}

static bool op_is_admin(const struct silofs_task *task)
{
	return (sbi_of(task) == NULL) || op_is_kernel(task);
}

static bool op_is_fsowner(const struct silofs_task *task)
{
	const struct silofs_creds *creds = creds_of(task);

	return uid_eq(creds->xcred.uid, task->t_uber->ub_owner.uid);
}

static bool op_cap_sys_admin(const struct silofs_task *task)
{
	const struct silofs_creds *creds = creds_of(task);

	return (task->t_uber->ub_ctl_flags & SILOFS_UBF_ALLOWADMIN) &&
	       silofs_user_cap_sys_admin(&creds->xcred);
}

static bool op_allow_other(const struct silofs_task *task)
{
	return (task->t_uber->ub_ctl_flags & SILOFS_UBF_ALLOWOTHER) > 0;
}

static int op_authorize(const struct silofs_task *task)
{
	if (sbi_of(task) == NULL) {
		return 0; /* case unpack */
	}
	if (op_is_kernel(task)) {
		return 0; /* request by kernel */
	}
	if (op_is_fsowner(task)) {
		return 0; /* request by file-system's owner */
	}
	if (op_cap_sys_admin(task)) {
		return 0;  /* request by system administrator */
	}
	if (op_allow_other(task)) {
		return 0; /* request by other users */
	}
	return -SILOFS_EPERM;
}

static int op_map_creds(struct silofs_task *task)
{
	struct silofs_creds *creds = creds_of2(task);
	int ret = 0;

	creds->icred.uid = creds->xcred.uid;
	creds->icred.gid = creds->xcred.gid;
	creds->icred.pid = creds->xcred.pid;
	creds->icred.umask = creds->xcred.umask;

	if (!op_is_admin(task)) {
		ret = silofs_idsmap_map_creds(idsm_of(task), creds);
	}
	return (ret == -SILOFS_ENOENT) ? -SILOFS_EPERM : ret;
}

static int op_map_uidgid(const struct silofs_task *task,
                         uid_t uid, gid_t gid, uid_t *out_uid, gid_t *out_gid)
{
	int ret;

	ret = silofs_idsmap_map_uidgid(idsm_of(task),
	                               uid, gid, out_uid, out_gid);
	return (ret == -SILOFS_ENOENT) ? -SILOFS_EPERM : ret;
}

static int op_rmap_stat(const struct silofs_task *task, struct silofs_stat *st)
{
	int ret;

	ret = silofs_idsmap_rmap_stat(idsm_of(task), st);
	return (ret == -SILOFS_ENOENT) ? 0 : ret;
}

static int op_rmap_statx(const struct silofs_task *task, struct statx *stx)
{
	int ret;

	ret = silofs_idsmap_rmap_statx(idsm_of(task), stx);
	return (ret == -SILOFS_ENOENT) ? 0 : ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int op_stage_cacheonly_inode(struct silofs_task *task, ino_t ino,
                                    struct silofs_inode_info **out_ii)
{
	return silofs_stage_cached_inode(task, ino, out_ii);
}

static int op_stage_cur_inode(struct silofs_task *task, ino_t ino,
                              struct silofs_inode_info **out_ii)
{
	return silofs_stage_inode(task, ino, SILOFS_STG_CUR, out_ii);
}

static int op_stage_mut_inode(struct silofs_task *task, ino_t ino,
                              struct silofs_inode_info **out_ii)
{
	return silofs_stage_inode(task, ino, SILOFS_STG_COW, out_ii);
}

static int op_stage_mut_inode2(struct silofs_task *task,
                               ino_t ino1, ino_t ino2,
                               struct silofs_inode_info **out_ii1,
                               struct silofs_inode_info **out_ii2)
{
	int err;

	err = op_stage_mut_inode(task, ino1, out_ii1);
	if (!err) {
		ii_incref(*out_ii1);
		err = op_stage_mut_inode(task, ino2, out_ii2);
		ii_decref(*out_ii1);
	}
	return err;
}


static int
op_stage_openable_inode(struct silofs_task *task, ino_t ino,
                        int o_flags, struct silofs_inode_info **out_ii)
{
	int err;

	if (o_flags & (O_RDWR | O_WRONLY | O_TRUNC | O_APPEND)) {
		err = op_stage_mut_inode(task, ino, out_ii);
	} else {
		err = op_stage_cur_inode(task, ino, out_ii);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_fs_forget(struct silofs_task *task, ino_t ino, size_t nlookup)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_cacheonly_inode(task, ino, &ii);
	ok_or_goto_out_ok(err);

	err = silofs_do_forget(task, ii, nlookup);
	ok_or_goto_out(err);
out_ok:
	err = 0;
out:
	return op_finish(task, ino, err);
}

int silofs_fs_statfs(struct silofs_task *task,
                     ino_t ino, struct statvfs *stvfs)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(task, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_statvfs(task, ii, stvfs);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

int silofs_fs_lookup(struct silofs_task *task, ino_t parent,
                     const char *name, struct silofs_stat *out_stat)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = NULL;
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start(task, parent);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(task, parent, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, dir_ii, name);
	ok_or_goto_out(err);

	err = silofs_do_lookup(task, dir_ii, &nstr, &ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(task, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(task, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(task, parent, err);
}

int silofs_fs_getattr(struct silofs_task *task,
                      ino_t ino, struct silofs_stat *out_stat)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(task, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(task, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(task, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

int silofs_fs_access(struct silofs_task *task, ino_t ino, int mode)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(task, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_access(task, ii, mode);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

int silofs_fs_mkdir(struct silofs_task *task, ino_t parent,
                    const char *name, mode_t mode,
                    struct silofs_stat *out_stat)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = NULL;
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start1(task, parent);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(task, parent, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, dir_ii, name);
	ok_or_goto_out(err);

	err = op_try_flush(task, dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_mkdir(task, dir_ii, &nstr, mode, &ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(task, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(task, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(task, parent, err);
}

int silofs_fs_rmdir(struct silofs_task *task,
                    ino_t parent, const char *name)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start1(task, parent);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(task, parent, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, dir_ii, name);
	ok_or_goto_out(err);

	err = op_try_flush(task, dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_rmdir(task, dir_ii, &nstr);
	ok_or_goto_out(err);
out:
	return op_finish(task, parent, err);
}

int silofs_fs_symlink(struct silofs_task *task, ino_t parent,
                      const char *name, const char *symval,
                      struct silofs_stat *out_stat)
{
	struct silofs_str value;
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = NULL;
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start1(task, parent);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(task, parent, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, dir_ii, name);
	ok_or_goto_out(err);

	err = symval_to_str(symval, &value);
	ok_or_goto_out(err);

	err = op_try_flush(task, dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_symlink(task, dir_ii, &nstr, &value, &ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(task, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(task, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(task, parent, err);
}

int silofs_fs_readlink(struct silofs_task *task, ino_t ino,
                       char *ptr, size_t lim, size_t *out_len)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start1(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(task, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_readlink(task, ii, ptr, lim, out_len);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

int silofs_fs_unlink(struct silofs_task *task,
                     ino_t parent, const char *name)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start1(task, parent);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(task, parent, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, dir_ii, name);
	ok_or_goto_out(err);

	err = op_try_flush(task, dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_unlink(task, dir_ii, &nstr);
	ok_or_goto_out(err);
out:
	return op_finish(task, parent, err);
}

int silofs_fs_link(struct silofs_task *task, ino_t ino, ino_t parent,
                   const char *name, struct silofs_stat *out_stat)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = NULL;
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start1(task, parent);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(task, parent, &dir_ii);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(task, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, dir_ii, name);
	ok_or_goto_out(err);

	err = op_try_flush(task, dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_link(task, dir_ii, &nstr, ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(task, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(task, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(task, parent, err);
}

int silofs_fs_opendir(struct silofs_task *task, ino_t ino)
{
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(task, ino, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_opendir(task, dir_ii);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

int silofs_fs_releasedir(struct silofs_task *task, ino_t ino, int o_flags)
{
	struct silofs_inode_info *dir_ii = NULL;
	const bool flush = (o_flags & O_SYNC) > 0;
	int err;

	err = op_start(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(task, ino, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_releasedir(task, dir_ii, flush);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

int silofs_fs_readdir(struct silofs_task *task, ino_t ino,
                      struct silofs_readdir_ctx *rd_ctx)
{
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start1(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(task, ino, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_readdir(task, dir_ii, rd_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

struct silofs_readdir_filter_ctx {
	struct silofs_readdir_ctx *rd_ctx_orig;
	struct silofs_task      *task;
	struct silofs_readdir_ctx  rd_ctx;
};

static int readdirplus_actor(struct silofs_readdir_ctx *rd_ctx,
                             const struct silofs_readdir_info *rdi)
{
	struct silofs_readdir_info rdi2;
	struct silofs_readdir_filter_ctx *rdf_ctx =
	        container_of(rd_ctx, struct silofs_readdir_filter_ctx, rd_ctx);
	int ret;

	if (rdi->attr.st.st_ino == 0) {
		/* case1: fast; no need to re-map attr */
		ret = rdf_ctx->rd_ctx_orig->actor(rdf_ctx->rd_ctx_orig, rdi);
	} else {
		/* case2: copy attr to local and re-map uid-gid */
		memcpy(&rdi2, rdi, sizeof(rdi2));
		op_rmap_stat(rdf_ctx->task, &rdi2.attr);
		rdf_ctx->rd_ctx_orig->pos = rdf_ctx->rd_ctx.pos;
		ret = rdf_ctx->rd_ctx_orig->actor(rdf_ctx->rd_ctx_orig, &rdi2);
	}
	return ret;
}

int silofs_fs_readdirplus(struct silofs_task *task, ino_t ino,
                          struct silofs_readdir_ctx *rd_ctx)
{
	struct silofs_readdir_filter_ctx rdf_ctx = {
		.rd_ctx_orig = rd_ctx,
		.task = task,
		.rd_ctx.actor = readdirplus_actor,
		.rd_ctx.pos = rd_ctx->pos,
	};
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(task, ino, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_readdirplus(task, dir_ii, &rdf_ctx.rd_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

int silofs_fs_fsyncdir(struct silofs_task *task, ino_t ino, bool datasync)
{
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start1(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(task, ino, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_fsyncdir(task, dir_ii, datasync);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

int silofs_fs_chmod(struct silofs_task *task, ino_t ino, mode_t mode,
                    const struct stat *st, struct silofs_stat *out_stat)
{
	struct silofs_itimes itimes;
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start1(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(task, ino, &ii);
	ok_or_goto_out(err);

	err = op_try_flush(task, ii);
	ok_or_goto_out(err);

	stat_to_itimes(st, &itimes);
	err = silofs_do_chmod(task, ii, mode, &itimes);
	ok_or_goto_out(err);

	err = silofs_do_getattr(task, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(task, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

int silofs_fs_chown(struct silofs_task *task, ino_t ino, uid_t uid, gid_t gid,
                    const struct stat *st, struct silofs_stat *out_stat)
{
	struct silofs_itimes itimes;
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start1(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_map_uidgid(task, uid, gid, &uid, &gid);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(task, ino, &ii);
	ok_or_goto_out(err);

	err = op_try_flush(task, ii);
	ok_or_goto_out(err);

	stat_to_itimes(st, &itimes);
	err = silofs_do_chown(task, ii, uid, gid, &itimes);
	ok_or_goto_out(err);

	err = silofs_do_getattr(task, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(task, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

int silofs_fs_utimens(struct silofs_task *task, ino_t ino,
                      const struct stat *times, struct silofs_stat *out_stat)
{
	struct silofs_itimes itimes;
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(task, ino, &ii);
	ok_or_goto_out(err);

	stat_to_itimes(times, &itimes);
	err = silofs_do_utimens(task, ii, &itimes);
	ok_or_goto_out(err);

	err = silofs_do_getattr(task, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(task, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

int silofs_fs_truncate(struct silofs_task *task,
                       ino_t ino, loff_t len, struct silofs_stat *out_stat)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start1(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(task, ino, &ii);
	ok_or_goto_out(err);

	err = op_try_flush(task, ii);
	ok_or_goto_out(err);

	err = silofs_do_truncate(task, ii, len);
	ok_or_goto_out(err);

	err = silofs_do_getattr(task, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(task, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

int silofs_fs_create(struct silofs_task *task, ino_t parent,
                     const char *name, int o_flags, mode_t mode,
                     struct silofs_stat *out_stat)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = NULL;
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	unused(o_flags); /* XXX use me */

	err = op_start1(task, parent);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(task, parent, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, dir_ii, name);
	ok_or_goto_out(err);

	err = op_try_flush(task, dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_create(task, dir_ii, &nstr, mode, &ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(task, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(task, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(task, parent, err);
}

int silofs_fs_open(struct silofs_task *task, ino_t ino, int o_flags)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_openable_inode(task, ino, o_flags, &ii);
	ok_or_goto_out(err);

	err = silofs_do_open(task, ii, o_flags);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

int silofs_fs_mknod(struct silofs_task *task, ino_t parent,
                    const char *name, mode_t mode, dev_t rdev,
                    struct silofs_stat *out_stat)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = NULL;
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start1(task, parent);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(task, parent, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, dir_ii, name);
	ok_or_goto_out(err);

	err = op_try_flush(task, dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_mknod(task, dir_ii, &nstr, mode, rdev, &ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(task, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(task, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(task, parent, err);
}

int silofs_fs_release(struct silofs_task *task,
                      ino_t ino, int o_flags, bool flush)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	/* TODO: useme */
	unused(o_flags);

	err = op_start1(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_try_flush(task, ii);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(task, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_release(task, ii, flush);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

int silofs_fs_flush(struct silofs_task *task, ino_t ino, bool now)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start1(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(task, ino, &ii);
	ok_or_goto_out(err);

	err = op_try_flush(task, ii);
	ok_or_goto_out(err);

	err = silofs_do_flush(task, ii, now);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

int silofs_fs_fsync(struct silofs_task *task, ino_t ino, bool datasync)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start1(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(task, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_fsync(task, ii, datasync);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

int silofs_fs_rename(struct silofs_task *task, ino_t parent,
                     const char *name, ino_t newparent,
                     const char *newname, int flags)
{
	struct silofs_namestr nstr;
	struct silofs_namestr newnstr;
	struct silofs_inode_info *curd_ii = NULL;
	struct silofs_inode_info *newd_ii = NULL;
	int err;

	err = op_start1(task, parent);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_mut_inode2(task, parent, newparent, &curd_ii, &newd_ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, curd_ii, name);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&newnstr, newd_ii, newname);
	ok_or_goto_out(err);

	err = op_try_flush2(task, curd_ii, newd_ii);
	ok_or_goto_out(err);

	err = silofs_do_rename(task, curd_ii, &nstr, newd_ii, &newnstr, flags);
	ok_or_goto_out(err);
out:
	return op_finish(task, parent, err);
}

int silofs_fs_read(struct silofs_task *task, ino_t ino, void *buf,
                   size_t len, loff_t off, size_t *out_len)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start1(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(task, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_read(task, ii, buf, len, off, out_len);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

int silofs_fs_read_iter(struct silofs_task *task, ino_t ino,
                        struct silofs_rwiter_ctx *rwi_ctx)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start1(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(task, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_read_iter(task, ii, rwi_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

int silofs_fs_write(struct silofs_task *task, ino_t ino,
                    const void *buf, size_t len, loff_t off, size_t *out_len)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start1(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(task, ino, &ii);
	ok_or_goto_out(err);

	err = op_try_flush(task, ii);
	ok_or_goto_out(err);

	err = silofs_do_write(task, ii, buf, len, off, out_len);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

int silofs_fs_write_iter(struct silofs_task *task, ino_t ino,
                         struct silofs_rwiter_ctx *rwi_ctx)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start1(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(task, ino, &ii);
	ok_or_goto_out(err);

	err = op_try_flush(task, ii);
	ok_or_goto_out(err);

	err = silofs_do_write_iter(task, ii, rwi_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

int silofs_fs_fallocate(struct silofs_task *task, ino_t ino,
                        int mode, loff_t offset, loff_t length)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start1(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(task, ino, &ii);
	ok_or_goto_out(err);

	err = op_try_flush(task, ii);
	ok_or_goto_out(err);

	err = silofs_do_fallocate(task, ii, mode, offset, length);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

int silofs_fs_lseek(struct silofs_task *task, ino_t ino,
                    loff_t off, int whence, loff_t *out_off)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(task, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_lseek(task, ii, off, whence, out_off);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

int silofs_fs_copy_file_range(struct silofs_task *task, ino_t ino_in,
                              loff_t off_in, ino_t ino_out, loff_t off_out,
                              size_t len, int flags, size_t *out_ncp)
{
	struct silofs_inode_info *ii_in = NULL;
	struct silofs_inode_info *ii_out = NULL;
	int err;

	err = op_start1(task, ino_in);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_mut_inode2(task, ino_in, ino_out, &ii_in, &ii_out);
	ok_or_goto_out(err);

	err = op_try_flush2(task, ii_in, ii_out);
	ok_or_goto_out(err);

	err = silofs_do_copy_file_range(task, ii_in, ii_out, off_in,
	                                off_out, len, flags, out_ncp);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino_in, err);
}

int silofs_fs_setxattr(struct silofs_task *task, ino_t ino,
                       const char *name, const void *value,
                       size_t size, int flags, bool kill_sgid)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start1(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(task, ino, &ii);
	ok_or_goto_out(err);

	err = op_try_flush(task, ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, ii, name);
	ok_or_goto_out(err);

	err = silofs_do_setxattr(task, ii, &nstr,
	                         value, size, flags, kill_sgid);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

int silofs_fs_getxattr(struct silofs_task *task, ino_t ino,
                       const char *name, void *buf, size_t size,
                       size_t *out_size)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start1(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(task, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, ii, name);
	ok_or_goto_out(err);

	err = silofs_do_getxattr(task, ii, &nstr, buf, size, out_size);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

int silofs_fs_listxattr(struct silofs_task *task, ino_t ino,
                        struct silofs_listxattr_ctx *lxa_ctx)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(task, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_listxattr(task, ii, lxa_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

int silofs_fs_removexattr(struct silofs_task *task,
                          ino_t ino, const char *name)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start1(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(task, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_make_namestr_by(&nstr, ii, name);
	ok_or_goto_out(err);

	err = op_try_flush(task, ii);
	ok_or_goto_out(err);

	err = silofs_do_removexattr(task, ii, &nstr);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

int silofs_fs_statx(struct silofs_task *task, ino_t ino,
                    unsigned int request_mask, struct statx *out_stx)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(task, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_statx(task, ii, request_mask, out_stx);
	ok_or_goto_out(err);

	err = op_rmap_statx(task, out_stx);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

int silofs_fs_fiemap(struct silofs_task *task,
                     ino_t ino, struct fiemap *fm)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(task, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_fiemap(task, ii, fm);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

int silofs_fs_syncfs(struct silofs_task *task, ino_t ino, int flags)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start1(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(task, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_syncfs(task, ii, flags);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

int silofs_fs_query(struct silofs_task *task, ino_t ino,
                    enum silofs_query_type qtype,
                    struct silofs_ioc_query *out_qry)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = op_start(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(task, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_query(task, ii, qtype, out_qry);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

int silofs_fs_clone(struct silofs_task *task, ino_t ino,
                    int flags, struct silofs_bootsecs *out_bsecs)
{
	struct silofs_inode_info *dir_ii = NULL;
	int err;

	err = op_start1(task, ino);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(task, ino, &dir_ii);
	ok_or_goto_out(err);

	err = op_try_flush(task, dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_clone(task, dir_ii, flags, out_bsecs);
	ok_or_goto_out(err);
out:
	return op_finish(task, ino, err);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_fs_rdwr_post(const struct silofs_task *task,
                        const struct silofs_iovec *iov, size_t cnt)
{
	int ret;

	op_lock_fs(task);
	ret = silofs_do_rdwr_post(task, iov, cnt);
	op_unlock_fs(task);
	return ret;
}

int silofs_fs_timedout(struct silofs_task *task, int flags)
{
	int err;

	err = op_start1(task, SILOFS_INO_NULL);
	ok_or_goto_out(err);

	err = silofs_flush_dirty(task, NULL, flags);
	ok_or_goto_out(err);

	silofs_relax_cache_by(task, flags);
out:
	return op_finish(task, SILOFS_INO_NULL, err);
}

int silofs_fs_inspect(struct silofs_task *task)
{
	int err;

	err = op_start1(task, SILOFS_INO_NULL);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = silofs_do_inspect(task);
	ok_or_goto_out(err);
out:
	return op_finish(task, SILOFS_INO_NULL, err);
}

int silofs_fs_unrefs(struct silofs_task *task)
{
	int err;

	err = op_start1(task, SILOFS_INO_NULL);
	ok_or_goto_out(err);

	err = op_authorize(task);
	ok_or_goto_out(err);

	err = op_map_creds(task);
	ok_or_goto_out(err);

	err = silofs_do_unrefs(task);
	ok_or_goto_out(err);
out:
	return op_finish(task, SILOFS_INO_NULL, err);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_remap_status_code(int status)
{
	int ret = status;

	if (ret) {
		ret = abs(status);
		if (ret >= SILOFS_ERRBASE2) {
			ret = EUCLEAN;
		} else if (ret >= SILOFS_ERRBASE) {
			ret = (ret - SILOFS_ERRBASE);
		}
	}
	return -ret;
}

