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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <fcntl.h>
#include <time.h>

#include <silofs/fs.h>
#include <silofs/run.h>

static void op_feed_prng(const struct silofs_task_ctx *task)
{
	const uint32_t d[] = {
		(uint32_t)((uintptr_t)task) >> 3,
		task->auth.opcode,
		(uint32_t)task->auth.pid,
		(uint32_t)task->auth.unique,
		(uint32_t)(task->auth.unique >> 32),
		(uint32_t)task->auth.ts.tv_nsec,
		(uint32_t)task->auth.ts.tv_sec,
		(uint32_t)task->auth.creds.host_cred.uid,
		(uint32_t)task->auth.creds.host_cred.gid,
		(uint32_t)gettid(),
	};

	silofs_prandgen_feed(task->ectx->prng, d, sizeof(d));
}

static int op_start(struct silofs_task_ctx *task)
{
	silofs_lock_fs_by(task);

	silofs_clock_gettime_mono(&task->op_start_time);
	if (!task->internal) {
		task->ectx->fsroot->opstat.op_count++;
		op_feed_prng(task);
	}
	return 0;
}

static int
op_try_flush(struct silofs_task_ctx *task, struct silofs_inode_info *ii)
{
	return silofs_flush_dirty(task, ii, SILOFS_CTLF_OPSTART);
}

static void op_probe_duration(const struct silofs_task_ctx *task, int res)
{
	const struct silofs_opstat *opstat = &task->ectx->fsroot->opstat;
	time_t time_now, time_dif;

	if (task->auth.opcode == 0) {
		return;
	}
	time_now = silofs_time_mono_now();
	time_dif = time_now - task->op_start_time.tv_sec;
	if (time_dif < 30) {
		return;
	}
	log_warn("slow-oper: op_count=%zu op_code=%u dif=%ld res=%d",
	         opstat->op_count, task->auth.opcode, time_dif, res);
}

static int op_unlooseq(struct silofs_task_ctx *task)
{
	int ret = 0;

	/*
	 * Task's loose-queue may hold one (or more) inodes which are no-longer
	 * alive but could not be fully dropped as they are still under to-be
	 * written state in submit-queue. This rare case may happen on heavy
	 * load with unlinked files. In this special case, we must do forced
	 * flush-all to purge and evict those pending inodes while current task
	 * still holds the fs-lock.
	 */
	if (task->looseq != nullptr) {
		ret = silofs_flush_dirty_now(task);
		silofs_assert_null(task->looseq);
	}
	return ret;
}

static int op_finish(struct silofs_task_ctx *task, int err)
{
	int err2 = 0;

	op_probe_duration(task, err);
	err2 = op_unlooseq(task);

	silofs_unlock_fs_by(task);
	return err ? err : err2;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int symval_to_str(const char *symval, struct silofs_strview *out_sv)
{
	size_t symlen;

	symlen = strnlen(symval, SILOFS_SYMLNK_MAX + 1);
	if (symlen == 0) {
		return -SILOFS_EINVAL;
	}
	if (symlen > SILOFS_SYMLNK_MAX) {
		return -SILOFS_ENAMETOOLONG;
	}
	silofs_strview_initn(out_sv, symval, symlen);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool op_is_kernel(const struct silofs_task_ctx *task)
{
	const struct silofs_creds *creds = &task->auth.creds;

	if (task->kwrite) {
		return true;
	}
	if (task->auth.pid) {
		return false;
	}
	if (!creds->host_cred.uid && !creds->host_cred.gid) {
		return true;
	}
	return false;
}

static bool op_is_admin(const struct silofs_task_ctx *task)
{
	return op_is_kernel(task);
}

static bool op_is_fsowner(const struct silofs_task_ctx *task)
{
	const struct silofs_creds *creds   = &task->auth.creds;
	const struct silofs_fsroot *fsroot = task->ectx->fsroot;

	return silofs_uid_eq(creds->host_cred.uid, fsroot->owner.uid);
}

static bool
op_has_ctl_flags(const struct silofs_task_ctx *task, enum silofs_flags mask)
{
	return ((task->ectx->fsroot->ctl_flags & mask) == mask);
}

static bool op_cap_sys_admin(const struct silofs_task_ctx *task)
{
	const struct silofs_creds *creds = &task->auth.creds;

	return op_has_ctl_flags(task, SILOFS_F_ALLOW_ADMIN) &&
	       silofs_user_cap_sys_admin(&creds->host_cred);
}

static bool op_allow_other(const struct silofs_task_ctx *task)
{
	return op_has_ctl_flags(task, SILOFS_F_ALLOW_OTHER);
}

static int op_authorize(const struct silofs_task_ctx *task)
{
	if (op_is_admin(task)) {
		return 0; /* case off-line operation XXX */
	}
	if (op_is_kernel(task)) {
		return 0; /* request by kernel */
	}
	if (op_is_fsowner(task)) {
		return 0; /* request by file-system's owner */
	}
	if (op_cap_sys_admin(task)) {
		return 0; /* request by system administrator */
	}
	if (op_allow_other(task)) {
		return 0; /* request by other users */
	}
	return -SILOFS_EPERM;
}

static int op_map_uidgid(const struct silofs_task_ctx *task, uid_t uid,
                         gid_t gid, uid_t *out_uid, gid_t *out_gid)
{
	const struct silofs_idsmap *idsmap = task->ectx->idsmap;
	int ret;

	ret = silofs_idsmap_mapcreds(idsmap, uid, gid, out_uid, out_gid);
	return (ret == -SILOFS_ENOENT) ? -SILOFS_EPERM : ret;
}

static int op_map_creds(struct silofs_task_ctx *task)
{
	const struct silofs_cred *host_cred = &task->auth.creds.host_cred;
	struct silofs_cred *fs_cred         = &task->auth.creds.fs_cred;
	int ret                             = 0;

	fs_cred->uid   = host_cred->uid;
	fs_cred->gid   = host_cred->gid;
	fs_cred->umask = host_cred->umask;

	if (!op_is_admin(task)) {
		ret = op_map_uidgid(task, host_cred->uid, host_cred->gid,
		                    &fs_cred->uid, &fs_cred->gid);
	}
	return (ret == -SILOFS_ENOENT) ? -SILOFS_EPERM : ret;
}

static int
op_rmap_stat(const struct silofs_task_ctx *task, struct silofs_stat *st)
{
	const uid_t uid_in = st->st.st_uid;
	const gid_t gid_in = st->st.st_gid;
	uid_t uid_out      = silofs_uid_null();
	gid_t gid_out      = silofs_gid_null();
	int ret;

	/*
	 * TODO-0062: Have fine-grained rmap for uid and for gid
	 *
	 * Separate into fine-grained functions (silofs_idsmap_rmap_uid and
	 * silofs_idsmap_rmap_gid). In case of rmap failure, emit 'nobody' only
	 * for the relevant id.
	 */
	ret = silofs_idsmap_rmapcreds(task->ectx->idsmap, uid_in, gid_in,
	                              &uid_out, &gid_out);
	st->st.st_uid = st->stx.stx_uid = uid_out;
	st->st.st_gid = st->stx.stx_gid = gid_out;
	return (ret == -SILOFS_ENOENT) ? 0 : ret;
}

static void
op_rmap_stat_any(const struct silofs_task_ctx *task, struct silofs_stat *st)
{
	int err;

	err = op_rmap_stat(task, st);
	if (err) {
		st->st.st_uid = st->stx.stx_uid = silofs_uid_nobody();
		st->st.st_gid = st->stx.stx_gid = silofs_gid_nobody();
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int op_stage_cacheonly_inode(struct silofs_task_ctx *task, ino_t ino,
                                    struct silofs_inode_info **out_ii)
{
	return silofs_lookup_cached_inode(task, ino, out_ii);
}

static int op_stage_inode(struct silofs_task_ctx *task, ino_t ino, bool mut,
                          struct silofs_inode_info **out_ii)
{
	enum silofs_stg_mode stg_mode = mut ? SILOFS_STG_COW : SILOFS_STG_CUR;

	return silofs_stage_inode_by(task, ino, stg_mode, out_ii);
}

static int op_stage_cur_inode(struct silofs_task_ctx *task, ino_t ino,
                              struct silofs_inode_info **out_ii)
{
	return op_stage_inode(task, ino, false, out_ii);
}

static int op_stage_mut_inode(struct silofs_task_ctx *task, ino_t ino,
                              struct silofs_inode_info *ii_alt,
                              struct silofs_inode_info **out_ii)
{
	int ret;

	silofs_ii_incref(ii_alt);
	ret = op_stage_inode(task, ino, true, out_ii);
	silofs_ii_decref(ii_alt);
	return ret;
}

static int op_stage_opt_inode(struct silofs_task_ctx *task, ino_t ino,
                              bool mut, struct silofs_inode_info **out_ii)
{
	int err;

	err = op_stage_inode(task, ino, mut, out_ii);
	if (!err && !mut && silofs_ii_isdirty(*out_ii)) {
		err = op_stage_inode(task, ino, true, out_ii);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_exec_forget(struct silofs_task_ctx *task, ino_t ino, size_t nlookup)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_cacheonly_inode(task, ino, &ii);
	goto_if_err(err, out_ok); /* Cache miss -- OK */

	err = silofs_do_forget(task, ii, nlookup);
	goto_out_if_err(err);
out_ok:
	err = 0;
out:
	return op_finish(task, err);
}

int silofs_exec_statfs(struct silofs_task_ctx *task, ino_t ino,
                       struct statvfs *stvfs)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_cur_inode(task, ino, &ii);
	goto_out_if_err(err);

	err = silofs_do_statvfs(task, ii, stvfs);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_lookup(struct silofs_task_ctx *task, ino_t parent,
                       const char *name, struct silofs_stat *out_stat)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii     = nullptr;
	struct silofs_inode_info *dir_ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_cur_inode(task, parent, &dir_ii);
	goto_out_if_err(err);

	err = silofs_make_linkname(task, dir_ii, name, &nstr);
	goto_out_if_err(err);

	err = silofs_do_lookup(task, dir_ii, &nstr, &ii);
	goto_out_if_err(err);

	err = silofs_do_getattr(task, ii, out_stat);
	goto_out_if_err(err);

	err = op_rmap_stat(task, out_stat);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_getattr(struct silofs_task_ctx *task, ino_t ino,
                        struct silofs_stat *out_st)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_cur_inode(task, ino, &ii);
	goto_out_if_err(err);

	err = silofs_do_getattr(task, ii, out_st);
	goto_out_if_err(err);

	err = op_rmap_stat(task, out_st);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_access(struct silofs_task_ctx *task, ino_t ino, int mode)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_cur_inode(task, ino, &ii);
	goto_out_if_err(err);

	err = silofs_do_access(task, ii, mode);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_mkdir(struct silofs_task_ctx *task, ino_t parent,
                      const char *name, mode_t mode,
                      struct silofs_stat *out_stat)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii     = nullptr;
	struct silofs_inode_info *dir_ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_mut_inode(task, parent, nullptr, &dir_ii);
	goto_out_if_err(err);

	err = silofs_make_linkname(task, dir_ii, name, &nstr);
	goto_out_if_err(err);

	err = op_try_flush(task, dir_ii);
	goto_out_if_err(err);

	err = silofs_do_mkdir(task, dir_ii, &nstr, mode, &ii);
	goto_out_if_err(err);

	err = silofs_do_getattr(task, ii, out_stat);
	goto_out_if_err(err);

	err = op_rmap_stat(task, out_stat);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_rmdir(struct silofs_task_ctx *task, ino_t parent,
                      const char *name)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *dir_ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_mut_inode(task, parent, nullptr, &dir_ii);
	goto_out_if_err(err);

	err = silofs_make_linkname(task, dir_ii, name, &nstr);
	goto_out_if_err(err);

	err = silofs_do_rmdir(task, dir_ii, &nstr);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_symlink(struct silofs_task_ctx *task, ino_t parent,
                        const char *name, const char *symval,
                        struct silofs_stat *out_stat)
{
	struct silofs_strview value;
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii     = nullptr;
	struct silofs_inode_info *dir_ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_mut_inode(task, parent, nullptr, &dir_ii);
	goto_out_if_err(err);

	err = silofs_make_linkname(task, dir_ii, name, &nstr);
	goto_out_if_err(err);

	err = symval_to_str(symval, &value);
	goto_out_if_err(err);

	err = op_try_flush(task, dir_ii);
	goto_out_if_err(err);

	err = silofs_do_symlink(task, dir_ii, &nstr, &value, &ii);
	goto_out_if_err(err);

	err = silofs_do_getattr(task, ii, out_stat);
	goto_out_if_err(err);

	err = op_rmap_stat(task, out_stat);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_readlink(struct silofs_task_ctx *task, ino_t ino, char *ptr,
                         size_t lim, size_t *out_len)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_cur_inode(task, ino, &ii);
	goto_out_if_err(err);

	err = silofs_do_readlink(task, ii, ptr, lim, out_len);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_unlink(struct silofs_task_ctx *task, ino_t parent,
                       const char *name)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *dir_ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_mut_inode(task, parent, nullptr, &dir_ii);
	goto_out_if_err(err);

	err = silofs_make_linkname(task, dir_ii, name, &nstr);
	goto_out_if_err(err);

	err = silofs_do_unlink(task, dir_ii, &nstr);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_link(struct silofs_task_ctx *task, ino_t ino, ino_t parent,
                     const char *name, struct silofs_stat *out_stat)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii     = nullptr;
	struct silofs_inode_info *dir_ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_mut_inode(task, parent, nullptr, &dir_ii);
	goto_out_if_err(err);

	err = op_stage_mut_inode(task, ino, dir_ii, &ii);
	goto_out_if_err(err);

	err = silofs_make_linkname(task, dir_ii, name, &nstr);
	goto_out_if_err(err);

	err = silofs_do_link(task, dir_ii, &nstr, ii);
	goto_out_if_err(err);

	err = silofs_do_getattr(task, ii, out_stat);
	goto_out_if_err(err);

	err = op_rmap_stat(task, out_stat);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_opendir(struct silofs_task_ctx *task, ino_t ino, int o_flags)
{
	struct silofs_inode_info *dir_ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_cur_inode(task, ino, &dir_ii);
	goto_out_if_err(err);

	err = silofs_do_opendir(task, dir_ii, o_flags);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_releasedir(struct silofs_task_ctx *task, ino_t ino,
                           int o_flags)
{
	struct silofs_inode_info *dir_ii = nullptr;
	const bool flush                 = (o_flags & O_SYNC) > 0;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_opt_inode(task, ino, flush, &dir_ii);
	goto_out_if_err(err);

	err = silofs_do_releasedir(task, dir_ii, o_flags, flush);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_readdir(struct silofs_task_ctx *task, ino_t ino,
                        struct silofs_readdir_ctx *rd_ctx)
{
	struct silofs_inode_info *dir_ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_cur_inode(task, ino, &dir_ii);
	goto_out_if_err(err);

	err = silofs_do_readdir(task, dir_ii, rd_ctx);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

struct silofs_readdir_filter_ctx {
	struct silofs_readdir_ctx *rd_ctx_orig;
	struct silofs_task_ctx *task;
	struct silofs_readdir_ctx rd_ctx;
};

static int readdirplus_actor(struct silofs_readdir_ctx *rd_ctx,
                             const struct silofs_readdir_info *rdi)
{
	struct silofs_readdir_info rdi2;
	struct silofs_readdir_filter_ctx *rdf_ctx =
		mut_container_of(rd_ctx, struct silofs_readdir_filter_ctx,
	                         rd_ctx);
	int ret;

	if (rdi->attr.st.st_ino == 0) {
		/* case1: fast; no need to re-map attr */
		ret = rdf_ctx->rd_ctx_orig->actor(rdf_ctx->rd_ctx_orig, rdi);
	} else {
		/* case2: copy attr to local and re-map uid-gid */
		memcpy(&rdi2, rdi, sizeof(rdi2));
		op_rmap_stat_any(rdf_ctx->task, &rdi2.attr);
		rdf_ctx->rd_ctx_orig->pos = rdf_ctx->rd_ctx.pos;
		ret = rdf_ctx->rd_ctx_orig->actor(rdf_ctx->rd_ctx_orig, &rdi2);
	}
	return ret;
}

int silofs_exec_readdirplus(struct silofs_task_ctx *task, ino_t ino,
                            struct silofs_readdir_ctx *rd_ctx)
{
	struct silofs_readdir_filter_ctx rdf_ctx = {
		.rd_ctx_orig  = rd_ctx,
		.task         = task,
		.rd_ctx.actor = readdirplus_actor,
		.rd_ctx.pos   = rd_ctx->pos,
	};
	struct silofs_inode_info *dir_ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_cur_inode(task, ino, &dir_ii);
	goto_out_if_err(err);

	err = silofs_do_readdirplus(task, dir_ii, &rdf_ctx.rd_ctx);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_fsyncdir(struct silofs_task_ctx *task, ino_t ino,
                         bool datasync)
{
	struct silofs_inode_info *dir_ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_opt_inode(task, ino, datasync, &dir_ii);
	goto_out_if_err(err);

	err = silofs_do_fsyncdir(task, dir_ii, datasync);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_chmod(struct silofs_task_ctx *task, ino_t ino, mode_t mode,
                      const struct silofs_itimes *itimes,
                      struct silofs_stat *out_stat)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_mut_inode(task, ino, nullptr, &ii);
	goto_out_if_err(err);

	err = silofs_do_chmod(task, ii, mode, itimes);
	goto_out_if_err(err);

	err = silofs_do_getattr(task, ii, out_stat);
	goto_out_if_err(err);

	err = op_rmap_stat(task, out_stat);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_chown(struct silofs_task_ctx *task, ino_t ino, uid_t uid,
                      gid_t gid, bool kill_suidgid,
                      const struct silofs_itimes *itimes,
                      struct silofs_stat *out_stat)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_map_uidgid(task, uid, gid, &uid, &gid);
	goto_out_if_err(err);

	err = op_stage_mut_inode(task, ino, nullptr, &ii);
	goto_out_if_err(err);

	err = silofs_do_chown(task, ii, uid, gid, kill_suidgid, itimes);
	goto_out_if_err(err);

	err = silofs_do_getattr(task, ii, out_stat);
	goto_out_if_err(err);

	err = op_rmap_stat(task, out_stat);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_utimens(struct silofs_task_ctx *task, ino_t ino,
                        const struct silofs_itimes *itimes,
                        struct silofs_stat *out_stat)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_mut_inode(task, ino, nullptr, &ii);
	goto_out_if_err(err);

	err = silofs_do_utimens(task, ii, itimes);
	goto_out_if_err(err);

	err = silofs_do_getattr(task, ii, out_stat);
	goto_out_if_err(err);

	err = op_rmap_stat(task, out_stat);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_truncate(struct silofs_task_ctx *task, ino_t ino, off_t len,
                         bool kill_suidgid, struct silofs_stat *out_stat)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_mut_inode(task, ino, nullptr, &ii);
	goto_out_if_err(err);

	err = op_try_flush(task, ii);
	goto_out_if_err(err);

	err = silofs_do_truncate(task, ii, len, kill_suidgid);
	goto_out_if_err(err);

	err = silofs_do_getattr(task, ii, out_stat);
	goto_out_if_err(err);

	err = op_rmap_stat(task, out_stat);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_create(struct silofs_task_ctx *task, ino_t parent,
                       const char *name, int o_flags, mode_t mode,
                       bool kill_suidgid, struct silofs_stat *out_stat)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii     = nullptr;
	struct silofs_inode_info *dir_ii = nullptr;
	int err;

	unused(o_flags); /* XXX use me */

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_mut_inode(task, parent, nullptr, &dir_ii);
	goto_out_if_err(err);

	err = silofs_make_linkname(task, dir_ii, name, &nstr);
	goto_out_if_err(err);

	err = op_try_flush(task, dir_ii);
	goto_out_if_err(err);

	err = silofs_do_create(task, dir_ii, &nstr, mode, kill_suidgid, &ii);
	goto_out_if_err(err);

	err = silofs_do_getattr(task, ii, out_stat);
	goto_out_if_err(err);

	err = op_rmap_stat(task, out_stat);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_open(struct silofs_task_ctx *task, ino_t ino, int o_flags,
                     bool kill_suidgid)
{
	struct silofs_inode_info *ii = nullptr;
	const int mutf = o_flags & (O_RDWR | O_WRONLY | O_TRUNC | O_APPEND);
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_inode(task, ino, mutf > 0, &ii);
	goto_out_if_err(err);

	err = silofs_do_open(task, ii, o_flags, kill_suidgid);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_mknod(struct silofs_task_ctx *task, ino_t parent,
                      const char *name, mode_t mode, dev_t rdev,
                      struct silofs_stat *out_stat)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii     = nullptr;
	struct silofs_inode_info *dir_ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_mut_inode(task, parent, nullptr, &dir_ii);
	goto_out_if_err(err);

	err = silofs_make_linkname(task, dir_ii, name, &nstr);
	goto_out_if_err(err);

	err = op_try_flush(task, dir_ii);
	goto_out_if_err(err);

	err = silofs_do_mknod(task, dir_ii, &nstr, mode, rdev, &ii);
	goto_out_if_err(err);

	err = silofs_do_getattr(task, ii, out_stat);
	goto_out_if_err(err);

	err = op_rmap_stat(task, out_stat);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_release(struct silofs_task_ctx *task, ino_t ino, int o_flags,
                        bool flush)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	/* TODO: useme */
	unused(o_flags);

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_opt_inode(task, ino, flush, &ii);
	goto_out_if_err(err);

	err = silofs_do_release(task, ii, flush);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_flush(struct silofs_task_ctx *task, ino_t ino, bool now)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_cur_inode(task, ino, &ii);
	goto_out_if_err(err);

	err = silofs_do_flush(task, ii, now);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_fsync(struct silofs_task_ctx *task, ino_t ino, bool datasync)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_opt_inode(task, ino, datasync, &ii);
	goto_out_if_err(err);

	err = silofs_do_fsync(task, ii, datasync);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_rename(struct silofs_task_ctx *task, ino_t parent_ino,
                       const char *name, ino_t newparent_ino,
                       const char *newname, int flags)
{
	struct silofs_namestr nstr;
	struct silofs_namestr newnstr;
	struct silofs_inode_info *curd_ii = nullptr;
	struct silofs_inode_info *newd_ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_mut_inode(task, parent_ino, nullptr, &curd_ii);
	goto_out_if_err(err);

	err = op_stage_mut_inode(task, newparent_ino, curd_ii, &newd_ii);
	goto_out_if_err(err);

	err = silofs_make_linkname(task, curd_ii, name, &nstr);
	goto_out_if_err(err);

	err = silofs_make_linkname(task, newd_ii, newname, &newnstr);
	goto_out_if_err(err);

	err = silofs_do_rename(task, curd_ii, &nstr, newd_ii, &newnstr, flags);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_read(struct silofs_task_ctx *task, ino_t ino, void *buf,
                     size_t len, off_t off, int o_flags, size_t *out_len)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_cur_inode(task, ino, &ii);
	goto_out_if_err(err);

	err = silofs_do_read(task, ii, buf, len, off, o_flags, out_len);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_read_iter(struct silofs_task_ctx *task, ino_t ino, int o_flags,
                          struct silofs_rwiter_ctx *rwi_ctx)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_cur_inode(task, ino, &ii);
	goto_out_if_err(err);

	err = silofs_do_read_iter(task, ii, o_flags, rwi_ctx);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_write(struct silofs_task_ctx *task, ino_t ino, const void *buf,
                      size_t len, off_t off, int o_flags, bool kill_suidgid,
                      size_t *out_len)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_mut_inode(task, ino, nullptr, &ii);
	goto_out_if_err(err);

	err = op_try_flush(task, ii);
	goto_out_if_err(err);

	err = silofs_do_write(task, ii, buf, len, off, o_flags, kill_suidgid,
	                      out_len);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_write_iter(struct silofs_task_ctx *task, ino_t ino,
                           int o_flags, bool kill_suidgid,
                           struct silofs_rwiter_ctx *rwi_ctx)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_mut_inode(task, ino, nullptr, &ii);
	goto_out_if_err(err);

	err = op_try_flush(task, ii);
	goto_out_if_err(err);

	err = silofs_do_write_iter(task, ii, o_flags, kill_suidgid, rwi_ctx);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_fallocate(struct silofs_task_ctx *task, ino_t ino, int mode,
                          off_t offset, off_t length)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_mut_inode(task, ino, nullptr, &ii);
	goto_out_if_err(err);

	err = op_try_flush(task, ii);
	goto_out_if_err(err);

	err = silofs_do_fallocate(task, ii, mode, offset, length);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_lseek(struct silofs_task_ctx *task, ino_t ino, off_t off,
                      int whence, off_t *out_off)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_cur_inode(task, ino, &ii);
	goto_out_if_err(err);

	err = silofs_do_lseek(task, ii, off, whence, out_off);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_copy_file_range(struct silofs_task_ctx *task, ino_t ino_in,
                                off_t off_in, ino_t ino_out, off_t off_out,
                                size_t len, int flags, size_t *out_ncp)
{
	struct silofs_inode_info *ii_in  = nullptr;
	struct silofs_inode_info *ii_out = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_cur_inode(task, ino_in, &ii_in);
	goto_out_if_err(err);

	err = op_stage_mut_inode(task, ino_out, ii_in, &ii_out);
	goto_out_if_err(err);

	err = silofs_do_copy_file_range(task, ii_in, ii_out, off_in, off_out,
	                                len, flags, out_ncp);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_setxattr(struct silofs_task_ctx *task, ino_t ino,
                         const char *name, const void *value, size_t size,
                         int flags, bool kill_sgid)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_mut_inode(task, ino, nullptr, &ii);
	goto_out_if_err(err);

	err = op_try_flush(task, ii);
	goto_out_if_err(err);

	err = silofs_make_xattrname(task, ii, name, &nstr);
	goto_out_if_err(err);

	err = silofs_do_setxattr(task, ii, &nstr, value, size, flags,
	                         kill_sgid);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_getxattr(struct silofs_task_ctx *task, ino_t ino,
                         const char *name, void *buf, size_t size,
                         size_t *out_size)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_cur_inode(task, ino, &ii);
	goto_out_if_err(err);

	err = silofs_make_xattrname(task, ii, name, &nstr);
	goto_out_if_err(err);

	err = silofs_do_getxattr(task, ii, &nstr, buf, size, out_size);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_listxattr(struct silofs_task_ctx *task, ino_t ino,
                          struct silofs_listxattr_ctx *lxa_ctx)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_cur_inode(task, ino, &ii);
	goto_out_if_err(err);

	err = silofs_do_listxattr(task, ii, lxa_ctx);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_removexattr(struct silofs_task_ctx *task, ino_t ino,
                            const char *name)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_mut_inode(task, ino, nullptr, &ii);
	goto_out_if_err(err);

	err = silofs_make_xattrname(task, ii, name, &nstr);
	goto_out_if_err(err);

	err = silofs_do_removexattr(task, ii, &nstr);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_statx(struct silofs_task_ctx *task, ino_t ino,
                      uint32_t sx_want_mask, struct silofs_stat *out_st)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_cur_inode(task, ino, &ii);
	goto_out_if_err(err);

	err = silofs_do_statx(task, ii, sx_want_mask, out_st);
	goto_out_if_err(err);

	err = op_rmap_stat(task, out_st);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_fiemap(struct silofs_task_ctx *task, ino_t ino,
                       struct fiemap *fm)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_cur_inode(task, ino, &ii);
	goto_out_if_err(err);

	err = silofs_do_fiemap(task, ii, fm);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_syncfs(struct silofs_task_ctx *task, ino_t ino, int flags)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_mut_inode(task, ino, nullptr, &ii);
	goto_out_if_err(err);

	err = silofs_do_syncfs(task, ii, flags);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_query(struct silofs_task_ctx *task, ino_t ino,
                      enum silofs_query_type qtype,
                      struct silofs_ioc_query *out_qry)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_cur_inode(task, ino, &ii);
	goto_out_if_err(err);

	err = silofs_do_query(task, ii, qtype, out_qry);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_forkfs(struct silofs_task_ctx *task, ino_t ino, int flags,
                       struct silofs_mbrefs *out_mbrefs)
{
	struct silofs_inode_info *dir_ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_cur_inode(task, ino, &dir_ii);
	goto_out_if_err(err);

	err = silofs_do_forkfs(task, dir_ii, flags, out_mbrefs);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_tune(struct silofs_task_ctx *task, ino_t ino, int iflags_want,
                     int iflags_dont)
{
	struct silofs_inode_info *dir_ii = nullptr;
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = op_stage_mut_inode(task, ino, nullptr, &dir_ii);
	goto_out_if_err(err);

	err = silofs_do_tune(task, dir_ii, iflags_want, iflags_dont);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_exec_rdwr_post(const struct silofs_task_ctx *task, int wr_mode,
                          const struct silofs_iovec *iov, size_t cnt)
{
	/*
	 * No need to have op_lock_fs(task),op_unlock_fs(task) here: the
	 * underlying operation is just atomic decrement.
	 */
	return silofs_do_rdwr_post(task, wr_mode, iov, cnt);
}

int silofs_exec_idle(struct silofs_task_ctx *task, int flags)
{
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = silofs_do_maintain(task, flags | SILOFS_CTLF_OPSTART);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_walkfs(struct silofs_task_ctx *task)
{
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = silofs_do_walkfs(task);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}

int silofs_exec_unrefs(struct silofs_task_ctx *task)
{
	int err;

	err = op_start(task);
	goto_out_if_err(err);

	err = op_authorize(task);
	goto_out_if_err(err);

	err = op_map_creds(task);
	goto_out_if_err(err);

	err = silofs_do_unrefs(task);
	goto_out_if_err(err);
out:
	return op_finish(task, err);
}
