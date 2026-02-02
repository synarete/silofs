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
#include "mbr.h"
#include "fs.h"
#include "ar.h"
#include "walk.h"
#include "exec.h"
#include "env.h"

#define status_ok(err_) ((err_) == 0)

#define ok_or_goto_out(err_)          \
	do {                          \
		if (!status_ok(err_)) \
			goto out;     \
	} while (0)

#define ok_or_goto_out_ok(err_)       \
	do {                          \
		if (!status_ok(err_)) \
			goto out_ok;  \
	} while (0)

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int op_start(struct silofs_exec_ctx *exct)
{
	struct silofs_env *env = exct->env;

	silofs_lock_fs_by(exct);
	env->opstat.op_time = exct->op_start_time = silofs_time_mono_now();
	env->opstat.op_count++;
	return 0;
}

static int
op_try_flush(struct silofs_exec_ctx *exct, struct silofs_inode_info *ii)
{
	return silofs_flush_dirty(exct, ii, SILOFS_CTLF_OPSTART);
}

static void op_probe_duration(const struct silofs_exec_ctx *exct, int res)
{
	const time_t time_dif  = silofs_time_mono_now() - exct->op_start_time;
	const uint32_t op_code = exct->auth.opcode;

	if (op_code && (time_dif > 30)) {
		log_warn("slow-oper: op_count=%zu op_code=%u dif=%ld res=%d",
			 exct->env->opstat.op_count, op_code, time_dif, res);
	}
}

static int op_unlooseq(struct silofs_exec_ctx *exct)
{
	int ret = 0;

	/*
	 * Task's loose-queue may hold one (or more) inodes which are no-longer
	 * alive but could not be fully dropped as they are still under to-be
	 * written state in submit-queue. This rare case may happen on heavy
	 * load with unlinked files. In this special case, we must do forced
	 * flush-all to purge and evict those pending inodes while current exct
	 * still holds the fs-lock.
	 */
	if (exct->looseq != nullptr) {
		ret = silofs_flush_dirty_now(exct);
		silofs_assert_null(exct->looseq);
	}
	return ret;
}

static int op_finish(struct silofs_exec_ctx *exct, int err)
{
	int err2 = 0;

	op_probe_duration(exct, err);
	err2 = op_unlooseq(exct);
	silofs_unlock_fs_by(exct);
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

static const struct silofs_sb_info *sbi_of(const struct silofs_exec_ctx *exct)
{
	return silofs_get_sbi(exct);
}

static bool op_is_kernel(const struct silofs_exec_ctx *exct)
{
	const struct silofs_creds *creds = &exct->auth.creds;

	if (exct->kwrite) {
		return true;
	}
	if (exct->auth.pid) {
		return false;
	}
	if (!creds->host_cred.uid && !creds->host_cred.gid) {
		return true;
	}
	return false;
}

static bool op_is_admin(const struct silofs_exec_ctx *exct)
{
	return (sbi_of(exct) == nullptr) || op_is_kernel(exct);
}

static bool op_is_fsowner(const struct silofs_exec_ctx *exct)
{
	const struct silofs_creds *creds = &exct->auth.creds;

	return silofs_uid_eq(creds->host_cred.uid, exct->env->owner_cred.uid);
}

static bool op_cap_sys_admin(const struct silofs_exec_ctx *exct)
{
	const struct silofs_creds *creds = &exct->auth.creds;

	return silofs_env_hasflag(exct->env, SILOFS_F_ALLOWADMIN) &&
	       silofs_user_cap_sys_admin(&creds->host_cred);
}

static bool op_allow_other(const struct silofs_exec_ctx *exct)
{
	return silofs_env_hasflag(exct->env, SILOFS_F_ALLOWOTHER);
}

static int op_authorize(const struct silofs_exec_ctx *exct)
{
	if (sbi_of(exct) == nullptr) {
		return 0; /* case off-line operation XXX */
	}
	if (op_is_kernel(exct)) {
		return 0; /* request by kernel */
	}
	if (op_is_fsowner(exct)) {
		return 0; /* request by file-system's owner */
	}
	if (op_cap_sys_admin(exct)) {
		return 0; /* request by system administrator */
	}
	if (op_allow_other(exct)) {
		return 0; /* request by other users */
	}
	return -SILOFS_EPERM;
}

static int op_map_uidgid(const struct silofs_exec_ctx *exct, uid_t uid,
			 gid_t gid, uid_t *out_uid, gid_t *out_gid)
{
	int ret;

	ret = silofs_idsmap_mapcreds(exct->idsm, uid, gid, out_uid, out_gid);
	return (ret == -SILOFS_ENOENT) ? -SILOFS_EPERM : ret;
}

static int op_map_creds(struct silofs_exec_ctx *exct)
{
	const struct silofs_cred *host_cred = &exct->auth.creds.host_cred;
	struct silofs_cred *fs_cred         = &exct->auth.creds.fs_cred;
	int ret                             = 0;

	fs_cred->uid   = host_cred->uid;
	fs_cred->gid   = host_cred->gid;
	fs_cred->umask = host_cred->umask;

	if (!op_is_admin(exct)) {
		ret = op_map_uidgid(exct, host_cred->uid, host_cred->gid,
				    &fs_cred->uid, &fs_cred->gid);
	}
	return (ret == -SILOFS_ENOENT) ? -SILOFS_EPERM : ret;
}

static int
op_rmap_stat(const struct silofs_exec_ctx *exct, struct silofs_stat *st)
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
	ret = silofs_idsmap_rmapcreds(exct->idsm, uid_in, gid_in, &uid_out,
				      &gid_out);
	st->st.st_uid = st->stx.stx_uid = uid_out;
	st->st.st_gid = st->stx.stx_gid = gid_out;
	return (ret == -SILOFS_ENOENT) ? 0 : ret;
}

static void
op_rmap_stat_any(const struct silofs_exec_ctx *exct, struct silofs_stat *st)
{
	int err;

	err = op_rmap_stat(exct, st);
	if (err) {
		st->st.st_uid = st->stx.stx_uid = silofs_uid_nobody();
		st->st.st_gid = st->stx.stx_gid = silofs_gid_nobody();
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int op_stage_cacheonly_inode(struct silofs_exec_ctx *exct, ino_t ino,
				    struct silofs_inode_info **out_ii)
{
	return silofs_fetch_cached_inode(exct, ino, out_ii);
}

static int op_stage_inode(struct silofs_exec_ctx *exct, ino_t ino, bool mut,
			  struct silofs_inode_info **out_ii)
{
	enum silofs_stg_mode stg_mode = mut ? SILOFS_STG_COW : SILOFS_STG_CUR;

	return silofs_stage_inode(exct, ino, stg_mode, out_ii);
}

static int op_stage_cur_inode(struct silofs_exec_ctx *exct, ino_t ino,
			      struct silofs_inode_info **out_ii)
{
	return op_stage_inode(exct, ino, false, out_ii);
}

static int op_stage_mut_inode(struct silofs_exec_ctx *exct, ino_t ino,
			      struct silofs_inode_info *ii_alt,
			      struct silofs_inode_info **out_ii)
{
	int ret;

	silofs_ii_incref(ii_alt);
	ret = op_stage_inode(exct, ino, true, out_ii);
	silofs_ii_decref(ii_alt);
	return ret;
}

static int op_stage_opt_inode(struct silofs_exec_ctx *exct, ino_t ino,
			      bool mut, struct silofs_inode_info **out_ii)
{
	int err;

	err = op_stage_inode(exct, ino, mut, out_ii);
	if (!err && !mut && silofs_ii_isdirty(*out_ii)) {
		err = op_stage_inode(exct, ino, true, out_ii);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_exec_forget(struct silofs_exec_ctx *exct, ino_t ino, size_t nlookup)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_cacheonly_inode(exct, ino, &ii);
	ok_or_goto_out_ok(err);

	err = silofs_do_forget(exct, ii, nlookup);
	ok_or_goto_out(err);
out_ok:
	err = 0;
out:
	return op_finish(exct, err);
}

int silofs_exec_statfs(struct silofs_exec_ctx *exct, ino_t ino,
		       struct statvfs *stvfs)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(exct, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_statvfs(exct, ii, stvfs);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_lookup(struct silofs_exec_ctx *exct, ino_t parent,
		       const char *name, struct silofs_stat *out_stat)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii     = nullptr;
	struct silofs_inode_info *dir_ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(exct, parent, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_linkname(exct, dir_ii, name, &nstr);
	ok_or_goto_out(err);

	err = silofs_do_lookup(exct, dir_ii, &nstr, &ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(exct, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(exct, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_getattr(struct silofs_exec_ctx *exct, ino_t ino,
			struct silofs_stat *out_st)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(exct, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(exct, ii, out_st);
	ok_or_goto_out(err);

	err = op_rmap_stat(exct, out_st);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_access(struct silofs_exec_ctx *exct, ino_t ino, int mode)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(exct, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_access(exct, ii, mode);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_mkdir(struct silofs_exec_ctx *exct, ino_t parent,
		      const char *name, mode_t mode,
		      struct silofs_stat *out_stat)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii     = nullptr;
	struct silofs_inode_info *dir_ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(exct, parent, nullptr, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_linkname(exct, dir_ii, name, &nstr);
	ok_or_goto_out(err);

	err = op_try_flush(exct, dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_mkdir(exct, dir_ii, &nstr, mode, &ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(exct, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(exct, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_rmdir(struct silofs_exec_ctx *exct, ino_t parent,
		      const char *name)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *dir_ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(exct, parent, nullptr, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_linkname(exct, dir_ii, name, &nstr);
	ok_or_goto_out(err);

	err = silofs_do_rmdir(exct, dir_ii, &nstr);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_symlink(struct silofs_exec_ctx *exct, ino_t parent,
			const char *name, const char *symval,
			struct silofs_stat *out_stat)
{
	struct silofs_strview value;
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii     = nullptr;
	struct silofs_inode_info *dir_ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(exct, parent, nullptr, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_linkname(exct, dir_ii, name, &nstr);
	ok_or_goto_out(err);

	err = symval_to_str(symval, &value);
	ok_or_goto_out(err);

	err = op_try_flush(exct, dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_symlink(exct, dir_ii, &nstr, &value, &ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(exct, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(exct, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_readlink(struct silofs_exec_ctx *exct, ino_t ino, char *ptr,
			 size_t lim, size_t *out_len)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(exct, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_readlink(exct, ii, ptr, lim, out_len);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_unlink(struct silofs_exec_ctx *exct, ino_t parent,
		       const char *name)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *dir_ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(exct, parent, nullptr, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_linkname(exct, dir_ii, name, &nstr);
	ok_or_goto_out(err);

	err = silofs_do_unlink(exct, dir_ii, &nstr);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_link(struct silofs_exec_ctx *exct, ino_t ino, ino_t parent,
		     const char *name, struct silofs_stat *out_stat)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii     = nullptr;
	struct silofs_inode_info *dir_ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(exct, parent, nullptr, &dir_ii);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(exct, ino, dir_ii, &ii);
	ok_or_goto_out(err);

	err = silofs_make_linkname(exct, dir_ii, name, &nstr);
	ok_or_goto_out(err);

	err = silofs_do_link(exct, dir_ii, &nstr, ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(exct, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(exct, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_opendir(struct silofs_exec_ctx *exct, ino_t ino, int o_flags)
{
	struct silofs_inode_info *dir_ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(exct, ino, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_opendir(exct, dir_ii, o_flags);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_releasedir(struct silofs_exec_ctx *exct, ino_t ino,
			   int o_flags)
{
	struct silofs_inode_info *dir_ii = nullptr;
	const bool flush                 = (o_flags & O_SYNC) > 0;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_opt_inode(exct, ino, flush, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_releasedir(exct, dir_ii, o_flags, flush);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_readdir(struct silofs_exec_ctx *exct, ino_t ino,
			struct silofs_readdir_ctx *rd_ctx)
{
	struct silofs_inode_info *dir_ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(exct, ino, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_readdir(exct, dir_ii, rd_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

struct silofs_readdir_filter_ctx {
	struct silofs_readdir_ctx *rd_ctx_orig;
	struct silofs_exec_ctx *exct;
	struct silofs_readdir_ctx rd_ctx;
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
		op_rmap_stat_any(rdf_ctx->exct, &rdi2.attr);
		rdf_ctx->rd_ctx_orig->pos = rdf_ctx->rd_ctx.pos;
		ret = rdf_ctx->rd_ctx_orig->actor(rdf_ctx->rd_ctx_orig, &rdi2);
	}
	return ret;
}

int silofs_exec_readdirplus(struct silofs_exec_ctx *exct, ino_t ino,
			    struct silofs_readdir_ctx *rd_ctx)
{
	struct silofs_readdir_filter_ctx rdf_ctx = {
		.rd_ctx_orig  = rd_ctx,
		.exct         = exct,
		.rd_ctx.actor = readdirplus_actor,
		.rd_ctx.pos   = rd_ctx->pos,
	};
	struct silofs_inode_info *dir_ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(exct, ino, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_readdirplus(exct, dir_ii, &rdf_ctx.rd_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_fsyncdir(struct silofs_exec_ctx *exct, ino_t ino,
			 bool datasync)
{
	struct silofs_inode_info *dir_ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_opt_inode(exct, ino, datasync, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_fsyncdir(exct, dir_ii, datasync);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_chmod(struct silofs_exec_ctx *exct, ino_t ino, mode_t mode,
		      const struct silofs_itimes *itimes,
		      struct silofs_stat *out_stat)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(exct, ino, nullptr, &ii);
	ok_or_goto_out(err);

	err = silofs_do_chmod(exct, ii, mode, itimes);
	ok_or_goto_out(err);

	err = silofs_do_getattr(exct, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(exct, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_chown(struct silofs_exec_ctx *exct, ino_t ino, uid_t uid,
		      gid_t gid, bool kill_suidgid,
		      const struct silofs_itimes *itimes,
		      struct silofs_stat *out_stat)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_map_uidgid(exct, uid, gid, &uid, &gid);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(exct, ino, nullptr, &ii);
	ok_or_goto_out(err);

	err = silofs_do_chown(exct, ii, uid, gid, kill_suidgid, itimes);
	ok_or_goto_out(err);

	err = silofs_do_getattr(exct, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(exct, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_utimens(struct silofs_exec_ctx *exct, ino_t ino,
			const struct silofs_itimes *itimes,
			struct silofs_stat *out_stat)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(exct, ino, nullptr, &ii);
	ok_or_goto_out(err);

	err = silofs_do_utimens(exct, ii, itimes);
	ok_or_goto_out(err);

	err = silofs_do_getattr(exct, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(exct, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_truncate(struct silofs_exec_ctx *exct, ino_t ino, off_t len,
			 bool kill_suidgid, struct silofs_stat *out_stat)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(exct, ino, nullptr, &ii);
	ok_or_goto_out(err);

	err = op_try_flush(exct, ii);
	ok_or_goto_out(err);

	err = silofs_do_truncate(exct, ii, len, kill_suidgid);
	ok_or_goto_out(err);

	err = silofs_do_getattr(exct, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(exct, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_create(struct silofs_exec_ctx *exct, ino_t parent,
		       const char *name, int o_flags, mode_t mode,
		       bool kill_suidgid, struct silofs_stat *out_stat)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii     = nullptr;
	struct silofs_inode_info *dir_ii = nullptr;
	int err;

	unused(o_flags); /* XXX use me */

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(exct, parent, nullptr, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_linkname(exct, dir_ii, name, &nstr);
	ok_or_goto_out(err);

	err = op_try_flush(exct, dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_create(exct, dir_ii, &nstr, mode, kill_suidgid, &ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(exct, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(exct, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_open(struct silofs_exec_ctx *exct, ino_t ino, int o_flags,
		     bool kill_suidgid)
{
	struct silofs_inode_info *ii = nullptr;
	const int mutf = o_flags & (O_RDWR | O_WRONLY | O_TRUNC | O_APPEND);
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_inode(exct, ino, mutf > 0, &ii);
	ok_or_goto_out(err);

	err = silofs_do_open(exct, ii, o_flags, kill_suidgid);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_mknod(struct silofs_exec_ctx *exct, ino_t parent,
		      const char *name, mode_t mode, dev_t rdev,
		      struct silofs_stat *out_stat)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii     = nullptr;
	struct silofs_inode_info *dir_ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(exct, parent, nullptr, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_make_linkname(exct, dir_ii, name, &nstr);
	ok_or_goto_out(err);

	err = op_try_flush(exct, dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_mknod(exct, dir_ii, &nstr, mode, rdev, &ii);
	ok_or_goto_out(err);

	err = silofs_do_getattr(exct, ii, out_stat);
	ok_or_goto_out(err);

	err = op_rmap_stat(exct, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_release(struct silofs_exec_ctx *exct, ino_t ino, int o_flags,
			bool flush)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	/* TODO: useme */
	unused(o_flags);

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_opt_inode(exct, ino, flush, &ii);
	ok_or_goto_out(err);

	err = silofs_do_release(exct, ii, flush);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_flush(struct silofs_exec_ctx *exct, ino_t ino, bool now)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(exct, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_flush(exct, ii, now);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_fsync(struct silofs_exec_ctx *exct, ino_t ino, bool datasync)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_opt_inode(exct, ino, datasync, &ii);
	ok_or_goto_out(err);

	err = silofs_do_fsync(exct, ii, datasync);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_rename(struct silofs_exec_ctx *exct, ino_t parent_ino,
		       const char *name, ino_t newparent_ino,
		       const char *newname, int flags)
{
	struct silofs_namestr nstr;
	struct silofs_namestr newnstr;
	struct silofs_inode_info *curd_ii = nullptr;
	struct silofs_inode_info *newd_ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(exct, parent_ino, nullptr, &curd_ii);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(exct, newparent_ino, curd_ii, &newd_ii);
	ok_or_goto_out(err);

	err = silofs_make_linkname(exct, curd_ii, name, &nstr);
	ok_or_goto_out(err);

	err = silofs_make_linkname(exct, newd_ii, newname, &newnstr);
	ok_or_goto_out(err);

	err = silofs_do_rename(exct, curd_ii, &nstr, newd_ii, &newnstr, flags);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_read(struct silofs_exec_ctx *exct, ino_t ino, void *buf,
		     size_t len, off_t off, int o_flags, size_t *out_len)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(exct, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_read(exct, ii, buf, len, off, o_flags, out_len);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_read_iter(struct silofs_exec_ctx *exct, ino_t ino, int o_flags,
			  struct silofs_rwiter_ctx *rwi_ctx)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(exct, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_read_iter(exct, ii, o_flags, rwi_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_write(struct silofs_exec_ctx *exct, ino_t ino, const void *buf,
		      size_t len, off_t off, int o_flags, bool kill_suidgid,
		      size_t *out_len)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(exct, ino, nullptr, &ii);
	ok_or_goto_out(err);

	err = op_try_flush(exct, ii);
	ok_or_goto_out(err);

	err = silofs_do_write(exct, ii, buf, len, off, o_flags, kill_suidgid,
			      out_len);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_write_iter(struct silofs_exec_ctx *exct, ino_t ino,
			   int o_flags, bool kill_suidgid,
			   struct silofs_rwiter_ctx *rwi_ctx)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(exct, ino, nullptr, &ii);
	ok_or_goto_out(err);

	err = op_try_flush(exct, ii);
	ok_or_goto_out(err);

	err = silofs_do_write_iter(exct, ii, o_flags, kill_suidgid, rwi_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_fallocate(struct silofs_exec_ctx *exct, ino_t ino, int mode,
			  off_t offset, off_t length)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(exct, ino, nullptr, &ii);
	ok_or_goto_out(err);

	err = op_try_flush(exct, ii);
	ok_or_goto_out(err);

	err = silofs_do_fallocate(exct, ii, mode, offset, length);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_lseek(struct silofs_exec_ctx *exct, ino_t ino, off_t off,
		      int whence, off_t *out_off)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(exct, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_lseek(exct, ii, off, whence, out_off);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_copy_file_range(struct silofs_exec_ctx *exct, ino_t ino_in,
				off_t off_in, ino_t ino_out, off_t off_out,
				size_t len, int flags, size_t *out_ncp)
{
	struct silofs_inode_info *ii_in  = nullptr;
	struct silofs_inode_info *ii_out = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(exct, ino_in, &ii_in);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(exct, ino_out, ii_in, &ii_out);
	ok_or_goto_out(err);

	err = silofs_do_copy_file_range(exct, ii_in, ii_out, off_in, off_out,
					len, flags, out_ncp);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_setxattr(struct silofs_exec_ctx *exct, ino_t ino,
			 const char *name, const void *value, size_t size,
			 int flags, bool kill_sgid)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(exct, ino, nullptr, &ii);
	ok_or_goto_out(err);

	err = op_try_flush(exct, ii);
	ok_or_goto_out(err);

	err = silofs_make_xattrname(exct, ii, name, &nstr);
	ok_or_goto_out(err);

	err = silofs_do_setxattr(exct, ii, &nstr, value, size, flags,
				 kill_sgid);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_getxattr(struct silofs_exec_ctx *exct, ino_t ino,
			 const char *name, void *buf, size_t size,
			 size_t *out_size)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(exct, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_make_xattrname(exct, ii, name, &nstr);
	ok_or_goto_out(err);

	err = silofs_do_getxattr(exct, ii, &nstr, buf, size, out_size);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_listxattr(struct silofs_exec_ctx *exct, ino_t ino,
			  struct silofs_listxattr_ctx *lxa_ctx)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(exct, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_listxattr(exct, ii, lxa_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_removexattr(struct silofs_exec_ctx *exct, ino_t ino,
			    const char *name)
{
	struct silofs_namestr nstr;
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(exct, ino, nullptr, &ii);
	ok_or_goto_out(err);

	err = silofs_make_xattrname(exct, ii, name, &nstr);
	ok_or_goto_out(err);

	err = silofs_do_removexattr(exct, ii, &nstr);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_statx(struct silofs_exec_ctx *exct, ino_t ino,
		      uint32_t sx_want_mask, struct silofs_stat *out_st)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(exct, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_statx(exct, ii, sx_want_mask, out_st);
	ok_or_goto_out(err);

	err = op_rmap_stat(exct, out_st);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_fiemap(struct silofs_exec_ctx *exct, ino_t ino,
		       struct fiemap *fm)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(exct, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_fiemap(exct, ii, fm);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_syncfs(struct silofs_exec_ctx *exct, ino_t ino, int flags)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(exct, ino, nullptr, &ii);
	ok_or_goto_out(err);

	err = silofs_do_syncfs(exct, ii, flags);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_query(struct silofs_exec_ctx *exct, ino_t ino,
		      enum silofs_query_type qtype,
		      struct silofs_ioc_query *out_qry)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(exct, ino, &ii);
	ok_or_goto_out(err);

	err = silofs_do_query(exct, ii, qtype, out_qry);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_forkfs(struct silofs_exec_ctx *exct, ino_t ino, int flags,
		       struct silofs_mbrefs *out_mbrefs)
{
	struct silofs_inode_info *dir_ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_cur_inode(exct, ino, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_forkfs(exct, dir_ii, flags, out_mbrefs);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_tune(struct silofs_exec_ctx *exct, ino_t ino, int iflags_want,
		     int iflags_dont)
{
	struct silofs_inode_info *dir_ii = nullptr;
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = op_stage_mut_inode(exct, ino, nullptr, &dir_ii);
	ok_or_goto_out(err);

	err = silofs_do_tune(exct, dir_ii, iflags_want, iflags_dont);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_exec_rdwr_post(const struct silofs_exec_ctx *exct, int wr_mode,
			  const struct silofs_iovec *iov, size_t cnt)
{
	/*
	 * No need to have op_lock_fs(exct),op_unlock_fs(exct) here: the
	 * underlying operation is just atomic decrement.
	 */
	return silofs_do_rdwr_post(exct, wr_mode, iov, cnt);
}

int silofs_exec_maintain(struct silofs_exec_ctx *exct, int flags)
{
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = silofs_do_maintain(exct, flags | SILOFS_CTLF_OPSTART);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_walkfs(struct silofs_exec_ctx *exct,
		       const struct silofs_laddr_visitor *lvis)
{
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = silofs_do_walkfs(exct, lvis);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

int silofs_exec_unrefs(struct silofs_exec_ctx *exct)
{
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = silofs_do_unrefs(exct);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_exec_preserve(struct silofs_exec_ctx *exct,
			 struct silofs_mbref *out_ar_mbref)
{
	int err;

	err = op_start(exct);
	ok_or_goto_out(err);

	err = op_authorize(exct);
	ok_or_goto_out(err);

	err = op_map_creds(exct);
	ok_or_goto_out(err);

	err = silofs_do_preserve_fs(exct, out_ar_mbref);
	ok_or_goto_out(err);
out:
	return op_finish(exct, err);
}
