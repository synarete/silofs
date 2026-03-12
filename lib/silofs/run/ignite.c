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
#include <dirent.h>

#include <silofs/ondisk.h>
#include <silofs/types.h>
#include <silofs/syscall.h>
#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/pv.h>
#include <silofs/fs.h>
#include "exec.h"
#include "env.h"

static void drop_caches(struct silofs_task_ctx *task)
{
	silofs_env_drop_caches(task->env);
}

static void relax_caches(struct silofs_task_ctx *task)
{
	silofs_env_relax_caches(task->env, SILOFS_CTLF_IDLE);
}

static void drop_relax_caches(struct silofs_task_ctx *task)
{
	drop_caches(task);
	relax_caches(task);
}

static int flush_destage_dirty(struct silofs_task_ctx *task)
{
	int err;

	err = silofs_flush_dirty_now(task);
	if (err) {
		log_err("failed to flush dirty: err=%d", err);
		return err;
	}
	err = silofs_destage_dirty(task);
	if (err) {
		log_err("failed to destage dirty: err=%d", err);
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const char *repodir_of(const struct silofs_task_ctx *task)
{
	return task->env->repodir;
}

static int iter_repodir(const char *repodir, size_t *out_ndes)
{
	struct dirent64 de[4];
	int dfd = -1;
	int err;

	err = silofs_sys_open(repodir, O_DIRECTORY | O_RDONLY, 0, &dfd);
	if (err) {
		log_dbg("opendir error: repodir=%s err=%d", repodir, err);
		goto out;
	}
	err = silofs_sys_getdents2(dfd, de, ARRAY_SIZE(de), out_ndes);
	if (err) {
		log_dbg("readdir error: repodir=%s err=%d", repodir, err);
		goto out;
	}
out:
	silofs_sys_closefd(&dfd);
	return err;
}

static int require_empty_repodir(const struct silofs_task_ctx *task)
{
	size_t ndes = 0;
	int err;

	err = iter_repodir(repodir_of(task), &ndes);
	if (err) {
		return err;
	}
	if (ndes > 2) {
		log_dbg("non empty repodir: %s", repodir_of(task));
		return -SILOFS_ENOTEMPTY;
	}
	return 0;
}

static int require_nonempty_repodir(const struct silofs_task_ctx *task)
{
	size_t ndes = 0;
	int err;

	err = iter_repodir(repodir_of(task), &ndes);
	if (err) {
		return err;
	}
	if (ndes <= 2) {
		log_dbg("bad repodir: %s", repodir_of(task));
		return -SILOFS_EBADREPO;
	}
	return 0;
}

static int pre_format_repo(const struct silofs_task_ctx *task)
{
	return require_empty_repodir(task);
}

static void post_format_repo(struct silofs_task_ctx *task)
{
	drop_relax_caches(task);
}

int silofs_exec_format_repo(struct silofs_task_ctx *task)
{
	int err;

	err = pre_format_repo(task);
	if (err) {
		return err;
	}
	err = silofs_repo_format(task->repo, task->env->repodir);
	if (err) {
		return err;
	}
	post_format_repo(task);
	return 0;
}

static int pre_reload_repo(struct silofs_task_ctx *task)
{
	return require_nonempty_repodir(task);
}

static int open_repo(struct silofs_task_ctx *task)
{
	return silofs_repo_open(task->repo, task->env->repodir,
	                        task->env->flags);
}

int silofs_exec_reload_repo(struct silofs_task_ctx *task)
{
	int err;

	if (task->repo->re_opened) {
		return 0; /* no-op */
	}
	err = pre_reload_repo(task);
	if (err) {
		return err;
	}
	err = open_repo(task);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int pre_format_ps(struct silofs_task_ctx *task)
{
	return silofs_env_reinit_ciphers(task->env);
}

static int post_format_ps(struct silofs_task_ctx *task)
{
	return flush_destage_dirty(task);
}

int silofs_exec_format_pv(struct silofs_task_ctx *task)
{
	int err;

	err = pre_format_ps(task);
	if (err) {
		return err;
	}
	err = silofs_format_pv(task);
	if (err) {
		return err;
	}
	err = post_format_ps(task);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int format_super(struct silofs_task_ctx *task)
{
	return silofs_env_format_super(task->env, task->env->fscap);
}

static int
require_spmaps_of(struct silofs_task_ctx *task, enum silofs_vtype vtype)
{
	struct silofs_vaddr vaddr;
	struct silofs_spleaf_info *sli = nullptr;

	silofs_vaddr_setup(&vaddr, vtype, 0);
	return silofs_require_spleaf_of(task, &vaddr, SILOFS_STG_COW, &sli);
}

static int
format_spmaps_of(struct silofs_task_ctx *task, enum silofs_vtype vtype)
{
	int err;

	err = require_spmaps_of(task, vtype);
	if (err) {
		log_err("format spmaps failed: vtype=%d err=%d", vtype, err);
		return err;
	}
	err = flush_destage_dirty(task);
	if (err) {
		return err;
	}
	log_dbg("format spmaps of: vtype=%d", vtype);
	return 0;
}

static int format_spmaps(struct silofs_task_ctx *task)
{
	enum silofs_vtype vtype = SILOFS_VTYPE_NONE;
	int err;

	while (++vtype < SILOFS_VTYPE_LAST) {
		if (!silofs_vtype_isvnode(vtype)) {
			continue;
		}
		err = format_spmaps_of(task, vtype);
		if (err) {
			return err;
		}
		drop_relax_caches(task);
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
claim_reclaim_of(struct silofs_task_ctx *task, enum silofs_vtype vtype)
{
	struct silofs_vaddr vaddr;
	const off_t voff_exp = 0;
	int err;

	err = silofs_claim_vspace(task, vtype, &vaddr);
	if (err) {
		log_err("claim failed: vtype=%d err=%d", vtype, err);
		return err;
	}
	if (vaddr.off != voff_exp) {
		log_err("bad claim: vtype=%d exp=%ld got=%ld", vtype, voff_exp,
		        vaddr.off);
		return -SILOFS_EFSCORRUPTED;
	}
	drop_caches(task);
	err = silofs_reclaim_vspace(task, &vaddr);
	if (err) {
		log_err("bad reclaim: vtype=%d voff=%ld err=%d", vtype,
		        vaddr.off, err);
	}
	return 0;
}

static int claim_recalim_space(struct silofs_task_ctx *task)
{
	enum silofs_vtype vtype = SILOFS_VTYPE_NONE;
	int err;

	while (++vtype < SILOFS_VTYPE_LAST) {
		if (!silofs_vtype_isvnode(vtype) ||
		    (vtype == SILOFS_VTYPE_LSMAP)) {
			continue;
		}
		err = claim_reclaim_of(task, vtype);
		if (err) {
			return err;
		}
		err = flush_destage_dirty(task);
		if (err) {
			return err;
		}
		drop_relax_caches(task);
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static off_t vni_offset(const struct silofs_vnode_info *vni)
{
	const struct silofs_vaddr *vaddr = silofs_vni_vaddr(vni);

	return vaddr->off;
}

static int
claim_offset_zero(struct silofs_task_ctx *task, enum silofs_vtype vtype)
{
	struct silofs_vnode_info *vni = nullptr;
	off_t off                     = -1;
	int err;

	err = silofs_spawn_vnode(task, nullptr, vtype, &vni);
	if (err) {
		log_err("failed to spawn: vtype=%d err=%d", vtype, err);
		return err;
	}
	off = vni_offset(vni);
	if (off != 0) {
		log_err("format zspace failed: vtype=%d off=%ld", vtype, off);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int format_nil_space(struct silofs_task_ctx *task)
{
	enum silofs_vtype vtype = SILOFS_VTYPE_NONE;
	int err;

	while (++vtype < SILOFS_VTYPE_LAST) {
		if (!silofs_vtype_isvnode(vtype) ||
		    (vtype == SILOFS_VTYPE_LSMAP)) { /* TODO: revisit */
			continue;
		}
		err = claim_offset_zero(task, vtype);
		if (err) {
			return err;
		}
		err = flush_destage_dirty(task);
		if (err) {
			return err;
		}
		drop_relax_caches(task);
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
spawn_rootdir(struct silofs_task_ctx *task, struct silofs_inode_info **out_ii)
{
	struct silofs_inew_params inp;
	struct silofs_inode_info *ii;
	int err;

	silofs_inew_params_of(task, nullptr, S_IFDIR | 0755, 0, &inp);
	err = silofs_spawn_inode(task, &inp, &ii);
	if (err) {
		return err;
	}
	if (ii->i_ino != SILOFS_INO_ROOT) {
		log_err("failed to format root-dir: ino=%ld", ii->i_ino);
		return -SILOFS_EFSCORRUPTED;
	}
	*out_ii = ii;
	return 0;
}

static void update_rootdir(struct silofs_inode_info *rootd_ii, bool utf8_names)
{
	silofs_ii_fixup_as_rootdir(rootd_ii);
	if (utf8_names) {
		silofs_dir_set_flag(rootd_ii, SILOFS_DIRF_NAME_UTF8);
	} else {
		silofs_dir_unset_flag(rootd_ii, SILOFS_DIRF_NAME_UTF8);
	}
}

static bool use_utf8_names(const struct silofs_task_ctx *task)
{
	return (task->env->flags & SILOFS_F_UTF8NAMES) > 0;
}

static int format_rootdir(struct silofs_task_ctx *task)
{
	struct silofs_inode_info *rootd_ii = nullptr;
	int err;

	err = spawn_rootdir(task, &rootd_ii);
	if (err) {
		return err;
	}
	update_rootdir(rootd_ii, use_utf8_names(task));

	err = flush_destage_dirty(task);
	if (err) {
		return err;
	}
	return 0;
}

static int format_fs(struct silofs_task_ctx *task)
{
	int err;

	err = format_super(task);
	if (err) {
		return err;
	}
	err = format_spmaps(task);
	if (err) {
		return err;
	}
	err = claim_recalim_space(task);
	if (err) {
		return err;
	}
	err = format_nil_space(task);
	if (err) {
		return err;
	}
	err = format_rootdir(task);
	if (err) {
		return err;
	}
	return 0;
}

static int pre_format_fs(struct silofs_task_ctx *task)
{
	drop_relax_caches(task);
	return 0;
}

static int
commit_mbr(struct silofs_task_ctx *task, struct silofs_mbref *out_mbref)
{
	return silofs_env_commit_fs_mbr(task->env, out_mbref);
}

static int post_format_fs(struct silofs_task_ctx *task)
{
	return flush_destage_dirty(task);
}

int silofs_exec_format_fs(struct silofs_task_ctx *task,
                          struct silofs_mbref *out_mbref)
{
	int err;

	err = pre_format_fs(task);
	if (err) {
		return err;
	}
	err = format_fs(task);
	if (err) {
		return err;
	}
	err = commit_mbr(task, out_mbref);
	if (err) {
		return err;
	}
	err = post_format_fs(task);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int resolve_root_uber(const struct silofs_task_ctx *task,
                             struct silofs_pnptr *out_pnptr)
{
	const struct silofs_env_mbis *mbis = &task->env->mbis;

	return silofs_mbi_uber_root(&mbis->fs_mbi, out_pnptr);
}

static int
reload_mbr(struct silofs_task_ctx *task, const struct silofs_mbref *mbref)
{
	return silofs_env_reload_fs_mbr(task->env, mbref);
}

int silofs_exec_reload_pv(struct silofs_task_ctx *task,
                          const struct silofs_mbref *mbref)
{
	struct silofs_pnptr pnptr = {};
	int err;

	err = reload_mbr(task, mbref);
	if (err) {
		return err;
	}
	err = resolve_root_uber(task, &pnptr);
	if (err) {
		return err;
	}
	err = silofs_reload_pv(task, &pnptr);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int reload_super(struct silofs_task_ctx *task)
{
	int err;

	err = silofs_env_reload_sb_lseg(task->env);
	if (err) {
		return err;
	}
	err = silofs_env_reload_super(task->env);
	if (err) {
		return err;
	}
	return 0;
}

static int reload_vspace(struct silofs_task_ctx *task)
{
	return silofs_reload_vspace(task);
}

static int reload_rootd(struct silofs_task_ctx *task)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = silofs_stage_inode(task, SILOFS_INO_ROOT, SILOFS_STG_CUR, &ii);
	if (err) {
		log_err("failed to reload root-inode: err=%d", err);
		return err;
	}
	if (!silofs_ii_isdir(ii)) {
		log_err("root-inode is not-a-dir: mode=0%o",
		        silofs_ii_mode(ii));
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

int silofs_exec_reload_fs(struct silofs_task_ctx *task)
{
	int err;

	err = reload_super(task);
	if (err) {
		return err;
	}
	err = reload_vspace(task);
	if (err) {
		return err;
	}
	err = reload_rootd(task);
	if (err) {
		return err;
	}
	return 0;
}
