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
#include <silofs/ondisk.h>
#include <silofs/types.h>
#include <silofs/syscall.h>
#include <dirent.h>
#include "infra.h"
#include "addr.h"
#include "bs.h"
#include "fs.h"
#include "exec.h"
#include "env.h"

static int require_empty_repodir(const struct silofs_task_ctx *task)
{
	struct dirent64 de[4];
	const char *path = task->env->repodir;
	size_t ndes      = 0;
	int dfd          = -1;
	int err;

	err = silofs_sys_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	if (err) {
		log_dbg("opendir error: repodir=%s err=%d", path, err);
		goto out;
	}
	err = silofs_sys_getdents2(dfd, de, ARRAY_SIZE(de), &ndes);
	if (err) {
		log_dbg("readdir error: repodir=%s err=%d", path, err);
		goto out;
	}
	if (ndes > 2) {
		err = -SILOFS_ENOTEMPTY;
		goto out;
	}
out:
	silofs_sys_closefd(&dfd);
	return err;
}

static int pre_format_repo(const struct silofs_task_ctx *task)
{
	return require_empty_repodir(task);
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
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int pre_format_obs(struct silofs_task_ctx *task)
{
	return silofs_env_reinit_ciphers(task->env);
}

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
	err = silofs_destage_dirty(task->env);
	if (err) {
		log_err("failed to destage dirty: err=%d", err);
		return err;
	}
	return 0;
}

static int post_format_fs(struct silofs_task_ctx *task)
{
	int err;

	err = flush_destage_dirty(task);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void
make_base_nodeptr(const struct silofs_task_ctx *task, enum silofs_mtype mtype,
                  struct silofs_nodeptr *out_nodeptr)
{
	struct silofs_prandgen *prng = task->env->base.prng;

	silofs_make_base_nodeptr(prng, mtype, out_nodeptr);
}

static int format_uber(struct silofs_task_ctx *task)
{
	struct silofs_nodeptr nodeptr = {};
	struct silofs_uber_info *ubi  = nullptr;
	int err;

	make_base_nodeptr(task, SILOFS_MTYPE_UBER, &nodeptr);
	err = silofs_spawn_uber(task->env, &nodeptr, &ubi);
	if (err) {
		return err;
	}
	silofs_env_update_uber(task->env, ubi);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
spawn_btree_root(struct silofs_task_ctx *task, enum silofs_mtype mtype)
{
	struct silofs_nodeptr nodeptr;
	struct silofs_btnode_info *bti = nullptr;
	int err;

	make_base_nodeptr(task, SILOFS_MTYPE_BTNODE, &nodeptr);
	err = silofs_spawn_btnode(task->env, &nodeptr, &bti);
	if (err) {
		return err;
	}
	silofs_ubi_set_child(task->env->ubi, mtype, &nodeptr);
	return 0;
}

static int
format_btree_of(struct silofs_task_ctx *task, enum silofs_mtype mtype)
{
	int err;

	err = spawn_btree_root(task, mtype);
	if (err) {
		log_err("format btree failed: mtype=%d err=%d", mtype, err);
		return err;
	}
	err = flush_destage_dirty(task);
	if (err) {
		return err;
	}
	log_dbg("format btree of: mtype=%d", mtype);
	return 0;
}

static int format_btrees(struct silofs_task_ctx *task)
{
	enum silofs_mtype mtype = SILOFS_MTYPE_NONE;
	int err;

	while (++mtype < SILOFS_MTYPE_LAST) {
		if (!silofs_mtype_isvnode2(mtype)) {
			continue;
		}
		err = format_btree_of(task, mtype);
		if (err) {
			return err;
		}
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_exec_format_obs(struct silofs_task_ctx *task)
{
	int err;

	err = pre_format_obs(task);
	if (err) {
		return err;
	}
	err = format_uber(task);
	if (err) {
		return err;
	}
	err = format_btrees(task);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int format_super(struct silofs_task_ctx *task)
{
	return silofs_env_format_super(task->env, task->env->fscap);
}

static int
require_spmaps_of(struct silofs_task_ctx *task, enum silofs_mtype mtype)
{
	struct silofs_vaddr vaddr;
	struct silofs_spleaf_info *sli = nullptr;

	silofs_vaddr_setup(&vaddr, mtype, 0);
	return silofs_require_spleaf_of(task, &vaddr, SILOFS_STG_COW, &sli);
}

static int
format_spmaps_of(struct silofs_task_ctx *task, enum silofs_mtype mtype)
{
	int err;

	err = require_spmaps_of(task, mtype);
	if (err) {
		log_err("format spmaps failed: mtype=%d err=%d", mtype, err);
		return err;
	}
	err = flush_destage_dirty(task);
	if (err) {
		return err;
	}
	log_dbg("format spmaps of: mtype=%d", mtype);
	return 0;
}

static int format_spmaps(struct silofs_task_ctx *task)
{
	enum silofs_mtype mtype = SILOFS_MTYPE_NONE;
	int err;

	while (++mtype < SILOFS_MTYPE_LAST) {
		if (!silofs_mtype_isvnode(mtype)) {
			continue;
		}
		err = format_spmaps_of(task, mtype);
		if (err) {
			return err;
		}
		drop_relax_caches(task);
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
claim_reclaim_of(struct silofs_task_ctx *task, enum silofs_mtype mtype)
{
	struct silofs_vaddr vaddr;
	const off_t voff_exp = 0;
	int err;

	err = silofs_claim_vspace(task, mtype, &vaddr);
	if (err) {
		log_err("claim failed: mtype=%d err=%d", mtype, err);
		return err;
	}
	if (vaddr.off != voff_exp) {
		log_err("bad claim: mtype=%d exp=%ld got=%ld", mtype, voff_exp,
		        vaddr.off);
		return -SILOFS_EFSCORRUPTED;
	}
	drop_caches(task);
	err = silofs_reclaim_vspace(task, &vaddr);
	if (err) {
		log_err("bad reclaim: mtype=%d voff=%ld err=%d", mtype,
		        vaddr.off, err);
	}
	return 0;
}

static int claim_recalim_space(struct silofs_task_ctx *task)
{
	enum silofs_mtype mtype = SILOFS_MTYPE_NONE;
	int err;

	while (++mtype < SILOFS_MTYPE_LAST) {
		if (!silofs_mtype_isvnode(mtype) ||
		    (mtype == SILOFS_MTYPE_LSMAP)) {
			continue;
		}
		err = claim_reclaim_of(task, mtype);
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
claim_offset_zero(struct silofs_task_ctx *task, enum silofs_mtype mtype)
{
	struct silofs_vnode_info *vni = nullptr;
	off_t off                     = -1;
	int err;

	err = silofs_spawn_vnode(task, nullptr, mtype, &vni);
	if (err) {
		log_err("failed to spawn: mtype=%d err=%d", mtype, err);
		return err;
	}
	off = vni_offset(vni);
	if (off != 0) {
		log_err("format zspace failed: mtype=%d off=%ld", mtype, off);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int format_nil_space(struct silofs_task_ctx *task)
{
	enum silofs_mtype mtype = SILOFS_MTYPE_NONE;
	int err;

	while (++mtype < SILOFS_MTYPE_LAST) {
		if (!silofs_mtype_isvnode(mtype) ||
		    (mtype == SILOFS_MTYPE_LSMAP)) { /* TODO: revisit */
			continue;
		}
		err = claim_offset_zero(task, mtype);
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

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

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
