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
#include <dirent.h>
#include "infra.h"
#include "addr.h"
#include "fs.h"
#include "exec.h"
#include "env.h"

static int require_nonempty_repodir(const struct silofs_task_ctx *task)
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
	if (ndes <= 2) {
		log_dbg("bad repodir: %s", path);
		err = -SILOFS_EBADREPO;
		goto out;
	}
out:
	silofs_sys_closefd(&dfd);
	return err;
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

static int resolve_root_uber(const struct silofs_task_ctx *task,
                             struct silofs_pnodeptr *out_pnodeptr)
{
	const struct silofs_env_mbis *mbis = &task->env->mbis;

	return silofs_mbi_uber_root(&mbis->fs_mbi, out_pnodeptr);
}

static int reload_uber(struct silofs_task_ctx *task)
{
	struct silofs_pnodeptr pnodeptr = {};
	struct silofs_uber_info *ubi    = nullptr;
	int err;

	err = resolve_root_uber(task, &pnodeptr);
	if (err) {
		return err;
	}
	err = silofs_stage_uber(task->env, &pnodeptr, &ubi);
	if (err) {
		return err;
	}
	silofs_env_update_uber(task->env, ubi);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
stage_btree_root(struct silofs_task_ctx *task, enum silofs_mtype mtype)
{
	struct silofs_pnodeptr pnodeptr;
	struct silofs_btnode_info *bti = nullptr;
	int err;

	silofs_ubi_get_child(task->env->ubi, mtype, &pnodeptr);
	if (silofs_paddr_isnull(&pnodeptr.paddr)) {
		log_dbg("missing btree root: mtype=%d", mtype);
		return -SILOFS_ENOENT;
	}
	err = silofs_stage_btnode(task->env, &pnodeptr, &bti);
	if (err) {
		return err;
	}
	return 0;
}

static int
reload_btree_of(struct silofs_task_ctx *task, enum silofs_mtype mtype)
{
	int err;

	err = stage_btree_root(task, mtype);
	if (err) {
		log_err("reload btree failed: mtype=%d err=%d", mtype, err);
		return err;
	}
	log_dbg("reload btree of: mtype=%d", mtype);
	return 0;
}

static int reload_btrees(struct silofs_task_ctx *task)
{
	enum silofs_mtype mtype = SILOFS_MTYPE_NONE;
	int err;

	while (++mtype < SILOFS_MTYPE_LAST) {
		if (!silofs_mtype_isvnode2(mtype)) {
			continue;
		}
		err = reload_btree_of(task, mtype);
		if (err) {
			return err;
		}
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
reload_mbr(struct silofs_task_ctx *task, const struct silofs_mbref *mbref)
{
	return silofs_env_reload_fs_mbr(task->env, mbref);
}

int silofs_exec_reload_obs(struct silofs_task_ctx *task,
                           const struct silofs_mbref *mbref)
{
	int err;

	err = reload_mbr(task, mbref);
	if (err) {
		return err;
	}
	err = reload_uber(task);
	if (err) {
		return err;
	}
	err = reload_btrees(task);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

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
