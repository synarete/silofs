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
#include "infra.h"
#include "addr.h"
#include "fs.h"
#include "exec.h"
#include "env.h"

static int resolve_root_uber(const struct silofs_exec_ctx *exct,
                             struct silofs_pnodeptr *out_pnodeptr)
{
	const struct silofs_env_mbis *mbis = &exct->env->mbis;

	return silofs_mbi_uber_root(&mbis->fs_mbi, out_pnodeptr);
}

static int reload_uber(struct silofs_exec_ctx *exct)
{
	struct silofs_pnodeptr pnodeptr = {};
	struct silofs_uber_info *ubi    = nullptr;
	int err;

	err = resolve_root_uber(exct, &pnodeptr);
	if (err) {
		return err;
	}
	err = silofs_stage_uber(exct->env, &pnodeptr, &ubi);
	if (err) {
		return err;
	}
	silofs_env_update_uber(exct->env, ubi);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
stage_btree_root(struct silofs_exec_ctx *exct, enum silofs_mtype mtype)
{
	struct silofs_pnodeptr pnodeptr;
	struct silofs_btnode_info *bti = nullptr;
	int err;

	silofs_ubi_get_child(exct->env->ubi, mtype, &pnodeptr);
	if (silofs_paddr_isnull(&pnodeptr.paddr)) {
		log_dbg("missing btree root: mtype=%d", mtype);
		return -SILOFS_ENOENT;
	}
	err = silofs_stage_btnode(exct->env, &pnodeptr, &bti);
	if (err) {
		return err;
	}
	return 0;
}

static int
reload_btree_of(struct silofs_exec_ctx *exct, enum silofs_mtype mtype)
{
	int err;

	err = stage_btree_root(exct, mtype);
	if (err) {
		log_err("reload btree failed: mtype=%d err=%d", mtype, err);
		return err;
	}
	log_dbg("reload btree of: mtype=%d", mtype);
	return 0;
}

static int reload_btrees(struct silofs_exec_ctx *exct)
{
	enum silofs_mtype mtype = SILOFS_MTYPE_NONE;
	int err;

	while (++mtype < SILOFS_MTYPE_LAST) {
		if (!silofs_mtype_isvnode2(mtype)) {
			continue;
		}
		err = reload_btree_of(exct, mtype);
		if (err) {
			return err;
		}
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int reload_obs(struct silofs_exec_ctx *exct)
{
	int err;

	err = reload_uber(exct);
	if (err) {
		return err;
	}
	err = reload_btrees(exct);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int reload_super(struct silofs_exec_ctx *exct)
{
	int err;

	err = silofs_env_reload_sb_lseg(exct->env);
	if (err) {
		return err;
	}
	err = silofs_env_reload_super(exct->env);
	if (err) {
		return err;
	}
	return 0;
}

static int reload_vspace(struct silofs_exec_ctx *exct)
{
	return silofs_reload_vspace(exct);
}

static int reload_rootd(struct silofs_exec_ctx *exct)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = silofs_stage_inode(exct, SILOFS_INO_ROOT, SILOFS_STG_CUR, &ii);
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

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int
reload_fs_mbr(struct silofs_exec_ctx *exct, const struct silofs_mbref *mbref)
{
	return silofs_env_reload_fs_mbr(exct->env, mbref);
}

int silofs_exec_reload_fs(struct silofs_exec_ctx *exct,
                          const struct silofs_mbref *mbref)
{
	int err;

	err = reload_fs_mbr(exct, mbref);
	if (err) {
		return err;
	}
	err = reload_obs(exct);
	if (err) {
		return err;
	}
	err = reload_super(exct);
	if (err) {
		return err;
	}
	err = reload_vspace(exct);
	if (err) {
		return err;
	}
	err = reload_rootd(exct);
	if (err) {
		return err;
	}
	return 0;
}
