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

static int pre_format_fs(struct silofs_exec_ctx *ectx)
{
	return silofs_env_reinit_ciphers(ectx->ex_env);
}

static void drop_caches(struct silofs_exec_ctx *ectx)
{
	silofs_env_drop_caches(ectx->ex_env);
}

static void relax_caches(struct silofs_exec_ctx *ectx)
{
	silofs_env_relax_caches(ectx->ex_env, SILOFS_CTLF_IDLE);
}

static void drop_relax_caches(struct silofs_exec_ctx *ectx)
{
	drop_caches(ectx);
	relax_caches(ectx);
}

static int flush_destage_dirty(struct silofs_exec_ctx *ectx)
{
	int err;

	err = silofs_flush_dirty_now(ectx);
	if (err) {
		log_err("failed to flush dirty: err=%d", err);
		return err;
	}
	err = silofs_destage_dirty(ectx->ex_env);
	if (err) {
		log_err("failed to destage dirty: err=%d", err);
		return err;
	}
	return 0;
}

static int post_format_fs(struct silofs_exec_ctx *ectx)
{
	int err;

	err = flush_destage_dirty(ectx);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int format_uber(struct silofs_exec_ctx *ectx)
{
	return silofs_env_format_uber(ectx->ex_env);
}

static int format_obs(struct silofs_exec_ctx *ectx)
{
	int err;

	err = format_uber(ectx);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static size_t calc_fs_cap(size_t fs_cap_want)
{
	const size_t align_size = SILOFS_LSEG_SIZE_MAX;

	return (fs_cap_want / align_size) * align_size;
}

static int format_super(struct silofs_exec_ctx *ectx, size_t fs_cap_want)
{
	return silofs_env_format_super(ectx->ex_env, calc_fs_cap(fs_cap_want));
}

static int
require_spmaps_of(struct silofs_exec_ctx *ectx, enum silofs_mtype mtype)
{
	struct silofs_vaddr vaddr;
	struct silofs_spleaf_info *sli = nullptr;

	silofs_vaddr_setup(&vaddr, mtype, 0);
	return silofs_require_spleaf_of(ectx, &vaddr, SILOFS_STG_COW, &sli);
}

static int
format_spmaps_of(struct silofs_exec_ctx *ectx, enum silofs_mtype mtype)
{
	int err;

	err = require_spmaps_of(ectx, mtype);
	if (err) {
		log_err("format spmaps failed: mtype=%d err=%d", mtype, err);
		return err;
	}
	err = flush_destage_dirty(ectx);
	if (err) {
		return err;
	}
	log_dbg("format spmaps of: mtype=%d", mtype);
	return 0;
}

static int format_spmaps(struct silofs_exec_ctx *ectx)
{
	enum silofs_mtype mtype = SILOFS_MTYPE_NONE;
	int err;

	while (++mtype < SILOFS_MTYPE_LAST) {
		if (!silofs_mtype_isvnode(mtype)) {
			continue;
		}
		err = format_spmaps_of(ectx, mtype);
		if (err) {
			return err;
		}
		drop_relax_caches(ectx);
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
claim_reclaim_of(struct silofs_exec_ctx *ectx, enum silofs_mtype mtype)
{
	struct silofs_vaddr vaddr;
	const off_t voff_exp = 0;
	int err;

	err = silofs_claim_vspace(ectx, mtype, &vaddr);
	if (err) {
		log_err("claim failed: mtype=%d err=%d", mtype, err);
		return err;
	}
	if (vaddr.off != voff_exp) {
		log_err("bad claim: mtype=%d exp=%ld got=%ld", mtype, voff_exp,
		        vaddr.off);
		return -SILOFS_EFSCORRUPTED;
	}
	drop_caches(ectx);
	err = silofs_reclaim_vspace(ectx, &vaddr);
	if (err) {
		log_err("bad reclaim: mtype=%d voff=%ld err=%d", mtype,
		        vaddr.off, err);
	}
	return 0;
}

static int claim_recalim_space(struct silofs_exec_ctx *ectx)
{
	enum silofs_mtype mtype = SILOFS_MTYPE_NONE;
	int err;

	while (++mtype < SILOFS_MTYPE_LAST) {
		if (!silofs_mtype_isvnode(mtype) ||
		    (mtype == SILOFS_MTYPE_LSMAP)) {
			continue;
		}
		err = claim_reclaim_of(ectx, mtype);
		if (err) {
			return err;
		}
		err = flush_destage_dirty(ectx);
		if (err) {
			return err;
		}
		drop_relax_caches(ectx);
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
claim_offset_zero(struct silofs_exec_ctx *ectx, enum silofs_mtype mtype)
{
	struct silofs_vnode_info *vni = nullptr;
	off_t off                     = -1;
	int err;

	err = silofs_spawn_vnode(ectx, nullptr, mtype, &vni);
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

static int format_nil_space(struct silofs_exec_ctx *ectx)
{
	enum silofs_mtype mtype = SILOFS_MTYPE_NONE;
	int err;

	while (++mtype < SILOFS_MTYPE_LAST) {
		if (!silofs_mtype_isvnode(mtype) ||
		    (mtype == SILOFS_MTYPE_LSMAP)) { /* TODO: revisit */
			continue;
		}
		err = claim_offset_zero(ectx, mtype);
		if (err) {
			return err;
		}
		err = flush_destage_dirty(ectx);
		if (err) {
			return err;
		}
		drop_relax_caches(ectx);
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
spawn_rootdir(struct silofs_exec_ctx *ectx, struct silofs_inode_info **out_ii)
{
	struct silofs_inew_params inp;
	struct silofs_inode_info *ii;
	int err;

	silofs_inew_params_of(ectx, nullptr, S_IFDIR | 0755, 0, &inp);
	err = silofs_spawn_inode(ectx, &inp, &ii);
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

static int format_rootdir(struct silofs_exec_ctx *ectx, bool utf8_names)
{
	struct silofs_inode_info *rootd_ii = nullptr;
	int err;

	err = spawn_rootdir(ectx, &rootd_ii);
	if (err) {
		return err;
	}
	update_rootdir(rootd_ii, utf8_names);

	err = flush_destage_dirty(ectx);
	if (err) {
		return err;
	}
	return 0;
}

static int format_fs(struct silofs_exec_ctx *ectx, size_t cap, bool utf8_names)
{
	int err;

	err = format_super(ectx, cap);
	if (err) {
		return err;
	}
	err = format_spmaps(ectx);
	if (err) {
		return err;
	}
	err = claim_recalim_space(ectx);
	if (err) {
		return err;
	}
	err = format_nil_space(ectx);
	if (err) {
		return err;
	}
	err = format_rootdir(ectx, utf8_names);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int
commit_mbr(struct silofs_exec_ctx *ectx, struct silofs_mbref *out_mbref)
{
	return silofs_env_commit_fs_mbr(ectx->ex_env, out_mbref);
}

int silofs_exec_format_fs(struct silofs_exec_ctx *ectx, size_t capacity,
                          bool utf8_names, struct silofs_mbref *out_mbref)
{
	int err;

	err = pre_format_fs(ectx);
	if (err) {
		return err;
	}
	err = format_obs(ectx);
	if (err) {
		return err;
	}
	err = format_fs(ectx, capacity, utf8_names);
	if (err) {
		return err;
	}
	err = commit_mbr(ectx, out_mbref);
	if (err) {
		return err;
	}
	err = post_format_fs(ectx);
	if (err) {
		return err;
	}
	return 0;
}
