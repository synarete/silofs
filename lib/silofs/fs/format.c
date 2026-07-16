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
#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/nodes.h>
#include <silofs/pstor.h>
#include <silofs/fs.h>

static void drop_caches(const struct silofs_task_ctx *task)
{
	silofs_lcache_drop(task->ectx->lcache);
	silofs_pcache_drop(task->ectx->pcache);
}

static int flush_dirty(const struct silofs_task_ctx *task)
{
	return silofs_destage_dirty_nodes(task->ectx);
}

static int flush_dirty_nodes(const struct silofs_task_ctx *task, bool drop)
{
	int err;

	err = flush_dirty(task);
	return_if_err(err);

	if (drop) {
		drop_caches(task);
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void update_active_uber(const struct silofs_exec_ctx *ectx,
                               struct silofs_uber_info *ubi)
{
	log_dbg("update uber: ubi=%p", (void *)ubi);
	silofs_update_uber_ref(ectx->fsroot, ubi);
}

static int format_uber(struct silofs_task_ctx *task)
{
	struct silofs_pnptr pnptr    = {};
	struct silofs_uber_info *ubi = nullptr;
	int err;

	err = silofs_carve_base_ubspace(task->ectx, &pnptr);
	return_if_err(err);

	err = silofs_spawn_uber(task->ectx, &pnptr, &ubi);
	return_if_err(err);

	update_active_uber(task->ectx, ubi);
	return 0;
}

static void
fixup_spawned_btroot(struct silofs_btnode_info *bti, enum silofs_ltype ltype)
{
	silofs_bti_set_vspace(bti, ltype);
	silofs_bti_mark_root(bti, true);
}

static int
spawn_btroot_of(const struct silofs_task_ctx *task, enum silofs_ltype ltype,
                struct silofs_btnode_info **out_bti)
{
	struct silofs_pnptr pnptr = {};
	int err;

	err = silofs_carve_base_btspace(task->ectx, ltype, &pnptr);
	return_if_err(err);

	err = silofs_spawn_btnode(task->ectx, &pnptr, out_bti);
	return_if_err(err);

	fixup_spawned_btroot(*out_bti, ltype);
	return 0;
}

static const struct silofs_paddr *
bti_paddr(const struct silofs_btnode_info *bti)
{
	return silofs_pni_paddr(&bti->btn_pni);
}

static void update_formatted_btroot(const struct silofs_task_ctx *task,
                                    const struct silofs_btnode_info *bti)
{
	struct silofs_uber_info *ubi = task->ectx->fsroot->ubi;

	silofs_ubi_set_btroot_by(ubi, bti);
	silofs_ubi_start_spdesc(ubi, bti_paddr(bti));
}

static int format_btree_root_of(const struct silofs_task_ctx *task,
                                enum silofs_ltype ltype)
{
	struct silofs_btnode_info *bti = nullptr;
	int err;

	err = spawn_btroot_of(task, ltype, &bti);
	return_if_err(err);

	update_formatted_btroot(task, bti);
	return 0;
}

static int format_lspace_root_of(const struct silofs_task_ctx *task,
                                 enum silofs_ltype ltype)
{
	struct silofs_paddr paddr = {};
	int err;

	err = silofs_carve_base_lspace(task->ectx, ltype, &paddr);
	return_if_err(err);

	silofs_ubi_start_spdesc(task->ectx->fsroot->ubi, &paddr);
	return 0;
}

static int format_lspace_roots(const struct silofs_task_ctx *task)
{
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (!silofs_ltype_isnone(ltype)) {
			err = format_btree_root_of(task, ltype);
			return_if_err(err);

			err = format_lspace_root_of(task, ltype);
			return_if_err(err);
		}
	}
	return flush_dirty(task);
}

static bool has_lspace_mapping(enum silofs_ltype ltype)
{
	return silofs_ltype_usespmap(ltype);
}

static int format_base_spnode_of(const struct silofs_task_ctx *task,
                                 enum silofs_ltype ltype)
{
	struct silofs_spnode_info *spi = nullptr;

	return silofs_spawn_apex_spnode_of(task, ltype, &spi);
}

static int format_base_spnodes(const struct silofs_task_ctx *task)
{
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (has_lspace_mapping(ltype)) {
			err = format_base_spnode_of(task, ltype);
			return_if_err(err);
		}
	}
	return 0;
}

static int format_stage_node_at(const struct silofs_task_ctx *task,
                                const struct silofs_laddr *laddr,
                                struct silofs_lnode_info **out_lni)
{
	int err;

	err = silofs_stage_curr_lnode(task, laddr, out_lni);
	if (err) {
		log_err("failed to re-stage node: ltype=%d off=%ld err=%d",
		        (int)laddr->ltype, (long)laddr->off, err);
	}
	return err;
}

static int format_restage_zero_node(const struct silofs_task_ctx *task,
                                    enum silofs_ltype ltype,
                                    struct silofs_lnode_info **out_lni)
{
	struct silofs_laddr laddr;

	silofs_laddr_setup(&laddr, ltype, 0);
	return format_stage_node_at(task, &laddr, out_lni);
}

static int
create_lnode(const struct silofs_task_ctx *task, enum silofs_ltype ltype,
             struct silofs_lnode_info **out_lni)
{
	int err;

	err = silofs_spawn_take_lnode(task, ltype, out_lni);
	if (err) {
		log_err("failed to create lnode: ltype=%d err=%d", ltype, err);
	}
	return err;
}

static int check_zero_node_by(const struct silofs_lnode_info *lni)
{
	const struct silofs_laddr *laddr = silofs_lni_laddr(lni);

	if (laddr->off != 0) {
		log_err("bad offset for zero node: ltype=%d off=%ld",
		        (int)laddr->ltype, (long)laddr->off);
		return -SILOFS_EBUG;
	}
	return 0;
}

static int check_base_node_by(const struct silofs_lnode_info *lni)
{
	const struct silofs_laddr *laddr = silofs_lni_laddr(lni);
	ssize_t lsize;

	lsize = silofs_ltype_ssize(laddr->ltype);
	if (laddr->off != lsize) {
		log_err("bad offset for base node: ltype=%d off=%ld",
		        (int)laddr->ltype, (long)laddr->off);
		return -SILOFS_EBUG;
	}
	return 0;
}

static int format_zero_node_step1(const struct silofs_task_ctx *task,
                                  enum silofs_ltype ltype)
{
	struct silofs_lnode_info *lni = nullptr;
	int err;

	err = create_lnode(task, ltype, &lni);
	return_if_err(err);

	err = check_zero_node_by(lni);
	return_if_err(err);

	err = flush_dirty_nodes(task, true);
	return_if_err(err);

	return 0;
}

static int reclaim_lnode(const struct silofs_task_ctx *task,
                         struct silofs_lnode_info *lni)
{
	const enum silofs_ltype ltype = silofs_lni_ltype(lni);
	int err;

	err = silofs_remove_give_lnode(task, lni);
	if (err) {
		log_err("failed to reclaim lnode: ltype=%d err=%d", ltype,
		        err);
	}
	return err;
}

static int format_zero_node_step2(const struct silofs_task_ctx *task,
                                  enum silofs_ltype ltype)
{
	struct silofs_lnode_info *lni = nullptr;
	int err;

	err = format_restage_zero_node(task, ltype, &lni);
	return_if_err(err);

	err = reclaim_lnode(task, lni);
	return_if_err(err);

	err = flush_dirty_nodes(task, true);
	return_if_err(err);

	return 0;
}

static int format_zero_node_step3(const struct silofs_task_ctx *task,
                                  enum silofs_ltype ltype)
{
	struct silofs_lnode_info *lni = nullptr;
	int err;

	/* Occupy laddr pos=0 forever */
	err = create_lnode(task, ltype, &lni);
	return_if_err(err);

	err = check_zero_node_by(lni);
	return_if_err(err);

	err = flush_dirty_nodes(task, true);
	return_if_err(err);

	return 0;
}

static int format_zero_node_step4(const struct silofs_task_ctx *task,
                                  enum silofs_ltype ltype)
{
	struct silofs_lnode_info *lni = nullptr;

	return format_restage_zero_node(task, ltype, &lni);
}

static int format_zero_node_of(const struct silofs_task_ctx *task,
                               enum silofs_ltype ltype)
{
	int err;

	err = format_zero_node_step1(task, ltype);
	return_if_err(err);

	err = format_zero_node_step2(task, ltype);
	return_if_err(err);

	err = format_zero_node_step3(task, ltype);
	return_if_err(err);

	err = format_zero_node_step4(task, ltype);
	return_if_err(err);

	return 0;
}

static int format_base_node_of(const struct silofs_task_ctx *task,
                               enum silofs_ltype ltype)
{
	struct silofs_lnode_info *lni = nullptr;
	int err;

	err = create_lnode(task, ltype, &lni);
	return_if_err(err);

	err = check_base_node_by(lni);
	return_if_err(err);

	err = reclaim_lnode(task, lni);
	return_if_err(err);

	err = flush_dirty_nodes(task, true);
	return_if_err(err);

	return 0;
}

static int format_lspace_node_of(const struct silofs_task_ctx *task,
                                 enum silofs_ltype ltype)
{
	int err;

	err = format_zero_node_of(task, ltype);
	return_if_err(err);

	err = format_base_node_of(task, ltype);
	return_if_err(err);

	return 0;
}

static int format_lspace_nodes(const struct silofs_task_ctx *task)
{
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (has_lspace_mapping(ltype)) {
			err = format_lspace_node_of(task, ltype);
			return_if_err(err);
		}
	}
	return 0;
}

static void resolve_uber(const struct silofs_task_ctx *task,
                         struct silofs_pnptr *out_pnptr)
{
	const struct silofs_uber_info *ubi = task->ectx->fsroot->ubi;

	silofs_pnptr_assign(out_pnptr, silofs_ubi_self(ubi));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int format_super(struct silofs_task_ctx *task, size_t fs_capacity)
{
	struct silofs_sbnode_info *sbi = nullptr;
	int err;

	err = silofs_spawn_super(task, &sbi);
	return_if_err(err);

	silofs_sbi_setup_spawned(sbi, fs_capacity);
	return 0;
}

static int check_rootdir(const struct silofs_inode_info *ii)
{
	if (ii->i_ino != SILOFS_INO_ROOT) {
		log_err("bad root-dir: ino=%ld", ii->i_ino);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int
spawn_rootdir(struct silofs_task_ctx *task, struct silofs_inode_info **out_ii)
{
	struct silofs_inew_params inp = {};
	uint64_t igen;
	int err;

	err = silofs_next_inogen(task, &igen);
	return_if_err(err);

	silofs_inew_params_of(task, nullptr, S_IFDIR | 0755, 0, igen, &inp);
	err = silofs_spawn_inode_by(task, &inp, out_ii);
	return_if_err(err);

	err = check_rootdir(*out_ii);
	return_if_err(err);

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
	return (task->ectx->fsroot->ctl_flags & SILOFS_F_UTF8NAMES) > 0;
}

static int format_rootdir(struct silofs_task_ctx *task)
{
	struct silofs_inode_info *rootd_ii = nullptr;
	int err;

	err = spawn_rootdir(task, &rootd_ii);
	return_if_err(err);

	update_rootdir(rootd_ii, use_utf8_names(task));
	return 0;
}

int silofs_format(struct silofs_task_ctx *task, size_t fs_capacity,
                  struct silofs_pnptr *out_pnptr)
{
	int err;

	err = format_uber(task);
	return_if_err(err);

	err = format_lspace_roots(task);
	return_if_err(err);

	err = format_super(task, fs_capacity);
	return_if_err(err);

	err = format_base_spnodes(task);
	return_if_err(err);

	err = format_lspace_nodes(task);
	return_if_err(err);

	err = format_rootdir(task);
	return_if_err(err);

	resolve_uber(task, out_pnptr);

	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int reload_uber(const struct silofs_task_ctx *task,
                       const struct silofs_pnptr *pnptr)
{
	struct silofs_uber_info *ubi = nullptr;
	int err;

	err = silofs_stage_uber(task->ectx, pnptr, &ubi);
	return_if_err(err);

	update_active_uber(task->ectx, ubi);
	return 0;
}

static int reload_btree_root_of(const struct silofs_task_ctx *task,
                                enum silofs_ltype ltype)
{
	struct silofs_pnptr pnptr = {};
	struct silofs_btnode_info *bti;
	int err;

	silofs_ubi_btroot_of(task->ectx->fsroot->ubi, ltype, &pnptr);
	if (silofs_pnptr_isnull(&pnptr)) {
		log_dbg("missing btree root: ltype=%d", ltype);
		return -SILOFS_EFSCORRUPTED;
	}
	err = silofs_stage_btnode(task->ectx, &pnptr, &bti);
	if (err) {
		log_dbg("failed to reload btroot: ltype=%d", ltype);
		return err;
	}
	return 0;
}

static int reload_btree_roots(const struct silofs_task_ctx *task)
{
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (!silofs_ltype_isnone(ltype)) {
			err = reload_btree_root_of(task, ltype);
			return_if_err(err);
		}
	}
	return 0;
}

static int reload_apex_spnode_of(const struct silofs_task_ctx *task,
                                 enum silofs_ltype ltype)
{
	struct silofs_spnode_info *spi = nullptr;

	return silofs_stage_apex_spnode_of(task, ltype, &spi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int reload_super(struct silofs_task_ctx *task)
{
	struct silofs_sbnode_info *sbi = nullptr;

	return silofs_stage_super(task, SILOFS_STG_CUR, &sbi);
}

static int reload_apex_spnodes(struct silofs_task_ctx *task)
{
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (has_lspace_mapping(ltype)) {
			err = reload_apex_spnode_of(task, ltype);
			return_if_err(err);
		}
	}
	return 0;
}

static int reload_rootdir(struct silofs_task_ctx *task)
{
	struct silofs_inode_info *ii = nullptr;
	constexpr ino_t ino          = SILOFS_INO_ROOT;
	int err;

	err = silofs_stage_inode_by(task, ino, SILOFS_STG_CUR, &ii);
	if (err) {
		log_err("failed to reload root-inode: err=%d", err);
		return err;
	}
	if (!silofs_ii_isdir(ii)) {
		const mode_t mode = silofs_ii_mode(ii);

		log_err("root-inode is not-a-dir: mode=0%o", mode);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

int silofs_reload(struct silofs_task_ctx *task,
                  const struct silofs_pnptr *pnptr)
{
	int err;

	err = reload_uber(task, pnptr);
	return_if_err(err);

	err = reload_btree_roots(task);
	return_if_err(err);

	err = reload_super(task);
	return_if_err(err);

	err = reload_apex_spnodes(task);
	return_if_err(err);

	err = reload_rootdir(task);
	return_if_err(err);

	return 0;
}
