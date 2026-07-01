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

static void
laddr_of(const struct silofs_lnode_info *lni, struct silofs_laddr *out_laddr)
{
	silofs_laddr_assign(out_laddr, silofs_lni_laddr(lni));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void drop_caches(const struct silofs_pexec_ctx *pexec)
{
	silofs_vcache_drop(pexec->vcache);
	silofs_pcache_drop(pexec->pcache);
}

static int flush_dirty_nodes(const struct silofs_pexec_ctx *pexec, bool drop)
{
	int err;

	err = silofs_destage_dirty_nodes(pexec);
	return_if_err(err);

	if (drop) {
		drop_caches(pexec);
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void update_active_uber(const struct silofs_pexec_ctx *pexec,
                               struct silofs_uber_info *ubi)
{
	log_dbg("update uber: ubi=%p", (void *)ubi);
	silofs_ubref_update(pexec->ubref, ubi);
}

static int format_uber(struct silofs_task_ctx *task)
{
	struct silofs_pnptr pnptr    = {};
	struct silofs_uber_info *ubi = nullptr;
	int err;

	err = silofs_carve_base_ubspace(&task->pexec, &pnptr);
	return_if_err(err);

	err = silofs_spawn_uber(&task->pexec, &pnptr, &ubi);
	return_if_err(err);

	update_active_uber(&task->pexec, ubi);
	return 0;
}

static void
fixup_spawned_btroot(const struct silofs_pexec_ctx *pexec,
                     struct silofs_btnode_info *bti, enum silofs_ltype ltype)
{
	silofs_bti_set_vspace(bti, ltype);
	silofs_bti_mark_root(bti, true);
	silofs_unused(pexec);
}

static int
spawn_btroot_of(const struct silofs_pexec_ctx *pexec, enum silofs_ltype ltype,
                struct silofs_btnode_info **out_bti)
{
	struct silofs_pnptr pnptr = {};
	int err;

	err = silofs_carve_base_btspace(pexec, ltype, &pnptr);
	return_if_err(err);

	err = silofs_spawn_btnode(pexec, &pnptr, out_bti);
	return_if_err(err);

	fixup_spawned_btroot(pexec, *out_bti, ltype);
	return 0;
}

static const struct silofs_paddr *
bti_paddr(const struct silofs_btnode_info *bti)
{
	return silofs_pni_paddr(&bti->btn_pni);
}

static void update_formatted_btroot(const struct silofs_pexec_ctx *pexec,
                                    const struct silofs_btnode_info *bti)
{
	struct silofs_uber_info *ubi = pexec->ubref->ubi;

	silofs_ubi_set_btroot_by(ubi, bti);
	silofs_ubi_start_spdesc(ubi, bti_paddr(bti));
}

static int format_btree_root_of(const struct silofs_pexec_ctx *pexec,
                                enum silofs_ltype ltype)
{
	struct silofs_btnode_info *bti = nullptr;
	int err;

	err = spawn_btroot_of(pexec, ltype, &bti);
	return_if_err(err);

	update_formatted_btroot(pexec, bti);
	return 0;
}

static int format_vspace_root_of(const struct silofs_pexec_ctx *pexec,
                                 enum silofs_ltype ltype)
{
	struct silofs_paddr paddr = {};
	int err;

	err = silofs_carve_base_vspace(pexec, ltype, &paddr);
	return_if_err(err);

	silofs_ubi_start_spdesc(pexec->ubref->ubi, &paddr);
	return 0;
}

static int format_vspace_roots(struct silofs_task_ctx *task)
{
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (!silofs_ltype_isnone(ltype)) {
			err = format_btree_root_of(&task->pexec, ltype);
			return_if_err(err);

			err = format_vspace_root_of(&task->pexec, ltype);
			return_if_err(err);

			err = flush_dirty_nodes(&task->pexec, false);
			return_if_err(err);
		}
	}
	return 0;
}

static int format_space_node_of(const struct silofs_pexec_ctx *pexec,
                                enum silofs_ltype ltype)
{
	struct silofs_laddr ref_laddr;
	struct silofs_spnode_info *spi = nullptr;

	silofs_laddr_setup(&ref_laddr, ltype, 0);
	return silofs_spawn_spnode2_by(pexec, &ref_laddr, &spi);
}

static int format_refetch_node_at(const struct silofs_pexec_ctx *pexec,
                                  const struct silofs_laddr *laddr,
                                  struct silofs_lnode_info **out_lni)
{
	int err;

	err = silofs_stage_lnode2_at(pexec, laddr, out_lni);
	if (err) {
		log_err("failed to re-fetch node: ltype=%d off=%ld err=%d",
		        (int)laddr->ltype, (long)laddr->off, err);
	}
	return err;
}

static int format_refetch_zero_node(const struct silofs_pexec_ctx *pexec,
                                    enum silofs_ltype ltype,
                                    struct silofs_lnode_info **out_lni)
{
	struct silofs_laddr laddr;

	silofs_laddr_setup(&laddr, ltype, 0);
	return format_refetch_node_at(pexec, &laddr, out_lni);
}

static int
create_lnode(const struct silofs_pexec_ctx *pexec, enum silofs_ltype ltype,
             struct silofs_lnode_info **out_lni)
{
	int err;

	err = silofs_spawn_lnode2(pexec, ltype, out_lni);
	if (err) {
		log_err("failed to create lnode: ltype=%d err=%d", //
		        ltype, err);
	}
	return err;
}

static int format_zero_node_step1(const struct silofs_pexec_ctx *pexec,
                                  enum silofs_ltype ltype)
{
	const struct silofs_laddr *laddr = nullptr;
	struct silofs_lnode_info *lni    = nullptr;
	int err;

	err = create_lnode(pexec, ltype, &lni);
	return_if_err(err);

	laddr = silofs_lni_laddr(lni);
	if (laddr->off != 0) {
		log_err("bad offset for node zero: ltype=%d off=%ld",
		        (int)laddr->ltype, (long)laddr->off);
		return -SILOFS_EBUG;
	}

	err = flush_dirty_nodes(pexec, true);
	return_if_err(err);

	return 0;
}

static int reclaim_lnode(const struct silofs_pexec_ctx *pexec,
                         struct silofs_lnode_info *lni)
{
	struct silofs_laddr laddr;
	bool last = false;
	int err;

	laddr_of(lni, &laddr);
	err = silofs_reclaim_lnode2_at(pexec, &laddr, &last);
	if (err || !last) {
		log_err("failed to reclaim lnode: ltype=%d off=%zd err=%d",
		        laddr.ltype, laddr.off, err);
	}
	return err;
}

static int format_zero_node_step2(const struct silofs_pexec_ctx *pexec,
                                  enum silofs_ltype ltype)
{
	struct silofs_lnode_info *lni = nullptr;
	int err;

	err = format_refetch_zero_node(pexec, ltype, &lni);
	return_if_err(err);

	err = reclaim_lnode(pexec, lni);
	return_if_err(err);

	err = flush_dirty_nodes(pexec, true);
	return_if_err(err);

	return 0;
}

static int format_zero_node_step3(const struct silofs_pexec_ctx *pexec,
                                  enum silofs_ltype ltype)
{
	struct silofs_laddr laddr;
	struct silofs_lnode_info *lni = nullptr;
	int err;

	/* Occupy laddr pos=0 indefinitely */
	err = create_lnode(pexec, ltype, &lni);
	return_if_err(err);

	laddr_of(lni, &laddr);
	if (laddr.off != 0) {
		log_err("bad offset for node zero: ltype=%d off=%ld",
		        (int)laddr.ltype, (long)laddr.off);
		return -SILOFS_EBUG;
	}

	err = flush_dirty_nodes(pexec, true);
	return_if_err(err);

	return 0;
}

static int format_zero_node_step4(const struct silofs_pexec_ctx *pexec,
                                  enum silofs_ltype ltype)
{
	struct silofs_lnode_info *lni = nullptr;

	return format_refetch_zero_node(pexec, ltype, &lni);
}

static int format_zero_node_of(const struct silofs_pexec_ctx *pexec,
                               enum silofs_ltype ltype)
{
	int err;

	err = format_zero_node_step1(pexec, ltype);
	return_if_err(err);

	err = format_zero_node_step2(pexec, ltype);
	return_if_err(err);

	err = format_zero_node_step3(pexec, ltype);
	return_if_err(err);

	err = format_zero_node_step4(pexec, ltype);
	return_if_err(err);

	return 0;
}

static int format_base_node_of(const struct silofs_pexec_ctx *pexec,
                               enum silofs_ltype ltype)
{
	const struct silofs_laddr *laddr = nullptr;
	struct silofs_lnode_info *lni    = nullptr;
	ssize_t ssize;
	int err;

	err = create_lnode(pexec, ltype, &lni);
	return_if_err(err);

	laddr = silofs_lni_laddr(lni);
	ssize = silofs_ltype_ssize(laddr->ltype);
	if (laddr->off != ssize) {
		log_err("bad offset for non-zero: ltype=%d ssize=%d off=%ld",
		        (int)laddr->ltype, (int)ssize, (long)laddr->off);
		return -SILOFS_EBUG;
	}

	err = reclaim_lnode(pexec, lni);
	return_if_err(err);

	err = flush_dirty_nodes(pexec, true);
	return_if_err(err);

	return 0;
}

static int format_vspace_node_of(const struct silofs_pexec_ctx *pexec,
                                 enum silofs_ltype ltype)
{
	int err;

	err = format_space_node_of(pexec, ltype);
	return_if_err(err);

	err = format_zero_node_of(pexec, ltype);
	return_if_err(err);

	err = format_base_node_of(pexec, ltype);
	return_if_err(err);

	return 0;
}

static bool has_vspace_mapping(enum silofs_ltype ltype)
{
	return silofs_ltype_usespmap(ltype);
}

static int format_vspace_nodes(const struct silofs_pexec_ctx *pexec)
{
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (has_vspace_mapping(ltype)) {
			err = format_vspace_node_of(pexec, ltype);
			return_if_err(err);
		}
	}
	return 0;
}

static int format_vspace(struct silofs_task_ctx *task)
{
	int err;

	err = format_vspace_roots(task);
	return_if_err(err);

	err = format_vspace_nodes(&task->pexec);
	return_if_err(err);

	return 0;
}

static void resolve_uber(const struct silofs_task_ctx *task,
                         struct silofs_pnptr *out_pnptr)
{
	const struct silofs_uber_info *ubi = task->pexec.ubref->ubi;

	silofs_pnptr_assign(out_pnptr, silofs_ubi_self(ubi));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int format_super(struct silofs_task_ctx *task, size_t fs_capacity)
{
	struct silofs_sbnode_info *sbi = nullptr;
	int err;

	err = silofs_spawn_super2(task, &sbi);
	return_if_err(err);

	silofs_sbi_setup_spawned(sbi, fs_capacity);
	return 0;
}

static int
spawn_rootdir(struct silofs_task_ctx *task, struct silofs_inode_info **out_ii)
{
	struct silofs_inew_params inp = {};
	struct silofs_inode_info *ii;
	uint64_t igen;
	int err;

	err = silofs_next_inogen(task, &igen);
	return_if_err(err);

	silofs_inew_params_of(task, nullptr, S_IFDIR | 0755, 0, igen, &inp);
	err = silofs_spawn_inode_by(task, &inp, &ii);
	return_if_err(err);

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
	return (task->pexec.ubref->ctl_flags & SILOFS_F_UTF8NAMES) > 0;
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

	/* format pstor */
	err = format_uber(task);
	return_if_err(err);

	err = format_vspace(task);
	return_if_err(err);

	/* format fs-meta */
	err = format_super(task, fs_capacity);
	return_if_err(err);

	err = format_rootdir(task);
	return_if_err(err);

	/* resolve root uber-node */
	resolve_uber(task, out_pnptr);

	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int reload_uber(const struct silofs_pexec_ctx *pexec,
                       const struct silofs_pnptr *pnptr)
{
	struct silofs_uber_info *ubi = nullptr;
	int err;

	err = silofs_stage_uber(pexec, pnptr, &ubi);
	return_if_err(err);

	update_active_uber(pexec, ubi);
	return 0;
}

static int reload_btree_root_of(const struct silofs_pexec_ctx *pexec,
                                enum silofs_ltype ltype)
{
	struct silofs_pnptr pnptr = {};
	struct silofs_btnode_info *bti;
	int err;

	silofs_ubi_btroot_of(pexec->ubref->ubi, ltype, &pnptr);
	if (silofs_pnptr_isnull(&pnptr)) {
		log_dbg("missing btree root: ltype=%d", ltype);
		return -SILOFS_EFSCORRUPTED;
	}
	err = silofs_stage_btnode(pexec, &pnptr, &bti);
	if (err) {
		log_dbg("failed to reload btroot: ltype=%d", ltype);
		return err;
	}
	return 0;
}

static int reload_vspace_roots(const struct silofs_pexec_ctx *pexec)
{
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (!silofs_ltype_isnone(ltype)) {
			err = reload_btree_root_of(pexec, ltype);
			return_if_err(err);
		}
	}
	return 0;
}

static int reload_node_zero_of(const struct silofs_pexec_ctx *pexec,
                               enum silofs_ltype ltype)
{
	struct silofs_laddr laddr;
	struct silofs_vspace_ref vspref;
	struct silofs_spnode_info *spi = nullptr;
	struct silofs_lnode_info *lni  = nullptr;
	int err;

	silofs_laddr_setup(&laddr, ltype, 0);

	err = silofs_stage_spnode2_by(pexec, &laddr, &spi);
	return_if_err(err);

	silofs_spi_vspace_ref(spi, &laddr, &vspref);
	if (vspref.refcnt != 1) {
		return -SILOFS_EFSCORRUPTED;
	}

	err = silofs_stage_lnode2_at(pexec, &laddr, &lni);
	return_if_err(err);

	return 0;
}

static int reload_vspace_nodes(const struct silofs_pexec_ctx *pexec)
{
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (has_vspace_mapping(ltype)) {
			err = reload_node_zero_of(pexec, ltype);
			return_if_err(err);
		}
	}
	return 0;
}

static int reload_vspace(const struct silofs_pexec_ctx *pexec)
{
	int err;

	err = reload_vspace_roots(pexec);
	return_if_err(err);

	err = reload_vspace_nodes(pexec);
	return_if_err(err);

	return 0;
}

static int
reload_pstor(struct silofs_task_ctx *task, const struct silofs_pnptr *pnptr)
{
	int err;

	err = reload_uber(&task->pexec, pnptr);
	return_if_err(err);

	err = reload_vspace(&task->pexec);
	return_if_err(err);

	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int reload_super(struct silofs_task_ctx *task)
{
	struct silofs_sbnode_info *sbi = nullptr;

	return silofs_stage_super2(task, SILOFS_STG_CUR, &sbi);
}

static int reload_apex_spnode_at(struct silofs_task_ctx *task,
                                 const struct silofs_laddr *laddr)
{
	struct silofs_spnode_info *spi = nullptr;

	return silofs_stage_spnode2_of(task, laddr, SILOFS_STG_CUR, &spi);
}

static int
reload_apex_spnode_of(struct silofs_task_ctx *task, enum silofs_ltype ltype)
{
	struct silofs_laddr laddr;
	struct silofs_sbnode_info *sbi = nullptr;
	int err;

	err = silofs_curr_sbi(task, &sbi);
	return_if_err(err);

	silofs_sbi_apex_of(sbi, ltype, &laddr);

	err = reload_apex_spnode_at(task, &laddr);
	return_if_err(err);

	return 0;
}

static int reload_apex_spnodes(struct silofs_task_ctx *task)
{
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (has_vspace_mapping(ltype)) {
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

static int reload_vfs(struct silofs_task_ctx *task)
{
	int err;

	err = reload_super(task);
	return_if_err(err);

	err = reload_apex_spnodes(task);
	return_if_err(err);

	err = reload_rootdir(task);
	return_if_err(err);

	return 0;
}

int silofs_reload(struct silofs_task_ctx *task,
                  const struct silofs_pnptr *pnptr)
{
	int err;

	err = reload_pstor(task, pnptr);
	return_if_err(err);

	err = reload_vfs(task);
	return_if_err(err);

	return 0;
}
