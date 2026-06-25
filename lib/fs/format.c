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
#include <silofs/base.h>
#include <silofs/addr.h>
#include <silofs/nodes.h>
#include <silofs/pv.h>
#include <silofs/fs.h>

static void
vaddr_of(const struct silofs_vnode_info *vni, struct silofs_vaddr *out_vaddr)
{
	silofs_vaddr_assign(out_vaddr, silofs_vni_vaddr(vni));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void drop_caches(struct silofs_pexec_ctx *pexec)
{
	silofs_vcache_drop(pexec->vcache);
	silofs_pcache_drop(pexec->pcache);
}

static int flush_dirty_nodes(struct silofs_pexec_ctx *pexec, bool drop)
{
	int err;

	err = silofs_destage_dirty_nodes(pexec);
	if (err) {
		log_err("failed to flush dirty nodes: err=%d", err);
		return err;
	}
	if (drop) {
		drop_caches(pexec);
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void update_active_uber(struct silofs_pexec_ctx *pexec,
                               struct silofs_uber_info *ubi)
{
	log_dbg("update uber: ubi=%p", (void *)ubi);
	silofs_ubref_update(pexec->ubref, ubi);
}

static int format_uber(struct silofs_pexec_ctx *pexec)
{
	struct silofs_pnptr pnptr    = {};
	struct silofs_uber_info *ubi = nullptr;
	int err;

	err = silofs_carve_base_ubspace(pexec, &pnptr);
	return_if_err(err);

	err = silofs_spawn_uber(pexec, &pnptr, &ubi);
	return_if_err(err);

	update_active_uber(pexec, ubi);
	return 0;
}

static void
fixup_spawned_btroot(const struct silofs_pexec_ctx *pexec,
                     struct silofs_btnode_info *bti, enum silofs_vtype vtype)
{
	silofs_bti_set_vspace(bti, vtype);
	silofs_bti_mark_root(bti, true);
	silofs_unused(pexec);
}

static int
spawn_btroot_of(struct silofs_pexec_ctx *pexec, enum silofs_vtype vtype,
                struct silofs_btnode_info **out_bti)
{
	struct silofs_pnptr pnptr = {};
	int err;

	err = silofs_carve_base_btspace(pexec, vtype, &pnptr);
	return_if_err(err);

	err = silofs_spawn_btnode(pexec, &pnptr, out_bti);
	return_if_err(err);

	fixup_spawned_btroot(pexec, *out_bti, vtype);
	return 0;
}

static const struct silofs_paddr *
bti_paddr(const struct silofs_btnode_info *bti)
{
	return silofs_pni_paddr(&bti->btn_pni);
}

static void update_formatted_btroot(struct silofs_pexec_ctx *pexec,
                                    const struct silofs_btnode_info *bti)
{
	struct silofs_uber_info *ubi = pexec->ubref->ubi;

	silofs_ubi_set_btroot_by(ubi, bti);
	silofs_ubi_start_spdesc(ubi, bti_paddr(bti));
}

static int
format_btree_root_of(struct silofs_pexec_ctx *pexec, enum silofs_vtype vtype)
{
	struct silofs_btnode_info *bti = nullptr;
	int err;

	err = spawn_btroot_of(pexec, vtype, &bti);
	return_if_err(err);

	update_formatted_btroot(pexec, bti);
	return 0;
}

static int
format_vspace_root_of(struct silofs_pexec_ctx *pexec, enum silofs_vtype vtype)
{
	struct silofs_paddr paddr = {};
	int err;

	err = silofs_carve_base_vspace(pexec, vtype, &paddr);
	return_if_err(err);

	silofs_ubi_start_spdesc(pexec->ubref->ubi, &paddr);
	return 0;
}

static int format_vspace_roots(struct silofs_pexec_ctx *pexec)
{
	enum silofs_vtype vtype = SILOFS_VTYPE_NONE;
	int err;

	while (++vtype < SILOFS_VTYPE_LAST) {
		if (!silofs_vtype_isvnode(vtype)) {
			continue;
		}
		err = format_btree_root_of(pexec, vtype);
		return_if_err(err);

		err = format_vspace_root_of(pexec, vtype);
		return_if_err(err);

		err = flush_dirty_nodes(pexec, false);
		return_if_err(err);
	}
	return 0;
}

static int
format_space_node_of(struct silofs_pexec_ctx *pexec, enum silofs_vtype vtype)
{
	struct silofs_vaddr ref_vaddr;
	struct silofs_spnode_info2 *spi = nullptr;

	silofs_vaddr_setup(&ref_vaddr, vtype, 0);
	return silofs_spawn_spnode2_by(pexec, &ref_vaddr, &spi);
}

static int format_refetch_node_at(struct silofs_pexec_ctx *pexec,
                                  const struct silofs_vaddr *vaddr,
                                  struct silofs_vnode_info **out_vni)
{
	int err;

	err = silofs_stage_vnode2_at(pexec, vaddr, out_vni);
	if (err) {
		log_err("failed to re-fetch node: vtype=%d off=%ld err=%d",
		        (int)vaddr->vtype, (long)vaddr->off, err);
	}
	return err;
}

static int format_refetch_zero_node(struct silofs_pexec_ctx *pexec,
                                    enum silofs_vtype vtype,
                                    struct silofs_vnode_info **out_vni)
{
	struct silofs_vaddr vaddr;

	silofs_vaddr_setup(&vaddr, vtype, 0);
	return format_refetch_node_at(pexec, &vaddr, out_vni);
}

static int
create_vnode(struct silofs_pexec_ctx *pexec, enum silofs_vtype vtype,
             struct silofs_vnode_info **out_vni)
{
	int err;

	err = silofs_spawn_vnode2(pexec, vtype, out_vni);
	if (err) {
		log_err("failed to create vnode: vtype=%d err=%d", //
		        vtype, err);
	}
	return err;
}

static int
format_zero_node_step1(struct silofs_pexec_ctx *pexec, enum silofs_vtype vtype)
{
	const struct silofs_vaddr *vaddr = nullptr;
	struct silofs_vnode_info *vni    = nullptr;
	int err;

	err = create_vnode(pexec, vtype, &vni);
	return_if_err(err);

	vaddr = silofs_vni_vaddr(vni);
	if (vaddr->off != 0) {
		log_err("bad offset for node zero: vtype=%d off=%ld",
		        (int)vaddr->vtype, (long)vaddr->off);
		return -SILOFS_EBUG;
	}

	err = flush_dirty_nodes(pexec, true);
	return_if_err(err);

	return 0;
}

static int
reclaim_vnode(struct silofs_pexec_ctx *pexec, struct silofs_vnode_info *vni)
{
	struct silofs_vaddr vaddr;
	int err;

	vaddr_of(vni, &vaddr);
	err = silofs_reclaim_vnode2_at(pexec, &vaddr);
	if (err) {
		log_err("failed to reclaim vnode: vtype=%d off=%zd err=%d",
		        vaddr.vtype, vaddr.off, err);
	}
	return err;
}

static int
format_zero_node_step2(struct silofs_pexec_ctx *pexec, enum silofs_vtype vtype)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

	err = format_refetch_zero_node(pexec, vtype, &vni);
	return_if_err(err);

	err = reclaim_vnode(pexec, vni);
	return_if_err(err);

	err = flush_dirty_nodes(pexec, true);
	return_if_err(err);

	return 0;
}

static int
format_zero_node_step3(struct silofs_pexec_ctx *pexec, enum silofs_vtype vtype)
{
	struct silofs_vaddr vaddr;
	struct silofs_vnode_info *vni = nullptr;
	int err;

	/* Occupy vaddr pos=0 indefinitely */
	err = create_vnode(pexec, vtype, &vni);
	return_if_err(err);

	vaddr_of(vni, &vaddr);
	if (vaddr.off != 0) {
		log_err("bad offset for node zero: vtype=%d off=%ld",
		        (int)vaddr.vtype, (long)vaddr.off);
		return -SILOFS_EBUG;
	}

	err = flush_dirty_nodes(pexec, true);
	return_if_err(err);

	return 0;
}

static int
format_zero_node_step4(struct silofs_pexec_ctx *pexec, enum silofs_vtype vtype)
{
	struct silofs_vnode_info *vni = nullptr;

	return format_refetch_zero_node(pexec, vtype, &vni);
}

static int
format_zero_node_of(struct silofs_pexec_ctx *pexec, enum silofs_vtype vtype)
{
	int err;

	err = format_zero_node_step1(pexec, vtype);
	return_if_err(err);

	err = format_zero_node_step2(pexec, vtype);
	return_if_err(err);

	err = format_zero_node_step3(pexec, vtype);
	return_if_err(err);

	err = format_zero_node_step4(pexec, vtype);
	return_if_err(err);

	return 0;
}

static int
format_base_node_of(struct silofs_pexec_ctx *pexec, enum silofs_vtype vtype)
{
	const struct silofs_vaddr *vaddr = nullptr;
	struct silofs_vnode_info *vni    = nullptr;
	ssize_t ssize;
	int err;

	err = create_vnode(pexec, vtype, &vni);
	return_if_err(err);

	vaddr = silofs_vni_vaddr(vni);
	ssize = silofs_vtype_ssize(vaddr->vtype);
	if (vaddr->off != ssize) {
		log_err("bad offset for non-zero: vtype=%d ssize=%d off=%ld",
		        (int)vaddr->vtype, (int)ssize, (long)vaddr->off);
		return -SILOFS_EBUG;
	}

	err = reclaim_vnode(pexec, vni);
	return_if_err(err);

	err = flush_dirty_nodes(pexec, true);
	return_if_err(err);

	return 0;
}

static int
format_vspace_node_of(struct silofs_pexec_ctx *pexec, enum silofs_vtype vtype)
{
	int err;

	err = format_space_node_of(pexec, vtype);
	return_if_err(err);

	err = format_zero_node_of(pexec, vtype);
	return_if_err(err);

	err = format_base_node_of(pexec, vtype);
	return_if_err(err);

	return 0;
}

static bool has_vspace_mapping(enum silofs_vtype vtype)
{
	return silofs_vtype_usespmap(vtype);
}

static int format_vspace_nodes(struct silofs_pexec_ctx *pexec)
{
	enum silofs_vtype vtype = SILOFS_VTYPE_NONE;
	int err;

	while (++vtype < SILOFS_VTYPE_LAST) {
		if (has_vspace_mapping(vtype)) {
			err = format_vspace_node_of(pexec, vtype);
			return_if_err(err);
		}
	}
	return 0;
}

static int format_vspace(struct silofs_pexec_ctx *pexec)
{
	int err;

	err = format_vspace_roots(pexec);
	return_if_err(err);

	err = format_vspace_nodes(pexec);
	return_if_err(err);

	return 0;
}

static void resolve_uber(const struct silofs_pexec_ctx *pexec,
                         struct silofs_pnptr *out_pnptr)
{
	const struct silofs_uber_info *ubi = pexec->ubref->ubi;

	silofs_pnptr_assign(out_pnptr, silofs_pni_self(&ubi->ub_pni));
}

static int
do_format_pbs(struct silofs_pexec_ctx *pexec, struct silofs_pnptr *out_pnptr)
{
	int err;

	err = format_uber(pexec);
	return_if_err(err);

	err = format_vspace(pexec);
	return_if_err(err);

	resolve_uber(pexec, out_pnptr);
	return 0;
}

static int
format_pbs(struct silofs_task_ctx *task, struct silofs_pnptr *out_pnptr)
{
	struct silofs_pexec_ctx pexec;

	silofs_make_pexec(task, &pexec);
	return do_format_pbs(&pexec, out_pnptr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int format_super(struct silofs_task_ctx *task, size_t fs_capacity)
{
	struct silofs_sbnode_info2 *sbi = nullptr;
	int err;

	err = silofs_spawn_super2(task, &sbi);
	return_if_err(err);

	silofs_sbi2_setup_spawned(sbi, fs_capacity);
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
	return (task->ubref->ctl_flags & SILOFS_F_UTF8NAMES) > 0;
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

static int format_vfs(struct silofs_task_ctx *task, size_t fs_capacity)
{
	int err;

	err = format_super(task, fs_capacity);
	return_if_err(err);

	err = format_rootdir(task);
	return_if_err(err);

	return 0;
}

int silofs_format(struct silofs_task_ctx *task, size_t fs_capacity,
                  struct silofs_pnptr *out_pnptr)
{
	int err;

	err = format_pbs(task, out_pnptr);
	return_if_err(err);

	err = format_vfs(task, fs_capacity);
	return_if_err(err);

	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int
reload_uber(struct silofs_pexec_ctx *pexec, const struct silofs_pnptr *pnptr)
{
	struct silofs_uber_info *ubi = nullptr;
	int err;

	err = silofs_stage_uber(pexec, pnptr, &ubi);
	return_if_err(err);

	update_active_uber(pexec, ubi);
	return 0;
}

static int
reload_btree_root_of(struct silofs_pexec_ctx *pexec, enum silofs_vtype vtype)
{
	struct silofs_pnptr pnptr = {};
	struct silofs_btnode_info *bti;
	int err;

	silofs_ubi_btroot_of(pexec->ubref->ubi, vtype, &pnptr);
	if (silofs_pnptr_isnull(&pnptr)) {
		log_dbg("missing btree root: vtype=%d", vtype);
		return -SILOFS_EFSCORRUPTED;
	}
	err = silofs_stage_btnode(pexec, &pnptr, &bti);
	if (err) {
		log_dbg("failed to reload btroot: vtype=%d", vtype);
		return err;
	}
	return 0;
}

static int reload_vspace_roots(struct silofs_pexec_ctx *pexec)
{
	enum silofs_vtype vtype = SILOFS_VTYPE_NONE;
	int err;

	while (++vtype < SILOFS_VTYPE_LAST) {
		if (!silofs_vtype_isvnode(vtype)) {
			continue;
		}
		err = reload_btree_root_of(pexec, vtype);
		return_if_err(err);
	}
	return 0;
}

static int
reload_node_zero_of(struct silofs_pexec_ctx *pexec, enum silofs_vtype vtype)
{
	struct silofs_vaddr vaddr;
	struct silofs_vspace_ref vspref;
	struct silofs_spnode_info2 *spi = nullptr;
	struct silofs_vnode_info *vni   = nullptr;
	int err;

	silofs_vaddr_setup(&vaddr, vtype, 0);

	err = silofs_stage_spnode2_by(pexec, &vaddr, &spi);
	return_if_err(err);

	silofs_spi_vspace_ref(spi, &vaddr, &vspref);
	if (vspref.refcnt != 1) {
		return -SILOFS_EFSCORRUPTED;
	}

	err = silofs_stage_vnode2_at(pexec, &vaddr, &vni);
	return_if_err(err);

	return 0;
}

static int reload_vspace_nodes(struct silofs_pexec_ctx *pexec)
{
	enum silofs_vtype vtype = SILOFS_VTYPE_NONE;
	int err;

	while (++vtype < SILOFS_VTYPE_LAST) {
		if (has_vspace_mapping(vtype)) {
			err = reload_node_zero_of(pexec, vtype);
			return_if_err(err);
		}
	}
	return 0;
}

static int reload_vspace(struct silofs_pexec_ctx *pexec)
{
	int err;

	err = reload_vspace_roots(pexec);
	return_if_err(err);

	err = reload_vspace_nodes(pexec);
	return_if_err(err);

	return 0;
}

static int
do_reload_pbs(struct silofs_pexec_ctx *pexec, const struct silofs_pnptr *pnptr)
{
	int err;

	err = reload_uber(pexec, pnptr);
	return_if_err(err);

	err = reload_vspace(pexec);
	return_if_err(err);

	return 0;
}

static int
reload_pbs(struct silofs_task_ctx *task, const struct silofs_pnptr *pnptr)
{
	struct silofs_pexec_ctx pexec;

	silofs_make_pexec(task, &pexec);
	return do_reload_pbs(&pexec, pnptr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int reload_super(struct silofs_task_ctx *task)
{
	struct silofs_sbnode_info2 *sbi = nullptr;

	return silofs_stage_super2(task, SILOFS_STG_CUR, &sbi);
}

static int reload_apex_spnode_at(struct silofs_task_ctx *task,
                                 const struct silofs_vaddr *vaddr)
{
	struct silofs_spnode_info2 *spi = nullptr;

	return silofs_stage_spnode2_of(task, vaddr, SILOFS_STG_CUR, &spi);
}

static int
reload_apex_spnode_of(struct silofs_task_ctx *task, enum silofs_vtype vtype)
{
	struct silofs_vaddr vaddr;
	struct silofs_sbnode_info2 *sbi = nullptr;
	int err;

	err = silofs_curr_sbi2(task, &sbi);
	return_if_err(err);

	silofs_sbi2_apex_of(sbi, vtype, &vaddr);

	err = reload_apex_spnode_at(task, &vaddr);
	return_if_err(err);

	return 0;
}

static int reload_apex_spnodes(struct silofs_task_ctx *task)
{
	enum silofs_vtype vtype = SILOFS_VTYPE_NONE;
	int err;

	while (++vtype < SILOFS_VTYPE_LAST) {
		if (has_vspace_mapping(vtype)) {
			err = reload_apex_spnode_of(task, vtype);
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

	err = silofs_stage_inode_of(task, ino, SILOFS_STG_CUR, &ii);
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

	err = reload_pbs(task, pnptr);
	return_if_err(err);

	err = reload_vfs(task);
	return_if_err(err);

	return 0;
}
