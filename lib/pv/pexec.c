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
	if (err) {
		return err;
	}
	err = silofs_spawn_uber(pexec, &pnptr, &ubi);
	if (err) {
		return err;
	}
	update_active_uber(pexec, ubi);
	return 0;
}

static void
fixup_spawned_btroot(struct silofs_btnode_info *bti, enum silofs_vtype vtype)
{
	silofs_bti_set_vspace(bti, vtype);
	silofs_bti_mark_root(bti);
}

static int
spawn_btroot_of(struct silofs_pexec_ctx *pexec, enum silofs_vtype vtype,
                struct silofs_btnode_info **out_bti)
{
	struct silofs_pnptr pnptr = {};
	int err;

	err = silofs_carve_base_btspace(pexec, vtype, &pnptr);
	if (err) {
		return err;
	}
	err = silofs_spawn_btnode(pexec, &pnptr, out_bti);
	if (err) {
		return err;
	}
	fixup_spawned_btroot(*out_bti, vtype);
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
	if (err) {
		return err;
	}
	update_formatted_btroot(pexec, bti);
	return 0;
}

static int
format_vspace_root_of(struct silofs_pexec_ctx *pexec, enum silofs_vtype vtype)
{
	struct silofs_paddr paddr = {};
	int err;

	err = silofs_carve_base_vspace(pexec, vtype, &paddr);
	if (err) {
		return err;
	}
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
		if (err) {
			return err;
		}
		err = format_vspace_root_of(pexec, vtype);
		if (err) {
			return err;
		}
	}
	return silofs_destage_dirty(pexec);
}

static int
format_space_node_of(struct silofs_pexec_ctx *pexec, enum silofs_vtype vtype)
{
	struct silofs_vaddr ref_vaddr;
	struct silofs_space_info *spi;

	silofs_vaddr_setup(&ref_vaddr, vtype, 0);
	return silofs_spawn_spnode2_of(pexec, &ref_vaddr, &spi);
}

static int
format_zero_node_of(struct silofs_pexec_ctx *pexec, enum silofs_vtype vtype)
{
	struct silofs_vaddr vaddr;
	struct silofs_space_info *spi = nullptr;
	struct silofs_vnode_info *vni = nullptr;
	int err;

	silofs_vaddr_setup(&vaddr, vtype, 0);
	err = silofs_stage_spnode2_of(pexec, &vaddr, &spi);
	if (err) {
		return err;
	}
	err = silofs_spi_find_free(spi, &vaddr);
	if (err) {
		return err;
	}
	silofs_assert_eq(vaddr.off, 0);

	err = silofs_spawn_vnode2_at(pexec, &vaddr, &vni);
	if (err) {
		return err;
	}
	silofs_spi_inc_allocated(spi, &vaddr);
	return 0;
}

static int format_vspace_nodes(struct silofs_pexec_ctx *pexec)
{
	enum silofs_vtype vtype = SILOFS_VTYPE_NONE;
	int err;

	while (++vtype < SILOFS_VTYPE_LAST) {
		if (!silofs_vtype_isvnode(vtype) ||
		    (vtype == SILOFS_VTYPE_SPNODE2)) {
			continue;
		}
		err = format_space_node_of(pexec, vtype);
		if (err) {
			return err;
		}
		err = format_zero_node_of(pexec, vtype);
		if (err) {
			return err;
		}
	}
	return silofs_destage_dirty(pexec);
}

static int format_vspace(struct silofs_pexec_ctx *pexec)
{
	int err;

	err = format_vspace_roots(pexec);
	if (err) {
		return err;
	}
	err = format_vspace_nodes(pexec);
	if (err) {
		return err;
	}
	return 0;
}

static void resolve_uber(const struct silofs_pexec_ctx *pexec,
                         struct silofs_pnptr *out_pnptr)
{
	const struct silofs_uber_info *ubi = pexec->ubref->ubi;

	silofs_pnptr_assign(out_pnptr, silofs_pni_self(&ubi->ub_pni));
}

int silofs_format_pv(struct silofs_pexec_ctx *pexec,
                     struct silofs_pnptr *out_pnptr)
{
	int err;

	err = format_uber(pexec);
	if (err) {
		return err;
	}
	err = format_vspace(pexec);
	if (err) {
		return err;
	}
	resolve_uber(pexec, out_pnptr);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
reload_uber(struct silofs_pexec_ctx *pexec, const struct silofs_pnptr *pnptr)
{
	struct silofs_uber_info *ubi = nullptr;
	int err;

	err = silofs_stage_uber(pexec, pnptr, &ubi);
	if (err) {
		return err;
	}
	update_active_uber(pexec, ubi);
	return 0;
}

static int
reload_btree_root_of(struct silofs_pexec_ctx *pexec, enum silofs_vtype vtype)
{
	struct silofs_btnptr btnptr    = {};
	struct silofs_btnode_info *bti = nullptr;
	int err;

	silofs_ubi_btroot_of(pexec->ubref->ubi, vtype, &btnptr);
	if (silofs_btnptr_isnull(&btnptr)) {
		log_dbg("missing btree root: vtype=%d", vtype);
		return -SILOFS_EFSCORRUPTED;
	}
	err = silofs_stage_btnode(pexec, &btnptr.base, &bti);
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
		if (err) {
			return err;
		}
	}
	return 0;
}

static int
reload_zero_node_of(struct silofs_pexec_ctx *pexec, enum silofs_vtype vtype)
{
	struct silofs_vaddr vaddr;
	struct silofs_space_info *spi = nullptr;
	struct silofs_vnode_info *vni = nullptr;
	size_t nalloc;
	int err;

	silofs_vaddr_setup(&vaddr, vtype, 0);
	err = silofs_stage_spnode2_of(pexec, &vaddr, &spi);
	if (err) {
		return err;
	}
	nalloc = silofs_spi_get_allocated(spi, &vaddr);
	if (!nalloc) {
		return -SILOFS_EFSCORRUPTED;
	}
	err = silofs_stage_vnode2_at(pexec, &vaddr, &vni);
	if (err) {
		return err;
	}
	return 0;
}

static int reload_vspace_nodes(struct silofs_pexec_ctx *pexec)
{
	enum silofs_vtype vtype = SILOFS_VTYPE_NONE;
	int err;

	while (++vtype < SILOFS_VTYPE_LAST) {
		if (!silofs_vtype_isvnode(vtype) ||
		    (vtype == SILOFS_VTYPE_SPNODE2)) {
			continue;
		}
		err = reload_zero_node_of(pexec, vtype);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int reload_vspace(struct silofs_pexec_ctx *pexec)
{
	int err;

	err = reload_vspace_roots(pexec);
	if (err) {
		return err;
	}
	err = reload_vspace_nodes(pexec);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_reload_pv(struct silofs_pexec_ctx *pexec,
                     const struct silofs_pnptr *pnptr)
{
	int err;

	err = reload_uber(pexec, pnptr);
	if (err) {
		return err;
	}
	err = reload_vspace(pexec);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void vni_dirtify(struct silofs_vnode_info *vni)
{
	silofs_vni_dirtify(vni, nullptr);
}

int silofs_spawn_vnode2_at(struct silofs_pexec_ctx *pexec,
                           const struct silofs_vaddr *vaddr,
                           struct silofs_vnode_info **out_vni)
{
	struct silofs_pnptr pnptr = {};
	int err;

	err = silofs_carve_next_vspace(pexec, vaddr->vtype, &pnptr);
	if (err) {
		return err;
	}
	err = silofs_spawn_vnode2(pexec, vaddr, &pnptr, out_vni);
	if (err) {
		return err;
	}
	err = silofs_insert_vtop(pexec, vaddr, &pnptr);
	if (err) {
		return err;
	}
	vni_dirtify(*out_vni);
	return 0;
}

int silofs_stage_vnode2_at(struct silofs_pexec_ctx *pexec,
                           const struct silofs_vaddr *vaddr,
                           struct silofs_vnode_info **out_vni)
{
	struct silofs_pnptr pnptr;
	int err;

	err = silofs_resolve_vtop(pexec, vaddr, &pnptr);
	if (err) {
		return err;
	}
	err = silofs_stage_vnode2(pexec, vaddr, &pnptr, out_vni);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int silofs_spawn_spnode2(struct silofs_pexec_ctx *pexec,
                                const struct silofs_vaddr *vaddr,
                                const struct silofs_vaddr *ref_vaddr,
                                struct silofs_space_info **out_spi)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

	err = silofs_spawn_vnode2_at(pexec, vaddr, &vni);
	if (err) {
		return err;
	}
	*out_spi = silofs_spi_from_vni(vni);
	silofs_spi_setup_spawned(*out_spi, ref_vaddr);
	return 0;
}

int silofs_spawn_spnode2_of(struct silofs_pexec_ctx *pexec,
                            const struct silofs_vaddr *ref_vaddr,
                            struct silofs_space_info **out_spi)
{
	struct silofs_vaddr vaddr;

	silofs_vaddr_of_spnode2(ref_vaddr, &vaddr);
	return silofs_spawn_spnode2(pexec, &vaddr, ref_vaddr, out_spi);
}

static int silofs_stage_spnode2(struct silofs_pexec_ctx *pexec,
                                const struct silofs_vaddr *vaddr,
                                struct silofs_space_info **out_spi)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

	err = silofs_stage_vnode2_at(pexec, vaddr, &vni);
	if (err) {
		return err;
	}
	*out_spi = silofs_spi_from_vni(vni);
	silofs_spi_setup_staged(*out_spi);
	return 0;
}

int silofs_stage_spnode2_of(struct silofs_pexec_ctx *pexec,
                            const struct silofs_vaddr *ref_vaddr,
                            struct silofs_space_info **out_spi)
{
	struct silofs_vaddr vaddr;

	silofs_vaddr_of_spnode2(ref_vaddr, &vaddr);
	return silofs_stage_spnode2(pexec, &vaddr, out_spi);
}
