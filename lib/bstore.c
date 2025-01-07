/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
#include <silofs/repo.h>
#include <silofs/pnodes.h>
#include <silofs/pcache.h>
#include <silofs/bstore.h>

static bool paddr_isbtnode(const struct silofs_paddr *paddr)
{
	return !paddr_isnull(paddr) && (paddr->ptype == SILOFS_PTYPE_BTNODE);
}

static bool paddr_isbtleaf(const struct silofs_paddr *paddr)
{
	return !paddr_isnull(paddr) && (paddr->ptype == SILOFS_PTYPE_BTLEAF);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void pvrange_init(struct silofs_pvrange *pvrange)
{
	silofs_pvid_generate(&pvrange->pvid);
	pvrange->base_index = 1;
	pvrange->curr_index = 1;
	pvrange->curr_pos = 0;
}

static void pvrange_fini(struct silofs_pvrange *pvrange)
{
	pvrange->base_index = 0;
	pvrange->curr_index = 0;
	pvrange->curr_pos = -1;
}

void silofs_pvrange_assign(struct silofs_pvrange *pvrange,
                           const struct silofs_pvrange *other)
{
	silofs_pvid_assign(&pvrange->pvid, &other->pvid);
	pvrange->base_index = other->base_index;
	pvrange->curr_index = other->curr_index;
	pvrange->curr_pos = other->curr_pos;
}

static void pvrange_curr_psid(const struct silofs_pvrange *pvrange,
                              struct silofs_psid *out_psid)
{
	silofs_psid_init(out_psid, &pvrange->pvid, pvrange->curr_index);
}

static void
pvrange_curr_paddr_at(const struct silofs_pvrange *pvrange, loff_t pos,
                      enum silofs_ptype ptype, struct silofs_paddr *out_paddr)
{
	struct silofs_psid psid;
	const size_t len = silofs_ptype_size(ptype);

	pvrange_curr_psid(pvrange, &psid);
	silofs_paddr_init(out_paddr, &psid, ptype, pos, len);
}

static void
pvrange_curr_paddr(const struct silofs_pvrange *pvrange,
                   enum silofs_ptype ptype, struct silofs_paddr *out_paddr)
{
	pvrange_curr_paddr_at(pvrange, pvrange->curr_pos, ptype, out_paddr);
}

static void
pvrange_last_paddr(const struct silofs_pvrange *pvrange,
                   enum silofs_ptype ptype, struct silofs_paddr *out_paddr)
{
	const loff_t off = pvrange->curr_pos;
	const ssize_t len = (ssize_t)silofs_ptype_size(ptype);
	const loff_t pos = (off > len) ? (off - len) : 0;

	pvrange_curr_paddr_at(pvrange, pos, ptype, out_paddr);
}

static void pvrange_advance_by(struct silofs_pvrange *pvrange,
                               const struct silofs_paddr *paddr)
{
	pvrange->curr_pos = off_end(paddr->off, paddr->len);
}

static void
pvrange_carve(struct silofs_pvrange *pvrange, enum silofs_ptype ptype,
              struct silofs_paddr *out_paddr)
{
	pvrange_curr_paddr(pvrange, ptype, out_paddr);
	pvrange_advance_by(pvrange, out_paddr);
}

static bool pvrange_has_pvid(const struct silofs_pvrange *pvrange,
                             const struct silofs_pvid *pvid)
{
	return silofs_pvid_isequal(&pvrange->pvid, pvid);
}

static bool
pvrange_has_index(const struct silofs_pvrange *pvrange, uint32_t idx)
{
	return (idx >= pvrange->base_index) && (idx <= pvrange->curr_index);
}

static bool pvrange_has_paddr(const struct silofs_pvrange *pvrange,
                              const struct silofs_paddr *paddr)
{
	if (paddr_isnull(paddr)) {
		return false;
	}
	if (!pvrange_has_pvid(pvrange, &paddr->psid.pvid)) {
		return false;
	}
	if (!pvrange_has_index(pvrange, paddr->psid.index)) {
		return false;
	}
	return true;
}

static int pvrange_check_valid(const struct silofs_pvrange *pvrange)
{
	if (pvrange->base_index > pvrange->curr_index) {
		return -SILOFS_EINVAL;
	}
	if (pvrange->base_index > (UINT32_MAX / 2)) {
		return -SILOFS_EINVAL;
	}
	if (off_isnull(pvrange->curr_pos)) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

static void pvrange_next_chkpt(struct silofs_pvrange *pvrange,
                               struct silofs_paddr *out_paddr)
{
	pvrange_carve(pvrange, SILOFS_PTYPE_CHKPT, out_paddr);
}

static void pvrange_last_chkpt(const struct silofs_pvrange *pvrange,
                               struct silofs_paddr *out_paddr)
{
	pvrange_last_paddr(pvrange, SILOFS_PTYPE_CHKPT, out_paddr);
}

static void pvrange_next_btnode(struct silofs_pvrange *pvrange,
                                struct silofs_paddr *out_paddr)
{
	silofs_assert_gt(pvrange->curr_pos, 0);

	pvrange_carve(pvrange, SILOFS_PTYPE_BTNODE, out_paddr);
}

void silofs_pvrange64b_htox(struct silofs_pvrange64b *pvrange64,
                            const struct silofs_pvrange *pvrange)
{
	memset(pvrange64, 0, sizeof(*pvrange64));
	silofs_pvid_assign(&pvrange64->pvid, &pvrange->pvid);
	pvrange64->base_index = silofs_cpu_to_le32(pvrange->base_index);
	pvrange64->curr_index = silofs_cpu_to_le32(pvrange->curr_index);
	pvrange64->curr_pos = silofs_cpu_to_off(pvrange->curr_pos);
}

void silofs_pvrange64b_xtoh(const struct silofs_pvrange64b *pvrange64,
                            struct silofs_pvrange *pvrange)
{
	silofs_pvid_assign(&pvrange->pvid, &pvrange64->pvid);
	pvrange->base_index = silofs_le32_to_cpu(pvrange64->base_index);
	pvrange->curr_index = silofs_le32_to_cpu(pvrange64->curr_index);
	pvrange->curr_pos = silofs_off_to_cpu(pvrange64->curr_pos);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_bstore_init(struct silofs_bstore *bstore, struct silofs_repo *repo)
{
	int err;

	pvrange_init(&bstore->pvrange);
	err = silofs_pcache_init(&bstore->pcache, repo->re.alloc);
	if (err) {
		return err;
	}
	silofs_btree_init(&bstore->btree, &bstore->pcache, repo);
	bstore->repo = repo;
	return 0;
}

void silofs_bstore_fini(struct silofs_bstore *bstore)
{
	silofs_btree_fini(&bstore->btree);
	silofs_pcache_drop(&bstore->pcache);
	silofs_pcache_fini(&bstore->pcache);
	pvrange_fini(&bstore->pvrange);
	bstore->repo = NULL;
}

static int bstore_validate_paddr(const struct silofs_bstore *bstore,
                                 const struct silofs_paddr *paddr)
{
	return pvrange_has_paddr(&bstore->pvrange, paddr) ? 0 : -SILOFS_EINVAL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_paddr *
cpi_paddr(const struct silofs_chkpt_info *cpi)
{
	return &cpi->cp_pni.pn_paddr;
}

static int bstore_save_chkpt(const struct silofs_bstore *bstore,
                             const struct silofs_chkpt_info *cpi)
{
	const struct silofs_rovec rov = {
		.rov_base = cpi->cp,
		.rov_len = sizeof(*cpi->cp),
	};

	return silofs_repo_save_pobj(bstore->repo, cpi_paddr(cpi), &rov);
}

static int bstore_load_chkpt(const struct silofs_bstore *bstore,
                             const struct silofs_chkpt_info *cpi)
{
	const struct silofs_rwvec rwv = {
		.rwv_base = cpi->cp,
		.rwv_len = sizeof(*cpi->cp),
	};

	return silofs_repo_load_pobj(bstore->repo, cpi_paddr(cpi), &rwv);
}

static int bstore_commit_chkpt(const struct silofs_bstore *bstore,
                               struct silofs_chkpt_info *cpi)
{
	int err;

	err = bstore_save_chkpt(bstore, cpi);
	if (err) {
		return err;
	}
	silofs_cpi_undirtify(cpi);
	return 0;
}

static int bstore_create_cached_cpi(struct silofs_bstore *bstore,
                                    const struct silofs_paddr *paddr,
                                    struct silofs_chkpt_info **out_cpi)
{
	struct silofs_chkpt_info *cpi;

	cpi = silofs_pcache_create_cpi(&bstore->pcache, paddr);
	if (cpi == NULL) {
		return -SILOFS_ENOMEM;
	}
	*out_cpi = cpi;
	return 0;
}

static int bstore_require_pseg(struct silofs_bstore *bstore, bool create,
                               const struct silofs_psid *psid)

{
	int err;

	if (create) {
		err = silofs_repo_create_pseg(bstore->repo, psid);
	} else {
		err = silofs_repo_stage_pseg(bstore->repo, psid);
	}
	return err;
}

static int bstore_require_pseg_of(struct silofs_bstore *bstore, bool create,
                                  const struct silofs_paddr *paddr)
{
	return bstore_require_pseg(bstore, create, &paddr->psid);
}

static void bstore_update_chkpt(const struct silofs_bstore *bstore,
                                struct silofs_chkpt_info *cpi)
{
	const struct silofs_btree *btree = &bstore->btree;

	silofs_cpi_set_btree_root(cpi, &btree->bt_root);
}

static int bstore_spawn_chkpt(struct silofs_bstore *bstore, bool create,
                              const struct silofs_paddr *paddr,
                              struct silofs_chkpt_info **out_cpi)
{
	int err;

	err = bstore_require_pseg_of(bstore, create, paddr);
	if (err) {
		return err;
	}
	err = bstore_create_cached_cpi(bstore, paddr, out_cpi);
	if (err) {
		return err;
	}
	bstore_update_chkpt(bstore, *out_cpi);
	return 0;
}

static void bstore_evict_cached_cpi(struct silofs_bstore *bstore,
                                    struct silofs_chkpt_info *cpi)
{
	silofs_pcache_evict_cpi(&bstore->pcache, cpi);
}

static int bstore_lookup_cached_chkpt(struct silofs_bstore *bstore,
                                      const struct silofs_paddr *paddr,
                                      struct silofs_chkpt_info **out_cpi)
{
	*out_cpi = silofs_pcache_lookup_cpi(&bstore->pcache, paddr);
	return (*out_cpi == NULL) ? -SILOFS_ENOENT : 0;
}

static int bstore_stage_chkpt(struct silofs_bstore *bstore,
                              const struct silofs_paddr *paddr,
                              struct silofs_chkpt_info **out_cpi)
{
	struct silofs_chkpt_info *cpi = NULL;
	int err;

	err = bstore_lookup_cached_chkpt(bstore, paddr, out_cpi);
	if (!err) {
		return 0; /* cache hit */
	}
	err = bstore_validate_paddr(bstore, paddr);
	if (err) {
		return err;
	}
	err = bstore_require_pseg_of(bstore, false, paddr);
	if (err) {
		return err;
	}
	err = bstore_create_cached_cpi(bstore, paddr, &cpi);
	if (err) {
		return err;
	}
	err = bstore_load_chkpt(bstore, cpi);
	if (err) {
		bstore_evict_cached_cpi(bstore, cpi);
		return err;
	}
	*out_cpi = cpi;
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_paddr *
bni_paddr(const struct silofs_btnode_info *bni)
{
	return &bni->bn_pni.pn_paddr;
}

static int bstore_save_btnode(const struct silofs_bstore *bstore,
                              const struct silofs_btnode_info *bni)
{
	const struct silofs_rovec rov = {
		.rov_base = bni->bn,
		.rov_len = sizeof(*bni->bn),
	};

	return silofs_repo_save_pobj(bstore->repo, bni_paddr(bni), &rov);
}

static int bstore_load_btnode(const struct silofs_bstore *bstore,
                              const struct silofs_btnode_info *bni)
{
	const struct silofs_rwvec rwv = {
		.rwv_base = bni->bn,
		.rwv_len = sizeof(*bni->bn),
	};

	return silofs_repo_load_pobj(bstore->repo, bni_paddr(bni), &rwv);
}

static int bstore_commit_btnode(const struct silofs_bstore *bstore,
                                struct silofs_btnode_info *bni)
{
	int err;

	err = bstore_save_btnode(bstore, bni);
	if (err) {
		return err;
	}
	silofs_bni_undirtify(bni);
	return 0;
}

static int bstore_create_cached_bni(struct silofs_bstore *bstore,
                                    const struct silofs_paddr *paddr,
                                    struct silofs_btnode_info **out_bni)
{
	struct silofs_btnode_info *bni;

	bni = silofs_pcache_create_bni(&bstore->pcache, paddr);
	if (bni == NULL) {
		return -SILOFS_ENOMEM;
	}
	*out_bni = bni;
	return 0;
}

static int bstore_spawn_btnode(struct silofs_bstore *bstore, bool create,
                               const struct silofs_paddr *paddr,
                               struct silofs_btnode_info **out_bni)
{
	int err;

	silofs_assert_eq(paddr->ptype, SILOFS_PTYPE_BTNODE);

	err = bstore_require_pseg_of(bstore, create, paddr);
	if (err) {
		return err;
	}
	err = bstore_create_cached_bni(bstore, paddr, out_bni);
	if (err) {
		return err;
	}
	silofs_bni_dirtify(*out_bni);
	return 0;
}

static int bstore_create_btroot_at(struct silofs_bstore *bstore,
                                   const struct silofs_paddr *paddr)
{
	struct silofs_btnode_info *bni = NULL;
	int err;

	err = bstore_spawn_btnode(bstore, false, paddr, &bni);
	if (err) {
		return err;
	}
	silofs_bni_mark_root(bni);
	return 0;
}

static int bstore_spawn_btroot(struct silofs_bstore *bstore)
{
	struct silofs_paddr paddr;
	int err;

	pvrange_next_btnode(&bstore->pvrange, &paddr);
	err = bstore_create_btroot_at(bstore, &paddr);
	if (err) {
		return err;
	}

	return 0;
}

static void bstore_evict_cached_bni(struct silofs_bstore *bstore,
                                    struct silofs_btnode_info *bni)
{
	silofs_pcache_evict_bni(&bstore->pcache, bni);
}

static int bstore_lookup_cached_btnode(struct silofs_bstore *bstore,
                                       const struct silofs_paddr *paddr,
                                       struct silofs_btnode_info **out_bni)
{
	*out_bni = silofs_pcache_lookup_bni(&bstore->pcache, paddr);
	return (*out_bni == NULL) ? -SILOFS_ENOENT : 0;
}

static int bstore_stage_btnode_at(struct silofs_bstore *bstore,
                                  const struct silofs_paddr *paddr,
                                  struct silofs_btnode_info **out_bni)
{
	struct silofs_btnode_info *bni = NULL;
	int err;

	silofs_assert_eq(paddr->ptype, SILOFS_PTYPE_BTNODE);

	err = bstore_lookup_cached_btnode(bstore, paddr, out_bni);
	if (!err) {
		return 0; /* cache hit */
	}
	err = bstore_validate_paddr(bstore, paddr);
	if (err) {
		return err;
	}
	err = bstore_require_pseg_of(bstore, false, paddr);
	if (err) {
		return err;
	}
	err = bstore_create_cached_bni(bstore, paddr, &bni);
	if (err) {
		return err;
	}
	err = bstore_load_btnode(bstore, bni);
	if (err) {
		bstore_evict_cached_bni(bstore, bni);
		return err;
	}
	*out_bni = bni;
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_paddr *
bli_paddr(const struct silofs_btleaf_info *bli)
{
	return &bli->bl_pni.pn_paddr;
}

static int bstore_save_btleaf(const struct silofs_bstore *bstore,
                              const struct silofs_btleaf_info *bli)
{
	const struct silofs_rovec rov = {
		.rov_base = bli->bl,
		.rov_len = sizeof(*bli->bl),
	};

	return silofs_repo_save_pobj(bstore->repo, bli_paddr(bli), &rov);
}

static int bstore_load_btleaf(const struct silofs_bstore *bstore,
                              const struct silofs_btleaf_info *bli)
{
	const struct silofs_rwvec rwv = {
		.rwv_base = bli->bl,
		.rwv_len = sizeof(*bli->bl),
	};

	return silofs_repo_load_pobj(bstore->repo, bli_paddr(bli), &rwv);
}

static int bstore_commit_btleaf(const struct silofs_bstore *bstore,
                                struct silofs_btleaf_info *bli)
{
	int err;

	err = bstore_save_btleaf(bstore, bli);
	if (err) {
		return err;
	}
	silofs_bli_undirtify(bli);
	return 0;
}

static int bstore_create_cached_bli(struct silofs_bstore *bstore,
                                    const struct silofs_paddr *paddr,
                                    struct silofs_btleaf_info **out_bli)
{
	struct silofs_btleaf_info *bli;

	bli = silofs_pcache_create_bli(&bstore->pcache, paddr);
	if (bli == NULL) {
		return -SILOFS_ENOMEM;
	}
	*out_bli = bli;
	return 0;
}

static void bstore_evict_cached_bli(struct silofs_bstore *bstore,
                                    struct silofs_btleaf_info *bli)
{
	silofs_pcache_evict_bli(&bstore->pcache, bli);
}

static int bstore_stage_btleaf_at(struct silofs_bstore *bstore,
                                  const struct silofs_paddr *paddr,
                                  struct silofs_btleaf_info **out_bli)
{
	struct silofs_btleaf_info *bli = NULL;
	int err;

	silofs_assert_eq(paddr->ptype, SILOFS_PTYPE_BTLEAF);

	err = bstore_validate_paddr(bstore, paddr);
	if (err) {
		return err;
	}
	err = bstore_require_pseg_of(bstore, false, paddr);
	if (err) {
		return err;
	}
	err = bstore_create_cached_bli(bstore, paddr, &bli);
	if (err) {
		return err;
	}
	err = bstore_load_btleaf(bstore, bli);
	if (err) {
		bstore_evict_cached_bli(bstore, bli);
		return err;
	}
	*out_bli = bli;
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int bstore_spawn_next_chkpt(struct silofs_bstore *bstore)
{
	struct silofs_paddr paddr;
	struct silofs_chkpt_info *cpi = NULL;

	pvrange_next_chkpt(&bstore->pvrange, &paddr);
	return bstore_spawn_chkpt(bstore, paddr.off == 0, &paddr, &cpi);
}

int silofs_bstore_format(struct silofs_bstore *bstore)
{
	int err;

	err = bstore_spawn_next_chkpt(bstore);
	if (err) {
		return err;
	}
	err = bstore_spawn_btroot(bstore);
	if (err) {
		return err;
	}
	err = bstore_spawn_next_chkpt(bstore);
	if (err) {
		return err;
	}
	err = silofs_bstore_flush_dirty(bstore);
	if (err) {
		return err;
	}
	return 0;
}

static int bstore_update_btree_root_by(struct silofs_bstore *bstore,
                                       const struct silofs_chkpt_info *cpi)
{
	struct silofs_paddr btree_root;

	silofs_cpi_btree_root(cpi, &btree_root);
	if (btree_root.ptype != SILOFS_PTYPE_BTNODE) {
		return -SILOFS_EFSCORRUPTED;
	}
	(void)bstore;
	return 0;
}

static int bstore_stage_last_chkpt(struct silofs_bstore *bstore)
{
	struct silofs_paddr paddr;
	struct silofs_chkpt_info *cpi = NULL;
	int err;

	pvrange_last_chkpt(&bstore->pvrange, &paddr);
	err = bstore_stage_chkpt(bstore, &paddr, &cpi);
	if (err) {
		return err;
	}
	err = bstore_update_btree_root_by(bstore, cpi);
	if (err) {
		return err;
	}
	return 0;
}

static int bstore_stage_btnode_childs(struct silofs_bstore *bstore,
                                      const struct silofs_btnode_info *bni)
{
	struct silofs_paddr paddr;
	struct silofs_btnode_info *child_bni = NULL;
	struct silofs_btleaf_info *child_bli = NULL;
	size_t nchilds;
	int err = 0;

	nchilds = silofs_bni_nchilds(bni);
	for (size_t slot = 0; (slot < nchilds) && !err; ++slot) {
		silofs_bni_child_at(bni, slot, &paddr);
		if (paddr_isbtnode(&paddr)) {
			child_bni = NULL;
			err = bstore_stage_btnode_at(bstore, &paddr,
			                             &child_bni);
		} else if (paddr_isbtleaf(&paddr)) {
			child_bli = NULL;
			err = bstore_stage_btleaf_at(bstore, &paddr,
			                             &child_bli);
		} else {
			err = -SILOFS_EFSCORRUPTED;
		}
	}
	return err;
}

static int validate_btroot(const struct silofs_btnode_info *bni)
{
	struct silofs_paddr paddr;
	size_t height;

	height = silofs_bni_height(bni);
	if ((height < 1) || (height > 8)) {
		return -SILOFS_EFSCORRUPTED;
	}
	silofs_bni_parent(bni, &paddr);
	if (!paddr_isnull(&paddr)) {
		return -SILOFS_EFSCORRUPTED;
	}
	if (!silofs_bni_marked_root(bni)) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int bstore_stage_btroot(struct silofs_bstore *bstore,
                               struct silofs_btnode_info **out_bni)
{
	struct silofs_paddr paddr = { .off = -1 };
	struct silofs_btnode_info *bni = NULL;
	int err;

	err = bstore_stage_btnode_at(bstore, &paddr, &bni);
	if (err) {
		return err;
	}
	err = validate_btroot(bni);
	if (err) {
		return err;
	}
	*out_bni = bni;
	return 0;
}

static int bstore_reload_btree_root(struct silofs_bstore *bstore)
{
	struct silofs_btnode_info *bni = NULL;
	int err;

	err = bstore_stage_btroot(bstore, &bni);
	if (err) {
		return err;
	}
	err = bstore_stage_btnode_childs(bstore, bni);
	if (err) {
		return err;
	}
	return 0;
}

static int bstore_assign_pvrange(struct silofs_bstore *bstore,
                                 const struct silofs_pvrange *pvrange)
{
	int err;

	err = pvrange_check_valid(pvrange);
	if (err) {
		return err;
	}
	silofs_pvrange_assign(&bstore->pvrange, pvrange);
	return 0;
}

int silofs_bstore_reload(struct silofs_bstore *bstore,
                         const struct silofs_pvrange *pvrange)
{
	int err;

	err = bstore_assign_pvrange(bstore, pvrange);
	if (err) {
		return err;
	}
	err = bstore_stage_last_chkpt(bstore);
	if (err) {
		return err;
	}
	err = bstore_reload_btree_root(bstore);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_bstore_close(struct silofs_bstore *bstore)
{
	int err;

	err = silofs_bstore_flush_dirty(bstore);
	if (err) {
		return err;
	}
	silofs_pcache_drop(&bstore->pcache);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int bstore_commit_pnode(struct silofs_bstore *bstore,
                               struct silofs_pnode_info *pni)
{
	const enum silofs_ptype ptype = silofs_pni_ptype(pni);
	int ret = -SILOFS_EINVAL;

	switch (ptype) {
	case SILOFS_PTYPE_CHKPT:
		ret = bstore_commit_chkpt(bstore, silofs_cpi_from_pni(pni));
		break;
	case SILOFS_PTYPE_BTNODE:
		ret = bstore_commit_btnode(bstore, silofs_bni_from_pni(pni));
		break;
	case SILOFS_PTYPE_BTLEAF:
		ret = bstore_commit_btleaf(bstore, silofs_bli_from_pni(pni));
		break;
	case SILOFS_PTYPE_NONE:
	case SILOFS_PTYPE_DATA:
	case SILOFS_PTYPE_LAST:
	default:
		silofs_panic("bad commit: ptype=%d", (int)ptype);
		break;
	}
	return ret;
}

static struct silofs_pnode_info *
bstore_dirtyq_front(const struct silofs_bstore *bstore)
{
	return silofs_pcache_dq_front(&bstore->pcache);
}

static void bstore_drop_dirty(struct silofs_bstore *bstore)
{
	struct silofs_pnode_info *pni;

	pni = bstore_dirtyq_front(bstore);
	while (pni != NULL) {
		silofs_pni_undirtify(pni);
		pni = bstore_dirtyq_front(bstore);
	}
}

int silofs_bstore_flush_dirty(struct silofs_bstore *bstore)
{
	struct silofs_pnode_info *pni;
	int err;

	pni = bstore_dirtyq_front(bstore);
	while (pni != NULL) {
		err = bstore_commit_pnode(bstore, pni);
		if (err) {
			return err;
		}
		pni = bstore_dirtyq_front(bstore);
	}
	return 0;
}

int silofs_bstore_dropall(struct silofs_bstore *bstore)
{
	bstore_drop_dirty(bstore);
	silofs_pcache_drop(&bstore->pcache);
	return 0;
}

void silofs_bstore_curr_pvrange(const struct silofs_bstore *bstore,
                                struct silofs_pvrange *out_pvrange)
{
	silofs_pvrange_assign(out_pvrange, &bstore->pvrange);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int validate_child_btnode(const struct silofs_btnode_info *parent_bni,
                                 const struct silofs_btnode_info *child_bni)
{
	struct silofs_paddr parent_paddr;
	const size_t parent_height = silofs_bni_height(parent_bni);
	const size_t child_height = silofs_bni_height(child_bni);

	if ((child_height + 1) != parent_height) {
		return -SILOFS_EFSCORRUPTED;
	}
	silofs_bni_parent(child_bni, &parent_paddr);
	if (!paddr_isequal(&parent_paddr, bni_paddr(parent_bni))) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int bstore_stage_child_btnode(struct silofs_bstore *bstore,
                                     struct silofs_btnode_info *parent_bni,
                                     const struct silofs_vaddr *vaddr,
                                     struct silofs_btnode_info **out_bni)
{
	struct silofs_paddr paddr = { .off = -1 };
	struct silofs_btnode_info *bni = NULL;
	int err;

	err = silofs_bni_resolve(parent_bni, vaddr, &paddr);
	if (err) {
		return err;
	}
	err = bstore_stage_btnode_at(bstore, &paddr, &bni);
	if (err) {
		return err;
	}
	err = validate_child_btnode(parent_bni, bni);
	if (err) {
		return err;
	}
	*out_bni = bni;
	return 0;
}

static int validate_child_btleaf(const struct silofs_btnode_info *parent_bni,
                                 const struct silofs_btleaf_info *child_bli)
{
	struct silofs_paddr parent_paddr;
	const size_t parent_height = silofs_bni_height(parent_bni);

	silofs_assert_eq(parent_height, 1);
	if (parent_height != 1) {
		return -SILOFS_EFSCORRUPTED;
	}
	silofs_bli_parent(child_bli, &parent_paddr);
	if (!paddr_isequal(&parent_paddr, bni_paddr(parent_bni))) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int bstore_stage_child_btleaf(struct silofs_bstore *bstore,
                                     struct silofs_btnode_info *parent_bni,
                                     const struct silofs_vaddr *vaddr,
                                     struct silofs_btleaf_info **out_bli)
{
	struct silofs_paddr paddr = { .off = -1 };
	struct silofs_btleaf_info *bli = NULL;
	int err;

	err = silofs_bni_resolve(parent_bni, vaddr, &paddr);
	if (err) {
		return err;
	}
	err = bstore_stage_btleaf_at(bstore, &paddr, &bli);
	if (err) {
		return err;
	}
	err = validate_child_btleaf(parent_bni, bli);
	if (err) {
		return err;
	}
	*out_bli = bli;
	return 0;
}

static int bstore_stage_btleaf(struct silofs_bstore *bstore,
                               struct silofs_btnode_info *root_bni,
                               const struct silofs_vaddr *vaddr,
                               struct silofs_btleaf_info **out_bli)
{
	struct silofs_btnode_info *bni = root_bni;
	struct silofs_btleaf_info *bli = NULL;
	size_t height;
	int err = 0;

	height = silofs_bni_height(bni);
	while (height > 1) {
		err = bstore_stage_child_btnode(bstore, bni, vaddr, &bni);
		if (err) {
			return err;
		}
		height--;
	}
	err = bstore_stage_child_btleaf(bstore, bni, vaddr, &bli);
	if (err) {
		return err;
	}
	*out_bli = bli;
	return 0;
}

static int bstore_resolve_btleaf_of(struct silofs_bstore *bstore,
                                    const struct silofs_vaddr *vaddr,
                                    struct silofs_btleaf_info **out_bli)
{
	struct silofs_btnode_info *root_bni = NULL;
	int err;

	err = bstore_stage_btroot(bstore, &root_bni);
	if (err) {
		return err;
	}
	err = bstore_stage_btleaf(bstore, root_bni, vaddr, out_bli);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_bstore_resolve(struct silofs_bstore *bstore,
                          const struct silofs_vaddr *vaddr,
                          struct silofs_paddr *out_paddr)
{
	struct silofs_btleaf_info *bli = NULL;
	int err;

	err = bstore_resolve_btleaf_of(bstore, vaddr, &bli);
	if (err) {
		return err;
	}
	err = silofs_bli_resolve(bli, vaddr, out_paddr);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int bstore_require_child_btnode(struct silofs_bstore *bstore,
                                       struct silofs_btnode_info *parent_bni,
                                       const struct silofs_vaddr *vaddr,
                                       struct silofs_btnode_info **out_bni)
{
	int err;

	err = bstore_stage_child_btnode(bstore, parent_bni, vaddr, out_bni);
	if (!err) {
		return 0;
	}
	if (err != -SILOFS_ENOENT) {
		return err;
	}
	/* XXX */

	return 0;
}

static int bstore_require_btleaf(struct silofs_bstore *bstore,
                                 struct silofs_btnode_info *root_bni,
                                 const struct silofs_vaddr *vaddr,
                                 struct silofs_btleaf_info **out_bli)
{
	struct silofs_btnode_info *bni = root_bni;
	struct silofs_btleaf_info *bli = NULL;
	size_t height;
	int err = 0;

	height = silofs_bni_height(bni);
	while (height > 1) {
		err = bstore_require_child_btnode(bstore, bni, vaddr, &bni);
		if (err) {
			return err;
		}
		height--;
	}
	err = bstore_stage_child_btleaf(bstore, bni, vaddr, &bli);
	if (err) {
		return err;
	}
	*out_bli = bli;
	return 0;
}

static int bstore_require_btleaf_of(struct silofs_bstore *bstore,
                                    const struct silofs_vaddr *vaddr,
                                    struct silofs_btleaf_info **out_bli)
{
	struct silofs_btnode_info *root_bni = NULL;
	int err;

	err = bstore_resolve_btleaf_of(bstore, vaddr, out_bli);
	if (!err || (err != -SILOFS_ENOENT)) {
		return err;
	}
	err = bstore_stage_btroot(bstore, &root_bni);
	if (err) {
		return err;
	}
	err = bstore_require_btleaf(bstore, root_bni, vaddr, out_bli);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_bstore_remap(struct silofs_bstore *bstore,
                        const struct silofs_vaddr *vaddr,
                        const struct silofs_paddr *paddr)
{
	struct silofs_btleaf_info *bli = NULL;
	int err;

	err = bstore_require_btleaf_of(bstore, vaddr, &bli);
	if (err) {
		return err;
	}
	err = silofs_bli_extend(bli, vaddr, paddr);
	if (err) {
		return err;
	}
	return err;
}
