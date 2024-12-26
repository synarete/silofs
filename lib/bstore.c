/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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

static void prange_init(struct silofs_prange *prange)
{
	silofs_pvid_generate(&prange->pvid);
	prange->base_index = 1;
	prange->curr_index = 1;
	prange->pos_in_curr = 0;
}

static void prange_fini(struct silofs_prange *prange)
{
	prange->base_index = 0;
	prange->curr_index = 0;
	prange->pos_in_curr = -1;
}

void silofs_prange_assign(struct silofs_prange *prange,
                          const struct silofs_prange *other)
{
	silofs_pvid_assign(&prange->pvid, &other->pvid);
	prange->base_index = other->base_index;
	prange->curr_index = other->curr_index;
	prange->pos_in_curr = other->pos_in_curr;
}

static void prange_curr_psid(const struct silofs_prange *prange,
                             struct silofs_psid *out_psid)
{
	silofs_psid_init(out_psid, &prange->pvid, prange->curr_index);
}

static void
prange_curr_paddr_at(const struct silofs_prange *prange, loff_t pos,
                     enum silofs_ptype ptype, struct silofs_paddr *out_paddr)
{
	struct silofs_psid psid;
	const size_t len = silofs_ptype_size(ptype);

	prange_curr_psid(prange, &psid);
	silofs_paddr_init(out_paddr, &psid, ptype, pos, len);
}

static void
prange_curr_paddr(const struct silofs_prange *prange, enum silofs_ptype ptype,
                  struct silofs_paddr *out_paddr)
{
	prange_curr_paddr_at(prange, prange->pos_in_curr, ptype, out_paddr);
}

static void
prange_last_paddr(const struct silofs_prange *prange, enum silofs_ptype ptype,
                  struct silofs_paddr *out_paddr)
{
	const loff_t off = prange->pos_in_curr;
	const ssize_t len = (ssize_t)silofs_ptype_size(ptype);
	const loff_t pos = (off > len) ? (off - len) : 0;

	prange_curr_paddr_at(prange, pos, ptype, out_paddr);
}

static void prange_advance_by(struct silofs_prange *prange,
                              const struct silofs_paddr *paddr)
{
	prange->pos_in_curr = off_end(paddr->off, paddr->len);
}

static void prange_carve(struct silofs_prange *prange, enum silofs_ptype ptype,
                         struct silofs_paddr *out_paddr)
{
	prange_curr_paddr(prange, ptype, out_paddr);
	prange_advance_by(prange, out_paddr);
}

static bool prange_has_pvid(const struct silofs_prange *prange,
                            const struct silofs_pvid *pvid)
{
	return silofs_pvid_isequal(&prange->pvid, pvid);
}

static bool prange_has_index(const struct silofs_prange *prange, uint32_t idx)
{
	return (idx >= prange->base_index) && (idx <= prange->curr_index);
}

static bool prange_has_paddr(const struct silofs_prange *prange,
                             const struct silofs_paddr *paddr)
{
	if (!prange_has_pvid(prange, &paddr->psid.pvid)) {
		return false;
	}
	if (!prange_has_index(prange, paddr->psid.index)) {
		return false;
	}
	return true;
}

static int prange_check_valid(const struct silofs_prange *prange)
{
	if (prange->base_index > prange->curr_index) {
		return -SILOFS_EINVAL;
	}
	if (prange->base_index > (UINT32_MAX / 2)) {
		return -SILOFS_EINVAL;
	}
	if (off_isnull(prange->pos_in_curr)) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

void silofs_prange64b_htox(struct silofs_prange64b *prange64,
                           const struct silofs_prange *prange)
{
	memset(prange64, 0, sizeof(*prange64));
	silofs_pvid_assign(&prange64->pvid, &prange->pvid);
	prange64->base_index = silofs_cpu_to_le32(prange->base_index);
	prange64->curr_index = silofs_cpu_to_le32(prange->curr_index);
	prange64->pos_in_curr = silofs_cpu_to_off(prange->pos_in_curr);
}

void silofs_prange64b_xtoh(const struct silofs_prange64b *prange64,
                           struct silofs_prange *prange)
{
	silofs_pvid_assign(&prange->pvid, &prange64->pvid);
	prange->base_index = silofs_le32_to_cpu(prange64->base_index);
	prange->curr_index = silofs_le32_to_cpu(prange64->curr_index);
	prange->pos_in_curr = silofs_off_to_cpu(prange64->pos_in_curr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void bstate_init(struct silofs_bstate *bstate)
{
	prange_init(&bstate->prange);
	paddr_reset(&bstate->btree_root);
}

static void bstate_fini(struct silofs_bstate *bstate)
{
	prange_fini(&bstate->prange);
	paddr_reset(&bstate->btree_root);
}

static int bstate_assign_prange(struct silofs_bstate *bstate,
                                const struct silofs_prange *prange)
{
	int err;

	err = prange_check_valid(prange);
	if (err) {
		return err;
	}
	silofs_prange_assign(&bstate->prange, prange);
	return 0;
}

static void
bstate_next_chkpt(struct silofs_bstate *bstate, struct silofs_paddr *out_paddr)
{
	prange_carve(&bstate->prange, SILOFS_PTYPE_CHKPT, out_paddr);
}

static void bstate_last_chkpt(const struct silofs_bstate *bstate,
                              struct silofs_paddr *out_paddr)
{
	prange_last_paddr(&bstate->prange, SILOFS_PTYPE_CHKPT, out_paddr);
}

static void bstate_next_btnode(struct silofs_bstate *bstate,
                               struct silofs_paddr *out_paddr)
{
	struct silofs_prange *prange = &bstate->prange;

	silofs_assert_gt(prange->pos_in_curr, 0);

	prange_carve(prange, SILOFS_PTYPE_BTNODE, out_paddr);
}

static bool bstate_has_paddr(const struct silofs_bstate *bstate,
                             const struct silofs_paddr *paddr)
{
	bool ret = false;

	if (!paddr_isnull(paddr)) {
		ret = prange_has_paddr(&bstate->prange, paddr);
	}
	return ret;
}

static void bstate_btree_root(const struct silofs_bstate *bstate,
                              struct silofs_paddr *out_paddr)
{
	paddr_assign(out_paddr, &bstate->btree_root);
}

static void bstate_update_btree_root(struct silofs_bstate *bstate,
                                     const struct silofs_paddr *paddr)
{
	silofs_assert_eq(paddr->ptype, SILOFS_PTYPE_BTNODE);

	paddr_assign(&bstate->btree_root, paddr);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_bstore_init(struct silofs_bstore *bstore, struct silofs_repo *repo)
{
	bstate_init(&bstore->bstate);
	bstore->repo = repo;
	return silofs_pcache_init(&bstore->pcache, repo->re.alloc);
}

void silofs_bstore_fini(struct silofs_bstore *bstore)
{
	silofs_pcache_drop(&bstore->pcache);
	silofs_pcache_fini(&bstore->pcache);
	bstate_fini(&bstore->bstate);
	bstore->repo = NULL;
}

static void
bstore_bind_pni(struct silofs_bstore *bstore, struct silofs_pnode_info *pni)
{
	silofs_assert_null(pni->pn_bstore);

	pni->pn_bstore = bstore;
}

static int bstore_validate_paddr(const struct silofs_bstore *bstore,
                                 const struct silofs_paddr *paddr)
{
	return bstate_has_paddr(&bstore->bstate, paddr) ? 0 : -SILOFS_EINVAL;
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
	bstore_bind_pni(bstore, &cpi->cp_pni);
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
	struct silofs_paddr btree_root;

	bstate_btree_root(&bstore->bstate, &btree_root);
	silofs_cpi_set_btree_root(cpi, &btree_root);
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
bti_paddr(const struct silofs_btnode_info *bti)
{
	return &bti->bn_pni.pn_paddr;
}

static int bstore_save_btnode(const struct silofs_bstore *bstore,
                              const struct silofs_btnode_info *bti)
{
	const struct silofs_rovec rov = {
		.rov_base = bti->bn,
		.rov_len = sizeof(*bti->bn),
	};

	return silofs_repo_save_pobj(bstore->repo, bti_paddr(bti), &rov);
}

static int bstore_load_btnode(const struct silofs_bstore *bstore,
                              const struct silofs_btnode_info *bti)
{
	const struct silofs_rwvec rwv = {
		.rwv_base = bti->bn,
		.rwv_len = sizeof(*bti->bn),
	};

	return silofs_repo_load_pobj(bstore->repo, bti_paddr(bti), &rwv);
}

static int bstore_commit_btnode(const struct silofs_bstore *bstore,
                                struct silofs_btnode_info *bti)
{
	int err;

	err = bstore_save_btnode(bstore, bti);
	if (err) {
		return err;
	}
	silofs_bti_undirtify(bti);
	return 0;
}

static int bstore_create_cached_bti(struct silofs_bstore *bstore,
                                    const struct silofs_paddr *paddr,
                                    struct silofs_btnode_info **out_bti)
{
	struct silofs_btnode_info *bti;

	bti = silofs_pcache_create_bti(&bstore->pcache, paddr);
	if (bti == NULL) {
		return -SILOFS_ENOMEM;
	}
	bstore_bind_pni(bstore, &bti->bn_pni);
	*out_bti = bti;
	return 0;
}

static int bstore_create_btree_root_at(struct silofs_bstore *bstore,
                                       const struct silofs_paddr *paddr)
{
	struct silofs_btnode_info *bti = NULL;
	int err;

	err = bstore_create_cached_bti(bstore, paddr, &bti);
	if (err) {
		return err;
	}
	silofs_bti_mark_root(bti);
	return 0;
}

static int bstore_spawn_btree_root(struct silofs_bstore *bstore)
{
	struct silofs_paddr paddr;
	int err;

	bstate_next_btnode(&bstore->bstate, &paddr);
	err = bstore_require_pseg_of(bstore, false, &paddr);
	if (err) {
		return err;
	}
	err = bstore_create_btree_root_at(bstore, &paddr);
	if (err) {
		return err;
	}
	bstate_update_btree_root(&bstore->bstate, &paddr);
	return 0;
}

static void bstore_evict_cached_bti(struct silofs_bstore *bstore,
                                    struct silofs_btnode_info *bti)
{
	silofs_pcache_evict_bti(&bstore->pcache, bti);
}

static int bstore_lookup_cached_btnode(struct silofs_bstore *bstore,
                                       const struct silofs_paddr *paddr,
                                       struct silofs_btnode_info **out_bti)
{
	*out_bti = silofs_pcache_lookup_bti(&bstore->pcache, paddr);
	return (*out_bti == NULL) ? -SILOFS_ENOENT : 0;
}

static int bstore_stage_btnode(struct silofs_bstore *bstore,
                               const struct silofs_paddr *paddr,
                               struct silofs_btnode_info **out_bti)
{
	struct silofs_btnode_info *bti = NULL;
	int err;

	err = bstore_lookup_cached_btnode(bstore, paddr, out_bti);
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
	err = bstore_create_cached_bti(bstore, paddr, &bti);
	if (err) {
		return err;
	}
	err = bstore_load_btnode(bstore, bti);
	if (err) {
		bstore_evict_cached_bti(bstore, bti);
		return err;
	}
	*out_bti = bti;
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
	bstore_bind_pni(bstore, &bli->bl_pni);
	*out_bli = bli;
	return 0;
}

static void bstore_evict_cached_bli(struct silofs_bstore *bstore,
                                    struct silofs_btleaf_info *bli)
{
	silofs_pcache_evict_bli(&bstore->pcache, bli);
}

static int bstore_stage_btleaf(struct silofs_bstore *bstore,
                               const struct silofs_paddr *paddr,
                               struct silofs_btleaf_info **out_bli)
{
	struct silofs_btleaf_info *bli = NULL;
	int err;

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

	bstate_next_chkpt(&bstore->bstate, &paddr);
	return bstore_spawn_chkpt(bstore, paddr.off == 0, &paddr, &cpi);
}

int silofs_bstore_format(struct silofs_bstore *bstore)
{
	int err;

	err = bstore_spawn_next_chkpt(bstore);
	if (err) {
		return err;
	}
	err = bstore_spawn_btree_root(bstore);
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
	bstate_update_btree_root(&bstore->bstate, &btree_root);
	return 0;
}

static int bstore_stage_last_chkpt(struct silofs_bstore *bstore)
{
	struct silofs_paddr paddr;
	struct silofs_chkpt_info *cpi = NULL;
	int err;

	bstate_last_chkpt(&bstore->bstate, &paddr);
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

static int bstore_stage_btnode_at(struct silofs_bstore *bstore,
                                  const struct silofs_paddr *paddr)
{
	struct silofs_btnode_info *bti = NULL;

	return bstore_stage_btnode(bstore, paddr, &bti);
}

static int bstore_stage_btleaf_at(struct silofs_bstore *bstore,
                                  const struct silofs_paddr *paddr)
{
	struct silofs_btleaf_info *bli = NULL;

	return bstore_stage_btleaf(bstore, paddr, &bli);
}

static int bstore_stage_btnode_childs(struct silofs_bstore *bstore,
                                      const struct silofs_btnode_info *bti)
{
	struct silofs_paddr paddr;
	size_t nchilds;
	int err = 0;

	nchilds = silofs_bti_nchilds(bti);
	for (size_t slot = 0; (slot < nchilds) && !err; ++slot) {
		silofs_bti_child_at(bti, slot, &paddr);
		if (paddr_isbtnode(&paddr)) {
			err = bstore_stage_btnode_at(bstore, &paddr);
		} else if (paddr_isbtleaf(&paddr)) {
			err = bstore_stage_btleaf_at(bstore, &paddr);
		} else {
			err = -SILOFS_EFSCORRUPTED;
		}
	}
	return err;
}

static int bstore_stage_btree_root(struct silofs_bstore *bstore,
                                   struct silofs_btnode_info **out_bti)
{
	struct silofs_paddr paddr;

	bstate_btree_root(&bstore->bstate, &paddr);
	return bstore_stage_btnode(bstore, &paddr, out_bti);
}

static int bstore_reload_btree_root(struct silofs_bstore *bstore)
{
	struct silofs_btnode_info *bti = NULL;
	int err;

	err = bstore_stage_btree_root(bstore, &bti);
	if (err) {
		return err;
	}
	err = bstore_stage_btnode_childs(bstore, bti);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_bstore_reload(struct silofs_bstore *bstore,
                         const struct silofs_prange *prange)
{
	int err;

	err = bstate_assign_prange(&bstore->bstate, prange);
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
		ret = bstore_commit_btnode(bstore, silofs_bti_from_pni(pni));
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

void silofs_bstore_curr_prange(const struct silofs_bstore *bstore,
                               struct silofs_prange *out_prange)
{
	silofs_prange_assign(out_prange, &bstore->bstate.prange);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
