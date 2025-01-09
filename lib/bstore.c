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

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_bstore_init(struct silofs_bstore *bstore,
                       struct silofs_pcache *pcache, struct silofs_repo *repo)
{
	silofs_pvsegr_init(&bstore->pvsegr);
	silofs_btree_init(&bstore->btree, bstore->pcache, repo);
	bstore->repo = repo;
	bstore->pcache = pcache;
	return 0;
}

void silofs_bstore_fini(struct silofs_bstore *bstore)
{
	silofs_btree_fini(&bstore->btree);
	silofs_pvsegr_fini(&bstore->pvsegr);
	bstore->repo = NULL;
	bstore->pcache = NULL;
}

static int bstore_validate_paddr(const struct silofs_bstore *bstore,
                                 const struct silofs_paddr *paddr)
{
	const struct silofs_pvsegr *pvsegr = &bstore->pvsegr;

	return silofs_pvsegr_has_paddr(pvsegr, paddr) ? 0 : -SILOFS_EINVAL;
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

	cpi = silofs_pcache_create_cpi(bstore->pcache, paddr);
	if (cpi == NULL) {
		return -SILOFS_ENOMEM;
	}
	*out_cpi = cpi;
	return 0;
}

static int bstore_require_pvseg(struct silofs_bstore *bstore, bool create,
                                const struct silofs_pvsid *pvsid)

{
	int err;

	if (create) {
		err = silofs_repo_create_pvseg(bstore->repo, pvsid);
	} else {
		err = silofs_repo_stage_pvseg(bstore->repo, pvsid);
	}
	return err;
}

static int bstore_require_pvseg_of(struct silofs_bstore *bstore, bool create,
                                   const struct silofs_paddr *paddr)
{
	return bstore_require_pvseg(bstore, create, &paddr->pvsid);
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

	err = bstore_require_pvseg_of(bstore, create, paddr);
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
	silofs_pcache_evict_cpi(bstore->pcache, cpi);
}

static int bstore_lookup_cached_chkpt(struct silofs_bstore *bstore,
                                      const struct silofs_paddr *paddr,
                                      struct silofs_chkpt_info **out_cpi)
{
	*out_cpi = silofs_pcache_lookup_cpi(bstore->pcache, paddr);
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
	err = bstore_require_pvseg_of(bstore, false, paddr);
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

	bni = silofs_pcache_create_bni(bstore->pcache, paddr);
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

	err = bstore_require_pvseg_of(bstore, create, paddr);
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

	silofs_pvsegr_next_btnode(&bstore->pvsegr, &paddr);
	err = bstore_create_btroot_at(bstore, &paddr);
	if (err) {
		return err;
	}

	return 0;
}

static void bstore_evict_cached_bni(struct silofs_bstore *bstore,
                                    struct silofs_btnode_info *bni)
{
	silofs_pcache_evict_bni(bstore->pcache, bni);
}

static int bstore_lookup_cached_btnode(struct silofs_bstore *bstore,
                                       const struct silofs_paddr *paddr,
                                       struct silofs_btnode_info **out_bni)
{
	*out_bni = silofs_pcache_lookup_bni(bstore->pcache, paddr);
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
	err = bstore_require_pvseg_of(bstore, false, paddr);
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

	bli = silofs_pcache_create_bli(bstore->pcache, paddr);
	if (bli == NULL) {
		return -SILOFS_ENOMEM;
	}
	*out_bli = bli;
	return 0;
}

static void bstore_evict_cached_bli(struct silofs_bstore *bstore,
                                    struct silofs_btleaf_info *bli)
{
	silofs_pcache_evict_bli(bstore->pcache, bli);
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
	err = bstore_require_pvseg_of(bstore, false, paddr);
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

	silofs_pvsegr_next_chkpt(&bstore->pvsegr, &paddr);
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

	silofs_pvsegr_last_chkpt(&bstore->pvsegr, &paddr);
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

static int bstore_assign_pvsegr(struct silofs_bstore *bstore,
                                const struct silofs_pvsegr *pvsegr)
{
	int err;

	err = silofs_pvsegr_validate(pvsegr);
	if (err) {
		return err;
	}
	silofs_pvsegr_assign(&bstore->pvsegr, pvsegr);
	return 0;
}

int silofs_bstore_reload(struct silofs_bstore *bstore,
                         const struct silofs_pvsegr *pvsegr)
{
	int err;

	err = bstore_assign_pvsegr(bstore, pvsegr);
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
	silofs_pcache_drop(bstore->pcache);
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
	return silofs_pcache_dq_front(bstore->pcache);
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
	silofs_pcache_drop(bstore->pcache);
	return 0;
}

void silofs_bstore_curr_pvsegr(const struct silofs_bstore *bstore,
                               struct silofs_pvsegr *out_pvsegr)
{
	silofs_pvsegr_assign(out_pvsegr, &bstore->pvsegr);
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
