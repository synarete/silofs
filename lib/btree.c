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
#include <silofs/errors.h>
#include <silofs/defs.h>
#include <silofs/addr.h>
#include <silofs/repo.h>
#include <silofs/pnodes.h>
#include <silofs/pcache.h>
#include <silofs/btree.h>

static const struct silofs_paddr *
bli_paddr(const struct silofs_btleaf_info *bli)
{
	return &bli->bl_pni.pn_paddr;
}

static const struct silofs_paddr *
bni_paddr(const struct silofs_btnode_info *bni)
{
	return &bni->bn_pni.pn_paddr;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_btree_init(struct silofs_btree *btree,
                       struct silofs_pcache *pcache, struct silofs_repo *repo)
{
	paddr_reset(&btree->bt_root);
	btree->bt_pcache = pcache;
	btree->bt_repo = repo;
}

void silofs_btree_fini(struct silofs_btree *btree)
{
	paddr_reset(&btree->bt_root);
	btree->bt_pcache = NULL;
	btree->bt_repo = NULL;
}

static const struct silofs_paddr *btree_root(const struct silofs_btree *btree)
{
	return &btree->bt_root;
}

void silofs_btree_update_root(struct silofs_btree *btree,
                              const struct silofs_paddr *paddr)
{
	silofs_assert_eq(paddr->ptype, SILOFS_PTYPE_BTNODE);

	paddr_assign(&btree->bt_root, paddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int btree_load_btleaf(const struct silofs_btree *btree,
                             const struct silofs_btleaf_info *bli)
{
	const struct silofs_rwvec rwv = {
		.rwv_base = bli->bl,
		.rwv_len = sizeof(*bli->bl),
	};

	return silofs_repo_load_pobj(btree->bt_repo, bli_paddr(bli), &rwv);
}

static int btree_load_btnode(const struct silofs_btree *btree,
                             const struct silofs_btnode_info *bni)
{
	const struct silofs_rwvec rwv = {
		.rwv_base = bni->bn,
		.rwv_len = sizeof(*bni->bn),
	};

	return silofs_repo_load_pobj(btree->bt_repo, bni_paddr(bni), &rwv);
}

static int btree_require_pvseg(const struct silofs_btree *btree,
                               const struct silofs_pvsid *pvsid, bool create)

{
	int err;

	if (create) {
		err = silofs_repo_create_pvseg(btree->bt_repo, pvsid);
	} else {
		err = silofs_repo_stage_pvseg(btree->bt_repo, pvsid);
	}
	return err;
}

static int
btree_require_pvseg_of(const struct silofs_btree *btree,
                       const struct silofs_paddr *paddr, bool create)
{
	return btree_require_pvseg(btree, &paddr->pvsid, create);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int validate_btleaf(const struct silofs_btleaf_info *bli)
{
	struct silofs_paddr parent_paddr;

	silofs_bli_parent(bli, &parent_paddr);
	if (paddr_isnull(&parent_paddr)) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int validate_child_btleaf(const struct silofs_btnode_info *parent_bni,
                                 const struct silofs_btleaf_info *child_bli)
{
	struct silofs_paddr parent_paddr;
	const size_t parent_height = silofs_bni_height(parent_bni);
	int err;

	err = validate_btleaf(child_bli);
	if (err) {
		return err;
	}
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

static int validate_btnode(const struct silofs_btnode_info *bni)
{
	size_t height;

	height = silofs_bni_height(bni);
	if ((height < 1) || (height > 8)) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int validate_btroot(const struct silofs_btnode_info *bni)
{
	struct silofs_paddr paddr;
	int err;

	err = validate_btnode(bni);
	if (err) {
		return err;
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int btree_create_cached_bli(const struct silofs_btree *btree,
                                   const struct silofs_paddr *paddr,
                                   struct silofs_btleaf_info **out_bli)
{
	*out_bli = silofs_pcache_create_bli(btree->bt_pcache, paddr);
	return (*out_bli != NULL) ? 0 : -SILOFS_ENOMEM;
}

static void btree_evict_cached_bli(const struct silofs_btree *btree,
                                   struct silofs_btleaf_info *bli)
{
	silofs_pcache_evict_bli(btree->bt_pcache, bli);
}

static int btree_lookup_cached_bli(const struct silofs_btree *btree,
                                   const struct silofs_paddr *paddr,
                                   struct silofs_btleaf_info **out_bli)
{
	*out_bli = silofs_pcache_lookup_bli(btree->bt_pcache, paddr);
	return (*out_bli == NULL) ? -SILOFS_ENOENT : 0;
}

static int btree_stage_btleaf_at(const struct silofs_btree *btree,
                                 const struct silofs_paddr *paddr,
                                 struct silofs_btleaf_info **out_bli)
{
	struct silofs_btleaf_info *bli = NULL;
	int err;

	silofs_assert_eq(paddr->ptype, SILOFS_PTYPE_BTLEAF);

	err = btree_require_pvseg_of(btree, paddr, false);
	if (err) {
		return err;
	}
	err = btree_create_cached_bli(btree, paddr, &bli);
	if (err) {
		return err;
	}
	err = btree_load_btleaf(btree, bli);
	if (err) {
		btree_evict_cached_bli(btree, bli);
		return err;
	}
	*out_bli = bli;
	return 0;
}

static int btree_stage_btleaf(const struct silofs_btree *btree,
                              const struct silofs_paddr *paddr,
                              struct silofs_btleaf_info **out_bli)
{
	struct silofs_btleaf_info *bli = NULL;
	int err;

	err = btree_lookup_cached_bli(btree, paddr, out_bli);
	if (!err) {
		return 0; /* cache hit */
	}
	err = btree_stage_btleaf_at(btree, paddr, &bli);
	if (err) {
		return err;
	}
	err = validate_btleaf(bli);
	if (err) {
		btree_evict_cached_bli(btree, bli);
		return err;
	}
	*out_bli = bli;
	return 0;
}

static int btree_create_cached_bni(const struct silofs_btree *btree,
                                   const struct silofs_paddr *paddr,
                                   struct silofs_btnode_info **out_bni)
{
	*out_bni = silofs_pcache_create_bni(btree->bt_pcache, paddr);
	return (*out_bni != NULL) ? 0 : -SILOFS_ENOMEM;
}

static void btree_evict_cached_bni(const struct silofs_btree *btree,
                                   struct silofs_btnode_info *bni)
{
	silofs_pcache_evict_bni(btree->bt_pcache, bni);
}

static int btree_lookup_cached_bni(const struct silofs_btree *btree,
                                   const struct silofs_paddr *paddr,
                                   struct silofs_btnode_info **out_bni)
{
	*out_bni = silofs_pcache_lookup_bni(btree->bt_pcache, paddr);
	return (*out_bni == NULL) ? -SILOFS_ENOENT : 0;
}

static int btree_stage_btnode_at(const struct silofs_btree *btree,
                                 const struct silofs_paddr *paddr,
                                 struct silofs_btnode_info **out_bni)
{
	struct silofs_btnode_info *bni = NULL;
	int err;

	silofs_assert_eq(paddr->ptype, SILOFS_PTYPE_BTNODE);

	err = btree_require_pvseg_of(btree, paddr, false);
	if (err) {
		return err;
	}
	err = btree_create_cached_bni(btree, paddr, &bni);
	if (err) {
		return err;
	}
	err = btree_load_btnode(btree, bni);
	if (err) {
		btree_evict_cached_bni(btree, bni);
		return err;
	}
	*out_bni = bni;
	return 0;
}

static int btree_stage_btnode(const struct silofs_btree *btree,
                              const struct silofs_paddr *paddr,
                              struct silofs_btnode_info **out_bni)
{
	struct silofs_btnode_info *bni = NULL;
	int err;

	err = btree_lookup_cached_bni(btree, paddr, out_bni);
	if (!err) {
		return 0; /* cache hit */
	}
	err = btree_stage_btnode_at(btree, paddr, &bni);
	if (err) {
		return err;
	}
	err = validate_btnode(bni);
	if (err) {
		btree_evict_cached_bni(btree, bni);
		return err;
	}
	*out_bni = bni;
	return 0;
}

static int btree_stage_btroot(const struct silofs_btree *btree,
                              struct silofs_btnode_info **out_bni)
{
	const struct silofs_paddr *paddr = btree_root(btree);
	struct silofs_btnode_info *bni = NULL;
	int err;

	err = btree_lookup_cached_bni(btree, paddr, out_bni);
	if (!err) {
		return 0; /* cache hit */
	}
	err = btree_stage_btnode_at(btree, paddr, &bni);
	if (err) {
		return err;
	}
	err = validate_btroot(bni);
	if (err) {
		btree_evict_cached_bni(btree, bni);
		return err;
	}
	*out_bni = bni;
	return 0;
}

static int validate_child_btnode(const struct silofs_btnode_info *parent_bni,
                                 const struct silofs_btnode_info *child_bni)
{
	struct silofs_paddr parent_paddr;
	const size_t parent_height = silofs_bni_height(parent_bni);
	const size_t child_height = silofs_bni_height(child_bni);
	int err;

	err = validate_btnode(child_bni);
	if (err) {
		return err;
	}
	if ((child_height + 1) != parent_height) {
		return -SILOFS_EFSCORRUPTED;
	}
	silofs_bni_parent(child_bni, &parent_paddr);
	if (!paddr_isequal(&parent_paddr, bni_paddr(parent_bni))) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int btree_stage_child_btnode(const struct silofs_btree *btree,
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
	err = btree_stage_btnode(btree, &paddr, &bni);
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

static int btree_stage_level1_btnode(const struct silofs_btree *btree,
                                     struct silofs_btnode_info *from_bni,
                                     const struct silofs_vaddr *vaddr,
                                     struct silofs_btnode_info **out_bni)
{
	struct silofs_btnode_info *bni = from_bni;
	size_t height;
	int err = 0;

	height = silofs_bni_height(bni);
	while (height > 1) {
		err = btree_stage_child_btnode(btree, bni, vaddr, &bni);
		if (err) {
			return err;
		}
		height--;
	}
	*out_bni = bni;
	return 0;
}

static int btree_stage_child_btleaf(const struct silofs_btree *btree,
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
	err = btree_stage_btleaf(btree, &paddr, &bli);
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

static int btree_stage_btleaf_of(const struct silofs_btree *btree,
                                 const struct silofs_vaddr *vaddr,
                                 struct silofs_btleaf_info **out_bli)
{
	struct silofs_btnode_info *root_bni = NULL;
	struct silofs_btnode_info *bni = NULL;
	struct silofs_btleaf_info *bli = NULL;
	int err = 0;

	err = btree_stage_btroot(btree, &root_bni);
	if (err) {
		return err;
	}
	err = btree_stage_level1_btnode(btree, root_bni, vaddr, &bni);
	if (err) {
		return err;
	}
	err = btree_stage_child_btleaf(btree, bni, vaddr, &bli);
	if (err) {
		return err;
	}
	*out_bli = bli;
	return 0;
}

static int
btree_resolve(const struct silofs_btree *btree,
              const struct silofs_vaddr *vaddr, struct silofs_paddr *out_paddr)
{
	struct silofs_btleaf_info *bli = NULL;
	int err;

	err = btree_stage_btleaf_of(btree, vaddr, &bli);
	if (err) {
		return err;
	}
	err = silofs_bli_resolve(bli, vaddr, out_paddr);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_btree_lookup(const struct silofs_btree *btree,
                        const struct silofs_vaddr *vaddr,
                        struct silofs_paddr *out_paddr)
{
	return btree_resolve(btree, vaddr, out_paddr);
}
