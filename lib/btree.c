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

struct silofs_btree_path {
	struct silofs_btnode_info *bni[SILOFS_BTREE_HEIGHT_MAX];
	size_t cnt;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void bni_incref(struct silofs_btnode_info *bni)
{
	silofs_assert_not_null(bni);
	silofs_pni_incref(&bni->bn_pni);
}

static void bni_decref(struct silofs_btnode_info *bni)
{
	silofs_assert_not_null(bni);
	silofs_pni_decref(&bni->bn_pni);
}

static const struct silofs_paddr *
bni_paddr(const struct silofs_btnode_info *bni)
{
	return &bni->bn_pni.pn_paddr;
}

static const struct silofs_pvid *bni_pvid(const struct silofs_btnode_info *bni)
{
	return &bni->bn_pni.pn_paddr.pvsid.pvid;
}

static bool bni_has_same_pvid(const struct silofs_btnode_info *bni,
                              const struct silofs_btnode_info *bni_other)
{
	return silofs_pvid_isequal(bni_pvid(bni), bni_pvid(bni_other));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void bpath_init(struct silofs_btree_path *bpath)
{
	for (size_t i = 0; i < ARRAY_SIZE(bpath->bni); ++i) {
		bpath->bni[i] = NULL;
	}
	bpath->cnt = 0;
}

static void bpath_fini(struct silofs_btree_path *bpath)
{
	for (size_t i = 0; i < bpath->cnt; ++i) {
		bni_decref(bpath->bni[i]);
		bpath->bni[i] = NULL;
	}
	bpath->cnt = 0;
}

static void
bpath_append(struct silofs_btree_path *bpath, struct silofs_btnode_info *bni)
{
	silofs_assert_lt(bpath->cnt, ARRAY_SIZE(bpath->bni));
	bpath->bni[bpath->cnt++] = bni;
	bni_incref(bni);
}

static struct silofs_btnode_info *
bpath_last(const struct silofs_btree_path *bpath)
{
	struct silofs_btnode_info *bni = NULL;

	if (bpath->cnt > 0) {
		bni = bpath->bni[bpath->cnt - 1];
	}
	return bni;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void silofs_btree_init(struct silofs_btree *btree,
                       const struct silofs_btree_base *base)
{
	memcpy(&btree->bt_base, base, sizeof(btree->bt_base));
	paddr_reset(&btree->bt_root);
}

void silofs_btree_fini(struct silofs_btree *btree)
{
	memset(&btree->bt_base, 0, sizeof(btree->bt_base));
	paddr_reset(&btree->bt_root);
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

static int btree_load_btnode(const struct silofs_btree *btree,
                             const struct silofs_btnode_info *bni)
{
	struct silofs_repo *repo = btree->bt_base.repo;
	const struct silofs_rwvec rwv = {
		.rwv_base = bni->bn,
		.rwv_len = sizeof(*bni->bn),
	};

	return silofs_repo_load_pobj(repo, bni_paddr(bni), &rwv);
}

static int btree_require_pvseg(const struct silofs_btree *btree,
                               const struct silofs_pvsid *pvsid, bool create)

{
	struct silofs_repo *repo = btree->bt_base.repo;
	int err;

	if (create) {
		err = silofs_repo_create_pvseg(repo, pvsid);
	} else {
		err = silofs_repo_stage_pvseg(repo, pvsid);
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

static int validate_btnode(const struct silofs_btnode_info *bni)
{
	size_t height;

	height = silofs_bni_height(bni);
	if ((height < 1) || (height > SILOFS_BTREE_HEIGHT_MAX)) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int validate_btroot(const struct silofs_btnode_info *bni)
{
	int err;

	err = validate_btnode(bni);
	if (err) {
		return err;
	}
	if (!silofs_bni_marked_root(bni)) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int validate_child_btnode(const struct silofs_btnode_info *parent_bni,
                                 const struct silofs_btnode_info *child_bni)
{
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
	/* XXX */
	silofs_assert(bni_has_same_pvid(parent_bni, child_bni));
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int btree_create_cached_bni(const struct silofs_btree *btree,
                                   const struct silofs_paddr *paddr,
                                   struct silofs_btnode_info **out_bni)
{
	*out_bni = silofs_pcache_create_bni(btree->bt_base.pcache, paddr);
	return (*out_bni != NULL) ? 0 : -SILOFS_ENOMEM;
}

static void btree_evict_cached_bni(const struct silofs_btree *btree,
                                   struct silofs_btnode_info *bni)
{
	silofs_pcache_evict_bni(btree->bt_base.pcache, bni);
}

static int btree_lookup_cached_bni(const struct silofs_btree *btree,
                                   const struct silofs_paddr *paddr,
                                   struct silofs_btnode_info **out_bni)
{
	*out_bni = silofs_pcache_lookup_bni(btree->bt_base.pcache, paddr);
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

static int btree_resolve_path(const struct silofs_btree *btree,
                              const struct silofs_vaddr *vaddr,
                              struct silofs_btree_path *bpath)
{
	struct silofs_btnode_info *bni = NULL;
	size_t height;
	int err = 0;

	err = btree_stage_btroot(btree, &bni);
	if (err) {
		return err;
	}
	bpath_append(bpath, bni);

	height = silofs_bni_height(bni);
	while (height > 1) {
		err = btree_stage_child_btnode(btree, bni, vaddr, &bni);
		if (err) {
			return err;
		}
		bpath_append(bpath, bni);
		height = silofs_bni_height(bni);
	}
	return 0;
}

static int btree_resolve_rdonly(const struct silofs_btree *btree,
                                const struct silofs_vaddr *vaddr,
                                struct silofs_btree_path *bpath,
                                struct silofs_paddr *out_paddr)
{
	const struct silofs_btnode_info *bni = NULL;
	int err;

	err = btree_resolve_path(btree, vaddr, bpath);
	if (err) {
		return err;
	}
	bni = bpath_last(bpath);
	if (bni == NULL) {
		return -SILOFS_ENOENT;
	}
	err = silofs_bni_resolve(bni, vaddr, out_paddr);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_btree_lookup(const struct silofs_btree *btree,
                        const struct silofs_vaddr *vaddr,
                        struct silofs_paddr *out_paddr)
{
	struct silofs_btree_path bpath = { .cnt = 0 };
	int err;

	bpath_init(&bpath);
	err = btree_resolve_rdonly(btree, vaddr, &bpath, out_paddr);
	bpath_fini(&bpath);

	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

#if 0
static int btree_require_child_btnode(struct silofs_btree *btree,
				      struct silofs_btnode_info *parent_bni,
				      const struct silofs_vaddr *vaddr,
				      struct silofs_btnode_info **out_bni)
{
	int err;

	err = btree_stage_child_btnode(btree, parent_bni, vaddr, out_bni);
	if (!err || (err != -SILOFS_ENOENT)) {
		return err;
	}

	/* XXX */

	return 0;
}

static int btree_require_level1_btnode(struct silofs_btree *btree,
				       struct silofs_btnode_info *from_bni,
				       const struct silofs_vaddr *vaddr,
				       struct silofs_btnode_info **out_bni)
{
	struct silofs_btnode_info *bni = from_bni;
	size_t height;
	int err = 0;

	height = silofs_bni_height(bni);
	while (height > 1) {
		err = btree_require_child_btnode(btree, bni, vaddr, &bni);
		if (err) {
			return err;
		}
		height = silofs_bni_height(bni);
	}
	*out_bni = bni;
	return 0;
}

static int btree_require_child_btleaf(struct silofs_btree *btree,
				      struct silofs_btnode_info *bni,
				      const struct silofs_vaddr *vaddr,
				      struct silofs_btleaf_info **out_bli)
{
	int err;

	err = btree_stage_child_btleaf(btree, bni, vaddr, out_bli);
	if (!err || (err != -SILOFS_ENOENT)) {
		return err;
	}

	/* XXX */
	return 0;
}

static int btree_require_btleaf_of(struct silofs_btree *btree,
				   const struct silofs_vaddr *vaddr,
				   struct silofs_btleaf_info **out_bli)
{
	struct silofs_btnode_info *root_bni = NULL;
	struct silofs_btnode_info *bni = NULL;
	struct silofs_btleaf_info *bli = NULL;
	int err = 0;

	err = btree_stage_btleaf_of(btree, vaddr, &bli);
	if (!err || (err != -SILOFS_ENOENT)) {
		return err;
	}
	err = btree_stage_btroot(btree, &root_bni);
	if (err) {
		return err;
	}
	err = btree_require_level1_btnode(btree, root_bni, vaddr, &bni);
	if (!err || (err != -SILOFS_ENOENT)) {
		return err;
	}
	err = btree_require_child_btleaf(btree, bni, vaddr, &bli);
	if (err) {
		return err;
	}
	*out_bli = bli;
	return 0;
}

int silofs_btree_insert(struct silofs_btree *btree,
			const struct silofs_vaddr *vaddr,
			const struct silofs_paddr *paddr)
{
	struct silofs_btleaf_info *bli = NULL;
	int err;

	err = btree_require_btleaf_of(btree, vaddr, &bli);
	if (err) {
		return err;
	}
	err = silofs_bli_extend(bli, vaddr, paddr);
	if (err) {
		return err;
	}
	return err;
}
#endif
