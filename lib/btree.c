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
#include "configs.h"
#include <silofs/errors.h>
#include <silofs/defs.h>
#include "addr.h"
#include "pvlogs.h"
#include "repo.h"
#include "pnodes.h"
#include "pcache.h"
#include "btree.h"

struct silofs_btree_path {
	struct silofs_btnode_info *bni[SILOFS_BTREE_HEIGHT_MAX];
	size_t cnt;
};

struct silofs_btree_ctx {
	struct silofs_btree_path bpath;
	struct silofs_btree *btree;
	struct silofs_pcache *pcache;
	struct silofs_repo *repo;
	uint64_t key;
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

static const struct silofs_volumeid *
bni_volumeid(const struct silofs_btnode_info *bni)
{
	return &bni->bn_pni.pn_paddr.pvsid.volumeid;
}

static bool bni_has_same_volumeid(const struct silofs_btnode_info *bni,
                                  const struct silofs_btnode_info *bni_other)
{
	return silofs_volumeid_isequal(bni_volumeid(bni),
	                               bni_volumeid(bni_other));
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
	silofs_assert(bni_has_same_volumeid(parent_bni, child_bni));
	return 0;
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

static void bpath_replace(struct silofs_btree_path *bpath, size_t slot,
                          struct silofs_btnode_info *bni_new)
{
	struct silofs_btnode_info *bni = bpath->bni[slot];

	silofs_assert_lt(slot, bpath->cnt);
	bpath->bni[slot] = bni_new;
	bni_incref(bni_new);
	bni_decref(bni);
}

static struct silofs_btnode_info *
bpath_at(const struct silofs_btree_path *bpath, size_t slot)
{
	struct silofs_btnode_info *bni = NULL;

	silofs_assert_lt(slot, bpath->cnt);
	if (slot < bpath->cnt) {
		bni = bpath->bni[slot];
	}
	return bni;
}

static struct silofs_btnode_info *
bpath_root(const struct silofs_btree_path *bpath)
{
	return bpath_at(bpath, 0);
}

static struct silofs_btnode_info *
bpath_last(const struct silofs_btree_path *bpath)
{
	return bpath_at(bpath, bpath->cnt - 1);
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

static const struct silofs_volumeid *
btree_main_volumeid(const struct silofs_btree *btree)
{
	return &btree->bt_base.pvsegr->volumeid;
}

static bool btree_has_main_volumeid_as(const struct silofs_btree *btree,
                                       const struct silofs_paddr *paddr)
{
	const struct silofs_volumeid *volumeid = btree_main_volumeid(btree);

	return silofs_volumeid_isequal(volumeid, &paddr->pvsid.volumeid);
}

static bool btree_is_writeable(const struct silofs_btree *btree,
                               const struct silofs_btnode_info *bni)
{
	const struct silofs_paddr *paddr = bni_paddr(bni);

	return btree_has_main_volumeid_as(btree, paddr);
}

static void btree_update_bni(const struct silofs_btree *btree,
                             struct silofs_btnode_info *bni, bool as_rdonly)
{
	if (!bni->bn_rdonly) {
		bni->bn_rdonly = as_rdonly || !btree_is_writeable(btree, bni);
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int btc_stage_pvseg_of(const struct silofs_btree_ctx *btc,
                              const struct silofs_paddr *paddr)
{
	return silofs_repo_stage_pvseg(btc->repo, &paddr->pvsid);
}

static int btc_spawn_pvseg_of(const struct silofs_btree_ctx *btc,
                              const struct silofs_paddr *paddr)
{
	return silofs_repo_spawn_pvseg(btc->repo, &paddr->pvsid);
}

static int btc_require_pvseg_of(const struct silofs_btree_ctx *btc,
                                const struct silofs_paddr *paddr)
{
	int err;

	err = btc_stage_pvseg_of(btc, paddr);
	if (err == -SILOFS_ENOENT) {
		err = btc_spawn_pvseg_of(btc, paddr);
	}
	return err;
}

static int btc_load_btnode(const struct silofs_btree_ctx *btc,
                           const struct silofs_btnode_info *bni)
{
	const struct silofs_rwvec rwv = {
		.rwv_base = bni->bn,
		.rwv_len = sizeof(*bni->bn),
	};

	return silofs_repo_load_pobj(btc->repo, bni_paddr(bni), &rwv);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int btc_create_cached_bni(const struct silofs_btree_ctx *btc,
                                 const struct silofs_paddr *paddr,
                                 struct silofs_btnode_info **out_bni)
{
	*out_bni = silofs_pcache_create_bni(btc->pcache, paddr);
	if (*out_bni == NULL) {
		return -SILOFS_ENOMEM;
	}
	btree_update_bni(btc->btree, *out_bni, false);
	return 0;
}

static void btc_evict_cached_bni(const struct silofs_btree *btree,
                                 struct silofs_btnode_info *bni)
{
	silofs_pcache_evict_bni(btree->bt_base.pcache, bni);
}

static int btc_lookup_cached_bni(const struct silofs_btree_ctx *btc,
                                 const struct silofs_paddr *paddr,
                                 struct silofs_btnode_info **out_bni)
{
	*out_bni = silofs_pcache_lookup_bni(btc->pcache, paddr);
	if (*out_bni == NULL) {
		return -SILOFS_ENOENT;
	}
	btree_update_bni(btc->btree, *out_bni, false);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int btc_stage_btnode_at(const struct silofs_btree_ctx *btc,
                               const struct silofs_paddr *paddr,
                               struct silofs_btnode_info **out_bni)
{
	struct silofs_btnode_info *bni = NULL;
	int err;

	silofs_assert_eq(paddr->ptype, SILOFS_PTYPE_BTNODE);

	err = btc_stage_pvseg_of(btc, paddr);
	if (err) {
		return err;
	}
	err = btc_create_cached_bni(btc, paddr, &bni);
	if (err) {
		return err;
	}
	err = btc_load_btnode(btc, bni);
	if (err) {
		btc_evict_cached_bni(btc->btree, bni);
		return err;
	}
	*out_bni = bni;
	return 0;
}

static int btc_stage_btnode(const struct silofs_btree_ctx *btc,
                            const struct silofs_paddr *paddr,
                            struct silofs_btnode_info **out_bni)
{
	struct silofs_btnode_info *bni = NULL;
	int err;

	err = btc_lookup_cached_bni(btc, paddr, &bni);
	if (!err) {
		goto out; /* cache hit */
	}
	err = btc_stage_btnode_at(btc, paddr, &bni);
	if (err) {
		return err;
	}
	err = validate_btnode(bni);
	if (err) {
		btc_evict_cached_bni(btc->btree, bni);
		return err;
	}
out:
	*out_bni = bni;
	return 0;
}

static const struct silofs_paddr *
btc_root_paddr(const struct silofs_btree_ctx *btc)
{
	return btree_root(btc->btree);
}

static int btc_stage_btroot(const struct silofs_btree_ctx *btc,
                            struct silofs_btnode_info **out_bni)
{
	struct silofs_btnode_info *bni = NULL;
	int err;

	err = btc_stage_btnode(btc, btc_root_paddr(btc), &bni);
	if (err) {
		return err;
	}
	err = validate_btroot(bni);
	if (err) {
		btc_evict_cached_bni(btc->btree, bni);
		return err;
	}
	*out_bni = bni;
	return 0;
}

static int btc_stage_push_btroot(struct silofs_btree_ctx *btc)
{
	struct silofs_btnode_info *root_bni = NULL;
	int err;

	silofs_assert_eq(btc->bpath.cnt, 0);
	err = btc_stage_btroot(btc, &root_bni);
	if (err) {
		return err;
	}
	bpath_append(&btc->bpath, root_bni);
	return 0;
}

static int btc_stage_child_btnode(const struct silofs_btree_ctx *btc,
                                  struct silofs_btnode_info *parent_bni,
                                  struct silofs_btnode_info **out_bni)
{
	struct silofs_paddr paddr = { .off = -1 };
	struct silofs_btnode_info *bni = NULL;
	int err;

	err = silofs_bni_resolve(parent_bni, btc->key, &paddr);
	if (err) {
		return err;
	}
	err = btc_stage_btnode(btc, &paddr, &bni);
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

static struct silofs_btnode_info *
btc_path_root_bni(const struct silofs_btree_ctx *btc)
{
	silofs_assert_gt(btc->bpath.cnt, 0);

	return bpath_root(&btc->bpath);
}

static int btc_stage_full_path(struct silofs_btree_ctx *btc)
{
	struct silofs_btnode_info *bni = btc_path_root_bni(btc);
	size_t height;
	int err = 0;

	height = silofs_bni_height(bni);
	while (height > 1) {
		err = btc_stage_child_btnode(btc, bni, &bni);
		if (err) {
			return err;
		}
		bpath_append(&btc->bpath, bni);
		height = silofs_bni_height(bni);
	}
	return 0;
}

static int btc_stage_path(struct silofs_btree_ctx *btc)
{
	int err;

	err = btc_stage_push_btroot(btc);
	if (err) {
		return err;
	}
	err = btc_stage_full_path(btc);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int btc_spawn_btnode_at(const struct silofs_btree_ctx *btc,
                               const struct silofs_paddr *paddr,
                               struct silofs_btnode_info **out_bni)
{
	struct silofs_btnode_info *bni = NULL;
	int err;

	err = btc_require_pvseg_of(btc, paddr);
	if (err) {
		return err;
	}
	err = btc_create_cached_bni(btc, paddr, &bni);
	if (err) {
		return err;
	}
	*out_bni = bni;
	return 0;
}

static void btc_consume_btnode_space(const struct silofs_btree_ctx *btc,
                                     struct silofs_paddr *out_paddr)
{
	silofs_pvsegr_next_btnode(btc->btree->bt_base.pvsegr, out_paddr);
}

static int btc_spawn_btnode_by(const struct silofs_btree_ctx *btc,
                               const struct silofs_btnode_info *bni_src,
                               struct silofs_btnode_info **out_bni)
{
	struct silofs_paddr paddr = { .off = -1 };
	int err;

	btc_consume_btnode_space(btc, &paddr);
	err = btc_spawn_btnode_at(btc, &paddr, out_bni);
	if (err) {
		return err;
	}
	silofs_bni_dup_by(*out_bni, bni_src);
	return 0;
}

static int btc_require_btnode(const struct silofs_btree_ctx *btc,
                              const struct silofs_paddr *paddr,
                              struct silofs_btnode_info **out_bni)
{
	struct silofs_btnode_info *bni = NULL;
	int err;

	err = btc_stage_btnode(btc, paddr, &bni);
	if (!err) {
		if (btree_is_writeable(btc->btree, bni)) {
			goto out;
		}
		err = btc_spawn_btnode_by(btc, bni, &bni);
		if (err) {
			return err;
		}
	} else if (err == -SILOFS_ENOENT) {
		err = btc_spawn_btnode_at(btc, paddr, &bni);
		if (err) {
			return err;
		}
	} else {
		return err;
	}
out:
	*out_bni = bni;
	return 0;
}

static int btc_require_btroot(struct silofs_btree_ctx *btc,
                              const struct silofs_paddr *paddr)
{
	struct silofs_btnode_info *bni = NULL;
	int err;

	err = btc_require_btnode(btc, paddr, &bni);
	if (err) {
		return err;
	}
	silofs_btree_update_root(btc->btree, bni_paddr(bni));
	return 0;
}

static int btc_require_writable_path(struct silofs_btree_ctx *btc)
{
	struct silofs_btnode_info *bni = NULL;
	int err;

	for (size_t i = 0; i < btc->bpath.cnt; ++i) {
		bni = bpath_at(&btc->bpath, i);
		if (btree_is_writeable(btc->btree, bni)) {
			continue;
		}
		err = btc_spawn_btnode_by(btc, bni, &bni);
		if (err) {
			return err;
		}
		bpath_replace(&btc->bpath, i, bni);
	}
	return 0;
}

static void btc_update_root_by_path(const struct silofs_btree_ctx *btc)
{
	const struct silofs_btnode_info *bni = btc_path_root_bni(btc);
	const struct silofs_paddr *paddr = bni_paddr(bni);

	if (!paddr_isequal(&btc->btree->bt_root, paddr)) {
		paddr_assign(&btc->btree->bt_root, paddr);
	}
}

static int btc_relinked_path(struct silofs_btree_ctx *btc)
{
	struct silofs_btnode_info *bni = NULL;
	struct silofs_btnode_info *child_bni = NULL;
	const struct silofs_paddr *paddr = NULL;
	const size_t cnt = btc->bpath.cnt;
	int err;

	if (cnt == 0) {
		return -SILOFS_EINVAL;
	}
	if (cnt == 1) {
		goto out;
	}
	for (size_t i = 0; i < (cnt - 1); ++i) {
		bni = bpath_at(&btc->bpath, i);
		child_bni = bpath_at(&btc->bpath, i + 1);
		paddr = bni_paddr(child_bni);
		err = silofs_bni_update_child(bni, btc->key, paddr);
		if (err) {
			return err;
		}
	}
out:
	btc_update_root_by_path(btc);
	return 0;
}

static int btc_require_insertable(struct silofs_btree_ctx *btc)
{
	struct silofs_btnode_info *bni = NULL;
	const size_t cnt = btc->bpath.cnt;

	for (size_t i = cnt; i > 0; --i) {
		bni = bpath_at(&btc->bpath, i);
		if (!silofs_bni_isfull(bni)) {
			break;
		}

		/* XXX YOU ARE HERE */
	}
	return 0;
}

static int btc_require_path(struct silofs_btree_ctx *btc)
{
	int err;

	err = btc_stage_path(btc);
	if (err) {
		return err;
	}
	err = btc_require_writable_path(btc);
	if (err) {
		return err;
	}
	err = btc_relinked_path(btc);
	if (err) {
		return err;
	}
	err = btc_require_insertable(btc);
	if (err) {
		return err;
	}
	btc_update_root_by_path(btc);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int btc_resolve_rdonly(struct silofs_btree_ctx *btc,
                              struct silofs_paddr *out_paddr)
{
	const struct silofs_btnode_info *bni = NULL;
	int err;

	err = btc_stage_path(btc);
	if (err) {
		return err;
	}
	bni = bpath_last(&btc->bpath);
	if (bni == NULL) {
		return -SILOFS_ENOENT;
	}
	err = silofs_bni_resolve(bni, btc->key, out_paddr);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int btc_init(struct silofs_btree_ctx *btc, struct silofs_btree *btree,
                    const struct silofs_vaddr *vaddr)
{
	int ret = 0;

	silofs_memzero(btc, sizeof(*btc));
	btc->btree = btree;
	btc->pcache = btree->bt_base.pcache;
	btc->repo = btree->bt_base.repo;
	bpath_init(&btc->bpath);
	if (vaddr == NULL) {
		btc->key = SILOFS_BTREE_KEY_NULL;
	} else if (!silofs_vaddr_isnull(vaddr)) {
		btc->key = (uint64_t)(vaddr->off);
	} else {
		ret = -SILOFS_EINVAL;
	}
	return ret;
}

static void btc_fini(struct silofs_btree_ctx *btc)
{
	bpath_fini(&btc->bpath);
	btc->btree = NULL;
	btc->pcache = NULL;
	btc->repo = NULL;
}

int silofs_btree_format(struct silofs_btree *btree)
{
	struct silofs_btree_ctx btc;
	struct silofs_paddr paddr;
	int err;

	err = btc_init(&btc, btree, NULL);
	if (!err) {
		btc_consume_btnode_space(&btc, &paddr);
		err = btc_require_btroot(&btc, &paddr);
	}
	btc_fini(&btc);
	return err;
}

int silofs_btree_lookup(struct silofs_btree *btree,
                        const struct silofs_vaddr *vaddr,
                        struct silofs_paddr *out_paddr)
{
	struct silofs_btree_ctx btc;
	int err;

	err = btc_init(&btc, btree, vaddr);
	if (!err) {
		err = btc_resolve_rdonly(&btc, out_paddr);
	}
	btc_fini(&btc);
	return err;
}

int silofs_btree_insert(struct silofs_btree *btree,
                        const struct silofs_vaddr *vaddr,
                        const struct silofs_paddr *paddr)
{
	struct silofs_btree_ctx btc;
	int err;

	err = btc_init(&btc, btree, vaddr);
	if (!err) {
		err = btc_require_path(&btc);

		/* XXX */
		silofs_unused(paddr);
	}
	btc_fini(&btc);
	return err;
}
