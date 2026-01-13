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
#include <silofs/errors.h>
#include <silofs/ondisk.h>
#include "addr.h"
#include "nodes.h"
#include "repo.h"
#include "btnode.h"
#include "btree.h"

struct silofs_btree_path {
	struct silofs_btnode_info *bti[SILOFS_BTREE_HEIGHT_MAX];
	size_t cnt;
};

struct silofs_btree_ctx {
	struct silofs_btree_path bpath;
	struct silofs_btree *btree;
	struct silofs_pcache *pcache;
	struct silofs_repo *repo;
	struct silofs_dstor *dstor;
	uint64_t key;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void bti_incref(struct silofs_btnode_info *bti)
{
	silofs_assert_not_null(bti);
	silofs_pni_incref(&bti->btn_pni);
}

static void bti_decref(struct silofs_btnode_info *bti)
{
	silofs_assert_not_null(bti);
	silofs_pni_decref(&bti->btn_pni);
}

static const struct silofs_paddr *
bti_paddr(const struct silofs_btnode_info *bti)
{
	return &bti->btn_pni.pn_meta.paddr;
}

static const struct silofs_blobid *
bti_blobid(const struct silofs_btnode_info *bti)
{
	const struct silofs_paddr *paddr = bti_paddr(bti);

	return &paddr->blobid;
}

static bool bti_has_same_blobid(const struct silofs_btnode_info *bti,
                                const struct silofs_btnode_info *bti_other)
{
	return silofs_blobid_isequal(bti_blobid(bti), bti_blobid(bti_other));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int validate_btnode(const struct silofs_btnode_info *bti)
{
	size_t height;

	height = silofs_bti_height(bti);
	if ((height < 1) || (height > SILOFS_BTREE_HEIGHT_MAX)) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int validate_btroot(const struct silofs_btnode_info *bti)
{
	int err;

	err = validate_btnode(bti);
	if (err) {
		return err;
	}
	if (!silofs_bti_marked_root(bti)) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int validate_child_btnode(const struct silofs_btnode_info *parent_bti,
                                 const struct silofs_btnode_info *child_bti)
{
	const size_t parent_height = silofs_bti_height(parent_bti);
	const size_t child_height  = silofs_bti_height(child_bti);
	int err;

	err = validate_btnode(child_bti);
	if (err) {
		return err;
	}
	if ((child_height + 1) != parent_height) {
		return -SILOFS_EFSCORRUPTED;
	}
	/* XXX */
	silofs_assert(bti_has_same_blobid(parent_bti, child_bti));
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void bpath_init(struct silofs_btree_path *bpath)
{
	for (size_t i = 0; i < ARRAY_SIZE(bpath->bti); ++i) {
		bpath->bti[i] = nullptr;
	}
	bpath->cnt = 0;
}

static void bpath_fini(struct silofs_btree_path *bpath)
{
	for (size_t i = 0; i < bpath->cnt; ++i) {
		bti_decref(bpath->bti[i]);
		bpath->bti[i] = nullptr;
	}
	bpath->cnt = 0;
}

static void
bpath_append(struct silofs_btree_path *bpath, struct silofs_btnode_info *bti)
{
	silofs_assert_lt(bpath->cnt, ARRAY_SIZE(bpath->bti));
	bpath->bti[bpath->cnt++] = bti;
	bti_incref(bti);
}

static void bpath_replace(struct silofs_btree_path *bpath, size_t slot,
                          struct silofs_btnode_info *bti_new)
{
	struct silofs_btnode_info *bti = bpath->bti[slot];

	silofs_assert_lt(slot, bpath->cnt);
	bpath->bti[slot] = bti_new;
	bti_incref(bti_new);
	bti_decref(bti);
}

static struct silofs_btnode_info *
bpath_at(const struct silofs_btree_path *bpath, size_t slot)
{
	struct silofs_btnode_info *bti = nullptr;

	silofs_assert_lt(slot, bpath->cnt);
	if (slot < bpath->cnt) {
		bti = bpath->bti[slot];
	}
	return bti;
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
	silofs_paddr_reset(&btree->bt_root);
}

void silofs_btree_fini(struct silofs_btree *btree)
{
	memset(&btree->bt_base, 0, sizeof(btree->bt_base));
	silofs_paddr_reset(&btree->bt_root);
}

static const struct silofs_paddr *btree_root(const struct silofs_btree *btree)
{
	return &btree->bt_root;
}

void silofs_btree_update_root(struct silofs_btree *btree,
                              const struct silofs_paddr *paddr)
{
	silofs_paddr_assign(&btree->bt_root, paddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool btree_is_writeable(const struct silofs_btree *btree,
                               const struct silofs_btnode_info *bti)
{
	const struct silofs_paddr *paddr = bti_paddr(bti);

	// XXX FIXME
	silofs_unused(paddr);
	silofs_unused(btree);

	return true;
}

static void btree_update_bti(const struct silofs_btree *btree,
                             struct silofs_btnode_info *bti, bool as_rdonly)
{
	if (!bti->btn_rdonly) {
		bti->btn_rdonly = as_rdonly || !btree_is_writeable(btree, bti);
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int btc_stage_blob_of(const struct silofs_btree_ctx *btc,
                             const struct silofs_paddr *paddr)
{
	return silofs_dstor_stage_blob(btc->dstor, &paddr->blobid);
}

static int btc_spawn_blob_of(const struct silofs_btree_ctx *btc,
                             const struct silofs_paddr *paddr)
{
	return silofs_dstor_spawn_blob(btc->dstor, &paddr->blobid);
}

static int btc_require_blob_of(const struct silofs_btree_ctx *btc,
                               const struct silofs_paddr *paddr)
{
	int err;

	err = btc_stage_blob_of(btc, paddr);
	if (err == -SILOFS_ENOENT) {
		err = btc_spawn_blob_of(btc, paddr);
	}
	return err;
}

static int btc_load_btnode(const struct silofs_btree_ctx *btc,
                           const struct silofs_btnode_info *bti)
{
	const struct silofs_paddr *paddr = bti_paddr(bti);

	return silofs_dstor_read_blob_at(btc->dstor, &paddr->blobid,
	                                 paddr->pos, bti->btn,
	                                 sizeof(*bti->btn));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int btc_create_cached_bti(const struct silofs_btree_ctx *btc,
                                 const struct silofs_paddr *paddr,
                                 struct silofs_btnode_info **out_bti)
{
	*out_bti =
		nullptr; // XXX silofs_pcache_create_bti(btc->pcache, paddr);
	if (*out_bti == nullptr) {
		return -SILOFS_ENOMEM;
	}
	btree_update_bti(btc->btree, *out_bti, false);
	silofs_unused(paddr);
	return 0;
}

static void btc_evict_cached_bti(const struct silofs_btree *btree,
                                 struct silofs_btnode_info *bti)
{

	// XXX silofs_pcache_remove_bti(btree->bt_base.pcache, bti);
	(void)btree;
	(void)bti;
}

static int btc_lookup_cached_bti(const struct silofs_btree_ctx *btc,
                                 const struct silofs_paddr *paddr,
                                 struct silofs_btnode_info **out_bti)
{
	*out_bti =
		nullptr; // XXX silofs_pcache_lookup_bti(btc->pcache, paddr);
	if (*out_bti == nullptr) {
		return -SILOFS_ENOENT;
	}
	btree_update_bti(btc->btree, *out_bti, false);
	(void)paddr;
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int btc_stage_btnode_at(const struct silofs_btree_ctx *btc,
                               const struct silofs_paddr *paddr,
                               struct silofs_btnode_info **out_bti)
{
	struct silofs_btnode_info *bti = nullptr;
	int err;

	err = btc_stage_blob_of(btc, paddr);
	if (err) {
		return err;
	}
	err = btc_create_cached_bti(btc, paddr, &bti);
	if (err) {
		return err;
	}
	err = btc_load_btnode(btc, bti);
	if (err) {
		btc_evict_cached_bti(btc->btree, bti);
		return err;
	}
	*out_bti = bti;
	return 0;
}

static int btc_stage_btnode(const struct silofs_btree_ctx *btc,
                            const struct silofs_paddr *paddr,
                            struct silofs_btnode_info **out_bti)
{
	struct silofs_btnode_info *bti = nullptr;
	int err;

	err = btc_lookup_cached_bti(btc, paddr, &bti);
	if (!err) {
		goto out; /* cache hit */
	}
	err = btc_stage_btnode_at(btc, paddr, &bti);
	if (err) {
		return err;
	}
	err = validate_btnode(bti);
	if (err) {
		btc_evict_cached_bti(btc->btree, bti);
		return err;
	}
out:
	*out_bti = bti;
	return 0;
}

static const struct silofs_paddr *
btc_root_paddr(const struct silofs_btree_ctx *btc)
{
	return btree_root(btc->btree);
}

static int btc_stage_btroot(const struct silofs_btree_ctx *btc,
                            struct silofs_btnode_info **out_bti)
{
	struct silofs_btnode_info *bti = nullptr;
	int err;

	err = btc_stage_btnode(btc, btc_root_paddr(btc), &bti);
	if (err) {
		return err;
	}
	err = validate_btroot(bti);
	if (err) {
		btc_evict_cached_bti(btc->btree, bti);
		return err;
	}
	*out_bti = bti;
	return 0;
}

static int btc_stage_push_btroot(struct silofs_btree_ctx *btc)
{
	struct silofs_btnode_info *root_bti = nullptr;
	int err;

	silofs_assert_eq(btc->bpath.cnt, 0);
	err = btc_stage_btroot(btc, &root_bti);
	if (err) {
		return err;
	}
	bpath_append(&btc->bpath, root_bti);
	return 0;
}

static int btc_stage_child_btnode(const struct silofs_btree_ctx *btc,
                                  struct silofs_btnode_info *parent_bti,
                                  struct silofs_btnode_info **out_bti)
{
	struct silofs_pmeta pmeta;
	struct silofs_btnode_info *bti = nullptr;
	int err;

	err = silofs_bti_resolve(parent_bti, btc->key, &pmeta);
	if (err) {
		return err;
	}
	err = btc_stage_btnode(btc, &pmeta.paddr, &bti);
	if (err) {
		return err;
	}
	err = validate_child_btnode(parent_bti, bti);
	if (err) {
		return err;
	}
	*out_bti = bti;
	return 0;
}

static struct silofs_btnode_info *
btc_path_root_bti(const struct silofs_btree_ctx *btc)
{
	silofs_assert_gt(btc->bpath.cnt, 0);

	return bpath_root(&btc->bpath);
}

static int btc_stage_full_path(struct silofs_btree_ctx *btc)
{
	struct silofs_btnode_info *bti = btc_path_root_bti(btc);
	size_t height;
	int err = 0;

	height = silofs_bti_height(bti);
	while (height > 1) {
		err = btc_stage_child_btnode(btc, bti, &bti);
		if (err) {
			return err;
		}
		bpath_append(&btc->bpath, bti);
		height = silofs_bti_height(bti);
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
                               struct silofs_btnode_info **out_bti)
{
	struct silofs_btnode_info *bti = nullptr;
	int err;

	err = btc_require_blob_of(btc, paddr);
	if (err) {
		return err;
	}
	err = btc_create_cached_bti(btc, paddr, &bti);
	if (err) {
		return err;
	}
	*out_bti = bti;
	return 0;
}

static void btc_consume_btnode_space(const struct silofs_btree_ctx *btc,
                                     struct silofs_paddr *out_paddr)
{
	// XXX FIXME
	silofs_unused(btc);
	silofs_paddr_reset(out_paddr);
}

static int btc_spawn_btnode_by(const struct silofs_btree_ctx *btc,
                               const struct silofs_btnode_info *bti_src,
                               struct silofs_btnode_info **out_bti)
{
	struct silofs_paddr paddr = { .pos = -1 };
	int err;

	btc_consume_btnode_space(btc, &paddr);
	err = btc_spawn_btnode_at(btc, &paddr, out_bti);
	if (err) {
		return err;
	}
	silofs_bti_dup_by(*out_bti, bti_src);
	return 0;
}

static int btc_require_btnode(const struct silofs_btree_ctx *btc,
                              const struct silofs_paddr *paddr,
                              struct silofs_btnode_info **out_bti)
{
	struct silofs_btnode_info *bti = nullptr;
	int err;

	err = btc_stage_btnode(btc, paddr, &bti);
	if (!err) {
		if (btree_is_writeable(btc->btree, bti)) {
			goto out;
		}
		err = btc_spawn_btnode_by(btc, bti, &bti);
		if (err) {
			return err;
		}
	} else if (err == -SILOFS_ENOENT) {
		err = btc_spawn_btnode_at(btc, paddr, &bti);
		if (err) {
			return err;
		}
	} else {
		return err;
	}
out:
	*out_bti = bti;
	return 0;
}

static int btc_require_btroot(struct silofs_btree_ctx *btc,
                              const struct silofs_paddr *paddr)
{
	struct silofs_btnode_info *bti = nullptr;
	int err;

	err = btc_require_btnode(btc, paddr, &bti);
	if (err) {
		return err;
	}
	silofs_btree_update_root(btc->btree, bti_paddr(bti));
	return 0;
}

static int btc_require_writable_path(struct silofs_btree_ctx *btc)
{
	struct silofs_btnode_info *bti = nullptr;
	int err;

	for (size_t i = 0; i < btc->bpath.cnt; ++i) {
		bti = bpath_at(&btc->bpath, i);
		if (btree_is_writeable(btc->btree, bti)) {
			continue;
		}
		err = btc_spawn_btnode_by(btc, bti, &bti);
		if (err) {
			return err;
		}
		bpath_replace(&btc->bpath, i, bti);
	}
	return 0;
}

static void btc_update_root_by_path(const struct silofs_btree_ctx *btc)
{
	const struct silofs_btnode_info *bti = btc_path_root_bti(btc);
	const struct silofs_paddr *paddr     = bti_paddr(bti);

	if (!silofs_paddr_isequal(&btc->btree->bt_root, paddr)) {
		silofs_paddr_assign(&btc->btree->bt_root, paddr);
	}
}

static int btc_relinked_path(struct silofs_btree_ctx *btc)
{
	struct silofs_btnode_info *bti       = nullptr;
	struct silofs_btnode_info *child_bti = nullptr;
	const struct silofs_paddr *paddr     = nullptr;
	const size_t cnt                     = btc->bpath.cnt;
	int err;

	if (cnt == 0) {
		return -SILOFS_EINVAL;
	}
	if (cnt == 1) {
		goto out;
	}
	for (size_t i = 0; i < (cnt - 1); ++i) {
		bti       = bpath_at(&btc->bpath, i);
		child_bti = bpath_at(&btc->bpath, i + 1);
		paddr     = bti_paddr(child_bti);
		(void)paddr;
		/* XXX */
		err = silofs_bti_update_child(bti, btc->key, nullptr);
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
	struct silofs_btnode_info *bti = nullptr;
	const size_t cnt               = btc->bpath.cnt;

	for (size_t i = cnt; i > 0; --i) {
		bti = bpath_at(&btc->bpath, i);
		if (!silofs_bti_isfull(bti)) {
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
                              struct silofs_pmeta *out_child)
{
	const struct silofs_btnode_info *bti = nullptr;
	int err;

	err = btc_stage_path(btc);
	if (err) {
		return err;
	}
	bti = bpath_last(&btc->bpath);
	if (bti == nullptr) {
		return -SILOFS_ENOENT;
	}
	err = silofs_bti_resolve(bti, btc->key, out_child);
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
	btc->btree  = btree;
	btc->pcache = btree->bt_base.pcache;
	btc->repo   = btree->bt_base.repo;
	btc->dstor  = &btree->bt_base.repo->re_dstor;

	bpath_init(&btc->bpath);
	if (vaddr == nullptr) {
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
	btc->btree  = nullptr;
	btc->pcache = nullptr;
	btc->repo   = nullptr;
}

int silofs_btree_format(struct silofs_btree *btree)
{
	struct silofs_btree_ctx btc;
	struct silofs_paddr paddr;
	int err;

	err = btc_init(&btc, btree, nullptr);
	if (!err) {
		btc_consume_btnode_space(&btc, &paddr);
		err = btc_require_btroot(&btc, &paddr);
	}
	btc_fini(&btc);
	return err;
}

int silofs_btree_lookup(struct silofs_btree *btree,
                        const struct silofs_vaddr *vaddr,
                        struct silofs_pmeta *out_child)
{
	struct silofs_btree_ctx btc;
	int err;

	err = btc_init(&btc, btree, vaddr);
	if (!err) {
		err = btc_resolve_rdonly(&btc, out_child);
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
