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
#include <silofs/pvlogs.h>
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

static const struct silofs_volid *
bni_volid(const struct silofs_btnode_info *bni)
{
	return &bni->bn_pni.pn_paddr.pvsid.volid;
}

static bool bni_has_same_volid(const struct silofs_btnode_info *bni,
                               const struct silofs_btnode_info *bni_other)
{
	return silofs_volid_isequal(bni_volid(bni), bni_volid(bni_other));
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
		bni = bpath->bni[slot - 1];
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

static int btree_stage_pvseg_of(const struct silofs_btree *btree,
                                const struct silofs_paddr *paddr)
{
	return silofs_repo_stage_pvseg(btree->bt_base.repo, &paddr->pvsid);
}

static int btree_spawn_pvseg_of(const struct silofs_btree *btree,
                                const struct silofs_paddr *paddr)
{
	return silofs_repo_spawn_pvseg(btree->bt_base.repo, &paddr->pvsid);
}

static int btree_require_pvseg_of(const struct silofs_btree *btree,
                                  const struct silofs_paddr *paddr)
{
	int err;

	err = btree_stage_pvseg_of(btree, paddr);
	if (err == -SILOFS_ENOENT) {
		err = btree_spawn_pvseg_of(btree, paddr);
	}
	return err;
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
	silofs_assert(bni_has_same_volid(parent_bni, child_bni));
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_volid *
btree_main_volid(const struct silofs_btree *btree)
{
	return &btree->bt_base.pvsegr->volid;
}

static bool btree_has_main_volid_as(const struct silofs_btree *btree,
                                    const struct silofs_paddr *paddr)
{
	const struct silofs_volid *volid = btree_main_volid(btree);

	return silofs_volid_isequal(volid, &paddr->pvsid.volid);
}

static bool btree_is_writeable(const struct silofs_btree *btree,
                               const struct silofs_btnode_info *bni)
{
	const struct silofs_paddr *paddr = bni_paddr(bni);

	return btree_has_main_volid_as(btree, paddr);
}

static void btree_update_bni(const struct silofs_btree *btree,
                             struct silofs_btnode_info *bni, bool as_rdonly)
{
	if (!bni->bn_rdonly) {
		if (as_rdonly) {
			bni->bn_rdonly = true;
		} else if (!btree_is_writeable(btree, bni)) {
			bni->bn_rdonly = true;
		}
	}
}

static int btree_create_cached_bni(const struct silofs_btree *btree,
                                   const struct silofs_paddr *paddr,
                                   struct silofs_btnode_info **out_bni)
{
	*out_bni = silofs_pcache_create_bni(btree->bt_base.pcache, paddr);
	if (*out_bni == NULL) {
		return -SILOFS_ENOMEM;
	}
	btree_update_bni(btree, *out_bni, false);
	return 0;
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
	if (*out_bni == NULL) {
		return -SILOFS_ENOENT;
	}
	btree_update_bni(btree, *out_bni, false);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int btree_stage_btnode_at(const struct silofs_btree *btree,
                                 const struct silofs_paddr *paddr,
                                 struct silofs_btnode_info **out_bni)
{
	struct silofs_btnode_info *bni = NULL;
	int err;

	silofs_assert_eq(paddr->ptype, SILOFS_PTYPE_BTNODE);

	err = btree_stage_pvseg_of(btree, paddr);
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

	err = btree_lookup_cached_bni(btree, paddr, &bni);
	if (!err) {
		goto out; /* cache hit */
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
out:
	*out_bni = bni;
	return 0;
}

static int btree_stage_btroot(const struct silofs_btree *btree,
                              struct silofs_btnode_info **out_bni)
{
	const struct silofs_paddr *paddr = btree_root(btree);
	struct silofs_btnode_info *bni = NULL;
	int err;

	err = btree_stage_btnode(btree, paddr, &bni);
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

static int btree_stage_path_from(const struct silofs_btree *btree,
                                 const struct silofs_vaddr *vaddr,
                                 struct silofs_btnode_info *from,
                                 struct silofs_btree_path *bpath)
{
	struct silofs_btnode_info *bni = from;
	size_t height;
	int err = 0;

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

static int btree_stage_path(const struct silofs_btree *btree,
                            const struct silofs_vaddr *vaddr,
                            struct silofs_btree_path *bpath)
{
	struct silofs_btnode_info *root_bni = NULL;
	int err;

	err = btree_stage_btroot(btree, &root_bni);
	if (err) {
		return err;
	}
	bpath_append(bpath, root_bni);
	err = btree_stage_path_from(btree, vaddr, root_bni, bpath);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int btree_spawn_btnode_at(const struct silofs_btree *btree,
                                 const struct silofs_paddr *paddr,
                                 struct silofs_btnode_info **out_bni)
{
	struct silofs_btnode_info *bni = NULL;
	int err;

	err = btree_require_pvseg_of(btree, paddr);
	if (err) {
		return err;
	}
	err = btree_create_cached_bni(btree, paddr, &bni);
	if (err) {
		return err;
	}
	*out_bni = bni;
	return 0;
}

static int btree_spawn_btnode_by(const struct silofs_btree *btree,
                                 const struct silofs_btnode_info *bni_src,
                                 struct silofs_btnode_info **out_bni)
{
	struct silofs_paddr paddr = { .off = -1 };
	int err;

	silofs_pvsegr_next_btnode(btree->bt_base.pvsegr, &paddr);
	err = btree_spawn_btnode_at(btree, &paddr, out_bni);
	if (err) {
		return err;
	}
	silofs_bni_dup_by(*out_bni, bni_src);
	return 0;
}

static int btree_require_btnode(const struct silofs_btree *btree,
                                const struct silofs_paddr *paddr,
                                struct silofs_btnode_info **out_bni)
{
	struct silofs_btnode_info *bni = NULL;
	int err;

	err = btree_stage_btnode(btree, paddr, &bni);
	if (!err) {
		if (btree_is_writeable(btree, bni)) {
			goto out;
		}
		err = btree_spawn_btnode_by(btree, bni, &bni);
		if (err) {
			return err;
		}
	} else if (err == -SILOFS_ENOENT) {
		err = btree_spawn_btnode_at(btree, paddr, &bni);
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

static int btree_require_btroot(struct silofs_btree *btree,
                                const struct silofs_paddr *paddr)
{
	struct silofs_btnode_info *bni = NULL;
	int err;

	err = btree_require_btnode(btree, paddr, &bni);
	if (err) {
		return err;
	}
	silofs_btree_update_root(btree, bni_paddr(bni));
	return 0;
}

static int btree_require_writable_path(const struct silofs_btree *btree,
                                       struct silofs_btree_path *bpath)
{
	struct silofs_btnode_info *bni = NULL;
	int err;

	for (size_t i = 0; i < bpath->cnt; ++i) {
		bni = bpath_at(bpath, i);
		if (btree_is_writeable(btree, bni)) {
			continue;
		}
		err = btree_spawn_btnode_by(btree, bni, &bni);
		if (err) {
			return err;
		}
		bpath_replace(bpath, i, bni);
	}
	return 0;
}

static void btree_update_root_by(struct silofs_btree *btree,
                                 const struct silofs_btree_path *bpath)
{
	const struct silofs_btnode_info *bni = bpath_root(bpath);
	const struct silofs_paddr *paddr = bni_paddr(bni);

	if (!paddr_isequal(&btree->bt_root, paddr)) {
		paddr_assign(&btree->bt_root, paddr);
	}
}

static int btree_relinked_path(struct silofs_btree *btree,
                               const struct silofs_vaddr *vaddr,
                               struct silofs_btree_path *bpath)
{
	struct silofs_btnode_info *bni = NULL;
	struct silofs_btnode_info *child_bni = NULL;

	if (bpath->cnt == 0) {
		return -SILOFS_EINVAL;
	}
	if (bpath->cnt == 1) {
		goto out;
	}
	for (size_t i = 0; i < (bpath->cnt - 1); ++i) {
		bni = bpath_at(bpath, i);
		child_bni = bpath_at(bpath, i + 1);
		silofs_bni_update_child(bni, vaddr, bni_paddr(child_bni));
	}
out:
	btree_update_root_by(btree, bpath);
	return 0;
}

static int btree_require_insertable(struct silofs_btree *btree,
                                    const struct silofs_vaddr *vaddr,
                                    struct silofs_btree_path *bpath)
{
	struct silofs_btnode_info *bni = NULL;

	for (size_t i = bpath->cnt; i > 0; --i) {
		bni = bpath_at(bpath, i);
		if (!silofs_bni_isfull(bni)) {
			break;
		}

		/* XXX YOU ARE HERE */
		silofs_unused(vaddr);
		silofs_unused(btree);
	}
	return 0;
}

static int btree_require_path(struct silofs_btree *btree,
                              const struct silofs_vaddr *vaddr,
                              struct silofs_btree_path *bpath)
{
	int err;

	err = btree_stage_path(btree, vaddr, bpath);
	if (err) {
		return err;
	}
	err = btree_require_writable_path(btree, bpath);
	if (err) {
		return err;
	}
	err = btree_relinked_path(btree, vaddr, bpath);
	if (err) {
		return err;
	}
	err = btree_require_insertable(btree, vaddr, bpath);
	if (err) {
		return err;
	}
	btree_update_root_by(btree, bpath);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int btree_resolve_rdonly(const struct silofs_btree *btree,
                                const struct silofs_vaddr *vaddr,
                                struct silofs_btree_path *bpath,
                                struct silofs_paddr *out_paddr)
{
	const struct silofs_btnode_info *bni = NULL;
	int err;

	err = btree_stage_path(btree, vaddr, bpath);
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_btree_format(struct silofs_btree *btree)
{
	struct silofs_paddr paddr = { .off = -1 };

	silofs_pvsegr_next_btnode(btree->bt_base.pvsegr, &paddr);
	return btree_require_btroot(btree, &paddr);
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

int silofs_btree_insert(struct silofs_btree *btree,
                        const struct silofs_vaddr *vaddr,
                        const struct silofs_paddr *paddr)
{
	struct silofs_btree_path bpath = { .cnt = 0 };
	int err;

	bpath_init(&bpath);
	err = btree_require_path(btree, vaddr, &bpath);
	if (err) {
		goto out;
	}
	/* XXX */
	silofs_unused(paddr);
out:
	bpath_fini(&bpath);
	return err;
}
