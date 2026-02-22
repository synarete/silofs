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
#include "stage.h"
#include "uber.h"
#include "exectx.h"
#include "env.h"
#include "btree.h"

struct silofs_btree_path {
	struct silofs_btnode_info *bti[SILOFS_BTREE_HEIGHT_MAX];
	size_t cnt;
};

struct silofs_btree_ctx {
	struct silofs_btree_path bpath;
	struct silofs_vaddr vaddr;
	struct silofs_task_ctx *task;
	struct silofs_uber_info *ubi;
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
	return &bti->btn_pni.pn_self.paddr;
}

static const struct silofs_layerid *
bti_layerid(const struct silofs_btnode_info *bti)
{
	return silofs_pni_layerid(&bti->btn_pni);
}

static bool bti_has_same_layerid(const struct silofs_btnode_info *bti1,
                                 const struct silofs_btnode_info *bti2)
{
	return silofs_layerid_isequal(bti_layerid(bti1), bti_layerid(bti2));
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

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void
btc_init(struct silofs_btree_ctx *btc, struct silofs_task_ctx *task,
         const struct silofs_vaddr *vaddr)
{
	silofs_memzero(btc, sizeof(*btc));
	bpath_init(&btc->bpath);
	silofs_vaddr_assign(&btc->vaddr, vaddr);
	btc->task = task;
	btc->ubi  = task->env->ubi;
}

static void btc_fini(struct silofs_btree_ctx *btc)
{
	bpath_fini(&btc->bpath);
	btc->task = nullptr;
}

static uint64_t btc_key(const struct silofs_btree_ctx *btc)
{
	silofs_assert_ne(btc->vaddr.off, SILOFS_OFF_NULL);

	return (uint64_t)(btc->vaddr.off);
}

static enum silofs_vtype btc_vspace(const struct silofs_btree_ctx *btc)
{
	return btc->vaddr.vtype;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_btnode_info *
btc_path_btnode_at(const struct silofs_btree_ctx *btc, size_t slot)
{
	return bpath_at(&btc->bpath, slot);
}

static struct silofs_btnode_info *
btc_path_btroot(const struct silofs_btree_ctx *btc)
{
	return btc_path_btnode_at(btc, 0);
}

static void
btc_path_append(struct silofs_btree_ctx *btc, struct silofs_btnode_info *bti)
{
	bpath_append(&btc->bpath, bti);
}

static void btc_path_set_btroot(struct silofs_btree_ctx *btc,
                                struct silofs_btnode_info *bti)
{
	silofs_assert_eq(btc->bpath.cnt, 0);

	btc_path_append(btc, bti);
}

static void btc_path_replace_at(struct silofs_btree_ctx *btc, size_t slot,
                                struct silofs_btnode_info *bti_new)
{
	bpath_replace(&btc->bpath, slot, bti_new);
}

static struct silofs_btnode_info *
btc_path_last(const struct silofs_btree_ctx *btc)
{
	silofs_assert_gt(btc->bpath.cnt, 0);

	return bpath_at(&btc->bpath, btc->bpath.cnt - 1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int btc_stage_btnode(const struct silofs_btree_ctx *btc,
                            const struct silofs_btnptr *btnptr,
                            struct silofs_btnode_info **out_bti)
{
	return silofs_stage_btnode(btc->task, &btnptr->base, out_bti);
}

static void btc_resolve_btroot(const struct silofs_btree_ctx *btc,
                               struct silofs_btnptr *out_btnptr)
{
	silofs_ubi_btroot_of(btc->ubi, btc_vspace(btc), out_btnptr);
}

static int btc_validate_btroot(const struct silofs_btree_ctx *btc,
                               const struct silofs_btnode_info *bti)
{
	if (!silofs_bti_marked_root(bti)) {
		log_err("btroot not set properly (key=%lu)", btc_key(btc));
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int btc_stage_btroot(const struct silofs_btree_ctx *btc,
                            struct silofs_btnode_info **out_bti)
{
	struct silofs_btnptr btnptr = {};
	int err;

	btc_resolve_btroot(btc, &btnptr);
	err = btc_stage_btnode(btc, &btnptr, out_bti);
	if (err) {
		return err;
	}
	err = btc_validate_btroot(btc, *out_bti);
	if (err) {
		return err;
	}
	return 0;
}

static int btc_stage_push_btroot(struct silofs_btree_ctx *btc)
{
	struct silofs_btnode_info *root_bti = nullptr;
	int err;

	err = btc_stage_btroot(btc, &root_bti);
	if (err) {
		return err;
	}
	btc_path_set_btroot(btc, root_bti);
	return 0;
}

static int
btc_validate_child_btnode(const struct silofs_btree_ctx *btc,
                          const struct silofs_btnode_info *parent_bti,
                          const struct silofs_btnode_info *child_bti)
{
	size_t parent_height, child_height;
	enum silofs_vtype parent_vspace, child_vspace;
	const enum silofs_vtype vspace = btc_vspace(btc);

	parent_vspace = silofs_bti_vspace(parent_bti);
	child_vspace  = silofs_bti_vspace(child_bti);
	if ((parent_vspace != child_vspace) || (parent_vspace != vspace)) {
		log_err("bad btree: parent_vspace=%d child_vspace=%d "
		        "vspace=%d",
		        parent_vspace, child_vspace, vspace);
		return -SILOFS_EFSCORRUPTED;
	}

	parent_height = silofs_bti_height(parent_bti);
	child_height  = silofs_bti_height(child_bti);
	if ((child_height + 1) != parent_height) {
		log_err("bad btree: parent_height=%zu child_height=%zu",
		        parent_height, child_height);
		return -SILOFS_EFSCORRUPTED;
	}

	/* XXX */
	if (!bti_has_same_layerid(parent_bti, child_bti)) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int btc_stage_child_btnode(const struct silofs_btree_ctx *btc,
                                  struct silofs_btnode_info *parent_bti,
                                  struct silofs_btnode_info **out_bti)
{
	struct silofs_btnptr btnptr;
	struct silofs_btnode_info *bti = nullptr;
	int err;

	err = silofs_bti_resolve(parent_bti, btc_key(btc), &btnptr);
	if (err) {
		return err;
	}
	err = btc_stage_btnode(btc, &btnptr, &bti);
	if (err) {
		return err;
	}
	err = btc_validate_child_btnode(btc, parent_bti, bti);
	if (err) {
		return err;
	}
	*out_bti = bti;
	return 0;
}

static int btc_stage_full_path(struct silofs_btree_ctx *btc)
{
	struct silofs_btnode_info *bti = btc_path_btroot(btc);
	size_t height;
	int err = 0;

	height = silofs_bti_height(bti);
	while (height > SILOFS_BTREE_HEIGHT_MIN) {
		err = btc_stage_child_btnode(btc, bti, &bti);
		if (err) {
			return err;
		}
		btc_path_append(btc, bti);
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
	return silofs_spawn_btnode_at(btc->task, paddr, out_bti);
}

static int btc_carve_btspace(const struct silofs_btree_ctx *btc,
                             struct silofs_paddr *out_paddr)
{
	silofs_carve_btspace(btc->task, btc_vspace(btc), out_paddr);
	/* TODO: check avail space, RDONLY etc */
	return 0;
}

static int btc_spawn_btnode_by(const struct silofs_btree_ctx *btc,
                               const struct silofs_btnode_info *bti_src,
                               struct silofs_btnode_info **out_bti)
{
	struct silofs_paddr paddr = { .pos = -1 };
	int err;

	err = btc_carve_btspace(btc, &paddr);
	if (err) {
		return err;
	}
	err = btc_spawn_btnode_at(btc, &paddr, out_bti);
	if (err) {
		return err;
	}
	silofs_bti_dup_by(*out_bti, bti_src);
	return 0;
}

static bool btc_is_writeable_btnode(const struct silofs_btree_ctx *btc,
                                    const struct silofs_btnode_info *bti)
{
	return silofs_ubi_onsame_layer(btc->ubi, bti);
}

static int btc_require_writable_path(struct silofs_btree_ctx *btc)
{
	struct silofs_btnode_info *bti = nullptr;
	int err;

	for (size_t i = 0; i < btc->bpath.cnt; ++i) {
		bti = btc_path_btnode_at(btc, i);
		if (btc_is_writeable_btnode(btc, bti)) {
			continue;
		}
		err = btc_spawn_btnode_by(btc, bti, &bti);
		if (err) {
			return err;
		}
		btc_path_replace_at(btc, i, bti);
	}
	return 0;
}

static void btc_update_root_by_path(const struct silofs_btree_ctx *btc)
{
	const struct silofs_btnode_info *bti = btc_path_btroot(btc);
	const struct silofs_paddr *paddr     = bti_paddr(bti);

	/* XXX TODO: DOME */
	(void)bti;
	(void)paddr;
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

static int btc_resolve_leaf_by(const struct silofs_btree_ctx *btc,
                               const struct silofs_btnode_info *bti,
                               struct silofs_pnptr *out_pnptr)
{
	struct silofs_btnptr btnptr = {};
	int err;

	err = silofs_bti_resolve(bti, btc_key(btc), &btnptr);
	if (err) {
		return err;
	}
	silofs_assert_eq(btnptr.nsub_btnodes, 0);
	silofs_pnptr_assign(out_pnptr, &btnptr.base);
	return 0;
}

static int
btc_resolve_leaf(struct silofs_btree_ctx *btc, struct silofs_pnptr *out_pnptr)
{
	const struct silofs_btnode_info *bti = nullptr;
	int err;

	err = btc_stage_path(btc);
	if (err) {
		return err;
	}
	bti = btc_path_last(btc);
	if (bti == nullptr) {
		return -SILOFS_ENOENT;
	}
	err = btc_resolve_leaf_by(btc, bti, out_pnptr);
	if (err) {
		return err;
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

static int
btc_insert_leaf(struct silofs_btree_ctx *btc, const struct silofs_pnptr *pnptr)
{
	int err;

	err = btc_require_path(btc);
	if (err) {
		return err;
	}

	// XXX
	(void)pnptr;
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_resolve_vtop(struct silofs_task_ctx *task,
                        const struct silofs_vaddr *vaddr,
                        struct silofs_pnptr *out_pnptr)
{
	struct silofs_btree_ctx btc;
	int err;

	btc_init(&btc, task, vaddr);
	err = btc_resolve_leaf(&btc, out_pnptr);
	btc_fini(&btc);
	return err;
}

int silofs_insmap_vtop(struct silofs_task_ctx *task,
                       const struct silofs_vaddr *vaddr,
                       const struct silofs_pnptr *pnptr)
{
	struct silofs_btree_ctx btc;
	int err;

	btc_init(&btc, task, vaddr);
	err = btc_insert_leaf(&btc, pnptr);
	btc_fini(&btc);
	return err;
}
