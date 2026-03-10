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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void bti_incref(struct silofs_btnode_info *bti)
{
	if (likely(bti != nullptr)) {
		silofs_pni_incref(&bti->btn_pni);
	}
}

static void bti_decref(struct silofs_btnode_info *bti)
{
	if (likely(bti != nullptr)) {
		silofs_pni_decref(&bti->btn_pni);
	}
}

static void bti_self(const struct silofs_btnode_info *bti,
                     struct silofs_btnptr *out_btnptr)
{
	if (likely(bti != nullptr)) {
		silofs_bti_self(bti, out_btnptr);
	} else {
		silofs_btnptr_reset(out_btnptr);
	}
}

static bool bti_isleaf(const struct silofs_btnode_info *bti)
{
	return (silofs_bti_height(bti) == 1);
}

static bool bti_has_room(const struct silofs_btnode_info *bti)
{
	return !silofs_bti_isfull(bti);
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

struct silofs_btree_path {
	struct silofs_btnode_info *bti[SILOFS_BTREE_HEIGHT_MAX];
	size_t cnt;
};

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
	bpath->bti[bpath->cnt] = bti;
	bpath->cnt += 1;
	bti_incref(bti);
}

static void bpath_push_front(struct silofs_btree_path *bpath,
                             struct silofs_btnode_info *bti)
{
	silofs_assert_lt(bpath->cnt, ARRAY_SIZE(bpath->bti));

	for (size_t i = bpath->cnt; i > 0; --i) {
		bpath->bti[i] = bpath->bti[i - 1];
	}
	bpath->bti[0] = bti;
	bpath->cnt += 1;
	bti_incref(bti);
}

static void bpath_replace(struct silofs_btree_path *bpath, size_t slot,
                          struct silofs_btnode_info *bti_new)
{
	struct silofs_btnode_info *bti_old = bpath->bti[slot];

	silofs_assert_lt(slot, bpath->cnt);
	bpath->bti[slot] = bti_new;
	bti_incref(bti_new);
	bti_decref(bti_old);
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

struct silofs_btree_ctx {
	struct silofs_btree_path bpath;
	struct silofs_vaddr vaddr;
	struct silofs_task_ctx *task;
	struct silofs_uber_info *ubi;
	uint64_t key;
};

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
btc_path_front(const struct silofs_btree_ctx *btc)
{
	return btc_path_btnode_at(btc, 0);
}

static void
btc_path_append(struct silofs_btree_ctx *btc, struct silofs_btnode_info *bti)
{
	bpath_append(&btc->bpath, bti);
}

static void btc_path_push_front(struct silofs_btree_ctx *btc,
                                struct silofs_btnode_info *bti)
{
	bpath_push_front(&btc->bpath, bti);
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

static void
btc_path_post_split(struct silofs_btree_ctx *btc, size_t parent_idx,
                    struct silofs_btnode_info *bti_next, uint64_t key)
{
	if (btc_key(btc) >= key) {
		btc_path_replace_at(btc, parent_idx + 1, bti_next);
	}
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

static int btc_resolve_child(const struct silofs_btree_ctx *btc,
                             const struct silofs_btnode_info *bti,
                             struct silofs_btnptr *out_btnptr)
{
	return silofs_bti_resolve(bti, btc_key(btc), out_btnptr);
}

static int btc_stage_child_btnode(const struct silofs_btree_ctx *btc,
                                  struct silofs_btnode_info *parent_bti,
                                  struct silofs_btnode_info **out_bti)
{
	struct silofs_btnptr btnptr;
	struct silofs_btnode_info *bti = nullptr;
	int err;

	err = btc_resolve_child(btc, parent_bti, &btnptr);
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
	struct silofs_btnode_info *bti = btc_path_front(btc);
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
                               const struct silofs_pnptr *pnptr,
                               struct silofs_btnode_info **out_bti)
{
	return silofs_spawn_btnode(btc->task, pnptr, out_bti);
}

static int btc_carve_btspace(const struct silofs_btree_ctx *btc,
                             struct silofs_pnptr *out_pnptr)
{
	/* TODO: check avail space, RDONLY etc */
	return silofs_carve_next_btspace(btc->task, btc_vspace(btc),
	                                 out_pnptr);
}

static int btc_spawn_btnode(const struct silofs_btree_ctx *btc,
                            struct silofs_btnode_info **out_bti)
{
	struct silofs_pnptr pnptr = { .paddr.pos = -1 };
	int err;

	err = btc_carve_btspace(btc, &pnptr);
	if (err) {
		return err;
	}
	err = btc_spawn_btnode_at(btc, &pnptr, out_bti);
	if (err) {
		return err;
	}
	return 0;
}

static int btc_spawn_btroot(const struct silofs_btree_ctx *btc, size_t height,
                            struct silofs_btnode_info **out_bti)
{
	int err;

	err = btc_spawn_btnode(btc, out_bti);
	if (err) {
		return err;
	}
	silofs_bti_set_height(*out_bti, height);
	silofs_bti_mark_root(*out_bti);
	return 0;
}

static int btc_spawn_sibling_btnode(const struct silofs_btree_ctx *btc,
                                    const struct silofs_btnode_info *bti,
                                    struct silofs_btnode_info **out_bti)
{
	const size_t height = silofs_bti_height(bti);
	int err;

	err = btc_spawn_btnode(btc, out_bti);
	if (err) {
		return err;
	}
	silofs_bti_set_height(*out_bti, height);
	return 0;
}

static int btc_spawn_clone_btnode(const struct silofs_btree_ctx *btc,
                                  const struct silofs_btnode_info *bti_src,
                                  struct silofs_btnode_info **out_bti)
{
	int err;

	err = btc_spawn_btnode(btc, out_bti);
	if (err) {
		return err;
	}
	silofs_clone_btnode(bti_src, *out_bti);
	return 0;
}

static bool btc_is_writeable_btnode(const struct silofs_btree_ctx *btc,
                                    const struct silofs_btnode_info *bti)
{
	return silofs_ubi_onsame_layer(btc->ubi, bti);
}

static int btc_update_parent_at(const struct silofs_btree_ctx *btc, size_t i,
                                const struct silofs_btnode_info *bti_cur,
                                const struct silofs_btnode_info *bti_new)
{
	struct silofs_btnptr btnptr_cur, btnptr_new;
	struct silofs_btnode_info *bti_parent = nullptr;

	bti_self(bti_cur, &btnptr_cur);
	bti_self(bti_new, &btnptr_new);

	bti_parent = btc_path_btnode_at(btc, i);
	return silofs_bti_relink(bti_parent, &btnptr_cur, &btnptr_new);
}

static void btc_update_btroot(const struct silofs_btree_ctx *btc,
                              const struct silofs_btnode_info *bti_new)
{
	silofs_ubi_set_btroot_by(btc->ubi, bti_new);
}

static int btc_require_writable_btroot(struct silofs_btree_ctx *btc)
{
	struct silofs_btnode_info *bti_cur = nullptr;
	struct silofs_btnode_info *bti_new = nullptr;
	int err;

	bti_cur = btc_path_btnode_at(btc, 0);
	if (btc_is_writeable_btnode(btc, bti_cur)) {
		return 0;
	}
	err = btc_spawn_clone_btnode(btc, bti_cur, &bti_new);
	if (err) {
		return err;
	}
	btc_update_btroot(btc, bti_new);
	btc_path_replace_at(btc, 0, bti_new);
	return 0;
}

static int btc_require_writable_btnodes(struct silofs_btree_ctx *btc)
{
	struct silofs_btnode_info *bti_cur = nullptr;
	struct silofs_btnode_info *bti_new = nullptr;
	int err;

	for (size_t i = 1; i < btc->bpath.cnt; ++i) {
		bti_cur = btc_path_btnode_at(btc, i);
		if (btc_is_writeable_btnode(btc, bti_cur)) {
			continue;
		}
		err = btc_spawn_clone_btnode(btc, bti_cur, &bti_new);
		if (err) {
			return err;
		}
		err = btc_update_parent_at(btc, i - 1, bti_cur, bti_new);
		if (err) {
			return err;
		}
		btc_path_replace_at(btc, i, bti_new);
	}
	return 0;
}

static int btc_require_writable(struct silofs_btree_ctx *btc)
{
	int err;

	err = btc_require_writable_btroot(btc);
	if (err) {
		return err;
	}
	err = btc_require_writable_btnodes(btc);
	if (err) {
		return err;
	}
	return 0;
}

static int
btc_split_btnode(struct silofs_btree_ctx *btc, struct silofs_btnode_info *bti,
                 struct silofs_btnode_info **out_bti, uint64_t *out_key)
{
	int err;

	err = btc_spawn_sibling_btnode(btc, bti, out_bti);
	if (err) {
		return err;
	}
	*out_key = silofs_split_btnode(bti, *out_bti);
	return 0;
}

static void
rebind_btchilds(struct silofs_btnode_info *bti_parent,
                const struct silofs_btnode_info *bti_left,
                const struct silofs_btnode_info *bti_right, uint64_t key)
{
	struct silofs_btnptr btnptr_left;
	struct silofs_btnptr btnptr_right;

	bti_self(bti_left, &btnptr_left);
	bti_self(bti_right, &btnptr_right);
	silofs_rebind_btchilds(bti_parent, &btnptr_left, &btnptr_right, key);
}

static int
btc_increase_btree(struct silofs_btree_ctx *btc,
                   const struct silofs_btnode_info *bti_cur,
                   const struct silofs_btnode_info *bti_nxt, uint64_t key)
{
	struct silofs_btnode_info *bti_root;
	const size_t cur_height = silofs_bti_height(bti_cur);
	int err;

	err = btc_spawn_btroot(btc, cur_height + 1, &bti_root);
	if (err) {
		return err;
	}
	rebind_btchilds(bti_root, bti_cur, bti_nxt, key);
	btc_path_push_front(btc, bti_root);

	btc_update_btroot(btc, bti_root);
	return 0;
}

static int btc_require_insertable_btroot(struct silofs_btree_ctx *btc)
{
	struct silofs_btnode_info *bti;
	struct silofs_btnode_info *bti_nxt;
	uint64_t key;
	int err;

	bti = btc_path_front(btc);
	if (bti_has_room(bti)) {
		return 0;
	}
	err = btc_split_btnode(btc, bti, &bti_nxt, &key);
	if (err) {
		return err;
	}
	err = btc_increase_btree(btc, bti, bti_nxt, key);
	if (err) {
		return err;
	}
	btc_path_post_split(btc, 0, bti_nxt, key);
	return 0;
}

static int btc_require_insertable_at(struct silofs_btree_ctx *btc, size_t i)
{
	struct silofs_btnode_info *bti_parent = nullptr;
	struct silofs_btnode_info *bti_cur    = nullptr;
	struct silofs_btnode_info *bti_nxt    = nullptr;
	uint64_t key;
	int err;

	bti_parent = btc_path_btnode_at(btc, i);
	bti_cur    = btc_path_btnode_at(btc, i + 1);
	if (bti_has_room(bti_cur)) {
		return 0;
	}
	err = btc_split_btnode(btc, bti_cur, &bti_nxt, &key);
	if (err) {
		return err;
	}
	rebind_btchilds(bti_parent, bti_cur, bti_nxt, key);
	btc_path_post_split(btc, i, bti_nxt, key);
	return 0;
}

static int btc_require_insertable_btnodes(struct silofs_btree_ctx *btc)
{
	int err;

	for (size_t i = 0; i < btc->bpath.cnt - 1; ++i) {
		err = btc_require_insertable_at(btc, i);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int btc_require_insertable(struct silofs_btree_ctx *btc)
{
	int err;

	err = btc_require_insertable_btroot(btc);
	if (err) {
		return err;
	}
	err = btc_require_insertable_btnodes(btc);
	if (err) {
		return err;
	}
	return 0;
}

static int btc_resolve_leaf_by(const struct silofs_btree_ctx *btc,
                               const struct silofs_btnode_info *bti,
                               struct silofs_pnptr *out_pnptr)
{
	struct silofs_btnptr btnptr = {};
	int err;

	err = btc_resolve_child(btc, bti, &btnptr);
	if (err) {
		return err;
	}
	silofs_assert_eq(btnptr.nsub_btnodes, 0);
	silofs_pnptr_assign(out_pnptr, &btnptr.base);
	return 0;
}

static int
btc_resolve_vtop(struct silofs_btree_ctx *btc, struct silofs_pnptr *out_pnptr)
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

static int btc_require_cap_insert(struct silofs_btree_ctx *btc)
{
	int err;

	err = btc_stage_path(btc);
	if (err) {
		return err;
	}
	err = btc_require_writable(btc);
	if (err) {
		return err;
	}
	err = btc_require_insertable(btc);
	if (err) {
		return err;
	}
	return 0;
}

static int btc_insert_at_leaf(struct silofs_btree_ctx *btc,
                              const struct silofs_pnptr *pnptr)
{
	struct silofs_btnptr btnptr    = {};
	struct silofs_btnode_info *bti = btc_path_last(btc);

	if (!bti_isleaf(bti)) {
		return -SILOFS_EBUG;
	}
	silofs_btnptr_setup(&btnptr, pnptr);
	return silofs_bti_insert(bti, btc_key(btc), &btnptr);
}

static int
btc_insert_vtop(struct silofs_btree_ctx *btc, const struct silofs_pnptr *pnptr)
{
	int err;

	err = btc_require_cap_insert(btc);
	if (err) {
		return err;
	}
	err = btc_insert_at_leaf(btc, pnptr);
	if (err) {
		return err;
	}
	return 0;
}

static int btc_require_cap_update(struct silofs_btree_ctx *btc)
{
	int err;

	err = btc_stage_path(btc);
	if (err) {
		return err;
	}
	err = btc_require_writable(btc);
	if (err) {
		return err;
	}
	return 0;
}

static int btc_update_at_leaf(struct silofs_btree_ctx *btc,
                              const struct silofs_pnptr *pnptr)
{
	struct silofs_btnptr btnptr    = {};
	struct silofs_btnode_info *bti = btc_path_last(btc);

	if (!bti_isleaf(bti)) {
		return -SILOFS_EBUG;
	}
	silofs_btnptr_setup(&btnptr, pnptr);
	return silofs_bti_update(bti, btc_key(btc), &btnptr);
}

static int
btc_update_vtop(struct silofs_btree_ctx *btc, const struct silofs_pnptr *pnptr)
{
	int err;

	err = btc_require_cap_update(btc);
	if (err) {
		return err;
	}
	err = btc_update_at_leaf(btc, pnptr);
	if (err) {
		return err;
	}
	return 0;
}

static int btc_require_cap_remove(struct silofs_btree_ctx *btc)
{
	int err;

	err = btc_stage_path(btc);
	if (err) {
		return err;
	}
	err = btc_require_writable(btc);
	if (err) {
		return err;
	}
	return 0;
}

static int btc_remove_at_leaf(struct silofs_btree_ctx *btc)
{
	struct silofs_btnode_info *bti = btc_path_last(btc);

	return silofs_bti_remove(bti, btc_key(btc));
}

static int btc_remove_vtop(struct silofs_btree_ctx *btc)
{
	int err;

	err = btc_require_cap_remove(btc);
	if (err) {
		return err;
	}
	err = btc_remove_at_leaf(btc);
	if (err) {
		return err;
	}
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
	err = btc_resolve_vtop(&btc, out_pnptr);
	btc_fini(&btc);
	return err;
}

int silofs_insert_vtop(struct silofs_task_ctx *task,
                       const struct silofs_vaddr *vaddr,
                       const struct silofs_pnptr *pnptr)
{
	struct silofs_btree_ctx btc;
	int err;

	btc_init(&btc, task, vaddr);
	err = btc_insert_vtop(&btc, pnptr);
	btc_fini(&btc);
	return err;
}

int silofs_update_vtop(struct silofs_task_ctx *task,
                       const struct silofs_vaddr *vaddr,
                       const struct silofs_pnptr *pnptr)
{
	struct silofs_btree_ctx btc;
	int err;

	btc_init(&btc, task, vaddr);
	err = btc_update_vtop(&btc, pnptr);
	btc_fini(&btc);
	return err;
}

int silofs_remove_vtop(struct silofs_task_ctx *task,
                       const struct silofs_vaddr *vaddr)
{
	struct silofs_btree_ctx btc;
	int err;

	btc_init(&btc, task, vaddr);
	err = btc_remove_vtop(&btc);
	btc_fini(&btc);
	return err;
}
