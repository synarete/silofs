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
#include <silofs/base.h>
#include <silofs/addr.h>
#include <silofs/pv.h>

static enum silofs_btnodef btn_flags(const struct silofs_btree_node *btn)
{
	const uint32_t f = silofs_le32_to_cpu(btn->btn_flags);

	return (enum silofs_btnodef)f;
}

static void btn_set_flags(struct silofs_btree_node *btn, enum silofs_btnodef f)
{
	btn->btn_flags = silofs_cpu_to_le32((uint32_t)f);
}

static void btn_add_flags(struct silofs_btree_node *btn, enum silofs_btnodef f)
{
	btn_set_flags(btn, f | btn_flags(btn));
}

static enum silofs_vtype btn_vspace(const struct silofs_btree_node *btn)
{
	const unsigned vspace = btn->btn_vspace;

	return (enum silofs_vtype)vspace;
}

static void
btn_set_vspace(struct silofs_btree_node *btn, enum silofs_vtype vspace)
{
	btn->btn_vspace = (uint8_t)vspace;
}

static size_t btn_height(const struct silofs_btree_node *btn)
{
	return btn->btn_height;
}

static void btn_set_height(struct silofs_btree_node *btn, size_t height)
{
	silofs_assert_le(height, SILOFS_BTREE_HEIGHT_MAX);
	silofs_assert_gt(height, 0);
	btn->btn_height = (uint8_t)height;
}

static size_t btn_nkeys(const struct silofs_btree_node *btn)
{
	return silofs_le16_to_cpu(btn->btn_nkeys);
}

static void btn_set_nkeys(struct silofs_btree_node *btn, size_t nkeys)
{
	STATICASSERT_LT(ARRAY_SIZE(btn->btn_key), UINT8_MAX);
	silofs_assert_le(nkeys, ARRAY_SIZE(btn->btn_key));

	btn->btn_nkeys = silofs_cpu_to_le16((uint16_t)nkeys);
}

static void btn_inc_nkeys(struct silofs_btree_node *btn)
{
	btn_set_nkeys(btn, btn_nkeys(btn) + 1);
}

static void btn_dec_nkeys(struct silofs_btree_node *btn)
{
	btn_set_nkeys(btn, btn_nkeys(btn) - 1);
}

static size_t btn_nkeys_max(const struct silofs_btree_node *btn)
{
	return ARRAY_SIZE(btn->btn_key);
}

static size_t btn_nfree_keys(const struct silofs_btree_node *btn)
{
	const size_t nkeys     = btn_nkeys(btn);
	const size_t nkeys_max = btn_nkeys_max(btn);

	silofs_assert_le(nkeys, nkeys_max);
	return (nkeys_max - nkeys);
}

static uint64_t btn_key_at(const struct silofs_btree_node *btn, size_t slot)
{
	silofs_assert_lt(slot, btn_nkeys_max(btn));

	return silofs_le64_to_cpu(btn->btn_key[slot]);
}

static bool
btn_has_key_at(const struct silofs_btree_node *btn, size_t slot, uint64_t key)
{
	const size_t nkeys = btn_nkeys(btn);

	return (slot < nkeys) && (btn_key_at(btn, slot) == key);
}

static void
btn_set_key_at(struct silofs_btree_node *btn, size_t slot, uint64_t key)
{
	silofs_assert_lt(slot, ARRAY_SIZE(btn->btn_key));

	btn->btn_key[slot] = silofs_cpu_to_le64(key);
}

static void btn_reset_key_at(struct silofs_btree_node *btn, size_t slot)
{
	btn_set_key_at(btn, slot, SILOFS_BTREE_KEY_NULL);
}

static void btn_reset_keys(struct silofs_btree_node *btn)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(btn->btn_key); ++slot) {
		btn_reset_key_at(btn, slot);
	}
}

static void btn_append_key(struct silofs_btree_node *btn, uint64_t key)
{
	const size_t nkeys = btn_nkeys(btn);

	silofs_assert_lt(nkeys, btn_nkeys_max(btn));
	btn_set_key_at(btn, nkeys, key);
	btn_inc_nkeys(btn);
}

static void
btn_insert_key_at(struct silofs_btree_node *btn, size_t slot, uint64_t key)
{
	const size_t nkeys = btn_nkeys(btn);

	silofs_assert_lt(nkeys, btn_nkeys_max(btn));
	for (size_t i = nkeys; i > slot; --i) {
		btn_set_key_at(btn, i, btn_key_at(btn, i - 1));
	}
	btn_set_key_at(btn, slot, key);
	btn_inc_nkeys(btn);
}

static void btn_remove_key_at(struct silofs_btree_node *btn, size_t slot)
{
	const size_t nkeys = btn_nkeys(btn);

	silofs_assert_lt(slot, nkeys);
	for (size_t i = slot + 1; i < nkeys; ++i) {
		btn_set_key_at(btn, i - 1, btn_key_at(btn, i));
	}
	btn_reset_key_at(btn, nkeys - 1);
	btn_dec_nkeys(btn);
}

static size_t btn_nchilds(const struct silofs_btree_node *btn)
{
	return silofs_le16_to_cpu(btn->btn_nchilds);
}

static void btn_set_nchilds(struct silofs_btree_node *btn, size_t nchilds)
{
	STATICASSERT_LT(ARRAY_SIZE(btn->btn_child), UINT8_MAX);
	silofs_assert_le(nchilds, ARRAY_SIZE(btn->btn_child));

	btn->btn_nchilds = silofs_cpu_to_le16((uint16_t)nchilds);
}

static void btn_inc_nchilds(struct silofs_btree_node *btn)
{
	btn_set_nchilds(btn, btn_nchilds(btn) + 1);
}

static void btn_dec_nchilds(struct silofs_btree_node *btn)
{
	btn_set_nchilds(btn, btn_nchilds(btn) - 1);
}

static size_t btn_nchilds_max(const struct silofs_btree_node *btn)
{
	STATICASSERT_EQ(ARRAY_SIZE(btn->btn_child),
	                ARRAY_SIZE(btn->btn_key) + 1);

	return ARRAY_SIZE(btn->btn_child);
}

static void btn_child_at(const struct silofs_btree_node *btn, size_t slot,
                         struct silofs_pnptr *out_pnptr)
{
	silofs_assert_lt(slot, ARRAY_SIZE(btn->btn_child));
	silofs_assert_lt(slot, btn_nchilds(btn));

	silofs_pnptr256b_xtoh(&btn->btn_child[slot], out_pnptr);
}

static void btn_set_child_at(struct silofs_btree_node *btn, size_t slot,
                             const struct silofs_pnptr *pnptr)
{
	silofs_assert_lt(slot, ARRAY_SIZE(btn->btn_child));

	silofs_pnptr256b_htox(&btn->btn_child[slot], pnptr);
}

static void btn_reset_child_at(struct silofs_btree_node *btn, size_t slot)
{
	btn_set_child_at(btn, slot, silofs_pnptr_none());
}

static void btn_reset_childs(struct silofs_btree_node *btn)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(btn->btn_child); ++slot) {
		btn_reset_child_at(btn, slot);
	}
}

static bool btn_has_child_at(const struct silofs_btree_node *btn, size_t slot,
                             const struct silofs_pnptr *pnptr)
{
	struct silofs_pnptr pnptr_at_slot;

	btn_child_at(btn, slot, &pnptr_at_slot);
	return silofs_pnptr_isequal(pnptr, &pnptr_at_slot);
}

static void btn_reset_keys_tail(struct silofs_btree_node *btn)
{
	const size_t nkeys_max = btn_nkeys_max(btn);
	const size_t nkeys     = btn_nkeys(btn);

	for (size_t slot = nkeys; slot < nkeys_max; ++slot) {
		btn_reset_key_at(btn, slot);
	}
}

static void btn_reset_childs_tail(struct silofs_btree_node *btn)
{
	const size_t nchilds_max = btn_nchilds_max(btn);
	const size_t nchilds     = btn_nchilds(btn);

	for (size_t slot = nchilds; slot < nchilds_max; ++slot) {
		btn_reset_child_at(btn, slot);
	}
}

static void btn_reset_tail(struct silofs_btree_node *btn)
{
	btn_reset_keys_tail(btn);
	btn_reset_childs_tail(btn);
}

static void btn_append_child(struct silofs_btree_node *btn,
                             const struct silofs_pnptr *pnptr)
{
	const size_t nchilds = btn_nchilds(btn);

	silofs_assert_lt(nchilds, btn_nchilds_max(btn));
	btn_set_child_at(btn, nchilds, pnptr);
	btn_inc_nchilds(btn);
}

static void btn_insert_child_at(struct silofs_btree_node *btn, size_t slot,
                                const struct silofs_pnptr *pnptr)
{
	const size_t nchilds = btn_nchilds(btn);

	silofs_assert_lt(nchilds, btn_nchilds_max(btn));

	for (size_t i = nchilds; i > slot; --i) {
		struct silofs_pnptr pnptr_j;

		btn_child_at(btn, i - 1, &pnptr_j);
		btn_set_child_at(btn, i, &pnptr_j);
	}
	btn_set_child_at(btn, slot, pnptr);
	btn_inc_nchilds(btn);
}

static void btn_remove_child_at(struct silofs_btree_node *btn, size_t slot)
{
	const size_t nchilds = btn_nchilds(btn);

	silofs_assert_le(nchilds, btn_nchilds_max(btn));
	silofs_assert_lt(slot, nchilds);

	for (size_t i = slot + 1; i < nchilds; ++i) {
		struct silofs_pnptr pnptr_i;

		btn_child_at(btn, i, &pnptr_i);
		btn_set_child_at(btn, i - 1, &pnptr_i);
	}
	btn_reset_child_at(btn, nchilds - 1);
	btn_dec_nchilds(btn);
}

static void btn_setup(struct silofs_btree_node *btn)
{
	btn_set_flags(btn, SILOFS_BTNODEF_NONE);
	btn_set_height(btn, 1);
	btn_set_nkeys(btn, 0);
	btn_set_nchilds(btn, 0);
	btn_reset_childs(btn);
	btn_reset_keys(btn);
}

static void btn_clone_keys(const struct silofs_btree_node *btn,
                           struct silofs_btree_node *btn_other)
{
	const size_t nkeys = btn_nkeys(btn);

	for (size_t slot = 0; slot < nkeys; ++slot) {
		btn_set_key_at(btn_other, slot, btn_key_at(btn, slot));
	}
	btn_set_nkeys(btn_other, nkeys);
}

static void btn_clone_childs(const struct silofs_btree_node *btn,
                             struct silofs_btree_node *btn_other)
{
	const size_t nchilds = btn_nchilds(btn);

	for (size_t slot = 0; slot < nchilds; ++slot) {
		struct silofs_pnptr pnptr;

		btn_child_at(btn, slot, &pnptr);
		btn_set_child_at(btn_other, slot, &pnptr);
	}
	btn_set_nchilds(btn_other, nchilds);
}

static void btn_clone_into(const struct silofs_btree_node *btn,
                           struct silofs_btree_node *btn_other)
{
	btn_setup(btn_other);
	btn_set_flags(btn_other, btn_flags(btn));
	btn_set_vspace(btn_other, btn_vspace(btn));
	btn_set_height(btn_other, btn_height(btn));
	btn_clone_keys(btn, btn_other);
	btn_clone_childs(btn, btn_other);
}

static bool btn_isleaf(const struct silofs_btree_node *btn)
{
	const size_t height = btn_height(btn);

	silofs_assert_gt(height, 0);
	silofs_assert_le(height, SILOFS_BTREE_HEIGHT_MAX);

	if (height == 1) {
		silofs_assert_eq(btn_nkeys(btn), btn_nchilds(btn));
	} else {
		silofs_assert_eq(btn_nkeys(btn) + 1, btn_nchilds(btn));
	}

	return (height == 1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

enum btn_find_mode {
	BTN_FIND_GE,
	BTN_FIND_EQ,
	BTN_FIND_GT,
};

static size_t btn_find_slot(const struct silofs_btree_node *btn, uint64_t key,
                            enum btn_find_mode mode)
{
	size_t hi = btn_nkeys(btn);
	size_t lo = 0;

	while (lo < hi) {
		const size_t mid    = lo + (hi - lo) / 2;
		const uint64_t skey = btn_key_at(btn, mid);

		if (key < skey) {
			hi = mid;
		} else if (key > skey) {
			lo = mid + 1;
		} else {
			return (mode == BTN_FIND_GT) ? mid + 1 : mid;
		}
	}
	return (mode == BTN_FIND_EQ) ? btn_nkeys(btn) : lo;
}

static size_t
btn_find_slot_ge(const struct silofs_btree_node *btn, uint64_t key)
{
	return btn_find_slot(btn, key, BTN_FIND_GE);
}

static size_t
btn_find_slot_eq(const struct silofs_btree_node *btn, uint64_t key)
{
	return btn_find_slot(btn, key, BTN_FIND_EQ);
}

static size_t
btn_find_slot_gt(const struct silofs_btree_node *btn, uint64_t key)
{
	return btn_find_slot(btn, key, BTN_FIND_GT);
}

static int btn_resolve_at_leaf(const struct silofs_btree_node *btn,
                               uint64_t key, struct silofs_pnptr *out_pnptr)
{
	const size_t nkeys = btn_nkeys(btn);
	size_t slot;

	slot = btn_find_slot_eq(btn, key);
	if (slot >= nkeys) {
		return -SILOFS_ENOENT;
	}
	btn_child_at(btn, slot, out_pnptr);
	return 0;
}

static int btn_resolve_at_node(const struct silofs_btree_node *btn,
                               uint64_t key, struct silofs_pnptr *out_pnptr)
{
	size_t slot;

	slot = btn_find_slot_gt(btn, key);
	btn_child_at(btn, slot, out_pnptr);
	return 0;
}

static int btn_resolve(const struct silofs_btree_node *btn, uint64_t key,
                       struct silofs_pnptr *out_pnptr)
{
	int ret;

	if (btn_isleaf(btn)) {
		ret = btn_resolve_at_leaf(btn, key, out_pnptr);
	} else {
		ret = btn_resolve_at_node(btn, key, out_pnptr);
	}
	return ret;
}

static size_t btn_search_child(const struct silofs_btree_node *btn,
                               const struct silofs_pnptr *pnptr)
{
	const size_t nchilds = btn_nchilds(btn);

	silofs_assert_le(nchilds, btn_nchilds_max(btn));

	for (size_t slot = 0; slot < nchilds; ++slot) {
		if (btn_has_child_at(btn, slot, pnptr)) {
			return slot;
		}
	}
	return nchilds;
}

static void btn_insert_at(struct silofs_btree_node *btn, size_t slot,
                          uint64_t key, const struct silofs_pnptr *pnptr)
{
	btn_insert_child_at(btn, slot, pnptr);
	btn_insert_key_at(btn, slot, key);
}

static int btn_insert(struct silofs_btree_node *btn, uint64_t key,
                      const struct silofs_pnptr *pnptr)
{
	const size_t slot = btn_find_slot_ge(btn, key);

	if (!btn_nfree_keys(btn)) {
		return -SILOFS_ENOSPC;
	}
	if (btn_has_key_at(btn, slot, key)) {
		return -SILOFS_EEXIST;
	}
	btn_insert_at(btn, slot, key, pnptr);
	return 0;
}

static int btn_update(struct silofs_btree_node *btn, uint64_t key,
                      const struct silofs_pnptr *pnptr)
{
	const size_t slot = btn_find_slot_ge(btn, key);

	if (!btn_has_key_at(btn, slot, key)) {
		return -SILOFS_ENOENT;
	}
	btn_set_child_at(btn, slot, pnptr);
	return 0;
}

static size_t
btn_resolve_child_slot(const struct silofs_btree_node *btn, uint64_t key)
{
	size_t slot;

	if (btn_isleaf(btn)) {
		slot = btn_find_slot_eq(btn, key);
	} else {
		slot = btn_find_slot_gt(btn, key);
	}
	return slot;
}

static int btn_remove(struct silofs_btree_node *btn, uint64_t key)
{
	const size_t nkeys = btn_nkeys(btn);
	size_t slot;

	slot = btn_resolve_child_slot(btn, key);
	if (slot >= nkeys) {
		return -SILOFS_ENOENT;
	}
	btn_remove_key_at(btn, slot);
	btn_remove_child_at(btn, slot);
	return 0;
}

static int
btn_relink(struct silofs_btree_node *btn, const struct silofs_pnptr *cur,
           const struct silofs_pnptr *alt)
{
	size_t slot;

	slot = btn_search_child(btn, cur);
	if (slot >= btn_nchilds(btn)) {
		return -SILOFS_ENOENT;
	}
	btn_set_child_at(btn, slot, alt);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t btn_split_slot(const struct silofs_btree_node *btn)
{
	const size_t nkeys = btn_nkeys(btn);

	STATICASSERT_EQ(ARRAY_SIZE(btn->btn_key) % 2, 1);

	return nkeys / 2;
}

static void btn_trim_leaf(struct silofs_btree_node *btn, size_t nkeys)
{
	btn_set_nkeys(btn, nkeys);
	btn_set_nchilds(btn, nkeys);
}

static void btn_trim_node(struct silofs_btree_node *btn, size_t nkeys)
{
	btn_set_nkeys(btn, nkeys);
	btn_set_nchilds(btn, nkeys + 1);
}

static void btn_trim(struct silofs_btree_node *btn, size_t nkeys)
{
	if (btn_isleaf(btn)) {
		btn_trim_leaf(btn, nkeys);
	} else {
		btn_trim_node(btn, nkeys);
	}
	btn_reset_tail(btn);
}

static void
btn_insert_to(const struct silofs_btree_node *btn_from, size_t from_slot,
              struct silofs_btree_node *btn_to, size_t to_slot)
{
	struct silofs_pnptr pnptr;
	const uint64_t key = btn_key_at(btn_from, from_slot);

	btn_child_at(btn_from, from_slot, &pnptr);
	btn_insert_at(btn_to, to_slot, key, &pnptr);
}

static void btn_split_leaf(struct silofs_btree_node *btn_from, size_t mid_slot,
                           struct silofs_btree_node *btn_to)
{
	const size_t nkeys = btn_nkeys(btn_from);
	size_t from = mid_slot, to = 0;

	while (from < nkeys) {
		btn_insert_to(btn_from, from++, btn_to, to++);
	}
	btn_trim(btn_from, mid_slot);
}

static void btn_split_node(struct silofs_btree_node *btn_from, size_t mid_slot,
                           struct silofs_btree_node *btn_to)
{
	const size_t nkeys   = btn_nkeys(btn_from);
	const size_t nchilds = btn_nchilds(btn_from);

	/* copy children within range [mid+1, nchilds) */
	for (size_t i = mid_slot + 1; i < nchilds; ++i) {
		struct silofs_pnptr pnptr;

		btn_child_at(btn_from, i, &pnptr);
		btn_append_child(btn_to, &pnptr);
	}

	/* copy keys within range [mid+1, nkeys) */
	for (size_t i = mid_slot + 1; i < nkeys; ++i) {
		btn_append_key(btn_to, btn_key_at(btn_from, i));
	}

	/* trim source: keeps keys [0..mid_slot) */
	btn_trim(btn_from, mid_slot);

	/* clear target's tail */
	btn_reset_tail(btn_to);
}

static void btn_split_at(struct silofs_btree_node *btn_from, size_t slot,
                         struct silofs_btree_node *btn_to)
{
	if (btn_isleaf(btn_from)) {
		btn_split_leaf(btn_from, slot, btn_to);
	} else {
		btn_split_node(btn_from, slot, btn_to);
	}
}

static uint64_t split_btnode(struct silofs_btree_node *btn_from,
                             struct silofs_btree_node *btn_to)
{
	const size_t slot   = btn_split_slot(btn_from);
	const uint64_t skey = btn_key_at(btn_from, slot);

	btn_split_at(btn_from, slot, btn_to);
	return skey;
}

static void rebind_btchilds(struct silofs_btree_node *btn_parent,
                            const struct silofs_pnptr *left,
                            const struct silofs_pnptr *right, uint64_t key)
{
	const size_t nkeys = btn_nkeys(btn_parent);
	size_t slot;

	if (nkeys == 0) {
		/* case 1: fresh new empty node */
		btn_append_child(btn_parent, left);
		btn_append_key(btn_parent, key);
		btn_append_child(btn_parent, right);
	} else {
		/* case 2: left exists, add right */
		slot = btn_search_child(btn_parent, left);
		silofs_assert_lt(slot, btn_nchilds(btn_parent));
		btn_insert_child_at(btn_parent, slot + 1, right);
		btn_insert_key_at(btn_parent, slot, key);
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

const struct silofs_pnptr *
silofs_bti_self(const struct silofs_btnode_info *bti)
{
	return silofs_pni_self(&bti->btn_pni);
}

void silofs_bti_incref(struct silofs_btnode_info *bti)
{
	silofs_pni_incref(&bti->btn_pni);
}

void silofs_bti_decref(struct silofs_btnode_info *bti)
{
	silofs_pni_decref(&bti->btn_pni);
}

static void bti_markdirty(struct silofs_btnode_info *bti)
{
	silofs_pni_markdirty(&bti->btn_pni);
}

static void bti_markdirty2(struct silofs_btnode_info *bti1,
                           struct silofs_btnode_info *bti2)
{
	bti_markdirty(bti1);
	bti_markdirty(bti2);
}

void silofs_bti_markdirty(struct silofs_btnode_info *bti)
{
	bti_markdirty(bti);
}

void silofs_bti_cleardirty(struct silofs_btnode_info *bti)
{
	silofs_pni_cleardirty(&bti->btn_pni);
}

enum silofs_vtype silofs_bti_vspace(const struct silofs_btnode_info *bti)
{
	return btn_vspace(bti->btn);
}

void silofs_bti_set_vspace(struct silofs_btnode_info *bti,
                           enum silofs_vtype vspace)
{
	silofs_assert(silofs_vtype_isvnode(vspace));
	btn_set_vspace(bti->btn, vspace);
	bti_markdirty(bti);
}

void silofs_bti_mark_root(struct silofs_btnode_info *bti)
{
	btn_add_flags(bti->btn, SILOFS_BTNODEF_ROOT);
	bti_markdirty(bti);
}

bool silofs_bti_marked_root(const struct silofs_btnode_info *bti)
{
	const enum silofs_btnodef flags = btn_flags(bti->btn);

	return ((flags & SILOFS_BTNODEF_ROOT) > 0);
}

size_t silofs_bti_height(const struct silofs_btnode_info *bti)
{
	return btn_height(bti->btn);
}

void silofs_bti_set_height(struct silofs_btnode_info *bti, size_t height)
{
	btn_set_height(bti->btn, height);
	bti_markdirty(bti);
}

static size_t bti_nkeys(const struct silofs_btnode_info *bti)
{
	return btn_nkeys(bti->btn);
}

static bool btkey_isvalid(uint64_t key)
{
	return (key != SILOFS_BTREE_KEY_NULL);
}

static bool bti_isleaf(const struct silofs_btnode_info *bti)
{
	return btn_isleaf(bti->btn);
}

int silofs_bti_resolve(const struct silofs_btnode_info *bti, uint64_t key,
                       struct silofs_pnptr *out_pnptr)
{
	silofs_pnptr_reset(out_pnptr);
	return btn_resolve(bti->btn, key, out_pnptr);
}

int silofs_bti_insert(struct silofs_btnode_info *bti, uint64_t key,
                      const struct silofs_pnptr *pnptr)
{
	int err;

	silofs_assert(btkey_isvalid(key));

	err = btn_insert(bti->btn, key, pnptr);
	if (err) {
		return err;
	}
	bti_markdirty(bti);
	return 0;
}

int silofs_bti_update(struct silofs_btnode_info *bti, uint64_t key,
                      const struct silofs_pnptr *pnptr)
{
	int err;

	silofs_assert(btkey_isvalid(key));

	err = btn_update(bti->btn, key, pnptr);
	if (err) {
		return err;
	}
	bti_markdirty(bti);
	return 0;
}

int silofs_bti_relink(struct silofs_btnode_info *bti,
                      const struct silofs_pnptr *cur,
                      const struct silofs_pnptr *alt)
{
	int err;

	err = btn_relink(bti->btn, cur, alt);
	if (err) {
		return err;
	}
	bti_markdirty(bti);
	return 0;
}

int silofs_bti_remove(struct silofs_btnode_info *bti, uint64_t key)
{
	int err;

	silofs_assert(btkey_isvalid(key));

	if (!bti_isleaf(bti)) {
		return -SILOFS_EOPNOTSUPP;
	}
	err = btn_remove(bti->btn, key);
	if (err) {
		return err;
	}
	bti_markdirty(bti);
	return 0;
}

bool silofs_bti_isfull(const struct silofs_btnode_info *bti)
{
	return btn_nkeys(bti->btn) == btn_nkeys_max(bti->btn);
}

void silofs_bti_update_spawned(struct silofs_btnode_info *bti)
{
	btn_setup(bti->btn);
	bti_markdirty(bti);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_validate_btnode(const struct silofs_btnode_info *bti)
{
	const size_t height = silofs_bti_height(bti);

	if ((height < SILOFS_BTREE_HEIGHT_MIN) || //
	    (height > SILOFS_BTREE_HEIGHT_MAX)) {
		log_warn("bad btnode: height=%zu", height);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

uint64_t silofs_split_btnode(struct silofs_btnode_info *bti_from,
                             struct silofs_btnode_info *bti_to)
{
	uint64_t mkey;

	silofs_assert_eq(bti_nkeys(bti_from), SILOFS_BTREE_NODE_NKEYS);
	silofs_assert_eq(bti_nkeys(bti_to), 0);

	mkey = split_btnode(bti_from->btn, bti_to->btn);
	bti_markdirty2(bti_from, bti_to);
	return mkey;
}

void silofs_rebind_btchilds(struct silofs_btnode_info *bti_parent,
                            const struct silofs_pnptr *left,
                            const struct silofs_pnptr *right, uint64_t key)
{
	rebind_btchilds(bti_parent->btn, left, right, key);
	bti_markdirty(bti_parent);
}

void silofs_clone_btnode(const struct silofs_btnode_info *bti,
                         struct silofs_btnode_info *bti_other)
{
	btn_clone_into(bti->btn, bti_other->btn);
	silofs_bti_markdirty(bti_other);
}
