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
#include "infra.h"
#include "addr.h"
#include "btnode.h"

static enum silofs_pnodef btn_flags(const struct silofs_btree_node *btn)
{
	const uint32_t f = silofs_le32_to_cpu(btn->btn_flags);

	return (enum silofs_pnodef)f;
}

static void btn_set_flags(struct silofs_btree_node *btn, enum silofs_pnodef f)
{
	btn->btn_flags = silofs_cpu_to_le32((uint32_t)f);
}

static void btn_add_flags(struct silofs_btree_node *btn, enum silofs_pnodef f)
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
	return silofs_le16_to_cpu(btn->btn_height);
}

static void btn_set_height(struct silofs_btree_node *btn, size_t height)
{
	silofs_assert_le(height, SILOFS_BTREE_HEIGHT_MAX);
	silofs_assert_gt(height, 0);
	btn->btn_height = silofs_cpu_to_le16((uint16_t)height);
}

static bool btn_isleaf(const struct silofs_btree_node *btn)
{
	const size_t height = btn_height(btn);

	silofs_assert_gt(height, 0);
	silofs_assert_le(height, SILOFS_BTREE_HEIGHT_MAX);

	return (height == 1);
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

static size_t btn_nchilds(const struct silofs_btree_node *btn)
{
	return btn_nkeys(btn) + 1;
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
	uint64_t jkey;

	silofs_assert_lt(nkeys, btn_nkeys_max(btn));
	for (size_t i = nkeys; i > slot; --i) {
		jkey = btn_key_at(btn, i - 1);
		btn_set_key_at(btn, i, jkey);
	}
	btn_set_key_at(btn, slot, key);
	btn_inc_nkeys(btn);
}

static void btn_remove_key_at(struct silofs_btree_node *btn, size_t slot)
{
	const size_t nkeys = btn_nkeys(btn);
	uint64_t ikey;

	silofs_assert_lt(slot, nkeys);
	for (size_t i = slot + 1; i < nkeys; ++i) {
		ikey = btn_key_at(btn, i);
		btn_set_key_at(btn, i - 1, ikey);
	}
	btn_reset_key_at(btn, nkeys - 1);
	btn_dec_nkeys(btn);
}

static size_t btn_nchilds_max(const struct silofs_btree_node *btn)
{
	STATICASSERT_EQ(ARRAY_SIZE(btn->btn_child),
	                ARRAY_SIZE(btn->btn_key) + 1);

	return ARRAY_SIZE(btn->btn_child);
}

static void btn_child_at(const struct silofs_btree_node *btn, size_t slot,
                         struct silofs_btnptr *out_btnptr)
{
	silofs_assert_lt(slot, ARRAY_SIZE(btn->btn_child));

	silofs_btnptr256b_xtoh(&btn->btn_child[slot], out_btnptr);
}

static void btn_set_child_at(struct silofs_btree_node *btn, size_t slot,
                             const struct silofs_btnptr *btnptr)
{
	silofs_assert_lt(slot, ARRAY_SIZE(btn->btn_child));

	silofs_btnptr256b_htox(&btn->btn_child[slot], btnptr);
}

static void btn_reset_child_at(struct silofs_btree_node *btn, size_t slot)
{
	btn_set_child_at(btn, slot, silofs_btnptr_none());
}

static void btn_reset_childs(struct silofs_btree_node *btn)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(btn->btn_child); ++slot) {
		btn_reset_child_at(btn, slot);
	}
}

static bool btn_has_child_at(const struct silofs_btree_node *btn, size_t slot,
                             const struct silofs_btnptr *btnptr)
{
	struct silofs_btnptr btnptr_at_slot;

	btn_child_at(btn, slot, &btnptr_at_slot);
	return silofs_pnptr_isequal(&btnptr->base, &btnptr_at_slot.base);
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

	for (size_t slot = nchilds + 1; slot < nchilds_max; ++slot) {
		btn_reset_child_at(btn, slot);
	}
}

static void btn_reset_tail(struct silofs_btree_node *btn)
{
	btn_reset_keys_tail(btn);
	btn_reset_childs_tail(btn);
}

static void btn_insert_child_at(struct silofs_btree_node *btn, size_t slot,
                                const struct silofs_btnptr *btnptr)
{
	struct silofs_btnptr jbtnptr;
	const size_t nchilds = btn_nchilds(btn);

	silofs_assert_lt(nchilds, btn_nchilds_max(btn));

	for (size_t i = nchilds; i > slot; --i) {
		btn_child_at(btn, i - 1, &jbtnptr);
		btn_set_child_at(btn, i, &jbtnptr);
	}
	btn_set_child_at(btn, slot, btnptr);
}

static void btn_remove_child_at(struct silofs_btree_node *btn, size_t slot)
{
	struct silofs_btnptr ibtnptr;
	const size_t nchilds = btn_nchilds(btn);

	silofs_assert_le(nchilds, btn_nchilds_max(btn));
	silofs_assert_lt(slot, nchilds);

	for (size_t i = slot + 1; i < nchilds; ++i) {
		btn_child_at(btn, i, &ibtnptr);
		btn_set_child_at(btn, i - 1, &ibtnptr);
	}
	btn_reset_child_at(btn, nchilds - 1);
}

static void btn_setup(struct silofs_btree_node *btn)
{
	btn_set_flags(btn, SILOFS_PNODEF_NONE);
	btn_set_height(btn, 1);
	btn_set_nkeys(btn, 0);
	btn_reset_childs(btn);
	btn_reset_keys(btn);
}

static void btn_clone_keys_into(const struct silofs_btree_node *btn,
                                struct silofs_btree_node *btn_other)
{
	const size_t nkeys = btn_nkeys(btn);
	uint64_t key;

	for (size_t slot = 0; slot < nkeys; ++slot) {
		key = btn_key_at(btn, slot);
		btn_set_key_at(btn_other, slot, key);
	}
	btn_set_nkeys(btn_other, nkeys);
}

static void btn_clone_childs_into(const struct silofs_btree_node *btn,
                                  struct silofs_btree_node *btn_other)
{
	struct silofs_btnptr btnptr;
	const size_t nchilds = btn_nchilds(btn);

	for (size_t slot = 0; slot < nchilds; ++slot) {
		btn_child_at(btn, slot, &btnptr);
		btn_set_child_at(btn_other, slot, &btnptr);
	}
}

static void btn_clone_into(const struct silofs_btree_node *btn,
                           struct silofs_btree_node *btn_other)
{
	btn_setup(btn_other);
	btn_set_flags(btn_other, btn_flags(btn));
	btn_set_vspace(btn_other, btn_vspace(btn));
	btn_set_height(btn_other, btn_height(btn));
	btn_clone_keys_into(btn, btn_other);
	btn_clone_childs_into(btn, btn_other);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t
btn_find_slot_ge(const struct silofs_btree_node *btn, uint64_t key)
{
	size_t lo = 0;
	size_t hi = btn_nkeys(btn);

	while (lo < hi) {
		const size_t mid    = lo + (hi - lo) / 2;
		const uint64_t skey = btn_key_at(btn, mid);

		if (key < skey) {
			hi = mid;
		} else if (key > skey) {
			lo = mid + 1;
		} else {
			return mid;
		}
	}
	return lo;
}

static size_t
btn_find_slot_eq(const struct silofs_btree_node *btn, uint64_t key)
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
			return mid;
		}
	}
	return btn_nkeys(btn);
}

static size_t
btn_find_slot_gt(const struct silofs_btree_node *btn, uint64_t key)
{
	size_t hi = btn_nkeys(btn);
	size_t lo = 0;

	while (lo < hi) {
		const size_t mid    = lo + (hi - lo) / 2;
		const uint64_t skey = btn_key_at(btn, mid);

		if (key < skey) {
			hi = mid;
		} else {
			lo = mid + 1;
		}
	}
	return lo;
}

static void btn_resolve_at_leaf(const struct silofs_btree_node *btn,
                                uint64_t key, struct silofs_btnptr *out_btnptr)
{
	const size_t nkeys = btn_nkeys(btn);
	size_t slot;

	slot = btn_find_slot_eq(btn, key);
	if (slot < nkeys) {
		btn_child_at(btn, slot, out_btnptr);
	}
}

static void btn_resolve_at_node(const struct silofs_btree_node *btn,
                                uint64_t key, struct silofs_btnptr *out_btnptr)
{
	size_t slot;

	slot = btn_find_slot_gt(btn, key);
	btn_child_at(btn, slot, out_btnptr);
}

static void btn_resolve(const struct silofs_btree_node *btn, uint64_t key,
                        struct silofs_btnptr *out_btnptr)
{
	if (btn_isleaf(btn)) {
		btn_resolve_at_leaf(btn, key, out_btnptr);
	} else {
		btn_resolve_at_node(btn, key, out_btnptr);
	}
}

static size_t btn_search_child(const struct silofs_btree_node *btn,
                               const struct silofs_btnptr *btnptr)
{
	const size_t nchilds = btn_nchilds(btn);

	silofs_assert_le(nchilds, btn_nchilds_max(btn));

	for (size_t slot = 0; slot < nchilds; ++slot) {
		if (btn_has_child_at(btn, slot, btnptr)) {
			return slot;
		}
	}
	return nchilds;
}

static bool btn_update(struct silofs_btree_node *btn,
                       const struct silofs_btnptr *btnptr_cur,
                       const struct silofs_btnptr *btnptr_new)
{
	size_t slot;
	bool res = false;

	slot = btn_search_child(btn, btnptr_cur);
	if (slot < btn_nchilds(btn)) {
		btn_set_child_at(btn, slot, btnptr_new);
		res = true;
	}
	return res;
}

static void btn_insert_at(struct silofs_btree_node *btn, size_t slot,
                          uint64_t key, const struct silofs_btnptr *btnptr)
{
	btn_insert_child_at(btn, slot, btnptr);
	btn_insert_key_at(btn, slot, key);
}

static void btn_insert(struct silofs_btree_node *btn, uint64_t key,
                       const struct silofs_btnptr *btnptr)
{
	const size_t slot = btn_find_slot_ge(btn, key);

	if (btn_has_key_at(btn, slot, key)) {
		/* update existing (no duplicates) */
		btn_set_child_at(btn, slot, btnptr);
	} else {
		btn_insert_at(btn, slot, key, btnptr);
	}
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

static void btn_remove(struct silofs_btree_node *btn, uint64_t key)
{
	const size_t nkeys = btn_nkeys(btn);
	size_t slot;

	slot = btn_resolve_child_slot(btn, key);
	if (slot < nkeys) {
		btn_remove_child_at(btn, slot);
		btn_remove_key_at(btn, slot);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t btn_split_slot(const struct silofs_btree_node *btn)
{
	const size_t nkeys = btn_nkeys(btn);

	STATICASSERT_EQ(ARRAY_SIZE(btn->btn_key) % 2, 1);

	return nkeys / 2;
}

static void btn_trim(struct silofs_btree_node *btn, size_t nkeys)
{
	btn_set_nkeys(btn, nkeys);
	btn_reset_tail(btn);
}

static void
btn_insert_to(const struct silofs_btree_node *btn_from, size_t slot_from,
              struct silofs_btree_node *btn_to, size_t slot_to)
{
	struct silofs_btnptr btnptr;
	const uint64_t key = btn_key_at(btn_from, slot_from);

	btn_child_at(btn_from, slot_from, &btnptr);
	btn_insert_at(btn_to, slot_to, key, &btnptr);
}

static void btn_split_leaf_into(struct silofs_btree_node *btn_from,
                                size_t base, struct silofs_btree_node *btn_to)
{
	const size_t nkeys = btn_nkeys(btn_from);
	size_t from = base, to = 0;

	while (from < nkeys) {
		btn_insert_to(btn_from, from++, btn_to, to++);
	}
	btn_trim(btn_from, base);
}

static void
btn_split_node_into(struct silofs_btree_node *btn_from, size_t mid_slot,
                    struct silofs_btree_node *btn_to)
{
	const size_t nkeys   = btn_nkeys(btn_from);
	const size_t nchilds = btn_nchilds(btn_from);

	/* copy children within range [mid+1, bchilds) */
	for (size_t i = mid_slot + 1, j = 0; i < nchilds; ++i, ++j) {
		struct silofs_btnptr btnptr;

		btn_child_at(btn_from, i, &btnptr);
		btn_set_child_at(btn_to, j, &btnptr);
	}

	/* copy keys within range [mid+1, bchilds) */
	for (size_t i = mid_slot + 1; i < nkeys; ++i) {
		const uint64_t key = btn_key_at(btn_from, i);

		btn_append_key(btn_to, key);
	}

	/* trim source: keeps children [0..mid_slot) */
	btn_trim(btn_from, mid_slot);

	/* clear target's tail */
	btn_reset_tail(btn_to);
}

static void btn_split_at(struct silofs_btree_node *btn_from, size_t slot,
                         struct silofs_btree_node *btn_to)
{
	if (btn_isleaf(btn_from)) {
		btn_split_leaf_into(btn_from, slot, btn_to);
	} else {
		btn_split_node_into(btn_from, slot, btn_to);
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

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void silofs_bti_self(const struct silofs_btnode_info *bti,
                     struct silofs_btnptr *out_btnptr)
{
	const struct silofs_pnptr *pnptr = silofs_pni_self(&bti->btn_pni);

	silofs_btnptr_setup(out_btnptr, pnptr);
	out_btnptr->nsub_btnodes = bti->btn_nsub_btnodes;
	out_btnptr->nsub_vobjs   = bti->btn_nsub_vobjs;
}

void silofs_bti_incref(struct silofs_btnode_info *bti)
{
	silofs_pni_incref(&bti->btn_pni);
}

void silofs_bti_decref(struct silofs_btnode_info *bti)
{
	silofs_pni_decref(&bti->btn_pni);
}

static void bti_dirtify(struct silofs_btnode_info *bti)
{
	silofs_pni_dirtify(&bti->btn_pni);
}

static void
bti_dirtify2(struct silofs_btnode_info *bti1, struct silofs_btnode_info *bti2)
{
	bti_dirtify(bti1);
	bti_dirtify(bti2);
}

void silofs_bti_dirtify(struct silofs_btnode_info *bti)
{
	bti_dirtify(bti);
}

void silofs_bti_undirtify(struct silofs_btnode_info *bti)
{
	silofs_pni_undirtify(&bti->btn_pni);
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
	bti_dirtify(bti);
}

void silofs_bti_mark_root(struct silofs_btnode_info *bti)
{
	btn_add_flags(bti->btn, SILOFS_PNODEF_META | SILOFS_PNODEF_BTROOT);
	bti_dirtify(bti);
}

bool silofs_bti_marked_root(const struct silofs_btnode_info *bti)
{
	const enum silofs_pnodef flgs = btn_flags(bti->btn);

	return ((flgs & SILOFS_PNODEF_BTROOT) > 0);
}

size_t silofs_bti_height(const struct silofs_btnode_info *bti)
{
	return btn_height(bti->btn);
}

void silofs_bti_set_height(struct silofs_btnode_info *bti, size_t height)
{
	btn_set_height(bti->btn, height);
	bti_dirtify(bti);
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

void silofs_bti_resolve(const struct silofs_btnode_info *bti, uint64_t key,
                        struct silofs_btnptr *out_btnptr)
{
	silofs_btnptr_reset(out_btnptr);
	btn_resolve(bti->btn, key, out_btnptr);
}

static bool bti_has_space(const struct silofs_btnode_info *bti)
{
	const size_t nfree_keys = btn_nfree_keys(bti->btn);

	return (nfree_keys > 0);
}

void silofs_bti_insert(struct silofs_btnode_info *bti, uint64_t key,
                       const struct silofs_btnptr *btnptr)
{
	silofs_assert(btkey_isvalid(key));
	silofs_assert(bti_has_space(bti));

	btn_insert(bti->btn, key, btnptr);
	bti_dirtify(bti);
}

void silofs_bti_update(struct silofs_btnode_info *bti,
                       const struct silofs_btnptr *btnptr_cur,
                       const struct silofs_btnptr *btnptr_new)
{
	bool updated;

	updated = btn_update(bti->btn, btnptr_cur, btnptr_new);
	if (updated) {
		bti_dirtify(bti);
	}
}

void silofs_bti_remove(struct silofs_btnode_info *bti, uint64_t key)
{
	silofs_assert(btkey_isvalid(key));
	silofs_assert(bti_isleaf(bti));

	btn_remove(bti->btn, key);
	bti_dirtify(bti);
}

bool silofs_bti_isfull(const struct silofs_btnode_info *bti)
{
	return btn_nkeys(bti->btn) == btn_nkeys_max(bti->btn);
}

static void bti_setup_spawned(struct silofs_btnode_info *bti)
{
	btn_setup(bti->btn);
	bti_dirtify(bti);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

uint64_t silofs_split_btnode(struct silofs_btnode_info *bti_from,
                             struct silofs_btnode_info *bti_to)
{
	uint64_t mkey;

	silofs_assert_eq(bti_nkeys(bti_from), SILOFS_BTREE_NODE_NKEYS);
	silofs_assert_eq(bti_nkeys(bti_to), 0);

	mkey = split_btnode(bti_from->btn, bti_to->btn);
	bti_dirtify2(bti_from, bti_to);
	return mkey;
}

void silofs_rebind_btchilds(struct silofs_btnode_info *parent,
                            const struct silofs_btnptr *left,
                            const struct silofs_btnptr *right, uint64_t key)
{
	const size_t nkeys = btn_nkeys(parent->btn);
	size_t slot;

	if (nkeys == 0) {
		/* case 1: fresh new empty node */
		btn_insert_at(parent->btn, 0, key, left);
		btn_insert_child_at(parent->btn, 1, right);
	} else {
		/* case 2: left exists, and right */
		slot = btn_search_child(parent->btn, left);
		silofs_assert_lt(slot, btn_nchilds(parent->btn));
		btn_insert_child_at(parent->btn, slot + 1, right);
		btn_insert_key_at(parent->btn, slot, key);
	}
	bti_dirtify(parent);
}

void silofs_clone_btnode(const struct silofs_btnode_info *bti,
                         struct silofs_btnode_info *bti_other)
{
	btn_clone_into(bti->btn, bti_other->btn);
	silofs_bti_dirtify(bti_other);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_btnode_info *
silofs_lookup_cached_btnode(struct silofs_pcache *pcache,
                            const struct silofs_paddr *paddr)
{
	struct silofs_pnode_info *pni;

	silofs_assert_eq(paddr->ptype, SILOFS_PTYPE_BTNODE);
	pni = silofs_pcache_lookup_pnode(pcache, paddr);
	return silofs_bti_from_pni(pni);
}

struct silofs_btnode_info *
silofs_create_cached_btnode(struct silofs_pcache *pcache,
                            const struct silofs_pnptr *pnptr, bool spawn)
{
	struct silofs_pnode_info *pni;
	struct silofs_btnode_info *bti;

	pni = silofs_pcache_create_pnode(pcache, pnptr);
	bti = silofs_bti_from_pni(pni);
	if ((bti != nullptr) && spawn) {
		bti_setup_spawned(bti);
	}
	return bti;
}

void silofs_forget_cached_btnode(struct silofs_pcache *pcache,
                                 struct silofs_btnode_info *bti)
{
	silofs_pcache_delete_pnode(pcache, &bti->btn_pni);
}
