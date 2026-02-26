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

static long btn_compare_key_at(const struct silofs_btree_node *btn,
                               size_t slot, uint64_t key)
{
	const uint64_t skey = btn_key_at(btn, slot);

	return (long)(skey - key);
}

static size_t
btn_find_slot_ge(const struct silofs_btree_node *btn, uint64_t key)
{
	const size_t nkeys = btn_nkeys(btn);
	long cmp;

	for (size_t slot = 0; slot < nkeys; ++slot) {
		cmp = btn_compare_key_at(btn, slot, key);
		if (cmp <= 0) {
			return slot;
		}
	}
	return nkeys;
}

static size_t
btn_find_slot_eq(const struct silofs_btree_node *btn, uint64_t key)
{
	const size_t nkeys = btn_nkeys(btn);
	long cmp;

	for (size_t slot = 0; slot < nkeys; ++slot) {
		cmp = btn_compare_key_at(btn, slot, key);
		if (cmp == 0) {
			return slot;
		}
	}
	return nkeys;
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
	btn_reset_key_at(btn, nkeys);
	btn_dec_nkeys(btn);
}

static size_t btn_nchilds_max(const struct silofs_btree_node *btn)
{
	const size_t nchilds_max = ARRAY_SIZE(btn->btn_child);

	STATICASSERT_EQ(ARRAY_SIZE(btn->btn_child),
	                ARRAY_SIZE(btn->btn_key) + 1);

	return btn_isleaf(btn) ? (nchilds_max - 1) : nchilds_max;
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

static void btn_reset_tail(struct silofs_btree_node *btn)
{
	const size_t nkeys_max = btn_nkeys_max(btn);
	const size_t nkeys     = btn_nkeys(btn);

	for (size_t slot = nkeys; slot < nkeys_max; ++slot) {
		btn_reset_key_at(btn, slot);
	}
	for (size_t slot = nkeys + 1; slot <= nkeys_max; ++slot) {
		btn_reset_child_at(btn, slot);
	}
}

static size_t
btn_key_to_slot(const struct silofs_btree_node *btn, uint64_t key)
{
	size_t slot;

	if (btn_isleaf(btn)) {
		slot = btn_find_slot_eq(btn, key);
	} else {
		slot = btn_find_slot_ge(btn, key);
	}
	return slot;
}

static void btn_resolve_child(const struct silofs_btree_node *btn,
                              uint64_t key, struct silofs_btnptr *out_child)
{
	const size_t slot = btn_key_to_slot(btn, key);

	btn_child_at(btn, slot, out_child);
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
	btn_reset_child_at(btn, nchilds);
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

void silofs_bti_dirtify(struct silofs_btnode_info *bti)
{
	silofs_pni_dirtify(&bti->btn_pni);
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
	silofs_bti_dirtify(bti);
}

void silofs_bti_mark_root(struct silofs_btnode_info *bti)
{
	btn_add_flags(bti->btn, SILOFS_PNODEF_META | SILOFS_PNODEF_BTROOT);
	silofs_bti_dirtify(bti);
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
	silofs_bti_dirtify(bti);
}

static size_t bti_nkeys(const struct silofs_btnode_info *bti)
{
	return btn_nkeys(bti->btn);
}

static uint64_t bti_key_at(const struct silofs_btnode_info *bti, size_t slot)
{
	const size_t nkeys = bti_nkeys(bti);
	uint64_t key       = SILOFS_BTREE_KEY_NULL;

	silofs_assert_le(slot, nkeys);
	if (slot < nkeys) {
		key = btn_key_at(bti->btn, slot);
	}
	return key;
}

static bool btkey_isvalid(uint64_t key)
{
	return (key != SILOFS_BTREE_KEY_NULL);
}

static void bti_resolve(const struct silofs_btnode_info *bti, uint64_t key,
                        struct silofs_btnptr *out_btnptr)
{
	btn_resolve_child(bti->btn, key, out_btnptr);
}

static void bti_child_at(const struct silofs_btnode_info *bti, size_t slot,
                         struct silofs_btnptr *out_btnptr)
{
	btn_child_at(bti->btn, slot, out_btnptr);
}

int silofs_bti_resolve(const struct silofs_btnode_info *bti, uint64_t key,
                       struct silofs_btnptr *out_btnptr)
{
	const size_t nkeys = btn_nkeys(bti->btn);

	silofs_btnptr_reset(out_btnptr);
	if (!btkey_isvalid(key)) {
		return -SILOFS_EINVAL;
	}
	if (!nkeys) {
		return -SILOFS_ENOENT;
	}
	bti_resolve(bti, key, out_btnptr);
	return silofs_btnptr_isnull(out_btnptr) ? -SILOFS_ENOENT : 0;
}

static bool bti_has_space(const struct silofs_btnode_info *bti)
{
	const size_t nfree_keys = btn_nfree_keys(bti->btn);

	return (nfree_keys > 0);
}

static void bti_insert_at(struct silofs_btnode_info *bti, size_t slot,
                          uint64_t key, const struct silofs_btnptr *btnptr)
{
	btn_insert_child_at(bti->btn, slot, btnptr);
	if (key != SILOFS_BTREE_KEY_NULL) {
		btn_insert_key_at(bti->btn, slot, key);
	}
	silofs_bti_dirtify(bti);
}

static void bti_insert(struct silofs_btnode_info *bti, uint64_t key,
                       const struct silofs_btnptr *btnptr)
{
	const size_t slot = btn_key_to_slot(bti->btn, key);

	silofs_assert(bti_has_space(bti));
	bti_insert_at(bti, slot, key, btnptr);
}

int silofs_bti_insert(struct silofs_btnode_info *bti, uint64_t key,
                      const struct silofs_btnptr *btnptr)
{
	if (!btkey_isvalid(key)) {
		return -SILOFS_EINVAL;
	}
	if (!bti_has_space(bti)) {
		return -SILOFS_ENOSPC;
	}
	bti_insert(bti, key, btnptr);
	return 0;
}

int silofs_bti_insert_by(struct silofs_btnode_info *bti, uint64_t key,
                         const struct silofs_btnode_info *bti_child)
{
	struct silofs_btnptr btnptr;

	silofs_bti_self(bti_child, &btnptr);
	return silofs_bti_insert(bti, key, &btnptr);
}

static void bti_insert2(struct silofs_btnode_info *bti, uint64_t key,
                        const struct silofs_btnptr *btnptr1,
                        const struct silofs_btnptr *btnptr2)
{
	const size_t slot       = btn_key_to_slot(bti->btn, key);
	const uint64_t key_null = SILOFS_BTREE_KEY_NULL;

	silofs_assert(bti_has_space(bti));
	bti_insert_at(bti, slot, key, btnptr1);
	bti_insert_at(bti, slot, key_null, btnptr2);
}

int silofs_bti_insert2(struct silofs_btnode_info *bti, uint64_t key,
                       const struct silofs_btnptr *btnptr1,
                       const struct silofs_btnptr *btnptr2)
{
	if (!btkey_isvalid(key)) {
		return -SILOFS_EINVAL;
	}
	if (!bti_has_space(bti)) {
		return -SILOFS_ENOSPC;
	}
	bti_insert2(bti, key, btnptr1, btnptr2);
	return 0;
}

int silofs_bti_insert_by2(struct silofs_btnode_info *bti, uint64_t key,
                          const struct silofs_btnode_info *bti1,
                          const struct silofs_btnode_info *bti2)
{
	struct silofs_btnptr btnptr[2];

	silofs_bti_self(bti1, &btnptr[0]);
	silofs_bti_self(bti2, &btnptr[1]);
	return silofs_bti_insert2(bti, key, &btnptr[0], &btnptr[1]);
}

int silofs_bti_relink(struct silofs_btnode_info *bti, uint64_t key,
                      const struct silofs_btnptr *btnptr)
{
	size_t slot;

	if (!btkey_isvalid(key)) {
		return -SILOFS_EINVAL;
	}
	slot = btn_find_slot_ge(bti->btn, key);
	btn_set_child_at(bti->btn, slot, btnptr);
	silofs_bti_dirtify(bti);
	return 0;
}

static bool bti_isleaf(const struct silofs_btnode_info *bti)
{
	return btn_isleaf(bti->btn);
}

static void bti_remove_at(struct silofs_btnode_info *bti, size_t slot)
{
	btn_remove_child_at(bti->btn, slot);
	btn_remove_key_at(bti->btn, slot);
}

int silofs_bti_remove(struct silofs_btnode_info *bti, uint64_t key)
{
	size_t slot;

	if (!btkey_isvalid(key)) {
		return -SILOFS_EINVAL;
	}
	if (!bti_isleaf(bti)) {
		silofs_assert(!key); // XXX
		return -SILOFS_EOPNOTSUPP;
	}
	slot = btn_find_slot_eq(bti->btn, key);
	if (slot >= bti_nkeys(bti)) {
		silofs_assert(!key); // XXX
		return -SILOFS_ENOENT;
	}
	bti_remove_at(bti, slot);
	return 0;
}

bool silofs_bti_isfull(const struct silofs_btnode_info *bti)
{
	return btn_nkeys(bti->btn) == btn_nkeys_max(bti->btn);
}

static void bti_setup_spawned(struct silofs_btnode_info *bti)
{
	btn_setup(bti->btn);
	silofs_bti_dirtify(bti);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t bti_split_slot(const struct silofs_btnode_info *bti)
{
	const size_t nkeys = bti_nkeys(bti);

	STATICASSERT_EQ(SILOFS_BTREE_NODE_NKEYS % 2, 1);

	return nkeys / 2;
}

static void
bti_insert_to(const struct silofs_btnode_info *bti_from, size_t slot_from,
              struct silofs_btnode_info *bti_to, size_t slot_to)
{
	struct silofs_btnptr btnptr;
	const uint64_t key = bti_key_at(bti_from, slot_from);

	bti_child_at(bti_from, slot_from, &btnptr);
	bti_insert_at(bti_to, slot_to, key, &btnptr);
}

static void
bti_insert_to_last(const struct silofs_btnode_info *bti_from, size_t slot_from,
                   struct silofs_btnode_info *bti_to, size_t slot_to)
{
	struct silofs_btnptr btnptr;

	bti_child_at(bti_from, slot_from, &btnptr);
	bti_insert_at(bti_to, slot_to, SILOFS_BTREE_KEY_NULL, &btnptr);
}

static void bti_split_to(const struct silofs_btnode_info *bti_from,
                         size_t slot_from, struct silofs_btnode_info *bti_to)
{
	const size_t nkeys = btn_nkeys(bti_from->btn);
	size_t slot_to     = 0;

	while (slot_from <= nkeys) {
		bti_insert_to(bti_from, slot_from++, bti_to, slot_to++);
	}
	bti_insert_to_last(bti_from, slot_from, bti_to, slot_to);
}

static void bti_trim(struct silofs_btnode_info *bti, size_t nkeys)
{
	btn_set_nkeys(bti->btn, nkeys);
	btn_reset_tail(bti->btn);
	silofs_bti_dirtify(bti);
}

uint64_t silofs_split_btnode(struct silofs_btnode_info *bti,
                             struct silofs_btnode_info *bti_next)
{
	const size_t slot   = bti_split_slot(bti);
	const uint64_t mkey = bti_key_at(bti, slot);

	silofs_assert_eq(bti_nkeys(bti), SILOFS_BTREE_NODE_NKEYS);
	silofs_assert_eq(bti_nkeys(bti_next), 0);

	if (bti_isleaf(bti)) {
		bti_split_to(bti, slot, bti_next);
	} else {
		bti_split_to(bti, slot + 1, bti_next);
	}

	bti_trim(bti, slot);

	return mkey;
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
