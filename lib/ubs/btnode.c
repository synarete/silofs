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

static size_t btn_height(const struct silofs_btree_node *btn)
{
	return silofs_le16_to_cpu(btn->btn_height);
}

static void btn_set_height(struct silofs_btree_node *btn, size_t height)
{
	silofs_assert_le(height, 8);
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

static size_t btn_nchilds(const struct silofs_btree_node *btn)
{
	return btn->btn_nchilds;
}

static void btn_set_nchilds(struct silofs_btree_node *btn, size_t nchilds)
{
	STATICASSERT_LT(ARRAY_SIZE(btn->btn_child), UINT8_MAX);
	silofs_assert_le(nchilds, ARRAY_SIZE(btn->btn_child));

	btn->btn_nchilds = (uint8_t)nchilds;
}

static size_t btn_nkeys(const struct silofs_btree_node *btn)
{
	return btn->btn_nkeys;
}

static void btn_set_nkeys(struct silofs_btree_node *btn, size_t nkeys)
{
	STATICASSERT_LT(ARRAY_SIZE(btn->btn_key), UINT8_MAX);
	silofs_assert_le(nkeys, ARRAY_SIZE(btn->btn_key));

	btn->btn_nkeys = (uint8_t)nkeys;
}

static void btn_inc_nkeys(struct silofs_btree_node *btn)
{
	btn_set_nkeys(btn, btn_nkeys(btn) + 1);
}

static size_t btn_nkeys_max(const struct silofs_btree_node *btn)
{
	return ARRAY_SIZE(btn->btn_key);
}

static size_t btn_nfree_keys(const struct silofs_btree_node *btn)
{
	const size_t nkeys = btn_nkeys(btn);
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
btn_insert_key(struct silofs_btree_node *btn, size_t slot, uint64_t key)
{
	const size_t nkeys = btn_nkeys(btn);
	uint64_t ikey;

	silofs_assert_lt(nkeys, btn_nkeys_max(btn));
	for (size_t i = nkeys; i > slot; --i) {
		ikey = btn_key_at(btn, i - 1);
		btn_set_key_at(btn, i, ikey);
	}
	btn_set_key_at(btn, slot, key);
	btn_inc_nkeys(btn);
}

static size_t btn_nchilds_max(const struct silofs_btree_node *btn)
{
	const size_t nchilds_max = ARRAY_SIZE(btn->btn_child);

	return btn_isleaf(btn) ? (nchilds_max - 1) : nchilds_max;
}

static void btn_child_at(const struct silofs_btree_node *btn, size_t slot,
                         struct silofs_paddr *out_paddr)
{
	silofs_assert_lt(slot, ARRAY_SIZE(btn->btn_child));

	silofs_paddr64b_xtoh(&btn->btn_child[slot], out_paddr);
}

static bool btn_is_child_at(const struct silofs_btree_node *btn, size_t slot,
                            const struct silofs_paddr *paddr)
{
	struct silofs_paddr paddr_at;

	btn_child_at(btn, slot, &paddr_at);
	return silofs_paddr_isequal(paddr, &paddr_at);
}

static void btn_set_child_at(struct silofs_btree_node *btn, size_t slot,
                             const struct silofs_paddr *paddr)
{
	silofs_assert_lt(slot, ARRAY_SIZE(btn->btn_child));

	silofs_paddr64b_htox(&btn->btn_child[slot], paddr);
}

static void btn_reset_child_at(struct silofs_btree_node *btn, size_t slot)
{
	btn_set_child_at(btn, slot, silofs_paddr_none());
}

static void btn_reset_childs(struct silofs_btree_node *btn)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(btn->btn_child); ++slot) {
		btn_reset_child_at(btn, slot);
	}
}

static void btn_meta_at(const struct silofs_btree_node *btn, size_t slot,
                        struct silofs_btnode_meta *out_meta)
{
	const struct silofs_btree_node_meta *btn_meta = &btn->btn_meta[slot];
	uint16_t algo, mode;

	silofs_assert_lt(slot, ARRAY_SIZE(btn->btn_meta));

	silofs_iv_assign(&out_meta->ivkey.iv, &btn_meta->btm_cipher_iv);
	silofs_key_assign(&out_meta->ivkey.key, &btn_meta->btm_cipher_key);
	algo = silofs_le16_to_cpu(btn_meta->btm_cipher_algo);
	mode = silofs_le16_to_cpu(btn_meta->btm_cipher_mode);
	silofs_ciargs_setup(&out_meta->ciargs, algo, mode);
}

static void btn_set_meta_at(struct silofs_btree_node *btn, size_t slot,
                            const struct silofs_btnode_meta *meta)
{
	struct silofs_btree_node_meta *btn_meta = &btn->btn_meta[slot];
	uint16_t algo, mode;

	silofs_assert_lt(slot, ARRAY_SIZE(btn->btn_meta));

	silofs_iv_assign(&btn_meta->btm_cipher_iv, &meta->ivkey.iv);
	silofs_key_assign(&btn_meta->btm_cipher_key, &meta->ivkey.key);
	algo = meta->ciargs.algo;
	mode = meta->ciargs.mode;
	btn_meta->btm_cipher_algo = silofs_cpu_to_le16(algo);
	btn_meta->btm_cipher_mode = silofs_cpu_to_le16(mode);
}

static void btn_reset_meta(struct silofs_btree_node *btn)
{
	struct silofs_btnode_meta meta;

	silofs_ivkey_reset(&meta.ivkey);
	silofs_ciargs_reset(&meta.ciargs);

	for (size_t slot = 0; slot < ARRAY_SIZE(btn->btn_meta); ++slot) {
		btn_set_meta_at(btn, slot, &meta);
	}
}

static void
btn_resolve_internal_child(const struct silofs_btree_node *btn, uint64_t key,
                           struct silofs_btnode_child *out_child)
{
	const size_t slot = btn_find_slot_ge(btn, key);

	btn_child_at(btn, slot, &out_child->addr);
	btn_meta_at(btn, slot, &out_child->meta);
}

static void
btn_resolve_leaf_child(const struct silofs_btree_node *btn, uint64_t key,
                       struct silofs_btnode_child *out_child)
{
	const size_t slot = btn_find_slot_eq(btn, key);

	btn_child_at(btn, slot, &out_child->addr);
	btn_meta_at(btn, slot, &out_child->meta);
}

static void
btn_resolve_child(const struct silofs_btree_node *btn, uint64_t key,
                  struct silofs_btnode_child *out_child)
{
	if (btn_isleaf(btn)) {
		btn_resolve_leaf_child(btn, key, out_child);
	} else {
		btn_resolve_internal_child(btn, key, out_child);
	}
}

static void btn_insert_child(struct silofs_btree_node *btn, size_t slot,
                             const struct silofs_paddr *paddr)
{
	struct silofs_paddr paddr_at_slot;
	const size_t nkeys = btn_nkeys(btn);

	silofs_assert_lt(nkeys, btn_nchilds_max(btn));
	for (size_t i = nkeys; i > slot; --i) {
		btn_child_at(btn, i, &paddr_at_slot);
		btn_set_child_at(btn, i + 1, &paddr_at_slot);
	}
	btn_set_child_at(btn, slot, paddr);
}

static void btn_dup_keys(struct silofs_btree_node *btn,
                         const struct silofs_btree_node *btn_other)
{
	const size_t nkeys = btn_nkeys(btn_other);
	uint64_t key;

	for (size_t slot = 0; slot < nkeys; ++slot) {
		key = btn_key_at(btn_other, slot);
		btn_set_key_at(btn, slot, key);
	}
	btn_set_nkeys(btn, nkeys);
}

static void btn_dup_childs(struct silofs_btree_node *btn,
                           const struct silofs_btree_node *btn_other)
{
	struct silofs_paddr paddr;
	const size_t nchilds = btn_nchilds(btn_other);

	for (size_t slot = 0; slot < nchilds; ++slot) {
		btn_child_at(btn_other, slot, &paddr);
		btn_set_child_at(btn, slot, &paddr);
	}
}

static void btn_dup_by(struct silofs_btree_node *btn,
                       const struct silofs_btree_node *btn_other)
{
	btn_set_flags(btn, btn_flags(btn_other));
	btn_set_height(btn, btn_height(btn_other));
	btn_dup_keys(btn, btn_other);
	btn_dup_childs(btn, btn_other);
}

static void btn_setup(struct silofs_btree_node *btn)
{
	btn_set_flags(btn, SILOFS_PNODEF_NONE);
	btn_set_height(btn, 1);
	btn_set_nkeys(btn, 0);
	btn_set_nchilds(btn, 0);
	btn_reset_childs(btn);
	btn_reset_meta(btn);
	btn_reset_keys(btn);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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

size_t silofs_bti_nkeys(const struct silofs_btnode_info *bti)
{
	return btn_nkeys(bti->btn);
}

size_t silofs_bti_nchilds(const struct silofs_btnode_info *bti)
{
	return btn_nchilds(bti->btn);
}

static bool bti_has_child_at(const struct silofs_btnode_info *bti, size_t slot)
{
	return (slot < silofs_bti_nchilds(bti));
}

void silofs_bti_child_at(const struct silofs_btnode_info *bti, size_t slot,
                         struct silofs_paddr *out_paddr)
{
	silofs_paddr_reset(out_paddr);
	if (bti_has_child_at(bti, slot)) {
		btn_child_at(bti->btn, slot, out_paddr);
	}
}

uint64_t silofs_bti_median_key(const struct silofs_btnode_info *bti)
{
	const size_t nkeys = silofs_bti_nkeys(bti);
	uint64_t ikey[2];
	uint64_t mkey;

	if (nkeys == 0) {
		mkey = SILOFS_BTREE_KEY_NULL;
	} else if (nkeys % 2 == 1) {
		mkey = btn_key_at(bti->btn, nkeys / 2);
	} else {
		ikey[0] = btn_key_at(bti->btn, (nkeys - 1) / 2);
		ikey[1] = btn_key_at(bti->btn, nkeys / 2);
		mkey = (ikey[0] + ikey[1]) / 2;
	}
	return mkey;
}

static bool btkey_isvalid(uint64_t key)
{
	return (key != SILOFS_BTREE_KEY_NULL);
}

int silofs_bti_resolve(const struct silofs_btnode_info *bti, uint64_t key,
                       struct silofs_btnode_child *out_child)
{
	const size_t nkeys = btn_nkeys(bti->btn);

	silofs_paddr_reset(&out_child->addr);
	if (!btkey_isvalid(key)) {
		return -SILOFS_EINVAL;
	}
	if (!nkeys) {
		return -SILOFS_ENOENT;
	}
	btn_resolve_child(bti->btn, key, out_child);
	if (silofs_paddr_isnull(&out_child->addr)) {
		return -SILOFS_ENOENT;
	}
	return 0;
}

int silofs_bti_expand(struct silofs_btnode_info *bti, uint64_t key,
                      const struct silofs_paddr *paddr)
{
	struct silofs_btree_node *btn = bti->btn;
	const size_t nfree_keys = btn_nfree_keys(btn);
	size_t slot;

	if (!btkey_isvalid(key)) {
		return -SILOFS_EINVAL;
	}
	if (!nfree_keys) {
		return -SILOFS_ENOSPC;
	}
	slot = btn_find_slot_ge(btn, key);
	btn_insert_child(btn, slot, paddr);
	btn_insert_key(btn, slot, key);
	return 0;
}

void silofs_bti_set_final(struct silofs_btnode_info *bti,
                          const struct silofs_paddr *paddr)
{
	const size_t slot = btn_nkeys(bti->btn);

	btn_set_child_at(bti->btn, slot, paddr);
}

void silofs_bti_dup_by(struct silofs_btnode_info *bti,
                       const struct silofs_btnode_info *bti_other)
{
	btn_dup_by(bti->btn, bti_other->btn);
	silofs_bti_dirtify(bti);
}

int silofs_bti_update_child(struct silofs_btnode_info *bti, uint64_t key,
                            const struct silofs_paddr *paddr)
{
	size_t slot;

	if (!btkey_isvalid(key)) {
		return -SILOFS_EINVAL;
	}
	slot = btn_find_slot_ge(bti->btn, key);
	if (!btn_is_child_at(bti->btn, slot, paddr)) {
		btn_set_child_at(bti->btn, slot, paddr);
		silofs_bti_dirtify(bti);
	}
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

struct silofs_btnode_info *
silofs_lookup_cached_btnode(struct silofs_pcache *pcache,
                            const struct silofs_paddr *paddr)
{
	struct silofs_pnode_info *pni;

	silofs_assert_eq(paddr->mtype, SILOFS_MTYPE_BTNODE);
	pni = silofs_pcache_lookup_pnode(pcache, paddr);
	return silofs_bti_from_pni(pni);
}

struct silofs_btnode_info *
silofs_create_cached_btnode(struct silofs_pcache *pcache,
                            const struct silofs_paddr *paddr, bool spawn)
{
	struct silofs_pnode_info *pni;
	struct silofs_btnode_info *bti;

	silofs_assert_eq(paddr->mtype, SILOFS_MTYPE_BTNODE);
	pni = silofs_pcache_create_pnode(pcache, paddr);
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
