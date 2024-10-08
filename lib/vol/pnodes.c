/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
 *
 * Silofs is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *      ut_inspect_ok(ute, dino);
 * Silofs is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/vol.h>


static void btn_setup_hdr(struct silofs_btree_node *btn)
{
	silofs_hdr_setup(&btn->btn_hdr, SILOFS_OTYPE_BTNODE,
	                 sizeof(*btn), SILOFS_HDRF_OTYPE);
}

static size_t btn_nkeys(const struct silofs_btree_node *btn)
{
	return silofs_le16_to_cpu(btn->btn_nkeys);
}

static void btn_set_nkeys(struct silofs_btree_node *btn, size_t nkeys)
{
	silofs_assert_le(nkeys, ARRAY_SIZE(btn->btn_key));
	btn->btn_nkeys = silofs_cpu_to_le16((uint16_t)nkeys);
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

static void btn_key_at(const struct silofs_btree_node *btn, size_t slot,
                       struct silofs_laddr *out_laddr)
{
	silofs_assert_lt(slot, btn_nkeys_max(btn));

	silofs_laddr48b_xtoh(&btn->btn_key[slot], out_laddr);
}

static void btn_set_key_at(struct silofs_btree_node *btn, size_t slot,
                           const struct silofs_laddr *laddr)
{
	silofs_assert_lt(slot, ARRAY_SIZE(btn->btn_key));

	silofs_laddr48b_htox(&btn->btn_key[slot], laddr);
}

static void btn_reset_key_at(struct silofs_btree_node *btn, size_t slot)
{
	btn_set_key_at(btn, slot, laddr_none());
}

static void btn_reset_keys(struct silofs_btree_node *btn)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(btn->btn_key); ++slot) {
		btn_reset_key_at(btn, slot);
	}
}

static long btn_compare_key_at(const struct silofs_btree_node *btn,
                               size_t slot, const struct silofs_laddr *laddr)
{
	struct silofs_laddr laddr_at_slot = { .len = 0 };

	btn_key_at(btn, slot, &laddr_at_slot);
	return silofs_laddr_compare(laddr, &laddr_at_slot);
}

static bool btn_has_key_ge_at(const struct silofs_btree_node *btn, size_t slot,
                              const struct silofs_laddr *laddr)
{
	const long cmp = btn_compare_key_at(btn, slot, laddr);

	return (cmp <= 0);
}

static size_t btn_resolve_slot_by(const struct silofs_btree_node *btn,
                                  const struct silofs_laddr *laddr)
{
	const size_t nkeys = btn_nkeys(btn);

	for (size_t slot = 0; slot < nkeys; ++slot) {
		if (btn_has_key_ge_at(btn, slot, laddr)) {
			return slot;
		}
	}
	return nkeys;
}

static void btn_insert_key(struct silofs_btree_node *btn, size_t slot,
                           const struct silofs_laddr *laddr)
{
	struct silofs_laddr laddr_at_slot;
	const size_t nkeys = btn_nkeys(btn);

	silofs_assert_lt(nkeys, btn_nkeys_max(btn));
	for (size_t i = nkeys; i > slot; --i) {
		btn_key_at(btn, i - 1, &laddr_at_slot);
		btn_set_key_at(btn, i, &laddr_at_slot);
	}
	btn_set_key_at(btn, slot, laddr);
	btn_inc_nkeys(btn);
}

static size_t btn_nchilds_max(const struct silofs_btree_node *btn)
{
	return ARRAY_SIZE(btn->btn_child);
}

static void btn_child_at(const struct silofs_btree_node *btn, size_t slot,
                         struct silofs_oaddr *out_oaddr)
{
	silofs_assert_lt(slot, ARRAY_SIZE(btn->btn_child));

	silofs_oaddr32b_xtoh(&btn->btn_child[slot], out_oaddr);
}

static void btn_set_child_at(struct silofs_btree_node *btn, size_t slot,
                             const struct silofs_oaddr *oaddr)
{
	silofs_assert_lt(slot, ARRAY_SIZE(btn->btn_child));

	silofs_oaddr32b_htox(&btn->btn_child[slot], oaddr);
}

static void btn_reset_child_at(struct silofs_btree_node *btn, size_t slot)
{
	btn_set_child_at(btn, slot, oaddr_none());
}

static void btn_reset_childs(struct silofs_btree_node *btn)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(btn->btn_child); ++slot) {
		btn_reset_child_at(btn, slot);
	}
}

static void btn_insert_child(struct silofs_btree_node *btn, size_t slot,
                             const struct silofs_oaddr *oaddr)
{
	struct silofs_oaddr oaddr_at_slot;
	const size_t nkeys = btn_nkeys(btn);

	silofs_assert_lt(nkeys, btn_nchilds_max(btn));
	for (size_t i = nkeys; i > slot; --i) {
		btn_child_at(btn, i, &oaddr_at_slot);
		btn_set_child_at(btn, i + 1, &oaddr_at_slot);
	}
	btn_set_child_at(btn, slot, oaddr);
}

static void btn_init(struct silofs_btree_node *btn)
{
	btn_setup_hdr(btn);
	btn_set_nkeys(btn, 0);
	btn_reset_childs(btn);
	btn_reset_keys(btn);
}

static void btn_fini(struct silofs_btree_node *btn)
{
	btn_set_nkeys(btn, 0);
	btn_reset_childs(btn);
	btn_reset_keys(btn);
}

static struct silofs_btree_node *btn_malloc(struct silofs_alloc *alloc)
{
	struct silofs_btree_node *btn;

	btn = silofs_memalloc(alloc, sizeof(*btn), SILOFS_ALLOCF_BZERO);
	return btn;
}

static void btn_free(struct silofs_btree_node *btn, struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, btn, sizeof(*btn), 0);
}

static struct silofs_btree_node *btn_new(struct silofs_alloc *alloc)
{
	struct silofs_btree_node *btn;

	btn = btn_malloc(alloc);
	if (btn != NULL) {
		btn_init(btn);
	}
	return btn;
}

static void btn_del(struct silofs_btree_node *btn, struct silofs_alloc *alloc)
{
	btn_fini(btn);
	btn_free(btn, alloc);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

#define laddr48b_htox(lx_, lh_)         silofs_laddr48b_htox(lx_, lh_)
#define laddr48b_xtoh(lx_, lh_)         silofs_laddr48b_xtoh(lx_, lh_)
#define oaddr32b_htox(px_, ph_)         silofs_oaddr32b_htox(px_, ph_)
#define oaddr32b_xtoh(px_, ph_)         silofs_oaddr32b_xtoh(px_, ph_)

static void ltop_htox(struct silofs_btree_ltop *ltop,
                      const struct silofs_laddr *laddr,
                      const struct silofs_oaddr *oaddr)
{
	laddr48b_htox(&ltop->laddr, laddr);
	oaddr32b_htox(&ltop->oaddr, oaddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void btl_setup_hdr(struct silofs_btree_leaf *btl)
{
	silofs_hdr_setup(&btl->btl_hdr, SILOFS_OTYPE_BTLEAF,
	                 sizeof(*btl), SILOFS_HDRF_OTYPE);
}

static size_t btl_nltops(const struct silofs_btree_leaf *btl)
{
	return silofs_le16_to_cpu(btl->btl_nltops);
}

static void btl_set_nltops(struct silofs_btree_leaf *btl, size_t n)
{
	silofs_assert_le(n, ARRAY_SIZE(btl->btl_ltop));

	btl->btl_nltops = silofs_cpu_to_le16((uint16_t)n);
}

static void btl_inc_nltops(struct silofs_btree_leaf *btl)
{
	btl_set_nltops(btl, btl_nltops(btl) + 1);
}

static size_t btl_nltops_max(const struct silofs_btree_leaf *btl)
{
	return ARRAY_SIZE(btl->btl_ltop);
}

static size_t btl_nfree_ltops(const struct silofs_btree_leaf *btl)
{
	const size_t nltop = btl_nltops(btl);
	const size_t nltop_max = btl_nltops_max(btl);

	silofs_assert_le(nltop, nltop_max);
	return (nltop_max - nltop);
}

static void btl_laddr_at(const struct silofs_btree_leaf *btl,
                         size_t slot, struct silofs_laddr *out_laddr)
{
	silofs_assert_lt(slot, btl_nltops_max(btl));

	laddr48b_xtoh(&btl->btl_ltop[slot].laddr, out_laddr);
}

static void btl_oaddr_at(const struct silofs_btree_leaf *btl,
                         size_t slot, struct silofs_oaddr *out_oaddr)
{
	silofs_assert_lt(slot, btl_nltops_max(btl));

	oaddr32b_xtoh(&btl->btl_ltop[slot].oaddr, out_oaddr);
}

static void btl_ltop_at(const struct silofs_btree_leaf *btl, size_t slot,
                        struct silofs_laddr *out_laddr,
                        struct silofs_oaddr *out_oaddr)
{
	btl_laddr_at(btl, slot, out_laddr);
	btl_oaddr_at(btl, slot, out_oaddr);
}

static void btl_set_ltop_at(struct silofs_btree_leaf *btl, size_t slot,
                            const struct silofs_laddr *laddr,
                            const struct silofs_oaddr *oaddr)
{
	silofs_assert_lt(slot, btl_nltops_max(btl));

	ltop_htox(&btl->btl_ltop[slot], laddr, oaddr);
}

static void btl_reset_ltop_at(struct silofs_btree_leaf *btl, size_t slot)
{
	btl_set_ltop_at(btl, slot, laddr_none(), oaddr_none());
}

static void btl_reset_ltops(struct silofs_btree_leaf *btl)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(btl->btl_ltop); ++slot) {
		btl_reset_ltop_at(btl, slot);
	}
}

static long btl_compare_key_at(const struct silofs_btree_leaf *btl,
                               size_t slot, const struct silofs_laddr *laddr)
{
	struct silofs_laddr laddr_at_slot = { .len = 0 };

	btl_laddr_at(btl, slot, &laddr_at_slot);
	return silofs_laddr_compare(laddr, &laddr_at_slot);
}

static size_t btl_find_slot_of(const struct silofs_btree_leaf *btl,
                               const struct silofs_laddr *laddr)
{
	const size_t nltops = btl_nltops(btl);
	long cmp;

	for (size_t slot = 0; slot < nltops; ++slot) {
		cmp = btl_compare_key_at(btl, slot, laddr);
		if (cmp == 0) {
			return slot;
		}
		if (cmp > 0) {
			break;
		}
	}
	return nltops;
}

static size_t btl_insert_slot_of(const struct silofs_btree_leaf *btl,
                                 const struct silofs_laddr *laddr)
{
	const size_t nltops = btl_nltops(btl);
	long cmp;

	for (size_t slot = 0; slot < nltops; ++slot) {
		cmp = btl_compare_key_at(btl, slot, laddr);
		if (cmp >= 0) {
			return slot;
		}
	}
	return nltops;
}

static void btl_insert_ltop(struct silofs_btree_leaf *btl, size_t slot,
                            const struct silofs_laddr *laddr,
                            const struct silofs_oaddr *oaddr)
{
	struct silofs_laddr laddr_at_slot;
	struct silofs_oaddr oaddr_at_slot;
	const size_t nltop = btl_nltops(btl);

	silofs_assert_lt(nltop, btl_nltops_max(btl));
	for (size_t i = nltop; i > slot; --i) {
		btl_ltop_at(btl, i - 1, &laddr_at_slot, &oaddr_at_slot);
		btl_set_ltop_at(btl, i, &laddr_at_slot, &oaddr_at_slot);
	}
	btl_set_ltop_at(btl, slot, laddr, oaddr);
	btl_inc_nltops(btl);
}

static void btl_init(struct silofs_btree_leaf *btl)
{
	btl_setup_hdr(btl);
	btl_set_nltops(btl, 0);
	btl_reset_ltops(btl);
}

static void btl_fini(struct silofs_btree_leaf *btl)
{
	btl_set_nltops(btl, 0);
}

static struct silofs_btree_leaf *btl_malloc(struct silofs_alloc *alloc)
{
	struct silofs_btree_leaf *btl;

	btl = silofs_memalloc(alloc, sizeof(*btl), SILOFS_ALLOCF_BZERO);
	return btl;
}

static void btl_free(struct silofs_btree_leaf *btl, struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, btl, sizeof(*btl), 0);
}

static struct silofs_btree_leaf *btl_new(struct silofs_alloc *alloc)
{
	struct silofs_btree_leaf *btl;

	btl = btl_malloc(alloc);
	if (btl != NULL) {
		btl_init(btl);
	}
	return btl;
}

static void btl_del(struct silofs_btree_leaf *btl, struct silofs_alloc *alloc)
{
	btl_fini(btl);
	btl_free(btl, alloc);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void bni_init(struct silofs_bnode_info *bni, enum silofs_otype otype,
                     const struct silofs_oaddr *oaddr)
{
	silofs_assert(!silofs_oaddr_isnull(oaddr));

	silofs_oaddr_assign(&bni->bn_oaddr, oaddr);
	silofs_hmqe_init(&bni->bn_hmqe);
	silofs_hkey_by_oaddr(&bni->bn_hmqe.hme_key, &bni->bn_oaddr);
	bni->bn_otype = otype;
}

static void bni_fini(struct silofs_bnode_info *bni)
{
	silofs_oaddr_reset(&bni->bn_oaddr);
	silofs_hmqe_fini(&bni->bn_hmqe);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_btnode_info *bti_malloc(struct silofs_alloc *alloc)
{
	struct silofs_btnode_info *bti = NULL;

	bti = silofs_memalloc(alloc, sizeof(*bti), 0);
	return bti;
}

static void bti_free(struct silofs_btnode_info *bti,
                     struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, bti, sizeof(*bti), 0);
}

static void bti_init(struct silofs_btnode_info *bti,
                     const struct silofs_oaddr *oaddr)
{
	silofs_assert(!silofs_oaddr_isnull(oaddr));

	bni_init(&bti->btn_bni, SILOFS_OTYPE_BTNODE, oaddr);
	bti->btn = NULL;
}

static void bti_fini(struct silofs_btnode_info *bti)
{
	bni_fini(&bti->btn_bni);
	bti->btn = NULL;
}

struct silofs_btnode_info *
silofs_bti_new(const struct silofs_oaddr *oaddr, struct silofs_alloc *alloc)
{
	struct silofs_btree_node *btn = NULL;
	struct silofs_btnode_info *bti = NULL;

	btn = btn_new(alloc);
	if (btn == NULL) {
		return NULL;
	}
	bti = bti_malloc(alloc);
	if (bti == NULL) {
		btn_del(btn, alloc);
		return NULL;
	}
	bti_init(bti, oaddr);
	bti->btn = btn;
	return bti;
}

void silofs_bti_del(struct silofs_btnode_info *bti, struct silofs_alloc *alloc)
{
	struct silofs_btree_node *btn = bti->btn;

	bti_fini(bti);
	bti_free(bti, alloc);
	btn_del(btn, alloc);
}

int silofs_bti_resolve(const struct silofs_btnode_info *bti,
                       const struct silofs_laddr *laddr,
                       struct silofs_oaddr *out_oaddr)
{
	const size_t nkeys = btn_nkeys(bti->btn);
	size_t slot;

	if (!nkeys) {
		return -SILOFS_ENOENT;
	}
	slot = btn_resolve_slot_by(bti->btn, laddr);
	btn_child_at(bti->btn, slot, out_oaddr);
	if (oaddr_isnull(out_oaddr)) {
		return -SILOFS_ENOENT;
	}
	return 0;
}

int silofs_bti_expand(struct silofs_btnode_info *bti,
                      const struct silofs_laddr *laddr,
                      const struct silofs_oaddr *oaddr)
{
	struct silofs_btree_node *btn = bti->btn;
	const size_t nfree_keys = btn_nfree_keys(btn);
	size_t slot;

	if (!nfree_keys) {
		return -SILOFS_ENOSPC;
	}
	slot = btn_resolve_slot_by(btn, laddr);
	btn_insert_child(btn, slot, oaddr);
	btn_insert_key(btn, slot, laddr);
	return 0;
}

void silofs_bti_setapex(struct silofs_btnode_info *bti,
                        const struct silofs_oaddr *oaddr)
{
	const size_t slot = btn_nkeys(bti->btn);

	btn_set_child_at(bti->btn, slot, oaddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_btleaf_info *bli_malloc(struct silofs_alloc *alloc)
{
	struct silofs_btleaf_info *bli = NULL;

	bli = silofs_memalloc(alloc, sizeof(*bli), 0);
	return bli;
}

static void bli_free(struct silofs_btleaf_info *bli,
                     struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, bli, sizeof(*bli), 0);
}

static void bli_init(struct silofs_btleaf_info *bli,
                     const struct silofs_oaddr *oaddr)
{
	silofs_assert(!silofs_oaddr_isnull(oaddr));

	bni_init(&bli->btl_bni, SILOFS_OTYPE_BTLEAF, oaddr);
	bli->btl = NULL;
}

static void bli_fini(struct silofs_btleaf_info *bli)
{
	bni_fini(&bli->btl_bni);
	bli->btl = NULL;
}

struct silofs_btleaf_info *
silofs_bli_new(const struct silofs_oaddr *oaddr, struct silofs_alloc *alloc)
{
	struct silofs_btree_leaf *btl = NULL;
	struct silofs_btleaf_info *bli = NULL;

	btl = btl_new(alloc);
	if (btl == NULL) {
		return NULL;
	}
	bli = bli_malloc(alloc);
	if (bli == NULL) {
		btl_del(btl, alloc);
		return NULL;
	}
	bli_init(bli, oaddr);
	bli->btl = btl;
	return bli;
}

void silofs_bli_del(struct silofs_btleaf_info *bli, struct silofs_alloc *alloc)
{
	struct silofs_btree_leaf *btl = bli->btl;

	bli_fini(bli);
	bli_free(bli, alloc);
	btl_del(btl, alloc);
}

int silofs_bli_resolve(const struct silofs_btleaf_info *bli,
                       const struct silofs_laddr *laddr,
                       struct silofs_oaddr *out_oaddr)
{
	const struct silofs_btree_leaf *btl = bli->btl;
	const size_t nltops = btl_nltops(btl);
	size_t slot;

	if (!nltops) {
		return -SILOFS_ENOENT;
	}
	slot = btl_find_slot_of(btl, laddr);
	if (slot >= nltops) {
		return -SILOFS_ENOENT;
	}
	btl_oaddr_at(btl, slot, out_oaddr);
	return 0;
}

int silofs_bli_extend(struct silofs_btleaf_info *bli,
                      const struct silofs_laddr *laddr,
                      const struct silofs_oaddr *oaddr)
{
	struct silofs_btree_leaf *btl = bli->btl;
	const size_t nfree_ltops = btl_nfree_ltops(btl);
	size_t slot;

	if (!nfree_ltops) {
		return -SILOFS_ENOSPC;
	}
	slot = btl_insert_slot_of(btl, laddr);
	btl_insert_ltop(btl, slot, laddr, oaddr);
	return 0;
}
