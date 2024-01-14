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
#include <silofs/pv.h>


static void btn_setup_hdr(struct silofs_btree_node *btn)
{
	silofs_hdr_setup(&btn->btn_hdr, SILOFS_PTYPE_BTNODE,
	                 sizeof(*btn), SILOFS_HDRF_PTYPE);
}

static void btn_set_nchilds(struct silofs_btree_node *btn, size_t nchilds)
{
	btn->btn_nchilds = silofs_cpu_to_le16((uint16_t)nchilds);
}

static void btn_set_nkeys(struct silofs_btree_node *btn, size_t nkeys)
{
	btn->btn_nkeys = silofs_cpu_to_le16((uint16_t)nkeys);
}

static void btn_set_child_at(struct silofs_btree_node *btn, size_t slot,
                             const struct silofs_paddr *paddr)
{
	silofs_assert_lt(slot, ARRAY_SIZE(btn->btn_child));

	silofs_paddr32b_htox(&btn->btn_child[slot], paddr);
}

static void btn_reset_child_at(struct silofs_btree_node *btn, size_t slot)
{
	btn_set_child_at(btn, slot, paddr_none());
}

static void btn_reset_childs(struct silofs_btree_node *btn)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(btn->btn_child); ++slot) {
		btn_reset_child_at(btn, slot);
	}
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

static void btn_init(struct silofs_btree_node *btn)
{
	btn_setup_hdr(btn);
	btn_set_nchilds(btn, 0);
	btn_set_nkeys(btn, 0);
	btn_reset_childs(btn);
	btn_reset_keys(btn);
}

static void btn_fini(struct silofs_btree_node *btn)
{
	btn_set_nchilds(btn, 0);
	btn_set_nkeys(btn, 0);
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

static void ltop_htox(struct silofs_btree_ltop *ltop,
                      const struct silofs_laddr *laddr,
                      const struct silofs_paddr *paddr)
{
	silofs_laddr48b_htox(&ltop->laddr, laddr);
	silofs_paddr32b_htox(&ltop->paddr, paddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void btl_set_nltops(struct silofs_btree_leaf *btl, size_t n)
{
	btl->btl_nltops = silofs_cpu_to_le16((uint16_t)n);
}

static void btl_setup_hdr(struct silofs_btree_leaf *btl)
{
	silofs_hdr_setup(&btl->btl_hdr, SILOFS_PTYPE_BTLEAF,
	                 sizeof(*btl), SILOFS_HDRF_PTYPE);
}

static void btl_set_ltop_at(struct silofs_btree_leaf *btl, size_t slot,
                            const struct silofs_laddr *laddr,
                            const struct silofs_paddr *paddr)
{
	silofs_assert_lt(slot, ARRAY_SIZE(btl->btl_ltop));

	ltop_htox(&btl->btl_ltop[slot], laddr, paddr);
}

static void btl_reset_ltop_at(struct silofs_btree_leaf *btl, size_t slot)
{
	btl_set_ltop_at(btl, slot, laddr_none(), paddr_none());
}

static void btl_reset_ltops(struct silofs_btree_leaf *btl)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(btl->btl_ltop); ++slot) {
		btl_reset_ltop_at(btl, slot);
	}
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

static void pni_init(struct silofs_pnode_info *pni, enum silofs_ptype type,
                     const struct silofs_paddr *paddr)
{
	silofs_assert(!silofs_paddr_isnull(paddr));

	silofs_paddr_assign(&pni->p_paddr, paddr);
	silofs_hmqe_init(&pni->p_hmqe);
	silofs_hkey_by_paddr(&pni->p_hmqe.hme_key, &pni->p_paddr);
	pni->p_psenv = NULL;
	pni->p_type = type;
}

static void pni_fini(struct silofs_pnode_info *pni)
{
	silofs_paddr_reset(&pni->p_paddr);
	silofs_hmqe_fini(&pni->p_hmqe);
	pni->p_psenv = NULL;
}

bool silofs_pni_isevictable(const struct silofs_pnode_info *pni)
{
	return silofs_hmqe_is_evictable(&pni->p_hmqe);
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
                     const struct silofs_paddr *paddr)
{
	silofs_assert(!silofs_paddr_isnull(paddr));

	pni_init(&bti->btn_pni, SILOFS_PTYPE_BTNODE, paddr);
	bti->btn = NULL;
}

static void bti_fini(struct silofs_btnode_info *bti)
{
	pni_fini(&bti->btn_pni);
	bti->btn = NULL;
}

struct silofs_btnode_info *
silofs_bti_new(const struct silofs_paddr *paddr, struct silofs_alloc *alloc)
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
	bti_init(bti, paddr);
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

static struct silofs_btnode_info *
bti_unconst(const struct silofs_btnode_info *bti)
{
	union {
		const struct silofs_btnode_info *p;
		struct silofs_btnode_info *q;
	} u = {
		.p = bti
	};
	return u.q;
}

struct silofs_btnode_info *
silofs_bti_from_pni(const struct silofs_pnode_info *pni)
{
	const struct silofs_btnode_info *bti = NULL;

	if ((pni != NULL) && (pni->p_type == SILOFS_PTYPE_BTNODE)) {
		bti = container_of2(pni, struct silofs_btnode_info, btn_pni);
	}
	return bti_unconst(bti);
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
                     const struct silofs_paddr *paddr)
{
	silofs_assert(!silofs_paddr_isnull(paddr));

	pni_init(&bli->btl_pni, SILOFS_PTYPE_BTLEAF, paddr);
	bli->btl = NULL;
}

static void bli_fini(struct silofs_btleaf_info *bli)
{
	pni_fini(&bli->btl_pni);
	bli->btl = NULL;
}

struct silofs_btleaf_info *
silofs_bli_new(const struct silofs_paddr *paddr, struct silofs_alloc *alloc)
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
	bli_init(bli, paddr);
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

static struct silofs_btleaf_info *
bli_unconst(const struct silofs_btleaf_info *bli)
{
	union {
		const struct silofs_btleaf_info *p;
		struct silofs_btleaf_info *q;
	} u = {
		.p = bli
	};
	return u.q;
}

struct silofs_btleaf_info *
silofs_bli_from_pni(const struct silofs_pnode_info *pni)
{
	const struct silofs_btleaf_info *bli = NULL;

	if ((pni != NULL) && (pni->p_type == SILOFS_PTYPE_BTLEAF)) {
		bli = container_of2(pni, struct silofs_btleaf_info, btl_pni);
	}
	return bli_unconst(bli);
}

