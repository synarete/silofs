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
 *
 * Silofs is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/ps.h>

static void *pnode_memalloc(struct silofs_alloc *alloc, size_t size)
{
	return silofs_memalloc(alloc, size, SILOFS_ALLOCF_BZERO);
}

static void pnode_memfree(struct silofs_alloc *alloc, void *ptr, size_t size)
{
	silofs_memfree(alloc, ptr, size, SILOFS_ALLOCF_TRYPUNCH);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cpn_setup_hdr(struct silofs_chkpt_node *cpn)
{
	silofs_hdr_setup(&cpn->cpn_hdr, SILOFS_PTYPE_CHKPT, sizeof(*cpn),
	                 SILOFS_HDRF_PTYPE);
}

static void cpn_set_self_paddr(struct silofs_chkpt_node *cpn,
                               const struct silofs_paddr *paddr)
{
	silofs_assert_eq(paddr->ptype, SILOFS_PTYPE_CHKPT);

	silofs_paddr48b_htox(&cpn->cpn_self_paddr, paddr);
}

static void cpn_btree_root(const struct silofs_chkpt_node *cpn,
                           struct silofs_paddr *out_paddr)
{
	silofs_paddr48b_xtoh(&cpn->cpn_btree_root, out_paddr);
}

static void cpn_set_btree_root(struct silofs_chkpt_node *cpn,
                               const struct silofs_paddr *paddr)
{
	silofs_paddr48b_htox(&cpn->cpn_btree_root, paddr);
}

static void cpn_reset_btree_root(struct silofs_chkpt_node *cpn)
{
	cpn_set_btree_root(cpn, paddr_none());
}

static enum silofs_pnodef cpn_flags(const struct silofs_chkpt_node *cpn)
{
	const uint32_t f = silofs_le32_to_cpu(cpn->cpn_flags);

	return (enum silofs_pnodef)f;
}

static void cpn_set_flags(struct silofs_chkpt_node *cpn, enum silofs_pnodef f)
{
	cpn->cpn_flags = silofs_cpu_to_le32((uint32_t)f);
}

static void cpn_add_flags(struct silofs_chkpt_node *cpn, enum silofs_pnodef f)
{
	cpn_set_flags(cpn, f | cpn_flags(cpn));
}

static void
cpn_init(struct silofs_chkpt_node *cpn, const struct silofs_paddr *paddr)
{
	cpn_setup_hdr(cpn);
	cpn_set_self_paddr(cpn, paddr);
	cpn_reset_btree_root(cpn);
	cpn_set_flags(cpn, SILOFS_PNODEF_NONE);
	cpn_add_flags(cpn, SILOFS_PNODEF_META);
}

static void cpn_fini(struct silofs_chkpt_node *cpn)
{
	cpn_set_btree_root(cpn, paddr_none());
}

static struct silofs_chkpt_node *cpn_malloc(struct silofs_alloc *alloc)
{
	struct silofs_chkpt_node *cpn;

	cpn = pnode_memalloc(alloc, sizeof(*cpn));
	return cpn;
}

static void cpn_free(struct silofs_chkpt_node *cpn, struct silofs_alloc *alloc)
{
	pnode_memfree(alloc, cpn, sizeof(*cpn));
}

static struct silofs_chkpt_node *
cpn_new(struct silofs_alloc *alloc, const struct silofs_paddr *paddr)
{
	struct silofs_chkpt_node *cpn;

	cpn = cpn_malloc(alloc);
	if (cpn != NULL) {
		cpn_init(cpn, paddr);
	}
	return cpn;
}

static void cpn_del(struct silofs_chkpt_node *cpn, struct silofs_alloc *alloc)
{
	cpn_fini(cpn);
	cpn_free(cpn, alloc);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void btn_setup_hdr(struct silofs_btree_node *btn)
{
	silofs_hdr_setup(&btn->btn_hdr, SILOFS_PTYPE_BTNODE, sizeof(*btn),
	                 SILOFS_HDRF_PTYPE);
}

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

static void btn_set_nchilds(struct silofs_btree_node *btn, size_t nchilds)
{
	silofs_assert_le(nchilds, ARRAY_SIZE(btn->btn_child));
	btn->btn_nchilds = silofs_cpu_to_le16((uint16_t)nchilds);
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
                         struct silofs_paddr *out_paddr)
{
	silofs_assert_lt(slot, ARRAY_SIZE(btn->btn_child));

	silofs_paddr48b_xtoh(&btn->btn_child[slot], out_paddr);
}

static void btn_set_child_at(struct silofs_btree_node *btn, size_t slot,
                             const struct silofs_paddr *paddr)
{
	silofs_assert_lt(slot, ARRAY_SIZE(btn->btn_child));

	silofs_paddr48b_htox(&btn->btn_child[slot], paddr);
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

static void btn_init(struct silofs_btree_node *btn)
{
	btn_setup_hdr(btn);
	btn_set_flags(btn, SILOFS_PNODEF_NONE);
	btn_set_nkeys(btn, 0);
	btn_set_nchilds(btn, 0);
	btn_reset_childs(btn);
	btn_reset_keys(btn);
}

static void btn_fini(struct silofs_btree_node *btn)
{
	btn_set_nkeys(btn, 0);
	btn_set_nchilds(btn, 0);
	btn_reset_childs(btn);
	btn_reset_keys(btn);
}

static struct silofs_btree_node *btn_malloc(struct silofs_alloc *alloc)
{
	struct silofs_btree_node *btn;

	btn = pnode_memalloc(alloc, sizeof(*btn));
	return btn;
}

static void btn_free(struct silofs_btree_node *btn, struct silofs_alloc *alloc)
{
	pnode_memfree(alloc, btn, sizeof(*btn));
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

#define laddr48b_htox(lx_, lh_) silofs_laddr48b_htox(lx_, lh_)
#define laddr48b_xtoh(lx_, lh_) silofs_laddr48b_xtoh(lx_, lh_)
#define paddr48b_htox(px_, ph_) silofs_paddr48b_htox(px_, ph_)
#define paddr48b_xtoh(px_, ph_) silofs_paddr48b_xtoh(px_, ph_)

static void
ltop_htox(struct silofs_btree_ltop *ltop, const struct silofs_laddr *laddr,
          const struct silofs_paddr *paddr)
{
	laddr48b_htox(&ltop->laddr, laddr);
	paddr48b_htox(&ltop->paddr, paddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void btl_setup_hdr(struct silofs_btree_leaf *btl)
{
	silofs_hdr_setup(&btl->btl_hdr, SILOFS_PTYPE_BTLEAF, sizeof(*btl),
	                 SILOFS_HDRF_PTYPE);
}

static void btl_set_flags(struct silofs_btree_leaf *btl, enum silofs_pnodef f)
{
	btl->btl_flags = silofs_cpu_to_le32((uint32_t)f);
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

static void btl_laddr_at(const struct silofs_btree_leaf *btl, size_t slot,
                         struct silofs_laddr *out_laddr)
{
	silofs_assert_lt(slot, btl_nltops_max(btl));

	laddr48b_xtoh(&btl->btl_ltop[slot].laddr, out_laddr);
}

static void btl_paddr_at(const struct silofs_btree_leaf *btl, size_t slot,
                         struct silofs_paddr *out_paddr)
{
	silofs_assert_lt(slot, btl_nltops_max(btl));

	paddr48b_xtoh(&btl->btl_ltop[slot].paddr, out_paddr);
}

static void
btl_ltop_at(const struct silofs_btree_leaf *btl, size_t slot,
            struct silofs_laddr *out_laddr, struct silofs_paddr *out_paddr)
{
	btl_laddr_at(btl, slot, out_laddr);
	btl_paddr_at(btl, slot, out_paddr);
}

static void btl_set_ltop_at(struct silofs_btree_leaf *btl, size_t slot,
                            const struct silofs_laddr *laddr,
                            const struct silofs_paddr *paddr)
{
	silofs_assert_lt(slot, btl_nltops_max(btl));

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
                            const struct silofs_paddr *paddr)
{
	struct silofs_laddr laddr_at_slot;
	struct silofs_paddr paddr_at_slot;
	const size_t nltop = btl_nltops(btl);

	silofs_assert_lt(nltop, btl_nltops_max(btl));
	for (size_t i = nltop; i > slot; --i) {
		btl_ltop_at(btl, i - 1, &laddr_at_slot, &paddr_at_slot);
		btl_set_ltop_at(btl, i, &laddr_at_slot, &paddr_at_slot);
	}
	btl_set_ltop_at(btl, slot, laddr, paddr);
	btl_inc_nltops(btl);
}

static void btl_init(struct silofs_btree_leaf *btl)
{
	btl_setup_hdr(btl);
	btl_set_flags(btl, SILOFS_PNODEF_NONE);
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

	btl = pnode_memalloc(alloc, sizeof(*btl));
	return btl;
}

static void btl_free(struct silofs_btree_leaf *btl, struct silofs_alloc *alloc)
{
	pnode_memfree(alloc, btl, sizeof(*btl));
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

static void
pni_init(struct silofs_pnode_info *pni, const struct silofs_paddr *paddr)
{
	silofs_paddr_assign(&pni->pn_paddr, paddr);
	silofs_hmqe_init(&pni->pn_hmqe, ptype_size(paddr->ptype));
	silofs_hkey_by_paddr(&pni->pn_hmqe.hme_key, &pni->pn_paddr);
	pni->pn_bstore = NULL;
}

static void pni_fini(struct silofs_pnode_info *pni)
{
	silofs_paddr_fini(&pni->pn_paddr);
	silofs_hmqe_fini(&pni->pn_hmqe);
	pni->pn_bstore = NULL;
}

enum silofs_ptype silofs_pni_ptype(const struct silofs_pnode_info *pni)
{
	return pni->pn_paddr.ptype;
}

static struct silofs_dq_elem *pni_dqe(struct silofs_pnode_info *pni)
{
	return &pni->pn_hmqe.hme_dqe;
}

static const struct silofs_dq_elem *
pni_dqe2(const struct silofs_pnode_info *pni)
{
	return &pni->pn_hmqe.hme_dqe;
}

static void pni_set_dq(struct silofs_pnode_info *pni, struct silofs_dirtyq *dq)
{
	silofs_dqe_setq(pni_dqe(pni), dq);
}

static bool pni_isdirty(const struct silofs_pnode_info *pni)
{
	return silofs_dqe_is_dirty(pni_dqe2(pni));
}

static void silofs_pni_dirtify(struct silofs_pnode_info *pni)
{
	if (!pni_isdirty(pni)) {
		silofs_dqe_enqueue(pni_dqe(pni));
	}
}

void silofs_pni_undirtify(struct silofs_pnode_info *pni)
{
	if (pni_isdirty(pni)) {
		silofs_dqe_dequeue(pni_dqe(pni));
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_chkpt_info *cpi_malloc(struct silofs_alloc *alloc)
{
	struct silofs_chkpt_info *cpi = NULL;

	cpi = silofs_memalloc(alloc, sizeof(*cpi), 0);
	return cpi;
}

static void cpi_free(struct silofs_chkpt_info *cpi, struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, cpi, sizeof(*cpi), 0);
}

static void
cpi_init(struct silofs_chkpt_info *cpi, const struct silofs_paddr *paddr)
{
	silofs_assert(!silofs_paddr_isnull(paddr));
	silofs_assert_eq(paddr->ptype, SILOFS_PTYPE_CHKPT);

	pni_init(&cpi->cp_pni, paddr);
	cpi->cp = NULL;
}

static void cpi_fini(struct silofs_chkpt_info *cpi)
{
	pni_fini(&cpi->cp_pni);
	cpi->cp = NULL;
}

struct silofs_chkpt_info *
silofs_cpi_new(const struct silofs_paddr *paddr, struct silofs_alloc *alloc)
{
	struct silofs_chkpt_node *cpn = NULL;
	struct silofs_chkpt_info *cpi = NULL;

	cpn = cpn_new(alloc, paddr);
	if (cpn == NULL) {
		return NULL;
	}
	cpi = cpi_malloc(alloc);
	if (cpi == NULL) {
		cpn_del(cpn, alloc);
		return NULL;
	}
	cpi_init(cpi, paddr);
	cpi->cp = cpn;
	return cpi;
}

void silofs_cpi_del(struct silofs_chkpt_info *cpi, struct silofs_alloc *alloc)
{
	struct silofs_chkpt_node *cpn = cpi->cp;

	cpi_fini(cpi);
	cpi_free(cpi, alloc);
	cpn_del(cpn, alloc);
}

static struct silofs_chkpt_info *cpi_unconst(const struct silofs_chkpt_info *p)
{
	union {
		const struct silofs_chkpt_info *p;
		struct silofs_chkpt_info *q;
	} u = { .p = p };
	return u.q;
}

struct silofs_chkpt_info *
silofs_cpi_from_pni(const struct silofs_pnode_info *pni)
{
	const struct silofs_chkpt_info *cpi;

	silofs_assert_not_null(pni);
	silofs_assert_eq(pni->pn_paddr.ptype, SILOFS_PTYPE_CHKPT);

	cpi = container_of2(pni, struct silofs_chkpt_info, cp_pni);
	return cpi_unconst(cpi);
}

void silofs_cpi_set_dq(struct silofs_chkpt_info *cpi, struct silofs_dirtyq *dq)
{
	pni_set_dq(&cpi->cp_pni, dq);
}

void silofs_cpi_dirtify(struct silofs_chkpt_info *cpi)
{
	silofs_pni_dirtify(&cpi->cp_pni);
}

void silofs_cpi_undirtify(struct silofs_chkpt_info *cpi)
{
	silofs_pni_undirtify(&cpi->cp_pni);
}

void silofs_cpi_btree_root(const struct silofs_chkpt_info *cpi,
                           struct silofs_paddr *out_paddr)
{
	cpn_btree_root(cpi->cp, out_paddr);
}

void silofs_cpi_set_btree_root(struct silofs_chkpt_info *cpi,
                               const struct silofs_paddr *paddr)
{
	cpn_set_btree_root(cpi->cp, paddr);
	silofs_cpi_dirtify(cpi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_btnode_info *bti_malloc(struct silofs_alloc *alloc)
{
	struct silofs_btnode_info *bti = NULL;

	bti = silofs_memalloc(alloc, sizeof(*bti), 0);
	return bti;
}

static void
bti_free(struct silofs_btnode_info *bti, struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, bti, sizeof(*bti), 0);
}

static void
bti_init(struct silofs_btnode_info *bti, const struct silofs_paddr *paddr)
{
	silofs_assert(!silofs_paddr_isnull(paddr));
	silofs_assert_eq(paddr->ptype, SILOFS_PTYPE_BTNODE);

	pni_init(&bti->bn_pni, paddr);
	bti->bn = NULL;
}

static void bti_fini(struct silofs_btnode_info *bti)
{
	pni_fini(&bti->bn_pni);
	bti->bn = NULL;
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
	bti->bn = btn;
	return bti;
}

void silofs_bti_del(struct silofs_btnode_info *bti, struct silofs_alloc *alloc)
{
	struct silofs_btree_node *btn = bti->bn;

	bti_fini(bti);
	bti_free(bti, alloc);
	btn_del(btn, alloc);
}

void silofs_bti_set_dq(struct silofs_btnode_info *bti,
                       struct silofs_dirtyq *dq)
{
	pni_set_dq(&bti->bn_pni, dq);
}

void silofs_bti_mark_root(struct silofs_btnode_info *bti)
{
	btn_add_flags(bti->bn, SILOFS_PNODEF_META | SILOFS_PNODEF_BTROOT);
	silofs_bti_dirtify(bti);
}

int silofs_bti_resolve(const struct silofs_btnode_info *bti,
                       const struct silofs_laddr *laddr,
                       struct silofs_paddr *out_paddr)
{
	const size_t nkeys = btn_nkeys(bti->bn);
	size_t slot;

	if (!nkeys) {
		return -SILOFS_ENOENT;
	}
	slot = btn_resolve_slot_by(bti->bn, laddr);
	btn_child_at(bti->bn, slot, out_paddr);
	if (paddr_isnull(out_paddr)) {
		return -SILOFS_ENOENT;
	}
	return 0;
}

int silofs_bti_expand(struct silofs_btnode_info *bti,
                      const struct silofs_laddr *laddr,
                      const struct silofs_paddr *paddr)
{
	struct silofs_btree_node *btn = bti->bn;
	const size_t nfree_keys = btn_nfree_keys(btn);
	size_t slot;

	if (!nfree_keys) {
		return -SILOFS_ENOSPC;
	}
	slot = btn_resolve_slot_by(btn, laddr);
	btn_insert_child(btn, slot, paddr);
	btn_insert_key(btn, slot, laddr);
	return 0;
}

void silofs_bti_setapex(struct silofs_btnode_info *bti,
                        const struct silofs_paddr *paddr)
{
	const size_t slot = btn_nkeys(bti->bn);

	btn_set_child_at(bti->bn, slot, paddr);
}

void silofs_bti_dirtify(struct silofs_btnode_info *bti)
{
	silofs_pni_dirtify(&bti->bn_pni);
}

void silofs_bti_undirtify(struct silofs_btnode_info *bti)
{
	silofs_pni_undirtify(&bti->bn_pni);
}

static struct silofs_btnode_info *
bti_unconst(const struct silofs_btnode_info *p)
{
	union {
		const struct silofs_btnode_info *p;
		struct silofs_btnode_info *q;
	} u = { .p = p };
	return u.q;
}

struct silofs_btnode_info *
silofs_bti_from_pni(const struct silofs_pnode_info *pni)
{
	const struct silofs_btnode_info *bti = NULL;

	silofs_assert_not_null(pni);
	silofs_assert_eq(pni->pn_paddr.ptype, SILOFS_PTYPE_BTNODE);

	bti = container_of2(pni, struct silofs_btnode_info, bn_pni);
	return bti_unconst(bti);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_btleaf_info *bli_malloc(struct silofs_alloc *alloc)
{
	struct silofs_btleaf_info *bli = NULL;

	bli = silofs_memalloc(alloc, sizeof(*bli), 0);
	return bli;
}

static void
bli_free(struct silofs_btleaf_info *bli, struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, bli, sizeof(*bli), 0);
}

static void
bli_init(struct silofs_btleaf_info *bli, const struct silofs_paddr *paddr)
{
	silofs_assert(!silofs_paddr_isnull(paddr));
	silofs_assert_eq(paddr->ptype, SILOFS_PTYPE_BTLEAF);

	pni_init(&bli->bl_pni, paddr);
	bli->bl = NULL;
}

static void bli_fini(struct silofs_btleaf_info *bli)
{
	pni_fini(&bli->bl_pni);
	bli->bl = NULL;
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
	bli->bl = btl;
	return bli;
}

void silofs_bli_del(struct silofs_btleaf_info *bli, struct silofs_alloc *alloc)
{
	struct silofs_btree_leaf *btl = bli->bl;

	bli_fini(bli);
	bli_free(bli, alloc);
	btl_del(btl, alloc);
}

void silofs_bli_set_dq(struct silofs_btleaf_info *bli,
                       struct silofs_dirtyq *dq)
{
	pni_set_dq(&bli->bl_pni, dq);
}

void silofs_bli_dirtify(struct silofs_btleaf_info *bli)
{
	silofs_pni_dirtify(&bli->bl_pni);
}

void silofs_bli_undirtify(struct silofs_btleaf_info *bli)
{
	silofs_pni_undirtify(&bli->bl_pni);
}

int silofs_bli_resolve(const struct silofs_btleaf_info *bli,
                       const struct silofs_laddr *laddr,
                       struct silofs_paddr *out_paddr)
{
	const struct silofs_btree_leaf *btl = bli->bl;
	const size_t nltops = btl_nltops(btl);
	size_t slot;

	if (!nltops) {
		return -SILOFS_ENOENT;
	}
	slot = btl_find_slot_of(btl, laddr);
	if (slot >= nltops) {
		return -SILOFS_ENOENT;
	}
	btl_paddr_at(btl, slot, out_paddr);
	return 0;
}

int silofs_bli_extend(struct silofs_btleaf_info *bli,
                      const struct silofs_laddr *laddr,
                      const struct silofs_paddr *paddr)
{
	struct silofs_btree_leaf *btl = bli->bl;
	const size_t nfree_ltops = btl_nfree_ltops(btl);
	size_t slot;

	if (!nfree_ltops) {
		return -SILOFS_ENOSPC;
	}
	slot = btl_insert_slot_of(btl, laddr);
	btl_insert_ltop(btl, slot, laddr, paddr);
	return 0;
}

static struct silofs_btleaf_info *
bli_unconst(const struct silofs_btleaf_info *p)
{
	union {
		const struct silofs_btleaf_info *p;
		struct silofs_btleaf_info *q;
	} u = { .p = p };
	return u.q;
}

struct silofs_btleaf_info *
silofs_bli_from_pni(const struct silofs_pnode_info *pni)
{
	const struct silofs_btleaf_info *bli = NULL;

	silofs_assert_not_null(pni);
	silofs_assert_eq(pni->pn_paddr.ptype, SILOFS_PTYPE_BTLEAF);

	bli = container_of2(pni, struct silofs_btleaf_info, bl_pni);
	return bli_unconst(bli);
}
