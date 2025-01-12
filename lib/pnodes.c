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
#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/pnodes.h>

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

static size_t btn_height(const struct silofs_btree_node *btn)
{
	return btn->btn_height;
}

static void btn_set_height(struct silofs_btree_node *btn, size_t height)
{
	silofs_assert_le(height, 8);
	silofs_assert_gt(height, 0);
	btn->btn_height = (uint8_t)height;
}

static bool btn_isleaf(const struct silofs_btree_node *btn)
{
	const size_t height = btn_height(btn);

	silofs_assert_gt(height, 0);
	silofs_assert_le(height, SILOFS_BTREE_HEIGHT_MAX);

	return (height == 1);
}

static size_t btn_nchilds(struct silofs_btree_node *btn)
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

static loff_t btn_key_at(const struct silofs_btree_node *btn, size_t slot)
{
	silofs_assert_lt(slot, btn_nkeys_max(btn));

	return silofs_off_to_cpu(btn->btn_key[slot]);
}

static void
btn_set_key_at(struct silofs_btree_node *btn, size_t slot, loff_t off)
{
	silofs_assert_lt(slot, ARRAY_SIZE(btn->btn_key));

	btn->btn_key[slot] = silofs_cpu_to_off(off);
}

static void btn_reset_key_at(struct silofs_btree_node *btn, size_t slot)
{
	btn_set_key_at(btn, slot, SILOFS_OFF_NULL);
}

static void btn_reset_keys(struct silofs_btree_node *btn)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(btn->btn_key); ++slot) {
		btn_reset_key_at(btn, slot);
	}
}

static long btn_compare_key_at(const struct silofs_btree_node *btn,
                               size_t slot, loff_t off)
{
	const loff_t soff = btn_key_at(btn, slot);

	return soff - off;
}

static size_t
btn_resolve_slot_by(const struct silofs_btree_node *btn, loff_t off)
{
	const size_t nkeys = btn_nkeys(btn);
	long cmp;

	for (size_t slot = 0; slot < nkeys; ++slot) {
		cmp = btn_compare_key_at(btn, slot, off);
		if (cmp <= 0) {
			return slot;
		}
	}
	return nkeys;
}

static size_t
btn_lookup_slot_by(const struct silofs_btree_node *btn, loff_t off)
{
	const size_t nkeys = btn_nkeys(btn);
	long cmp;

	for (size_t slot = 0; slot < nkeys; ++slot) {
		cmp = btn_compare_key_at(btn, slot, off);
		if (cmp == 0) {
			return slot;
		}
	}
	return nkeys;
}

static void
btn_insert_key(struct silofs_btree_node *btn, size_t slot, loff_t off)
{
	const size_t nkeys = btn_nkeys(btn);
	loff_t ioff;

	silofs_assert_lt(nkeys, btn_nkeys_max(btn));
	for (size_t i = nkeys; i > slot; --i) {
		ioff = btn_key_at(btn, i - 1);
		btn_set_key_at(btn, i, ioff);
	}
	btn_set_key_at(btn, slot, off);
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

static void
btn_resolve_internal_child(const struct silofs_btree_node *btn, loff_t off,
                           struct silofs_paddr *out_paddr)
{
	size_t slot;

	slot = btn_resolve_slot_by(btn, off);
	btn_child_at(btn, slot, out_paddr);
}

static void btn_resolve_leaf_child(const struct silofs_btree_node *btn,
                                   loff_t off, struct silofs_paddr *out_paddr)
{
	size_t slot;

	slot = btn_lookup_slot_by(btn, off);
	btn_child_at(btn, slot, out_paddr);
}

static void btn_resolve_child(const struct silofs_btree_node *btn, loff_t off,
                              struct silofs_paddr *out_paddr)
{
	if (btn_isleaf(btn)) {
		btn_resolve_leaf_child(btn, off, out_paddr);
	} else {
		btn_resolve_internal_child(btn, off, out_paddr);
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
	btn_set_height(btn, 1);
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

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void
pni_init(struct silofs_pnode_info *pni, const struct silofs_paddr *paddr)
{
	silofs_paddr_assign(&pni->pn_paddr, paddr);
	silofs_hmqe_init(&pni->pn_hmqe, ptype_size(paddr->ptype));
	silofs_hkey_by_paddr(&pni->pn_hmqe.hme_key, &pni->pn_paddr);
}

static void pni_fini(struct silofs_pnode_info *pni)
{
	silofs_paddr_fini(&pni->pn_paddr);
	silofs_hmqe_fini(&pni->pn_hmqe);
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
	const struct silofs_chkpt_info *cpi = NULL;

	if (pni != NULL) {
		silofs_assert_eq(pni->pn_paddr.ptype, SILOFS_PTYPE_CHKPT);
		cpi = container_of2(pni, struct silofs_chkpt_info, cp_pni);
	}
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

static struct silofs_btnode_info *bni_malloc(struct silofs_alloc *alloc)
{
	struct silofs_btnode_info *bni = NULL;

	bni = silofs_memalloc(alloc, sizeof(*bni), 0);
	return bni;
}

static void
bni_free(struct silofs_btnode_info *bni, struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, bni, sizeof(*bni), 0);
}

static void
bni_init(struct silofs_btnode_info *bni, const struct silofs_paddr *paddr)
{
	silofs_assert(!silofs_paddr_isnull(paddr));
	silofs_assert_eq(paddr->ptype, SILOFS_PTYPE_BTNODE);

	pni_init(&bni->bn_pni, paddr);
	bni->bn = NULL;
}

static void bni_fini(struct silofs_btnode_info *bni)
{
	pni_fini(&bni->bn_pni);
	bni->bn = NULL;
}

struct silofs_btnode_info *
silofs_bni_new(const struct silofs_paddr *paddr, struct silofs_alloc *alloc)
{
	struct silofs_btree_node *btn = NULL;
	struct silofs_btnode_info *bni = NULL;

	btn = btn_new(alloc);
	if (btn == NULL) {
		return NULL;
	}
	bni = bni_malloc(alloc);
	if (bni == NULL) {
		btn_del(btn, alloc);
		return NULL;
	}
	bni_init(bni, paddr);
	bni->bn = btn;
	return bni;
}

void silofs_bni_del(struct silofs_btnode_info *bni, struct silofs_alloc *alloc)
{
	struct silofs_btree_node *btn = bni->bn;

	bni_fini(bni);
	bni_free(bni, alloc);
	btn_del(btn, alloc);
}

void silofs_bni_set_dq(struct silofs_btnode_info *bni,
                       struct silofs_dirtyq *dq)
{
	pni_set_dq(&bni->bn_pni, dq);
}

void silofs_bni_mark_root(struct silofs_btnode_info *bni)
{
	btn_add_flags(bni->bn, SILOFS_PNODEF_META | SILOFS_PNODEF_BTROOT);
	silofs_bni_dirtify(bni);
}

bool silofs_bni_marked_root(const struct silofs_btnode_info *bni)
{
	const enum silofs_pnodef flgs = btn_flags(bni->bn);

	return ((flgs & SILOFS_PNODEF_BTROOT) > 0);
}

size_t silofs_bni_height(const struct silofs_btnode_info *bni)
{
	return btn_height(bni->bn);
}

size_t silofs_bni_nkeys(const struct silofs_btnode_info *bni)
{
	return btn_nkeys(bni->bn);
}

size_t silofs_bni_nchilds(const struct silofs_btnode_info *bni)
{
	return btn_nchilds(bni->bn);
}

static bool bni_has_child_at(const struct silofs_btnode_info *bni, size_t slot)
{
	return (slot < silofs_bni_nchilds(bni));
}

void silofs_bni_child_at(const struct silofs_btnode_info *bni, size_t slot,
                         struct silofs_paddr *out_paddr)
{
	silofs_paddr_reset(out_paddr);
	if (bni_has_child_at(bni, slot)) {
		btn_child_at(bni->bn, slot, out_paddr);
	}
}

int silofs_bni_resolve(const struct silofs_btnode_info *bni,
                       const struct silofs_vaddr *vaddr,
                       struct silofs_paddr *out_paddr)
{
	const size_t nkeys = btn_nkeys(bni->bn);

	if (!nkeys) {
		return -SILOFS_ENOENT;
	}
	if (vaddr_isnull(vaddr)) {
		return -SILOFS_ENOENT;
	}
	btn_resolve_child(bni->bn, vaddr->off, out_paddr);
	if (paddr_isnull(out_paddr)) {
		return -SILOFS_ENOENT;
	}
	return 0;
}

int silofs_bni_expand(struct silofs_btnode_info *bni,
                      const struct silofs_vaddr *vaddr,
                      const struct silofs_paddr *paddr)
{
	struct silofs_btree_node *btn = bni->bn;
	const size_t nfree_keys = btn_nfree_keys(btn);
	const loff_t off = vaddr->off;
	size_t slot;

	if (!nfree_keys) {
		return -SILOFS_ENOSPC;
	}
	slot = btn_resolve_slot_by(btn, off);
	btn_insert_child(btn, slot, paddr);
	btn_insert_key(btn, slot, off);
	return 0;
}

void silofs_bni_setapex(struct silofs_btnode_info *bni,
                        const struct silofs_paddr *paddr)
{
	const size_t slot = btn_nkeys(bni->bn);

	btn_set_child_at(bni->bn, slot, paddr);
}

void silofs_bni_dirtify(struct silofs_btnode_info *bni)
{
	silofs_pni_dirtify(&bni->bn_pni);
}

void silofs_bni_undirtify(struct silofs_btnode_info *bni)
{
	silofs_pni_undirtify(&bni->bn_pni);
}

static struct silofs_btnode_info *
bni_unconst(const struct silofs_btnode_info *p)
{
	union {
		const struct silofs_btnode_info *p;
		struct silofs_btnode_info *q;
	} u = { .p = p };
	return u.q;
}

struct silofs_btnode_info *
silofs_bni_from_pni(const struct silofs_pnode_info *pni)
{
	const struct silofs_btnode_info *bni = NULL;

	if (pni != NULL) {
		silofs_assert_eq(pni->pn_paddr.ptype, SILOFS_PTYPE_BTNODE);
		bni = container_of2(pni, struct silofs_btnode_info, bn_pni);
	}
	return bni_unconst(bni);
}
