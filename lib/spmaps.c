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
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include "infra.h"
#include "lnodes.h"
#include "spmaps.h"

static void lrange_of_spleaf(struct silofs_lrange *lrange, loff_t voff)
{
	silofs_lrange_of_spmap(lrange, SILOFS_HEIGHT_SPLEAF, voff);
}

static void lrange_of_spnode(struct silofs_lrange *lrange,
                             enum silofs_height height, loff_t voff)
{
	silofs_lrange_of_spmap(lrange, height, voff);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t nkbs_of(const struct silofs_vaddr *vaddr)
{
	return silofs_ltype_nkbs(vaddr->ltype);
}

static size_t kbn_of(const struct silofs_vaddr *vaddr)
{
	return (size_t)((vaddr->off / SILOFS_KB_SIZE) % SILOFS_NKB_IN_LBK);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
spr_uaddr(const struct silofs_spmap_ref *spr, struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr64b_xtoh(&spr->sr_uaddr, out_uaddr);
}

static void
spr_set_uaddr(struct silofs_spmap_ref *spr, const struct silofs_uaddr *uaddr)
{
	silofs_uaddr64b_htox(&spr->sr_uaddr, uaddr);
}

static void spr_reset(struct silofs_spmap_ref *spr)
{
	silofs_uaddr64b_reset(&spr->sr_uaddr);
}

static bool spr_isactive(const struct silofs_spmap_ref *spr)
{
	struct silofs_uaddr uaddr;

	spr_uaddr(spr, &uaddr);
	return !silofs_uaddr_isnull(&uaddr);
}

static void spr_init(struct silofs_spmap_ref *spr)
{
	memset(spr, 0, sizeof(*spr));
	spr_reset(spr);
}

static void spr_initn(struct silofs_spmap_ref *spr, size_t n)
{
	for (size_t i = 0; i < n; ++i) {
		spr_init(&spr[i]);
	}
}

static void spr_clone_from(struct silofs_spmap_ref *spr,
                           const struct silofs_spmap_ref *spr_other)
{
	struct silofs_uaddr uaddr;

	spr_uaddr(spr_other, &uaddr);
	spr_set_uaddr(spr, &uaddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void spnode_parent(const struct silofs_spmap_node *spn,
                          struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr64b_xtoh(&spn->sn_parent, out_uaddr);
}

static void spnode_set_parent(struct silofs_spmap_node *spn,
                              const struct silofs_uaddr *uaddr)
{
	silofs_uaddr64b_htox(&spn->sn_parent, uaddr);
}

static void spnode_self(const struct silofs_spmap_node *spn,
                        struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr64b_xtoh(&spn->sn_self, out_uaddr);
}

static void spnode_set_self(struct silofs_spmap_node *spn,
                            const struct silofs_uaddr *uaddr)
{
	silofs_uaddr64b_htox(&spn->sn_self, uaddr);
}

static void spnode_lrange(const struct silofs_spmap_node *spn,
                          struct silofs_lrange *out_lrange)
{
	silofs_lrange128_xtoh(&spn->sn_lrange, out_lrange);
}

static void spnode_set_lrange(struct silofs_spmap_node *spn,
                              const struct silofs_lrange *lrange)
{
	silofs_lrange128_htox(&spn->sn_lrange, lrange);
}

static enum silofs_height spnode_heigth(const struct silofs_spmap_node *spn)
{
	struct silofs_uaddr self_uaddr;

	spnode_self(spn, &self_uaddr);
	return silofs_uaddr_height(&self_uaddr);
}

static void spnode_main_lsid(const struct silofs_spmap_node *spn,
                             struct silofs_lsid *out_lsid)
{
	silofs_lsid32b_xtoh(&spn->sn_main_lsid, out_lsid);
}

static void spnode_set_main_lsid(struct silofs_spmap_node *spn,
                                 const struct silofs_lsid *lsid)
{
	silofs_lsid32b_htox(&spn->sn_main_lsid, lsid);
}

static void
spnode_init(struct silofs_spmap_node *spn, const struct silofs_lrange *lrange)
{
	spnode_set_lrange(spn, lrange);
	silofs_lsid32b_reset(&spn->sn_main_lsid);
	silofs_uaddr64b_reset(&spn->sn_parent);
	silofs_uaddr64b_reset(&spn->sn_self);
	spr_initn(spn->sn_subrefs, ARRAY_SIZE(spn->sn_subrefs));
}

static size_t spnode_slot_of(const struct silofs_spmap_node *spn, loff_t voff)
{
	const size_t nslots = SILOFS_SPMAP_NCHILDS;
	struct silofs_lrange lrange;
	size_t len;
	size_t slot;
	ssize_t roff;

	STATICASSERT_EQ(ARRAY_SIZE(spn->sn_subrefs), SILOFS_SPMAP_NCHILDS);

	spnode_lrange(spn, &lrange);
	len = silofs_lrange_len(&lrange);
	roff = off_diff(lrange.beg, voff);
	slot = (size_t)(roff * (long)nslots) / len;
	silofs_assert_lt(slot, nslots);
	return slot;
}

static struct silofs_spmap_ref *
spnode_subref_at(const struct silofs_spmap_node *spn, size_t slot)
{
	const struct silofs_spmap_ref *spr = &spn->sn_subrefs[slot];

	return unconst(spr);
}

static struct silofs_spmap_ref *
spnode_subref_of(const struct silofs_spmap_node *spn, loff_t voff)
{
	return spnode_subref_at(spn, spnode_slot_of(spn, voff));
}

static void spnode_uaddr_of(const struct silofs_spmap_node *spn, loff_t voff,
                            struct silofs_uaddr *out_uaddr)
{
	const struct silofs_spmap_ref *spr = spnode_subref_of(spn, voff);

	spr_uaddr(spr, out_uaddr);
}

static void spnode_set_uaddr_of(struct silofs_spmap_node *spn, loff_t voff,
                                const struct silofs_uaddr *uaddr)
{
	struct silofs_spmap_ref *spr = spnode_subref_of(spn, voff);

	spr_set_uaddr(spr, uaddr);
}

static size_t spnode_count_nactive(const struct silofs_spmap_node *spn)
{
	const struct silofs_spmap_ref *spr = NULL;
	const size_t nslots_max = ARRAY_SIZE(spn->sn_subrefs);
	size_t count = 0;

	for (size_t slot = 0; slot < nslots_max; ++slot) {
		spr = spnode_subref_at(spn, slot);
		if (!spr_isactive(spr)) {
			break;
		}
		++count;
	}
	return count;
}

static void spnode_clone_subrefs(struct silofs_spmap_node *spn,
                                 const struct silofs_spmap_node *sn_other)
{
	struct silofs_spmap_ref *spr = NULL;
	const struct silofs_spmap_ref *spr_other = NULL;
	const size_t nslots_max = ARRAY_SIZE(spn->sn_subrefs);

	for (size_t slot = 0; slot < nslots_max; ++slot) {
		spr = spnode_subref_at(spn, slot);
		spr_other = spnode_subref_at(sn_other, slot);
		spr_clone_from(spr, spr_other);
	}
}

static bool
spnode_has_child_at(const struct silofs_spmap_node *spn, loff_t voff)
{
	const struct silofs_spmap_ref *spr = spnode_subref_of(spn, voff);

	return spr_isactive(spr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint64_t mask_of(size_t ki, size_t nk)
{
	uint64_t mask;
	const uint64_t zero = 0;

	if (nk < 64) {
		mask = (((1UL << nk) - 1UL) << ki);
	} else {
		mask = ~zero;
	}
	return mask;
}

static void
lbk_state_mask_of(struct silofs_lbk_state *lbk_st, size_t ki, size_t nk)
{
	size_t nn;

	lbk_st->state = 0;
	if (ki < 64) {
		nn = min(nk, 64 - ki);
		lbk_st->state = mask_of(ki, nn);
	}
}

static void lbk_state_none(struct silofs_lbk_state *lbk_st)
{
	lbk_st->state = 0;
}

static void lbk_state_mask_of_other(struct silofs_lbk_state *lbk_st,
                                    size_t kbn, size_t nkb)
{
	struct silofs_lbk_state lbk_st2;

	lbk_state_mask_of(&lbk_st2, kbn, nkb);
	lbk_st->state = ~lbk_st2.state;
}

static bool lbk_state_has_any(const struct silofs_lbk_state *lbk_st)
{
	return (lbk_st->state > 0);
}

static bool lbk_state_has_mask(const struct silofs_lbk_state *lbk_st,
                               const struct silofs_lbk_state *lbk_mask)
{
	return ((lbk_st->state & lbk_mask->state) == lbk_mask->state);
}

static bool lbk_state_has_mask_none(const struct silofs_lbk_state *lbk_st,
                                    const struct silofs_lbk_state *lbk_mask)
{
	return ((lbk_st->state & lbk_mask->state) == 0);
}

static bool lbk_state_has_mask_any(const struct silofs_lbk_state *lbk_st,
                                   const struct silofs_lbk_state *lbk_mask)
{
	return ((lbk_st->state & lbk_mask->state) > 0);
}

static void lbk_state_set_mask(struct silofs_lbk_state *lbk_st,
                               const struct silofs_lbk_state *lbk_mask)
{
	lbk_st->state |= lbk_mask->state;
}

static void lbk_state_unset_mask(struct silofs_lbk_state *lbk_st,
                                 const struct silofs_lbk_state *lbk_mask)
{
	lbk_st->state &= ~(lbk_mask->state);
}

static size_t lbk_state_popcount(const struct silofs_lbk_state *lbk_st)
{
	return silofs_popcount_u64(lbk_st->state);
}

static void lbk_state_xtoh(const struct silofs_lbk_state *lbk_st_le,
                           struct silofs_lbk_state *lbk_st)
{
	lbk_st->state = silofs_le64_to_cpu(lbk_st_le->state);
}

static void lbk_state_htox(struct silofs_lbk_state *lbk_st_le,
                           const struct silofs_lbk_state *lbk_st)
{
	lbk_st_le->state = silofs_cpu_to_le64(lbk_st->state);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_lbk_ref *lbr_unconst(const struct silofs_lbk_ref *lbr)
{
	return unconst(lbr);
}

static void
lbr_subref(const struct silofs_lbk_ref *lbr, struct silofs_laddr *out_laddr)
{
	silofs_laddr48b_xtoh(&lbr->lbr_subref, out_laddr);
}

static void
lbr_set_subref(struct silofs_lbk_ref *lbr, const struct silofs_laddr *laddr)
{
	silofs_laddr48b_htox(&lbr->lbr_subref, laddr);
}

static size_t lbr_refcnt(const struct silofs_lbk_ref *lbr)
{
	return silofs_le64_to_cpu(lbr->lbr_refcnt);
}

static void lbr_set_refcnt(struct silofs_lbk_ref *lbr, size_t n)
{
	lbr->lbr_refcnt = silofs_cpu_to_le64(n);
}

static void lbr_inc_refcnt(struct silofs_lbk_ref *lbr)
{
	lbr_set_refcnt(lbr, lbr_refcnt(lbr) + 1);
}

static void lbr_dec_refcnt(struct silofs_lbk_ref *lbr)
{
	const size_t cur = lbr_refcnt(lbr);

	silofs_expect_ge(cur, 1);

	lbr_set_refcnt(lbr, cur - 1);
}

static void lbr_allocated(const struct silofs_lbk_ref *lbr,
                          struct silofs_lbk_state *lbk_st)
{
	lbk_state_xtoh(&lbr->lbr_allocated, lbk_st);
}

static void lbr_set_allocated(struct silofs_lbk_ref *lbr,
                              const struct silofs_lbk_state *lbk_st)
{
	lbk_state_htox(&lbr->lbr_allocated, lbk_st);
}

static bool
lbr_test_allocated_at(const struct silofs_lbk_ref *lbr, size_t kbn, size_t nkb)
{
	struct silofs_lbk_state lbk_st;
	struct silofs_lbk_state bk_mask;

	lbr_allocated(lbr, &lbk_st);
	lbk_state_mask_of(&bk_mask, kbn, nkb);
	return lbk_state_has_mask(&lbk_st, &bk_mask);
}

static bool lbr_test_allocated_bk(const struct silofs_lbk_ref *lbr)
{
	return lbr_test_allocated_at(lbr, 0, SILOFS_NKB_IN_LBK);
}

static bool lbr_test_allocated_other(const struct silofs_lbk_ref *lbr,
                                     size_t kbn, size_t nkb)
{
	struct silofs_lbk_state lbk_st;
	struct silofs_lbk_state bk_mask;

	lbr_allocated(lbr, &lbk_st);
	lbk_state_mask_of_other(&bk_mask, kbn, nkb);
	return lbk_state_has_mask_any(&lbk_st, &bk_mask);
}

static void
lbr_set_allocated_at(struct silofs_lbk_ref *lbr, size_t kbn, size_t nkb)
{
	struct silofs_lbk_state lbk_st;
	struct silofs_lbk_state bk_mask;

	lbr_allocated(lbr, &lbk_st);
	lbk_state_mask_of(&bk_mask, kbn, nkb);
	lbk_state_set_mask(&lbk_st, &bk_mask);
	lbr_set_allocated(lbr, &lbk_st);
}

static void
lbr_clear_allocated_at(struct silofs_lbk_ref *lbr, size_t kbn, size_t nkb)
{
	struct silofs_lbk_state lbk_st;
	struct silofs_lbk_state bk_mask;

	lbr_allocated(lbr, &lbk_st);
	lbk_state_mask_of(&bk_mask, kbn, nkb);
	lbk_state_unset_mask(&lbk_st, &bk_mask);
	lbr_set_allocated(lbr, &lbk_st);
}

static size_t lbr_usecnt(const struct silofs_lbk_ref *lbr)
{
	struct silofs_lbk_state lbk_st;

	lbr_allocated(lbr, &lbk_st);
	return lbk_state_popcount(&lbk_st);
}

static size_t lbr_usecnt_nbytes(const struct silofs_lbk_ref *lbr)
{
	return SILOFS_KB_SIZE * lbr_usecnt(lbr);
}

static size_t lbr_freecnt(const struct silofs_lbk_ref *lbr)
{
	return SILOFS_NKB_IN_LBK - lbr_usecnt(lbr);
}

static bool lbr_isfull(const struct silofs_lbk_ref *lbr)
{
	return lbr_test_allocated_bk(lbr);
}

static bool lbr_isunused(const struct silofs_lbk_ref *lbr)
{
	struct silofs_lbk_state lbk_st;

	lbr_allocated(lbr, &lbk_st);
	return !lbk_state_has_any(&lbk_st);
}

static void lbr_unwritten(const struct silofs_lbk_ref *lbr,
                          struct silofs_lbk_state *lbk_st)
{
	lbk_state_xtoh(&lbr->lbr_unwritten, lbk_st);
}

static void lbr_set_unwritten(struct silofs_lbk_ref *lbr,
                              const struct silofs_lbk_state *lbk_st)
{
	lbk_state_htox(&lbr->lbr_unwritten, lbk_st);
}

static bool
lbr_test_unwritten_at(const struct silofs_lbk_ref *lbr, size_t kbn, size_t nkb)
{
	struct silofs_lbk_state lbk_st;
	struct silofs_lbk_state bk_mask;

	lbr_unwritten(lbr, &lbk_st);
	lbk_state_mask_of(&bk_mask, kbn, nkb);
	return lbk_state_has_mask(&lbk_st, &bk_mask);
}

static void
lbr_set_unwritten_at(struct silofs_lbk_ref *lbr, size_t kbn, size_t nkb)
{
	struct silofs_lbk_state lbk_st;
	struct silofs_lbk_state bk_mask;

	lbr_unwritten(lbr, &lbk_st);
	lbk_state_mask_of(&bk_mask, kbn, nkb);
	lbk_state_set_mask(&lbk_st, &bk_mask);
	lbr_set_unwritten(lbr, &lbk_st);
}

static void
lbr_clear_unwritten_at(struct silofs_lbk_ref *lbr, size_t kbn, size_t nkb)
{
	struct silofs_lbk_state lbk_st;
	struct silofs_lbk_state bk_mask;

	lbr_unwritten(lbr, &lbk_st);
	lbk_state_mask_of(&bk_mask, kbn, nkb);
	lbk_state_unset_mask(&lbk_st, &bk_mask);
	lbr_set_unwritten(lbr, &lbk_st);
}

static void lbr_clear_alloc_state(struct silofs_lbk_ref *lbr)
{
	struct silofs_lbk_state lbk_st;

	lbk_state_none(&lbk_st);
	lbr_set_allocated(lbr, &lbk_st);
	lbr_set_unwritten(lbr, &lbk_st);
	lbr_set_refcnt(lbr, 0);
}

static const struct silofs_key *lbr_key(const struct silofs_lbk_ref *lbr)
{
	return &lbr->lbr_key;
}

static void lbr_gen_key(struct silofs_lbk_ref *lbr)
{
	silofs_key_mkrand(&lbr->lbr_key);
}

static void
lbr_set_key(struct silofs_lbk_ref *lbr, const struct silofs_key *key)
{
	silofs_key_assign(&lbr->lbr_key, key);
}

static void lbr_reset(struct silofs_lbk_ref *lbr)
{
	memset(lbr, 0, sizeof(*lbr));
	lbr_clear_alloc_state(lbr);
	silofs_laddr48b_reset(&lbr->lbr_subref);
}

static void lbr_init(struct silofs_lbk_ref *lbr)
{
	lbr_reset(lbr);
}

static void lbr_init_arr(struct silofs_lbk_ref *arr, size_t cnt)
{
	for (size_t i = 0; i < cnt; ++i) {
		lbr_init(&arr[i]);
	}
}

static bool lbr_may_alloc(const struct silofs_lbk_ref *lbr, size_t nkb)
{
	return !lbr_isfull(lbr) && (nkb <= lbr_freecnt(lbr));
}

static int
lbr_find_free(const struct silofs_lbk_ref *lbr, size_t nkb, size_t *out_kbn)
{
	struct silofs_lbk_state lbk_st;
	struct silofs_lbk_state bk_mask;
	const size_t nkb_in_bk = SILOFS_NKB_IN_LBK;

	lbr_allocated(lbr, &lbk_st);
	for (size_t kbn = 0; (kbn + nkb) <= nkb_in_bk; kbn += nkb) {
		lbk_state_mask_of(&bk_mask, kbn, nkb);
		if (lbk_state_has_mask_none(&lbk_st, &bk_mask)) {
			*out_kbn = kbn;
			return 0;
		}
	}
	return -SILOFS_ENOSPC;
}

static void
lbr_make_vaddrs(const struct silofs_lbk_ref *lbr, enum silofs_ltype ltype,
                loff_t voff_base, struct silofs_vaddrs *vas)
{
	struct silofs_lbk_state lbk_st;
	struct silofs_lbk_state bk_mask;
	const size_t nkb = silofs_ltype_nkbs(ltype);
	const size_t nkb_in_bk = SILOFS_NKB_IN_LBK;
	loff_t voff;

	lbr_allocated(lbr, &lbk_st);
	vas->count = 0;
	for (size_t kbn = 0; (kbn + nkb) <= nkb_in_bk; kbn += nkb) {
		lbk_state_mask_of(&bk_mask, kbn, nkb);
		if (lbk_state_has_mask(&lbk_st, &bk_mask)) {
			voff = off_end(voff_base, kbn * SILOFS_KB_SIZE);
			vaddr_setup(&vas->vaddr[vas->count++], ltype, voff);
		}
	}
}

static void lbr_clone_from(struct silofs_lbk_ref *lbr,
                           const struct silofs_lbk_ref *lbr_other)
{
	struct silofs_laddr laddr;
	struct silofs_lbk_state lbk_st;
	size_t dbkref;

	lbr_subref(lbr_other, &laddr);
	lbr_set_subref(lbr, &laddr);

	lbr_allocated(lbr_other, &lbk_st);
	lbr_set_allocated(lbr, &lbk_st);

	lbr_unwritten(lbr_other, &lbk_st);
	lbr_set_unwritten(lbr, &lbk_st);

	dbkref = lbr_refcnt(lbr_other);
	lbr_set_refcnt(lbr, dbkref);

	lbr_set_key(lbr, lbr_key(lbr_other));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void spleaf_lrange(const struct silofs_spmap_leaf *spl,
                          struct silofs_lrange *out_lrange)
{
	silofs_lrange128_xtoh(&spl->sl_lrange, out_lrange);
}

static void spleaf_set_lrange(struct silofs_spmap_leaf *spl,
                              const struct silofs_lrange *lrange)
{
	silofs_lrange128_htox(&spl->sl_lrange, lrange);
}

static enum silofs_ltype spleaf_refltype(const struct silofs_spmap_leaf *spl)
{
	return (enum silofs_ltype)(spl->sl_refltype);
}

static void
spleaf_set_refltype(struct silofs_spmap_leaf *spl, enum silofs_ltype refltype)
{
	spl->sl_refltype = (uint8_t)refltype;
}

static void
spleaf_init(struct silofs_spmap_leaf *spl, const struct silofs_lrange *lrange,
            enum silofs_ltype refltype)
{
	spleaf_set_lrange(spl, lrange);
	spleaf_set_refltype(spl, refltype);
	silofs_lsid32b_reset(&spl->sl_main_lsid);
	silofs_uaddr64b_reset(&spl->sl_parent);
	silofs_uaddr64b_reset(&spl->sl_self);
	lbr_init_arr(spl->sl_lbrs, ARRAY_SIZE(spl->sl_lbrs));
}

static void spleaf_parent(const struct silofs_spmap_leaf *spl,
                          struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr64b_xtoh(&spl->sl_parent, out_uaddr);
}

static void spleaf_set_parent(struct silofs_spmap_leaf *spl,
                              const struct silofs_uaddr *uaddr)
{
	silofs_uaddr64b_htox(&spl->sl_parent, uaddr);
}

static void spleaf_self(const struct silofs_spmap_leaf *spl,
                        struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr64b_xtoh(&spl->sl_self, out_uaddr);
}

static void spleaf_set_self(struct silofs_spmap_leaf *spl,
                            const struct silofs_uaddr *uaddr)
{
	silofs_uaddr64b_htox(&spl->sl_self, uaddr);
}

static struct silofs_lbk_ref *
spleaf_lbr_at(const struct silofs_spmap_leaf *spl, size_t slot)
{
	const struct silofs_lbk_ref *lbr = &(spl->sl_lbrs[slot]);

	return lbr_unconst(lbr);
}

static size_t
spleaf_lba_slot(const struct silofs_spmap_leaf *spl, silofs_lba_t lba)
{
	return (size_t)lba % ARRAY_SIZE(spl->sl_lbrs);
}

static size_t spleaf_slot_of(const struct silofs_spmap_leaf *spl, loff_t voff)
{
	return spleaf_lba_slot(spl, off_to_lba(voff));
}

static struct silofs_lbk_ref *
spleaf_lbr_by_lba(const struct silofs_spmap_leaf *spl, silofs_lba_t lba)
{
	return spleaf_lbr_at(spl, spleaf_lba_slot(spl, lba));
}

static struct silofs_lbk_ref *
spleaf_lbr_by_voff(const struct silofs_spmap_leaf *spl, loff_t voff)
{
	return spleaf_lbr_at(spl, spleaf_slot_of(spl, voff));
}

static struct silofs_lbk_ref *
spleaf_lbr_by_vaddr(const struct silofs_spmap_leaf *spl,
                    const struct silofs_vaddr *vaddr)
{
	return spleaf_lbr_by_voff(spl, vaddr->off);
}

static bool spleaf_is_allocated_at(const struct silofs_spmap_leaf *spl,
                                   const struct silofs_vaddr *vaddr)
{
	const size_t kbn = kbn_of(vaddr);
	const size_t nkb = nkbs_of(vaddr);
	const struct silofs_lbk_ref *lbr;
	bool ret;

	lbr = spleaf_lbr_by_vaddr(spl, vaddr);
	if (vaddr_isdatabk(vaddr)) {
		ret = (lbr_refcnt(lbr) > 0);
	} else {
		ret = lbr_test_allocated_at(lbr, kbn, nkb);
	}
	return ret;
}

static bool spleaf_has_allocated_with(const struct silofs_spmap_leaf *spl,
                                      const struct silofs_vaddr *vaddr)
{
	const size_t kbn = kbn_of(vaddr);
	const size_t nkb = nkbs_of(vaddr);
	const struct silofs_lbk_ref *lbr;
	bool ret;

	lbr = spleaf_lbr_by_vaddr(spl, vaddr);
	if (vaddr_isdatabk(vaddr)) {
		ret = (lbr_refcnt(lbr) > 0);
	} else {
		ret = lbr_test_allocated_other(lbr, kbn, nkb);
	}
	return ret;
}

static bool spleaf_is_last_allocated(const struct silofs_spmap_leaf *spl,
                                     const struct silofs_vaddr *vaddr)
{
	const size_t kbn = kbn_of(vaddr);
	const size_t nkb = nkbs_of(vaddr);
	const struct silofs_lbk_ref *lbr;
	bool ret;

	lbr = spleaf_lbr_by_vaddr(spl, vaddr);
	if (vaddr_isdatabk(vaddr)) {
		ret = (lbr_refcnt(lbr) == 1);
	} else {
		ret = !lbr_test_allocated_other(lbr, kbn, nkb);
	}
	return ret;
}

static bool spleaf_test_unwritten_at(const struct silofs_spmap_leaf *spl,
                                     const struct silofs_vaddr *vaddr)
{
	const struct silofs_lbk_ref *lbr = spleaf_lbr_by_vaddr(spl, vaddr);

	return lbr_test_unwritten_at(lbr, kbn_of(vaddr), nkbs_of(vaddr));
}

static void spleaf_set_unwritten_at(struct silofs_spmap_leaf *spl,
                                    const struct silofs_vaddr *vaddr)
{
	struct silofs_lbk_ref *lbr = spleaf_lbr_by_vaddr(spl, vaddr);

	lbr_set_unwritten_at(lbr, kbn_of(vaddr), nkbs_of(vaddr));
}

static void spleaf_clear_unwritten_at(struct silofs_spmap_leaf *spl,
                                      const struct silofs_vaddr *vaddr)
{
	struct silofs_lbk_ref *lbr = spleaf_lbr_by_vaddr(spl, vaddr);

	lbr_clear_unwritten_at(lbr, kbn_of(vaddr), nkbs_of(vaddr));
}

static size_t spleaf_dbkref_at(const struct silofs_spmap_leaf *spl,
                               const struct silofs_vaddr *vaddr)
{
	const struct silofs_lbk_ref *lbr = spleaf_lbr_by_vaddr(spl, vaddr);

	silofs_assert_eq(vaddr->ltype, SILOFS_LTYPE_DATABK);

	return lbr_refcnt(lbr);
}

static void spleaf_ref_allocated_at(struct silofs_spmap_leaf *spl,
                                    const struct silofs_vaddr *vaddr)
{
	const size_t kbn = kbn_of(vaddr);
	const size_t nkb = nkbs_of(vaddr);
	struct silofs_lbk_ref *lbr = spleaf_lbr_by_vaddr(spl, vaddr);

	lbr_set_allocated_at(lbr, kbn, nkb);
	if (vaddr_isdatabk(vaddr)) {
		lbr_inc_refcnt(lbr);
	}
}

static void spleaf_unref_allocated_at(struct silofs_spmap_leaf *spl,
                                      const struct silofs_vaddr *vaddr)
{
	const size_t kbn = kbn_of(vaddr);
	const size_t nkb = nkbs_of(vaddr);
	struct silofs_lbk_ref *lbr = spleaf_lbr_by_vaddr(spl, vaddr);

	if (vaddr_isdatabk(vaddr)) {
		lbr_dec_refcnt(lbr);
	}
	if (!lbr_refcnt(lbr) || (nkb < SILOFS_NKB_IN_LBK)) {
		lbr_clear_allocated_at(lbr, kbn, nkb);
	}
}

static void spleaf_renew_bk_at(struct silofs_spmap_leaf *spl,
                               const struct silofs_vaddr *vaddr)
{
	struct silofs_lbk_ref *lbr = spleaf_lbr_by_vaddr(spl, vaddr);

	silofs_assert(lbr_isunused(lbr));
	lbr_clear_alloc_state(lbr);
}

static size_t spleaf_refltype_nkb(const struct silofs_spmap_leaf *spl)
{
	const enum silofs_ltype refltype = spleaf_refltype(spl);

	return silofs_ltype_nkbs(refltype);
}

static int spleaf_find_free_at(const struct silofs_spmap_leaf *spl, size_t bn,
                               size_t *out_kbn)
{
	const size_t nkb = spleaf_refltype_nkb(spl);
	const struct silofs_lbk_ref *lbr = spleaf_lbr_at(spl, bn);
	int err = -SILOFS_ENOSPC;

	if (lbr_may_alloc(lbr, nkb)) {
		err = lbr_find_free(lbr, nkb, out_kbn);
	}
	return err;
}

static int spleaf_find_free(const struct silofs_spmap_leaf *spl, size_t bn_beg,
                            size_t bn_end, size_t *out_bn, size_t *out_kbn)
{
	size_t kbn = 0;
	int err = -SILOFS_ENOSPC;

	for (size_t bn = bn_beg; bn < bn_end; ++bn) {
		err = spleaf_find_free_at(spl, bn, &kbn);
		if (!err) {
			*out_bn = bn;
			*out_kbn = kbn;
			break;
		}
	}
	return err;
}

static void spleaf_make_vaddrs(const struct silofs_spmap_leaf *spl,
                               enum silofs_ltype ltype, silofs_lba_t lba,
                               struct silofs_vaddrs *vas)
{
	const struct silofs_lbk_ref *lbr = spleaf_lbr_by_lba(spl, lba);
	const loff_t off = silofs_lba_to_off(lba);

	lbr_make_vaddrs(lbr, ltype, off, vas);
}

static void spleaf_main_lsid(const struct silofs_spmap_leaf *spl,
                             struct silofs_lsid *out_lsid)
{
	silofs_lsid32b_xtoh(&spl->sl_main_lsid, out_lsid);
}

static void spleaf_set_main_lsid(struct silofs_spmap_leaf *spl,
                                 const struct silofs_lsid *lsid)
{
	silofs_lsid32b_htox(&spl->sl_main_lsid, lsid);
}

static void spleaf_main_child_at(const struct silofs_spmap_leaf *spl,
                                 size_t slot, struct silofs_laddr *out_laddr)
{
	struct silofs_lsid lsid = { .height = SILOFS_HEIGHT_NONE };
	const loff_t pos = silofs_lba_to_off((silofs_lba_t)slot);

	spleaf_main_lsid(spl, &lsid);
	silofs_laddr_setup_lbk(out_laddr, &lsid, pos);
}

static void spleaf_bind_lbks_to_main(struct silofs_spmap_leaf *spl)
{
	struct silofs_laddr laddr;
	struct silofs_lbk_ref *lbr = NULL;
	const size_t nslots = ARRAY_SIZE(spl->sl_lbrs);

	for (size_t slot = 0; slot < nslots; ++slot) {
		lbr = spleaf_lbr_at(spl, slot);
		spleaf_main_child_at(spl, slot, &laddr);
		lbr_set_subref(lbr, &laddr);
	}
}

static size_t spleaf_calc_total_usecnt(const struct silofs_spmap_leaf *spl)
{
	const struct silofs_lbk_ref *lbr = NULL;
	const size_t nslots = ARRAY_SIZE(spl->sl_lbrs);
	size_t usecnt_sum = 0;

	for (size_t slot = 0; slot < nslots; ++slot) {
		lbr = spleaf_lbr_at(spl, slot);
		usecnt_sum += lbr_usecnt(lbr);
	}
	return usecnt_sum;
}

static size_t spleaf_sum_nbytes_used(const struct silofs_spmap_leaf *spl)
{
	return spleaf_calc_total_usecnt(spl) * SILOFS_KB_SIZE;
}

static void
spleaf_resolve_main_lbk(const struct silofs_spmap_leaf *spl, loff_t voff,
                        struct silofs_laddr *out_laddr)
{
	struct silofs_lsid lsid;

	spleaf_main_lsid(spl, &lsid);
	silofs_laddr_setup_lbk(out_laddr, &lsid, voff);
}

static void spleaf_child_of(const struct silofs_spmap_leaf *spl, loff_t voff,
                            struct silofs_laddr *out_laddr)
{
	const struct silofs_lbk_ref *lbr = spleaf_lbr_by_voff(spl, voff);

	lbr_subref(lbr, out_laddr);
}

static void spleaf_bind_child(struct silofs_spmap_leaf *spl, loff_t voff,
                              const struct silofs_llink *llink)
{
	struct silofs_lbk_ref *lbr = spleaf_lbr_by_voff(spl, voff);

	silofs_assert_gt(lbr_usecnt(lbr), 0);
	lbr_set_subref(lbr, &llink->laddr);
	lbr_set_key(lbr, &llink->ivkey.key);
}

static void spleaf_gen_child_keys(struct silofs_spmap_leaf *spl)
{
	struct silofs_lbk_ref *lbr;

	for (size_t slot = 0; slot < ARRAY_SIZE(spl->sl_lbrs); ++slot) {
		lbr = spleaf_lbr_at(spl, slot);
		lbr_gen_key(lbr);
	}
}

static const struct silofs_key *
spleaf_child_key_at(const struct silofs_spmap_leaf *spl, size_t slot)
{
	const struct silofs_lbk_ref *lbr = spleaf_lbr_at(spl, slot);

	return lbr_key(lbr);
}

static void spleaf_child_key_of(const struct silofs_spmap_leaf *spl,
                                loff_t voff, struct silofs_key *out_key)
{
	const size_t slot = spleaf_slot_of(spl, voff);

	silofs_key_assign(out_key, spleaf_child_key_at(spl, slot));
}

static void
spleaf_renew_child_key_of(struct silofs_spmap_leaf *spl, loff_t voff)
{
	struct silofs_lbk_ref *lbr = spleaf_lbr_by_voff(spl, voff);

	lbr_gen_key(lbr);
}

static void spleaf_resolve_child(const struct silofs_spmap_leaf *spl,
                                 loff_t voff, struct silofs_laddr *out_laddr,
                                 struct silofs_key *out_key)
{
	spleaf_child_of(spl, voff, out_laddr);
	spleaf_child_key_of(spl, voff, out_key);
}

static void spleaf_clone_subrefs(struct silofs_spmap_leaf *spl,
                                 const struct silofs_spmap_leaf *sl_other)
{
	struct silofs_lbk_ref *lbr;
	const struct silofs_lbk_ref *lbr_other;

	for (size_t slot = 0; slot < ARRAY_SIZE(spl->sl_lbrs); ++slot) {
		lbr = spleaf_lbr_at(spl, slot);
		lbr_other = spleaf_lbr_at(sl_other, slot);
		lbr_clone_from(lbr, lbr_other);
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_unode_info *sli_uni(struct silofs_spleaf_info *sli)
{
	return &sli->sl_uni;
}

const struct silofs_uaddr *
silofs_sli_uaddr(const struct silofs_spleaf_info *sli)
{
	return silofs_uni_uaddr(&sli->sl_uni);
}

const struct silofs_laddr *
silofs_sli_laddr(const struct silofs_spleaf_info *sli)
{
	return silofs_uni_laddr(&sli->sl_uni);
}

static enum silofs_ltype sli_refltype(const struct silofs_spleaf_info *sli)
{
	return spleaf_refltype(sli->sl);
}

enum silofs_ltype silofs_sli_refltype(const struct silofs_spleaf_info *sli)
{
	return sli_refltype(sli);
}

void silofs_sli_incref(struct silofs_spleaf_info *sli)
{
	if (likely(sli != NULL)) {
		uni_incref(sli_uni(sli));
	}
}

void silofs_sli_decref(struct silofs_spleaf_info *sli)
{
	if (likely(sli != NULL)) {
		uni_decref(sli_uni(sli));
	}
}

static void sli_dirtify(struct silofs_spleaf_info *sli)
{
	uni_dirtify(sli_uni(sli));
}

void silofs_sli_vspace_range(const struct silofs_spleaf_info *sli,
                             struct silofs_lrange *out_lrange)
{
	spleaf_lrange(sli->sl, out_lrange);
}

void silofs_sli_setup_spawned(struct silofs_spleaf_info *sli,
                              const struct silofs_uaddr *parent,
                              enum silofs_ltype refltype, loff_t voff)
{
	struct silofs_lrange lrange;
	struct silofs_spmap_leaf *sl = sli->sl;

	lrange_of_spleaf(&lrange, voff);
	spleaf_init(sl, &lrange, refltype);
	spleaf_set_parent(sl, parent);
	spleaf_set_self(sl, silofs_sli_uaddr(sli));
	spleaf_gen_child_keys(sl);
	sli_dirtify(sli);
}

static loff_t sli_start_voff(const struct silofs_spleaf_info *sli)
{
	struct silofs_lrange lrange;

	spleaf_lrange(sli->sl, &lrange);
	return lrange.beg;
}

void silofs_sli_update_nused(struct silofs_spleaf_info *sli)
{
	sli->sl_nused_bytes = spleaf_sum_nbytes_used(sli->sl);
	silofs_assert_le(sli->sl_nused_bytes, SILOFS_LSEG_SIZE_MAX);
}

loff_t silofs_sli_base_voff(const struct silofs_spleaf_info *sli)
{
	struct silofs_lrange lrange;

	silofs_sli_vspace_range(sli, &lrange);
	return lrange.beg;
}

static bool sli_is_inrange(const struct silofs_spleaf_info *sli, loff_t voff)
{
	struct silofs_lrange lrange;

	silofs_sli_vspace_range(sli, &lrange);
	return (lrange.beg <= voff) && (voff < lrange.end);
}

static size_t sli_voff_to_bn(const struct silofs_spleaf_info *sli, loff_t voff)
{
	const loff_t beg = sli_start_voff(sli);
	const size_t bn = (size_t)off_to_lba(voff - beg);

	return bn;
}

static void sli_vaddr_at(const struct silofs_spleaf_info *sli, size_t bn,
                         size_t kbn, struct silofs_vaddr *out_vaddr)
{
	const loff_t beg = sli_start_voff(sli);
	enum silofs_ltype refltype = sli_refltype(sli);

	silofs_vaddr_by_spleaf(out_vaddr, refltype, beg, bn, kbn);
}

static size_t sli_start_bn(const struct silofs_spleaf_info *sli)
{
	struct silofs_lrange lrange;
	loff_t voff_beg = sli->sl_voff_hint;

	silofs_sli_vspace_range(sli, &lrange);
	if (!silofs_lrange_within(&lrange, voff_beg)) {
		voff_beg = lrange.beg;
	}
	return sli_voff_to_bn(sli, voff_beg);
}

static size_t sli_finish_bn(const struct silofs_spleaf_info *sli)
{
	struct silofs_lrange lrange;

	silofs_sli_vspace_range(sli, &lrange);
	return sli_voff_to_bn(sli, lrange.end);
}

static int sli_find_free_space(const struct silofs_spleaf_info *sli,
                               struct silofs_vaddr *out_vaddr)
{
	size_t bn_beg = sli_start_bn(sli);
	size_t bn_end = sli_finish_bn(sli);
	size_t bn = 0;
	size_t kbn = 0;
	int err;

	err = spleaf_find_free(sli->sl, bn_beg, bn_end, &bn, &kbn);
	if (err && bn_beg) {
		err = spleaf_find_free(sli->sl, 0, bn_beg, &bn, &kbn);
	}
	if (!err) {
		sli_vaddr_at(sli, bn, kbn, out_vaddr);
	}
	silofs_assert_ok(err);
	return err;
}

static size_t sli_lrange_len(const struct silofs_spleaf_info *sli)
{
	struct silofs_lrange lrange;

	silofs_sli_vspace_range(sli, &lrange);
	return silofs_lrange_len(&lrange);
}

static size_t sli_refltype_size(const struct silofs_spleaf_info *sli)
{
	return silofs_ltype_size(sli_refltype(sli));
}

static bool sli_cap_allocate(const struct silofs_spleaf_info *sli)
{
	const size_t nlimit = sli_lrange_len(sli);
	const size_t nbytes_want = sli_refltype_size(sli);
	const size_t nbytes_used = sli->sl_nused_bytes;

	silofs_assert_le(nlimit, SILOFS_LSEG_SIZE_MAX);
	silofs_assert_le(nbytes_used, SILOFS_LSEG_SIZE_MAX);

	return ((nbytes_used + nbytes_want) <= nlimit);
}

int silofs_sli_find_free_space(const struct silofs_spleaf_info *sli,
                               struct silofs_vaddr *out_vaddr)
{
	int ret = -SILOFS_ENOSPC;

	if (sli_cap_allocate(sli)) {
		ret = sli_find_free_space(sli, out_vaddr);
	}
	return ret;
}

void silofs_sli_update_voff_hint(struct silofs_spleaf_info *sli,
                                 const struct silofs_vaddr *vaddr)
{
	struct silofs_lrange lrange;
	const loff_t voff = vaddr->off;

	silofs_sli_vspace_range(sli, &lrange);
	if (silofs_lrange_within(&lrange, voff)) {
		sli->sl_voff_hint = voff;
	} else {
		sli->sl_voff_hint = lrange.beg;
	}
}

void silofs_sli_mark_allocated_space(struct silofs_spleaf_info *sli,
                                     const struct silofs_vaddr *vaddr)
{
	const size_t len = vaddr_len(vaddr);

	silofs_assert_lt(sli->sl_nused_bytes, SILOFS_LSEG_SIZE_MAX);
	silofs_assert_le(sli->sl_nused_bytes + len, SILOFS_LSEG_SIZE_MAX);

	sli->sl_nused_bytes += len;

	spleaf_ref_allocated_at(sli->sl, vaddr);
	if (vaddr_isdata(vaddr)) {
		spleaf_set_unwritten_at(sli->sl, vaddr);
	}
	sli_dirtify(sli);
}

void silofs_sli_reref_allocated_space(struct silofs_spleaf_info *sli,
                                      const struct silofs_vaddr *vaddr)
{
	silofs_assert_eq(vaddr->ltype, SILOFS_LTYPE_DATABK);
	silofs_assert_ge(sli->sl_nused_bytes, SILOFS_LBK_SIZE);
	silofs_assert_le(sli->sl_nused_bytes, SILOFS_LSEG_SIZE_MAX);

	spleaf_ref_allocated_at(sli->sl, vaddr);
	sli_dirtify(sli);
}

void silofs_sli_unref_allocated_space(struct silofs_spleaf_info *sli,
                                      const struct silofs_vaddr *vaddr)
{
	struct silofs_spmap_leaf *sl = sli->sl;
	const size_t len = vaddr_len(vaddr);
	const bool last = spleaf_is_last_allocated(sl, vaddr);

	spleaf_unref_allocated_at(sl, vaddr);
	if (!spleaf_is_allocated_at(sl, vaddr)) {
		silofs_assert_ge(sli->sl_nused_bytes, len);
		sli->sl_nused_bytes -= len;
	}
	if (last) {
		spleaf_renew_bk_at(sl, vaddr);
		spleaf_renew_child_key_of(sl, vaddr->off);
	}
	sli_dirtify(sli);
}

size_t silofs_sli_dbkref_at(const struct silofs_spleaf_info *sli,
                            const struct silofs_vaddr *vaddr)
{
	size_t dbkref = 0;

	if (vaddr_isdatabk(vaddr)) {
		dbkref = spleaf_dbkref_at(sli->sl, vaddr);
	}
	return dbkref;
}

bool silofs_sli_has_allocated_with(const struct silofs_spleaf_info *sli,
                                   const struct silofs_vaddr *vaddr)
{
	return spleaf_has_allocated_with(sli->sl, vaddr);
}

bool silofs_sli_is_last_allocated(const struct silofs_spleaf_info *sli,
                                  const struct silofs_vaddr *vaddr)
{
	return spleaf_is_last_allocated(sli->sl, vaddr);
}

bool silofs_sli_has_allocated_space(const struct silofs_spleaf_info *sli,
                                    const struct silofs_vaddr *vaddr)
{
	return spleaf_is_allocated_at(sli->sl, vaddr);
}

bool silofs_sli_has_unwritten_at(const struct silofs_spleaf_info *sli,
                                 const struct silofs_vaddr *vaddr)
{
	return spleaf_test_unwritten_at(sli->sl, vaddr);
}

void silofs_sli_clear_unwritten_at(struct silofs_spleaf_info *sli,
                                   const struct silofs_vaddr *vaddr)
{
	struct silofs_spmap_leaf *sl = sli->sl;

	if (spleaf_test_unwritten_at(sl, vaddr)) {
		spleaf_clear_unwritten_at(sl, vaddr);
		sli_dirtify(sli);
	}
}

void silofs_sli_mark_unwritten_at(struct silofs_spleaf_info *sli,
                                  const struct silofs_vaddr *vaddr)
{
	struct silofs_spmap_leaf *sl = sli->sl;

	if (!spleaf_test_unwritten_at(sl, vaddr)) {
		spleaf_set_unwritten_at(sl, vaddr);
		sli_dirtify(sli);
	}
}

void silofs_sli_vaddrs_at(const struct silofs_spleaf_info *sli,
                          enum silofs_ltype ltype, silofs_lba_t lba,
                          struct silofs_vaddrs *vas)
{
	spleaf_make_vaddrs(sli->sl, ltype, lba, vas);
}

void silofs_sli_main_lseg(const struct silofs_spleaf_info *sli,
                          struct silofs_lsid *out_lsid)
{
	spleaf_main_lsid(sli->sl, out_lsid);
}

void silofs_sli_bind_main_lseg(struct silofs_spleaf_info *sli,
                               const struct silofs_lsid *lsid)
{
	spleaf_set_main_lsid(sli->sl, lsid);
	spleaf_bind_lbks_to_main(sli->sl);
	sli_dirtify(sli);
}

void silofs_sli_clone_from(struct silofs_spleaf_info *sli,
                           const struct silofs_spleaf_info *sli_other)
{
	spleaf_clone_subrefs(sli->sl, sli_other->sl);
	sli->sl_nused_bytes = sli_other->sl_nused_bytes;
	sli_dirtify(sli);
}

void silofs_sli_resolve_main_lbk(const struct silofs_spleaf_info *sli,
                                 loff_t voff, struct silofs_llink *out_llink)
{
	struct silofs_laddr laddr;
	struct silofs_key key;

	spleaf_resolve_main_lbk(sli->sl, voff, &laddr);
	spleaf_child_key_of(sli->sl, voff, &key);
	silofs_llink_setup(out_llink, &laddr, &key);
}

int silofs_sli_resolve_child(const struct silofs_spleaf_info *sli, loff_t voff,
                             struct silofs_llink *out_llink)
{
	struct silofs_laddr laddr;
	struct silofs_key key;

	if (!sli_is_inrange(sli, voff)) {
		return -SILOFS_ERANGE;
	}
	spleaf_resolve_child(sli->sl, voff, &laddr, &key);
	if (silofs_laddr_isnull(&laddr)) {
		return -SILOFS_ENOENT;
	}
	silofs_laddr_setpos(&laddr, voff);
	silofs_llink_setup(out_llink, &laddr, &key);
	return 0;
}

void silofs_sli_bind_child(struct silofs_spleaf_info *sli, loff_t voff,
                           const struct silofs_llink *llink)
{
	spleaf_bind_child(sli->sl, voff, llink);
	sli_dirtify(sli);
}

static void lmap_append_entry(struct silofs_spmap_lmap *lmap,
                              const struct silofs_laddr *laddr, size_t len)
{
	silofs_assert_lt(lmap->cnt, ARRAY_SIZE(lmap->laddr));
	silofs_assert_gt(len, 0);

	silofs_laddr_assign(&lmap->laddr[lmap->cnt], laddr);
	lmap->len[lmap->cnt] = len;
	lmap->cnt++;
}

static void lmap_append_length(struct silofs_spmap_lmap *lmap, size_t len)
{
	silofs_assert_lt(lmap->cnt, ARRAY_SIZE(lmap->laddr));
	silofs_assert_gt(lmap->cnt, 0);
	silofs_assert_gt(len, 0);

	lmap->len[lmap->cnt - 1] += len;
}

static bool
is_consecutive_laddrs(const struct silofs_laddr *laddr1, size_t len1,
                      const struct silofs_laddr *laddr2)
{
	loff_t end1;

	if (!silofs_lsid_isequal(&laddr1->lsid, &laddr2->lsid)) {
		return false;
	}
	end1 = off_end(laddr1->pos, len1);
	if (end1 != laddr2->pos) {
		return false;
	}
	if (end1 > (ssize_t)laddr2->lsid.lsize) {
		return false;
	}
	return true;
}

static bool lmap_may_append_length(const struct silofs_spmap_lmap *lmap,
                                   const struct silofs_laddr *laddr2)
{
	const struct silofs_laddr *laddr1;
	size_t len1;
	bool ret = false;

	if (lmap->cnt > 0) {
		laddr1 = &lmap->laddr[lmap->cnt - 1];
		len1 = lmap->len[lmap->cnt - 1];
		ret = is_consecutive_laddrs(laddr1, len1, laddr2);
	}
	return ret;
}

static void lmap_append(struct silofs_spmap_lmap *lmap,
                        const struct silofs_laddr *laddr, size_t len)
{
	silofs_assert_le(lmap->cnt, ARRAY_SIZE(lmap->laddr));

	if (!silofs_laddr_isnull(laddr)) {
		if (lmap_may_append_length(lmap, laddr)) {
			lmap_append_length(lmap, len);
		} else {
			lmap_append_entry(lmap, laddr, len);
		}
	}
}

void silofs_sli_resolve_lmap(const struct silofs_spleaf_info *sli,
                             struct silofs_spmap_lmap *out_lmap)
{
	struct silofs_laddr laddr = { .pos = -1 };
	const struct silofs_spmap_leaf *sl = sli->sl;
	const struct silofs_lbk_ref *lbr = NULL;
	const size_t nslots = ARRAY_SIZE(sl->sl_lbrs);
	const size_t nused = sli->sl_nused_bytes;
	size_t nused_at_slot = 0;
	size_t nbytes = 0;

	STATICASSERT_EQ(ARRAY_SIZE(out_lmap->laddr), ARRAY_SIZE(sl->sl_lbrs));

	out_lmap->cnt = 0;
	for (size_t slot = 0; (slot < nslots) && (nbytes < nused); ++slot) {
		lbr = spleaf_lbr_at(sl, slot);
		nused_at_slot = lbr_usecnt_nbytes(lbr);
		if (nused_at_slot > 0) {
			lbr_subref(lbr, &laddr);
			lmap_append(out_lmap, &laddr, SILOFS_LBK_SIZE);
			nbytes += nused_at_slot;
		}
	}

	silofs_assert_eq(nbytes, nused);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_unode_info *sni_uni(const struct silofs_spnode_info *sni)
{
	return silofs_unconst(&sni->sn_uni);
}

static void sni_dirtify(struct silofs_spnode_info *sni)
{
	uni_dirtify(sni_uni(sni));
}

const struct silofs_uaddr *
silofs_sni_uaddr(const struct silofs_spnode_info *sni)
{
	return silofs_uni_uaddr(&sni->sn_uni);
}

const struct silofs_laddr *
silofs_sni_laddr(const struct silofs_spnode_info *sni)
{
	return silofs_uni_laddr(&sni->sn_uni);
}

void silofs_sni_incref(struct silofs_spnode_info *sni)
{
	if (likely(sni != NULL)) {
		uni_incref(sni_uni(sni));
	}
}

void silofs_sni_decref(struct silofs_spnode_info *sni)
{
	if (likely(sni != NULL)) {
		uni_decref(sni_uni(sni));
	}
}

void silofs_sni_setup_spawned(struct silofs_spnode_info *sni,
                              const struct silofs_uaddr *parent, loff_t voff)
{
	struct silofs_lrange lrange = { .beg = -1, .end = -1 };
	const enum silofs_height parent_height = silofs_uaddr_height(parent);

	lrange_of_spnode(&lrange, parent_height - 1, voff);
	spnode_init(sni->sn, &lrange);
	spnode_set_parent(sni->sn, parent);
	spnode_set_self(sni->sn, silofs_sni_uaddr(sni));
	sni_dirtify(sni);
}

void silofs_sni_update_nactive(struct silofs_spnode_info *sni)
{
	sni->sn_nactive_subs = spnode_count_nactive(sni->sn);
}

enum silofs_height silofs_sni_height(const struct silofs_spnode_info *sni)
{
	return silofs_uaddr_height(silofs_sni_uaddr(sni));
}

static enum silofs_height sni_sub_height(const struct silofs_spnode_info *sni)
{
	return silofs_sni_height(sni) - 1;
}

void silofs_sni_bind_child(struct silofs_spnode_info *sni, loff_t voff,
                           const struct silofs_uaddr *uaddr)
{
	/* either we set new child or override upon clone */
	const bool bind_new = !spnode_has_child_at(sni->sn, voff);

	spnode_set_uaddr_of(sni->sn, voff, uaddr);
	if (bind_new) {
		sni->sn_nactive_subs++;
	}
	sni_dirtify(sni);
}

static bool sni_is_inrange(const struct silofs_spnode_info *sni, loff_t voff)
{
	struct silofs_lrange lrange;

	silofs_sni_vspace_range(sni, &lrange);
	return (lrange.beg <= voff) && (voff < lrange.end);
}

void silofs_sni_vspace_range(const struct silofs_spnode_info *sni,
                             struct silofs_lrange *out_lrange)
{
	spnode_lrange(sni->sn, out_lrange);
}

void silofs_sni_active_lrange(const struct silofs_spnode_info *sni,
                              struct silofs_lrange *out_lrange)
{
	struct silofs_lrange lrange;
	size_t nform_size;
	ssize_t span;

	silofs_sni_vspace_range(sni, &lrange);
	span = silofs_height_to_space_span(lrange.height - 1);
	nform_size = sni->sn_nactive_subs * (size_t)span;
	silofs_lrange_setup(out_lrange, lrange.height, lrange.beg,
	                    off_end(lrange.beg, nform_size));
}

loff_t silofs_sni_base_voff(const struct silofs_spnode_info *sni)
{
	struct silofs_lrange lrange;

	silofs_sni_vspace_range(sni, &lrange);
	return lrange.beg;
}

static enum silofs_ltype sni_child_ltype(const struct silofs_spnode_info *sni)
{
	enum silofs_ltype child_ltype;
	const size_t child_height = sni_sub_height(sni);

	if (child_height == SILOFS_HEIGHT_SPLEAF) {
		child_ltype = SILOFS_LTYPE_SPLEAF;
	} else {
		child_ltype = SILOFS_LTYPE_SPNODE;
	}
	return child_ltype;
}

static void sni_get_uaddr_of(const struct silofs_spnode_info *sni, loff_t voff,
                             struct silofs_uaddr *out_uaddr)
{
	spnode_uaddr_of(sni->sn, voff, out_uaddr);
}

int silofs_sni_resolve_child(const struct silofs_spnode_info *sni, loff_t voff,
                             struct silofs_uaddr *out_uaddr)
{
	silofs_assert(sni_is_inrange(sni, voff));
	if (!sni_is_inrange(sni, voff)) {
		return -SILOFS_ERANGE;
	}
	sni_get_uaddr_of(sni, voff, out_uaddr);
	if (silofs_uaddr_isnull(out_uaddr)) {
		return -SILOFS_ENOENT;
	}
	return 0;
}

void silofs_sni_main_lseg(const struct silofs_spnode_info *sni,
                          struct silofs_lsid *out_lsid)
{
	spnode_main_lsid(sni->sn, out_lsid);
}

void silofs_sni_bind_main_lseg(struct silofs_spnode_info *sni,
                               const struct silofs_lsid *lsid)
{
	spnode_set_main_lsid(sni->sn, lsid);
	sni_dirtify(sni);
}

static loff_t
sni_bpos_of_child(const struct silofs_spnode_info *sni, loff_t voff)
{
	const size_t spmap_size = SILOFS_SPMAP_SIZE;
	const size_t slot = spnode_slot_of(sni->sn, voff);

	return (loff_t)(slot * spmap_size);
}

static loff_t
sni_base_voff_of_child(const struct silofs_spnode_info *sni, loff_t voff)
{
	struct silofs_lrange lrange;
	const enum silofs_height child_height = sni_sub_height(sni);

	silofs_lrange_of_spmap(&lrange, child_height, voff);
	return lrange.beg;
}

void silofs_sni_resolve_main(const struct silofs_spnode_info *sni, loff_t voff,
                             struct silofs_uaddr *out_uaddr)
{
	struct silofs_lsid lsid;
	const loff_t bpos = sni_bpos_of_child(sni, voff);
	const loff_t base = sni_base_voff_of_child(sni, voff);
	enum silofs_ltype child_ltype = sni_child_ltype(sni);

	silofs_sni_main_lseg(sni, &lsid);
	silofs_assert_eq(child_ltype, lsid.ltype);

	silofs_uaddr_setup(out_uaddr, &lsid, bpos, base);

	silofs_unused(child_ltype);
}

void silofs_sni_clone_from(struct silofs_spnode_info *sni,
                           const struct silofs_spnode_info *sni_other)
{
	spnode_clone_subrefs(sni->sn, sni_other->sn);
	sni->sn_nactive_subs = sni_other->sn_nactive_subs;
	sni_dirtify(sni);
}

void silofs_sni_resolve_lmap(const struct silofs_spnode_info *sni,
                             struct silofs_spmap_lmap *out_lmap)
{
	struct silofs_uaddr uaddr = { .voff = -1 };
	const struct silofs_spmap_node *sn = sni->sn;
	const struct silofs_spmap_ref *spr = NULL;
	size_t len;

	STATICASSERT_EQ(ARRAY_SIZE(out_lmap->laddr),
	                ARRAY_SIZE(sn->sn_subrefs));

	out_lmap->cnt = 0;
	for (size_t slot = 0; slot < ARRAY_SIZE(sn->sn_subrefs); ++slot) {
		spr = spnode_subref_at(sn, slot);
		spr_uaddr(spr, &uaddr);
		len = silofs_laddr_len(&uaddr.laddr);
		lmap_append(out_lmap, &uaddr.laddr, len);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int verify_spnode_height(enum silofs_height height)
{
	if (height <= SILOFS_HEIGHT_SPLEAF) {
		return -SILOFS_EFSCORRUPTED;
	}
	if (height >= SILOFS_HEIGHT_SUPER) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int verify_lbk_ref(const struct silofs_lbk_ref *lbr)
{
	size_t val;

	val = lbr_refcnt(lbr);
	if (val >= INT_MAX) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int verify_spmap_leaf_parent(const struct silofs_spmap_leaf *sl)
{
	struct silofs_uaddr uaddr;

	spleaf_parent(sl, &uaddr);
	if (silofs_uaddr_isnull(&uaddr)) {
		return -SILOFS_EFSCORRUPTED;
	}
	if (silofs_uaddr_ltype(&uaddr) != SILOFS_LTYPE_SPNODE) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int verify_spmap_leaf_self(const struct silofs_spmap_leaf *sl)
{
	struct silofs_uaddr uaddr;

	spleaf_self(sl, &uaddr);
	if (silofs_uaddr_isnull(&uaddr)) {
		return -SILOFS_EFSCORRUPTED;
	}
	if (silofs_uaddr_ltype(&uaddr) != SILOFS_LTYPE_SPLEAF) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

int silofs_verify_spmap_leaf(const struct silofs_spmap_leaf *sl)
{
	const struct silofs_lbk_ref *lbr;
	int err;

	err = verify_spmap_leaf_parent(sl);
	if (err) {
		return err;
	}
	err = verify_spmap_leaf_self(sl);
	if (err) {
		return err;
	}
	for (size_t i = 0; i < ARRAY_SIZE(sl->sl_lbrs); ++i) {
		lbr = spleaf_lbr_at(sl, i);
		err = verify_lbk_ref(lbr);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int verify_uaddr(const struct silofs_uaddr *uaddr)
{
	return silofs_laddr_isvalid(&uaddr->laddr) ? 0 : -SILOFS_EFSCORRUPTED;
}

static int verify_spmap_ref(const struct silofs_spmap_ref *spr)
{
	struct silofs_uaddr uaddr;
	int err;

	spr_uaddr(spr, &uaddr);
	if (silofs_uaddr_isnull(&uaddr)) {
		return 0;
	}
	err = verify_uaddr(&uaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int verify_spmap_node_parent(const struct silofs_spmap_node *sn)
{
	struct silofs_uaddr parent_uaddr;
	const enum silofs_height height_max = SILOFS_HEIGHT_SUPER - 1;
	const enum silofs_height height = spnode_heigth(sn);
	enum silofs_ltype parent_ltype;
	enum silofs_height parent_height;

	spnode_parent(sn, &parent_uaddr);
	if (silofs_uaddr_isnull(&parent_uaddr)) {
		return -SILOFS_EFSCORRUPTED;
	}
	parent_height = silofs_uaddr_height(&parent_uaddr);
	if (parent_height != (height + 1)) {
		return -SILOFS_EFSCORRUPTED;
	}
	parent_ltype = silofs_uaddr_ltype(&parent_uaddr);
	if ((height == height_max) && !ltype_issuper(parent_ltype)) {
		return -SILOFS_EFSCORRUPTED;
	}
	if ((height < height_max) && !ltype_isspnode(parent_ltype)) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int verify_spmap_node_self(const struct silofs_spmap_node *sn)
{
	struct silofs_uaddr uaddr;
	enum silofs_height height;
	enum silofs_ltype ltype;
	int err;

	spnode_self(sn, &uaddr);
	if (silofs_uaddr_isnull(&uaddr)) {
		return -SILOFS_EFSCORRUPTED;
	}
	ltype = silofs_uaddr_ltype(&uaddr);
	if (!ltype_isspnode(ltype)) {
		return -SILOFS_EFSCORRUPTED;
	}
	height = silofs_uaddr_height(&uaddr);
	err = verify_spnode_height(height);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_verify_spmap_node(const struct silofs_spmap_node *sn)
{
	struct silofs_lrange lrange;
	enum silofs_height height;
	ssize_t lrange_len;
	ssize_t height_len;
	int err;

	height = spnode_heigth(sn);
	err = verify_spnode_height(height);
	if (err) {
		log_err("bad spnode height: height=%d", height);
		return err;
	}
	spnode_lrange(sn, &lrange);
	lrange_len = off_len(lrange.beg, lrange.end);
	height_len = silofs_height_to_space_span(height);
	if (lrange_len != height_len) {
		log_err("bad spmap-node lrange: height=%d "
		        "beg=0x%lx end=0x%lx",
		        height, lrange.beg, lrange.end);
		return -SILOFS_EFSCORRUPTED;
	}
	err = verify_spmap_node_self(sn);
	if (err) {
		log_err("illegal spmap-node self: height=%d "
		        "beg=0x%lx end=0x%lx",
		        height, lrange.beg, lrange.end);
		return err;
	}
	err = verify_spmap_node_parent(sn);
	if (err) {
		log_err("illegal spmap-node parent: height=%d "
		        "beg=0x%lx end=0x%lx",
		        height, lrange.beg, lrange.end);
		return err;
	}
	for (size_t i = 0; i < ARRAY_SIZE(sn->sn_subrefs); ++i) {
		err = verify_spmap_ref(&sn->sn_subrefs[i]);
		if (err) {
			return err;
		}
	}
	return 0;
}
