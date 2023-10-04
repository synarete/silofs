/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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
#include <silofs/fs.h>
#include <silofs/fs-private.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void vrange_of_spleaf(struct silofs_vrange *vrange, loff_t voff)
{
	silofs_vrange_of_spmap(vrange, SILOFS_HEIGHT_SPLEAF, voff);
}

static void vrange_of_spnode(struct silofs_vrange *vrange,
                             enum silofs_height height, loff_t voff)
{
	silofs_vrange_of_spmap(vrange, height, voff);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t nkbs_of(const struct silofs_vaddr *vaddr)
{
	return stype_nkbs(vaddr->stype);
}

static size_t kbn_of(const struct silofs_vaddr *vaddr)
{
	return (size_t)((vaddr->off / SILOFS_KB_SIZE) % SILOFS_NKB_IN_LBK);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void spr_uaddr(const struct silofs_spmap_ref *spr,
                      struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr64b_xtoh(&spr->sr_uaddr, out_uaddr);
}

static void spr_set_uaddr(struct silofs_spmap_ref *spr,
                          const struct silofs_uaddr *uaddr)
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
	return !uaddr_isnull(&uaddr);
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

static void spnode_parent(const struct silofs_spmap_node *sn,
                          struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr64b_xtoh(&sn->sn_parent, out_uaddr);
}

static void spnode_set_parent(struct silofs_spmap_node *sn,
                              const struct silofs_uaddr *uaddr)
{
	silofs_uaddr64b_htox(&sn->sn_parent, uaddr);
}

static void spnode_self(const struct silofs_spmap_node *sn,
                        struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr64b_xtoh(&sn->sn_self, out_uaddr);
}

static void spnode_set_self(struct silofs_spmap_node *sn,
                            const struct silofs_uaddr *uaddr)
{
	silofs_uaddr64b_htox(&sn->sn_self, uaddr);
}

static void spnode_vrange(const struct silofs_spmap_node *sn,
                          struct silofs_vrange *out_vrange)
{
	silofs_vrange128_xtoh(&sn->sn_vrange, out_vrange);
}

static void spnode_set_vrange(struct silofs_spmap_node *sn,
                              const struct silofs_vrange *vrange)
{
	silofs_vrange128_htox(&sn->sn_vrange, vrange);
}

static enum silofs_height spnode_heigth(const struct silofs_spmap_node *sn)
{
	struct silofs_uaddr self_uaddr;

	spnode_self(sn, &self_uaddr);
	return uaddr_height(&self_uaddr);
}

static void spnode_main_lextid(const struct silofs_spmap_node *sn,
                               struct silofs_lextid *out_lextid)
{
	silofs_lextid32b_xtoh(&sn->sn_main_lextid, out_lextid);
}

static void spnode_set_main_lextid(struct silofs_spmap_node *sn,
                                   const struct silofs_lextid *lextid)
{
	silofs_lextid32b_htox(&sn->sn_main_lextid, lextid);
}

static void spnode_init(struct silofs_spmap_node *sn,
                        const struct silofs_vrange *vrange)
{
	spnode_set_vrange(sn, vrange);
	silofs_lextid32b_reset(&sn->sn_main_lextid);
	silofs_uaddr64b_reset(&sn->sn_parent);
	silofs_uaddr64b_reset(&sn->sn_self);
	spr_initn(sn->sn_subrefs, ARRAY_SIZE(sn->sn_subrefs));
}

static size_t spnode_slot_of(const struct silofs_spmap_node *sn, loff_t voff)
{
	const size_t nslots = SILOFS_SPMAP_NCHILDS;
	struct silofs_vrange vrange;
	size_t len;
	size_t slot;
	ssize_t roff;

	STATICASSERT_EQ(ARRAY_SIZE(sn->sn_subrefs), SILOFS_SPMAP_NCHILDS);
	STATICASSERT_EQ(ARRAY_SIZE(sn->sn_rivs), SILOFS_SPMAP_NCHILDS);

	spnode_vrange(sn, &vrange);
	len = vrange.len;
	roff = off_diff(vrange.beg, voff);
	slot = (size_t)(roff * (long)nslots) / len;
	silofs_assert_lt(slot, nslots);
	return slot;
}

static struct silofs_spmap_ref *
spnode_subref_at(const struct silofs_spmap_node *sn, size_t slot)
{
	const struct silofs_spmap_ref *spr = &sn->sn_subrefs[slot];

	silofs_assert_lt(slot, ARRAY_SIZE(sn->sn_subrefs));

	return unconst(spr);
}

static struct silofs_spmap_ref *
spnode_subref_of(const struct silofs_spmap_node *sn, loff_t voff)
{
	return spnode_subref_at(sn, spnode_slot_of(sn, voff));
}

static void spnode_uaddr_of(const struct silofs_spmap_node *sn, loff_t voff,
                            struct silofs_uaddr *out_uaddr)
{
	const struct silofs_spmap_ref *spr = spnode_subref_of(sn, voff);

	spr_uaddr(spr, out_uaddr);
}

static void spnode_set_uaddr_of(struct silofs_spmap_node *sn, loff_t voff,
                                const struct silofs_uaddr *uaddr)
{
	struct silofs_spmap_ref *spr = spnode_subref_of(sn, voff);

	spr_set_uaddr(spr, uaddr);
}

static size_t spnode_count_nactive(const struct silofs_spmap_node *sn)
{
	size_t count = 0;
	const struct silofs_spmap_ref *spr = NULL;
	const size_t nslots_max = ARRAY_SIZE(sn->sn_subrefs);

	for (size_t slot = 0; slot < nslots_max; ++slot) {
		spr = spnode_subref_at(sn, slot);
		if (!spr_isactive(spr)) {
			break;
		}
		++count;
	}
	return count;
}

static void spnode_clone_subrefs(struct silofs_spmap_node *sn,
                                 const struct silofs_spmap_node *sn_other)
{
	struct silofs_spmap_ref *spr = NULL;
	const struct silofs_spmap_ref *spr_other = NULL;
	const size_t nslots_max = ARRAY_SIZE(sn->sn_subrefs);

	for (size_t slot = 0; slot < nslots_max; ++slot) {
		spr = spnode_subref_at(sn, slot);
		spr_other = spnode_subref_at(sn_other, slot);
		spr_clone_from(spr, spr_other);
	}
}

static bool
spnode_has_child_at(const struct silofs_spmap_node *sn, loff_t voff)
{
	const struct silofs_spmap_ref *spr = spnode_subref_of(sn, voff);

	return spr_isactive(spr);
}

static void spnode_gen_rivs(struct silofs_spmap_node *sn)
{
	silofs_gen_random_ivs(sn->sn_rivs, ARRAY_SIZE(sn->sn_rivs));
}

static struct silofs_iv *
spnode_riv_at(const struct silofs_spmap_node *sn, size_t slot)
{
	const struct silofs_iv *riv = &sn->sn_rivs[slot];

	silofs_assert_lt(slot, ARRAY_SIZE(sn->sn_rivs));

	return unconst(riv);
}

static void spnode_set_riv_at(struct silofs_spmap_node *sn, size_t slot,
                              const struct silofs_iv *iv)
{
	struct silofs_iv *riv = &sn->sn_rivs[slot];

	silofs_iv_assign(riv, iv);
}

static void spnode_riv_of(const struct silofs_spmap_node *sn, loff_t voff,
                          struct silofs_iv *out_riv)
{
	silofs_iv_assign(out_riv, spnode_riv_at(sn, spnode_slot_of(sn, voff)));
}

static void spnode_set_riv_of(struct silofs_spmap_node *sn, loff_t voff,
                              const struct silofs_iv *iv)
{
	spnode_set_riv_at(sn, spnode_slot_of(sn, voff), iv);
}

static void spnode_clone_rivs(struct silofs_spmap_node *sn,
                              const struct silofs_spmap_node *sn_other)
{
	const size_t nslots_max = ARRAY_SIZE(sn->sn_rivs);

	for (size_t slot = 0; slot < nslots_max; ++slot) {
		spnode_set_riv_at(sn, slot, spnode_riv_at(sn_other, slot));
	}
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

static void bk_state_mask_of(struct silofs_bk_state *bk_st,
                             size_t ki, size_t nk)
{
	size_t nn;

	bk_st->state = 0;
	if (ki < 64) {
		nn = min(nk, 64 - ki);
		bk_st->state = mask_of(ki, nn);
	}
}

static void bk_state_none(struct silofs_bk_state *bk_st)
{
	bk_st->state = 0;
}

static void bk_state_mask_of_other(struct silofs_bk_state *bk_st,
                                   size_t kbn, size_t nkb)
{
	struct silofs_bk_state bk_st2;

	bk_state_mask_of(&bk_st2, kbn, nkb);
	bk_st->state = ~bk_st2.state;
}

static bool bk_state_has_any(const struct silofs_bk_state *bk_st)
{
	return (bk_st->state > 0);
}

static bool bk_state_has_mask(const struct silofs_bk_state *bk_st,
                              const struct silofs_bk_state *bk_mask)
{
	return ((bk_st->state & bk_mask->state) == bk_mask->state);
}

static bool bk_state_has_mask_none(const struct silofs_bk_state *bk_st,
                                   const struct silofs_bk_state *bk_mask)
{
	return ((bk_st->state & bk_mask->state) == 0);
}

static bool bk_state_has_mask_any(const struct silofs_bk_state *bk_st,
                                  const struct silofs_bk_state *bk_mask)
{
	return ((bk_st->state & bk_mask->state) > 0);
}

static void bk_state_set_mask(struct silofs_bk_state *bk_st,
                              const struct silofs_bk_state *bk_mask)
{
	bk_st->state |= bk_mask->state;
}

static void bk_state_unset_mask(struct silofs_bk_state *bk_st,
                                const struct silofs_bk_state *bk_mask)
{
	bk_st->state &= ~(bk_mask->state);
}

static size_t bk_state_popcount(const struct silofs_bk_state *bk_st)
{
	return silofs_popcount64(bk_st->state);
}

static void bk_state_xtoh(const struct silofs_bk_state *bk_st_le,
                          struct silofs_bk_state *bk_st)
{
	bk_st->state = silofs_le64_to_cpu(bk_st_le->state);
}

static void bk_state_htox(struct silofs_bk_state *bk_st_le,
                          const struct silofs_bk_state *bk_st)
{
	bk_st_le->state = silofs_cpu_to_le64(bk_st->state);
}

void silofs_bk_state_init(struct silofs_bk_state *bk_st)
{
	bk_state_none(bk_st);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_bk_ref *bkr_unconst(const struct silofs_bk_ref *bkr)
{
	return unconst(bkr);
}

static void bkr_uref(const struct silofs_bk_ref *bkr,
                     struct silofs_laddr *out_laddr)
{
	silofs_laddr48b_xtoh(&bkr->bkr_uref, out_laddr);
}

static void bkr_set_uref(struct silofs_bk_ref *bkr,
                         const struct silofs_laddr *laddr)
{
	silofs_laddr48b_htox(&bkr->bkr_uref, laddr);
}

static size_t bkr_dbkref(const struct silofs_bk_ref *bkr)
{
	return silofs_le64_to_cpu(bkr->bkr_dbkref);
}

static void bkr_set_dbkref(struct silofs_bk_ref *bkr, size_t val)
{
	bkr->bkr_dbkref = silofs_cpu_to_le64(val);
}

static void bkr_inc_dbkref(struct silofs_bk_ref *bkr)
{
	bkr_set_dbkref(bkr, bkr_dbkref(bkr) + 1);
}

static void bkr_dec_dbkref(struct silofs_bk_ref *bkr)
{
	const size_t cur = bkr_dbkref(bkr);

	silofs_expect_ge(cur, 1);

	bkr_set_dbkref(bkr, cur - 1);
}

static void bkr_allocated(const struct silofs_bk_ref *bkr,
                          struct silofs_bk_state *bk_st)
{
	bk_state_xtoh(&bkr->bkr_allocated, bk_st);
}

static void bkr_set_allocated(struct silofs_bk_ref *bkr,
                              const struct silofs_bk_state *bk_st)
{
	bk_state_htox(&bkr->bkr_allocated, bk_st);
}

static bool bkr_test_allocated_at(const struct silofs_bk_ref *bkr,
                                  size_t kbn, size_t nkb)
{
	struct silofs_bk_state bk_st;
	struct silofs_bk_state bk_mask;

	bkr_allocated(bkr, &bk_st);
	bk_state_mask_of(&bk_mask, kbn, nkb);
	return bk_state_has_mask(&bk_st, &bk_mask);
}

static bool bkr_test_allocated_bk(const struct silofs_bk_ref *bkr)
{
	return bkr_test_allocated_at(bkr, 0, SILOFS_NKB_IN_LBK);
}

static bool bkr_test_allocated_other(const struct silofs_bk_ref *bkr,
                                     size_t kbn, size_t nkb)
{
	struct silofs_bk_state bk_st;
	struct silofs_bk_state bk_mask;

	bkr_allocated(bkr, &bk_st);
	bk_state_mask_of_other(&bk_mask, kbn, nkb);
	return bk_state_has_mask_any(&bk_st, &bk_mask);
}

static void bkr_set_allocated_at(struct silofs_bk_ref *bkr,
                                 size_t kbn, size_t nkb)
{
	struct silofs_bk_state bk_st;
	struct silofs_bk_state bk_mask;

	bkr_allocated(bkr, &bk_st);
	bk_state_mask_of(&bk_mask, kbn, nkb);
	bk_state_set_mask(&bk_st, &bk_mask);
	bkr_set_allocated(bkr, &bk_st);
}

static void bkr_clear_allocated_at(struct silofs_bk_ref *bkr,
                                   size_t kbn, size_t nkb)
{
	struct silofs_bk_state bk_st;
	struct silofs_bk_state bk_mask;

	bkr_allocated(bkr, &bk_st);
	bk_state_mask_of(&bk_mask, kbn, nkb);
	bk_state_unset_mask(&bk_st, &bk_mask);
	bkr_set_allocated(bkr, &bk_st);
}

static size_t bkr_usecnt(const struct silofs_bk_ref *bkr)
{
	struct silofs_bk_state bk_st;

	bkr_allocated(bkr, &bk_st);
	return bk_state_popcount(&bk_st);
}

static size_t bkr_freecnt(const struct silofs_bk_ref *bkr)
{
	return SILOFS_NKB_IN_LBK - bkr_usecnt(bkr);
}

static bool bkr_isfull(const struct silofs_bk_ref *bkr)
{
	return bkr_test_allocated_bk(bkr);
}

static bool bkr_isunused(const struct silofs_bk_ref *bkr)
{
	struct silofs_bk_state bk_st;

	bkr_allocated(bkr, &bk_st);
	return !bk_state_has_any(&bk_st);
}

static void bkr_unwritten(const struct silofs_bk_ref *bkr,
                          struct silofs_bk_state *bk_st)
{
	bk_state_xtoh(&bkr->bkr_unwritten, bk_st);
}

static void bkr_set_unwritten(struct silofs_bk_ref *bkr,
                              const struct silofs_bk_state *bk_st)
{
	bk_state_htox(&bkr->bkr_unwritten, bk_st);
}

static bool bkr_test_unwritten_at(const struct silofs_bk_ref *bkr,
                                  size_t kbn, size_t nkb)
{
	struct silofs_bk_state bk_st;
	struct silofs_bk_state bk_mask;

	bkr_unwritten(bkr, &bk_st);
	bk_state_mask_of(&bk_mask, kbn, nkb);
	return bk_state_has_mask(&bk_st, &bk_mask);
}

static void bkr_set_unwritten_at(struct silofs_bk_ref *bkr,
                                 size_t kbn, size_t nkb)
{
	struct silofs_bk_state bk_st;
	struct silofs_bk_state bk_mask;

	bkr_unwritten(bkr, &bk_st);
	bk_state_mask_of(&bk_mask, kbn, nkb);
	bk_state_set_mask(&bk_st, &bk_mask);
	bkr_set_unwritten(bkr, &bk_st);
}

static void bkr_clear_unwritten_at(struct silofs_bk_ref *bkr,
                                   size_t kbn, size_t nkb)
{
	struct silofs_bk_state bk_st;
	struct silofs_bk_state bk_mask;

	bkr_unwritten(bkr, &bk_st);
	bk_state_mask_of(&bk_mask, kbn, nkb);
	bk_state_unset_mask(&bk_st, &bk_mask);
	bkr_set_unwritten(bkr, &bk_st);
}

static void bkr_clear_alloc_state(struct silofs_bk_ref *bkr)
{
	struct silofs_bk_state bk_st;

	bk_state_none(&bk_st);
	bkr_set_allocated(bkr, &bk_st);
	bkr_set_unwritten(bkr, &bk_st);
	bkr_set_dbkref(bkr, 0);
}

static void bkr_reset(struct silofs_bk_ref *bkr)
{
	memset(bkr, 0, sizeof(*bkr));
	bkr_clear_alloc_state(bkr);
	silofs_laddr48b_reset(&bkr->bkr_uref);
}

static void bkr_init(struct silofs_bk_ref *bkr)
{
	bkr_reset(bkr);
}

static void bkr_init_arr(struct silofs_bk_ref *arr, size_t cnt)
{
	for (size_t i = 0; i < cnt; ++i) {
		bkr_init(&arr[i]);
	}
}

static bool bkr_may_alloc(const struct silofs_bk_ref *bkr, size_t nkb)
{
	return !bkr_isfull(bkr) && (nkb <= bkr_freecnt(bkr));
}

static int bkr_find_free(const struct silofs_bk_ref *bkr,
                         size_t nkb, size_t *out_kbn)
{
	struct silofs_bk_state bk_st;
	struct silofs_bk_state bk_mask;
	const size_t nkb_in_bk = SILOFS_NKB_IN_LBK;

	bkr_allocated(bkr, &bk_st);
	for (size_t kbn = 0; (kbn + nkb) <= nkb_in_bk; kbn += nkb) {
		bk_state_mask_of(&bk_mask, kbn, nkb);
		if (bk_state_has_mask_none(&bk_st, &bk_mask)) {
			*out_kbn = kbn;
			return 0;
		}
	}
	return -SILOFS_ENOSPC;
}

static void bkr_make_vaddrs(const struct silofs_bk_ref *bkr,
                            enum silofs_stype stype, loff_t voff_base,
                            struct silofs_vaddrs *vas)
{
	struct silofs_bk_state bk_st;
	struct silofs_bk_state bk_mask;
	const size_t nkb = stype_nkbs(stype);
	const size_t nkb_in_bk = SILOFS_NKB_IN_LBK;
	loff_t voff;

	bkr_allocated(bkr, &bk_st);
	vas->count = 0;
	for (size_t kbn = 0; (kbn + nkb) <= nkb_in_bk; kbn += nkb) {
		bk_state_mask_of(&bk_mask, kbn, nkb);
		if (bk_state_has_mask(&bk_st, &bk_mask)) {
			voff = off_end(voff_base, kbn * SILOFS_KB_SIZE);
			vaddr_setup(&vas->vaddr[vas->count++], stype, voff);
		}
	}
}

static void bkr_clone_from(struct silofs_bk_ref *bkr,
                           const struct silofs_bk_ref *bkr_other)
{
	struct silofs_laddr laddr;
	struct silofs_bk_state bk_st;
	size_t dbkref;

	bkr_uref(bkr_other, &laddr);
	bkr_set_uref(bkr, &laddr);

	bkr_allocated(bkr_other, &bk_st);
	bkr_set_allocated(bkr, &bk_st);

	bkr_unwritten(bkr_other, &bk_st);
	bkr_set_unwritten(bkr, &bk_st);

	dbkref = bkr_dbkref(bkr_other);
	bkr_set_dbkref(bkr, dbkref);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void spleaf_init(struct silofs_spmap_leaf *sl,
                        const struct silofs_vrange *vrange)
{
	silofs_vrange128_htox(&sl->sl_vrange, vrange);
	silofs_lextid32b_reset(&sl->sl_main_lextid);
	silofs_uaddr64b_reset(&sl->sl_parent);
	silofs_uaddr64b_reset(&sl->sl_self);
	bkr_init_arr(sl->sl_subrefs, ARRAY_SIZE(sl->sl_subrefs));
}

static void spleaf_parent(const struct silofs_spmap_leaf *sl,
                          struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr64b_xtoh(&sl->sl_parent, out_uaddr);
}

static void spleaf_set_parent(struct silofs_spmap_leaf *sl,
                              const struct silofs_uaddr *uaddr)
{
	silofs_uaddr64b_htox(&sl->sl_parent, uaddr);
}

static void spleaf_self(const struct silofs_spmap_leaf *sl,
                        struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr64b_xtoh(&sl->sl_self, out_uaddr);
}

static void spleaf_set_self(struct silofs_spmap_leaf *sl,
                            const struct silofs_uaddr *uaddr)
{
	silofs_uaddr64b_htox(&sl->sl_self, uaddr);
}

static void spleaf_vrange(const struct silofs_spmap_leaf *sl,
                          struct silofs_vrange *vrange)
{
	silofs_vrange128_xtoh(&sl->sl_vrange, vrange);
}

static struct silofs_bk_ref *
spleaf_subref_at(const struct silofs_spmap_leaf *sl, size_t slot)
{
	const struct silofs_bk_ref *bkr = &(sl->sl_subrefs[slot]);

	return bkr_unconst(bkr);
}

static size_t
spleaf_lba_slot(const struct silofs_spmap_leaf *sl, silofs_lba_t lba)
{
	return (size_t)lba % ARRAY_SIZE(sl->sl_subrefs);
}

static size_t
spleaf_slot_of(const struct silofs_spmap_leaf *sl, loff_t voff)
{
	return spleaf_lba_slot(sl, off_to_lba(voff));
}

static struct silofs_bk_ref *
spleaf_bkr_by_lba(const struct silofs_spmap_leaf *sl, silofs_lba_t lba)
{
	return spleaf_subref_at(sl, spleaf_lba_slot(sl, lba));
}

static struct silofs_bk_ref *
spleaf_bkr_by_voff(const struct silofs_spmap_leaf *sl, loff_t voff)
{
	return spleaf_subref_at(sl, spleaf_slot_of(sl, voff));
}

static struct silofs_bk_ref *
spleaf_bkr_by_vaddr(const struct silofs_spmap_leaf *sl,
                    const struct silofs_vaddr *vaddr)
{
	return spleaf_bkr_by_voff(sl, vaddr->off);
}

static bool spleaf_is_allocated_at(const struct silofs_spmap_leaf *sl,
                                   const struct silofs_vaddr *vaddr)
{
	const size_t kbn = kbn_of(vaddr);
	const size_t nkb = nkbs_of(vaddr);
	const struct silofs_bk_ref *bkr;
	bool ret;

	bkr = spleaf_bkr_by_vaddr(sl, vaddr);
	if (vaddr_isdatabk(vaddr)) {
		ret = (bkr_dbkref(bkr) > 0);
	} else {
		ret = bkr_test_allocated_at(bkr, kbn, nkb);
	}
	return ret;
}

static bool spleaf_has_allocated_with(const struct silofs_spmap_leaf *sl,
                                      const struct silofs_vaddr *vaddr)
{
	const size_t kbn = kbn_of(vaddr);
	const size_t nkb = nkbs_of(vaddr);
	const struct silofs_bk_ref *bkr;
	bool ret;

	bkr = spleaf_bkr_by_vaddr(sl, vaddr);
	if (vaddr_isdatabk(vaddr)) {
		ret = (bkr_dbkref(bkr) > 0);
	} else {
		ret = bkr_test_allocated_other(bkr, kbn, nkb);
	}
	return ret;
}

static bool spleaf_is_last_allocated(const struct silofs_spmap_leaf *sl,
                                     const struct silofs_vaddr *vaddr)
{
	const size_t kbn = kbn_of(vaddr);
	const size_t nkb = nkbs_of(vaddr);
	const struct silofs_bk_ref *bkr;
	bool ret;

	bkr = spleaf_bkr_by_vaddr(sl, vaddr);
	if (vaddr_isdatabk(vaddr)) {
		ret = (bkr_dbkref(bkr) == 1);
	} else {
		ret = !bkr_test_allocated_other(bkr, kbn, nkb);
	}
	return ret;
}

static bool spleaf_test_unwritten_at(const struct silofs_spmap_leaf *sl,
                                     const struct silofs_vaddr *vaddr)
{
	const struct silofs_bk_ref *bkr = spleaf_bkr_by_vaddr(sl, vaddr);

	return bkr_test_unwritten_at(bkr, kbn_of(vaddr), nkbs_of(vaddr));
}

static void spleaf_set_unwritten_at(struct silofs_spmap_leaf *sl,
                                    const struct silofs_vaddr *vaddr)
{
	struct silofs_bk_ref *bkr = spleaf_bkr_by_vaddr(sl, vaddr);

	bkr_set_unwritten_at(bkr, kbn_of(vaddr), nkbs_of(vaddr));
}

static void spleaf_clear_unwritten_at(struct silofs_spmap_leaf *sl,
                                      const struct silofs_vaddr *vaddr)
{
	struct silofs_bk_ref *bkr = spleaf_bkr_by_vaddr(sl, vaddr);

	bkr_clear_unwritten_at(bkr, kbn_of(vaddr), nkbs_of(vaddr));
}

static size_t spleaf_dbkref_at(const struct silofs_spmap_leaf *sl,
                               const struct silofs_vaddr *vaddr)
{
	const struct silofs_bk_ref *bkr = spleaf_bkr_by_vaddr(sl, vaddr);

	silofs_assert_eq(vaddr->stype, SILOFS_STYPE_DATABK);

	return bkr_dbkref(bkr);
}

static void spleaf_ref_allocated_at(struct silofs_spmap_leaf *sl,
                                    const struct silofs_vaddr *vaddr)
{
	const size_t kbn = kbn_of(vaddr);
	const size_t nkb = nkbs_of(vaddr);
	struct silofs_bk_ref *bkr = spleaf_bkr_by_vaddr(sl, vaddr);

	bkr_set_allocated_at(bkr, kbn, nkb);
	if (vaddr_isdatabk(vaddr)) {
		bkr_inc_dbkref(bkr);
	}
}

static void spleaf_unref_allocated_at(struct silofs_spmap_leaf *sl,
                                      const struct silofs_vaddr *vaddr)
{
	const size_t kbn = kbn_of(vaddr);
	const size_t nkb = nkbs_of(vaddr);
	struct silofs_bk_ref *bkr = spleaf_bkr_by_vaddr(sl, vaddr);

	if (vaddr_isdatabk(vaddr)) {
		bkr_dec_dbkref(bkr);
	}
	if (!bkr_dbkref(bkr) || (nkb < SILOFS_NKB_IN_LBK)) {
		bkr_clear_allocated_at(bkr, kbn, nkb);
	}
}

static void spleaf_renew_bk_at(struct silofs_spmap_leaf *sl,
                               const struct silofs_vaddr *vaddr)
{
	struct silofs_bk_ref *bkr = spleaf_bkr_by_vaddr(sl, vaddr);

	silofs_assert(bkr_isunused(bkr));
	bkr_clear_alloc_state(bkr);
}

static int
spleaf_find_nfree_at(const struct silofs_spmap_leaf *sl,
                     enum silofs_stype stype, size_t bn, size_t *out_kbn)
{
	const size_t nkb = stype_nkbs(stype);
	const struct silofs_bk_ref *bkr = spleaf_subref_at(sl, bn);
	int err = -SILOFS_ENOSPC;

	if (bkr_may_alloc(bkr, nkb)) {
		err = bkr_find_free(bkr, nkb, out_kbn);
	}
	return err;
}

static int
spleaf_find_free(const struct silofs_spmap_leaf *sl, enum silofs_stype stype,
                 size_t bn_beg, size_t bn_end, size_t *out_bn, size_t *out_kbn)
{
	size_t kbn = 0;
	int err = -SILOFS_ENOSPC;

	for (size_t bn = bn_beg; bn < bn_end; ++bn) {
		err = spleaf_find_nfree_at(sl, stype, bn, &kbn);
		if (!err) {
			*out_bn = bn;
			*out_kbn = kbn;
			break;
		}
	}
	return err;
}

static void spleaf_make_vaddrs(const struct silofs_spmap_leaf *sl,
                               enum silofs_stype stype, silofs_lba_t lba,
                               struct silofs_vaddrs *vas)
{
	const struct silofs_bk_ref *bkr = spleaf_bkr_by_lba(sl, lba);

	bkr_make_vaddrs(bkr, stype, lba_to_off(lba), vas);
}

static void spleaf_main_lextid(const struct silofs_spmap_leaf *sl,
                               struct silofs_lextid *out_lextid)
{
	silofs_lextid32b_xtoh(&sl->sl_main_lextid, out_lextid);
}

static void spleaf_set_main_lextid(struct silofs_spmap_leaf *sl,
                                   const struct silofs_lextid *lextid)
{
	silofs_lextid32b_htox(&sl->sl_main_lextid, lextid);
}

static void spleaf_main_uref_at(const struct silofs_spmap_leaf *sl,
                                size_t slot, struct silofs_laddr *out_laddr)
{
	struct silofs_lextid lextid;
	const loff_t pos = lba_to_off((silofs_lba_t)slot);

	spleaf_main_lextid(sl, &lextid);
	laddr_setup(out_laddr, &lextid, pos, SILOFS_LBK_SIZE);
}

static void spleaf_bind_bks_to_main(struct silofs_spmap_leaf *sl)
{
	struct silofs_laddr laddr;
	struct silofs_bk_ref *bkr = NULL;
	const size_t nslots = ARRAY_SIZE(sl->sl_subrefs);

	for (size_t slot = 0; slot < nslots; ++slot) {
		bkr = spleaf_subref_at(sl, slot);
		spleaf_main_uref_at(sl, slot, &laddr);
		bkr_set_uref(bkr, &laddr);
	}
}

static size_t spleaf_calc_total_usecnt(const struct silofs_spmap_leaf *sl)
{
	const struct silofs_bk_ref *bkr = NULL;
	const size_t nslots = ARRAY_SIZE(sl->sl_subrefs);
	size_t usecnt_sum = 0;

	for (size_t slot = 0; slot < nslots; ++slot) {
		bkr = spleaf_subref_at(sl, slot);
		usecnt_sum += bkr_usecnt(bkr);
	}
	return usecnt_sum;
}

static size_t spleaf_sum_nbytes_used(const struct silofs_spmap_leaf *sl)
{
	return spleaf_calc_total_usecnt(sl) * SILOFS_KB_SIZE;
}

static void
spleaf_resolve_main_ubk(const struct silofs_spmap_leaf *sl, loff_t voff,
                        struct silofs_bkaddr *out_bkaddr)
{
	struct silofs_lextid lextid;

	spleaf_main_lextid(sl, &lextid);
	silofs_bkaddr_by_off(out_bkaddr, &lextid, voff);
}

static void spleaf_child_of(const struct silofs_spmap_leaf *sl,
                            loff_t voff, struct silofs_bkaddr *out_bkaddr)
{
	struct silofs_laddr laddr = { .pos = -1 };
	const struct silofs_bk_ref *bkr = spleaf_bkr_by_voff(sl, voff);

	bkr_uref(bkr, &laddr);
	bkaddr_by_laddr(out_bkaddr, &laddr);
}

static void spleaf_bind_child(struct silofs_spmap_leaf *sl, loff_t voff,
                              const struct silofs_laddr *laddr)
{
	struct silofs_bk_ref *bkr = spleaf_bkr_by_voff(sl, voff);

	silofs_assert_gt(bkr_usecnt(bkr), 0);
	if (!laddr_isnull(laddr)) {
		silofs_assert_eq(laddr->len, SILOFS_LBK_SIZE);
	}
	bkr_set_uref(bkr, laddr);
}

static void spleaf_gen_rivs(struct silofs_spmap_leaf *sl)
{
	silofs_gen_random_ivs(sl->sl_rivs, ARRAY_SIZE(sl->sl_rivs));
}

static struct silofs_iv *
spleaf_riv_at(const struct silofs_spmap_leaf *sl, size_t slot)
{
	const struct silofs_iv *riv = &sl->sl_rivs[slot];

	silofs_assert_lt(slot, ARRAY_SIZE(sl->sl_rivs));

	return unconst(riv);
}

static void spleaf_riv_of(const struct silofs_spmap_leaf *sl, loff_t voff,
                          struct silofs_iv *out_riv)
{
	silofs_iv_assign(out_riv, spleaf_riv_at(sl, spleaf_slot_of(sl, voff)));
}

static void spleaf_set_riv_at(const struct silofs_spmap_leaf *sl, size_t slot,
                              const struct silofs_iv *riv)
{
	silofs_iv_assign(spleaf_riv_at(sl, slot), riv);
}

static void spleaf_set_riv_of(const struct silofs_spmap_leaf *sl, loff_t voff,
                              const struct silofs_iv *riv)
{
	spleaf_set_riv_at(sl, spleaf_slot_of(sl, voff), riv);
}

static void spleaf_resolve_blink(const struct silofs_spmap_leaf *sl,
                                 loff_t voff, struct silofs_blink *out_blink)
{
	spleaf_child_of(sl, voff, &out_blink->bka);
	spleaf_riv_of(sl, voff, &out_blink->riv);
}

static void spleaf_clone_subrefs(struct silofs_spmap_leaf *sl,
                                 const struct silofs_spmap_leaf *sl_other)
{
	struct silofs_bk_ref *bkr;
	const struct silofs_bk_ref *bkr_other;
	const size_t nslots = ARRAY_SIZE(sl->sl_subrefs);

	for (size_t slot = 0; slot < nslots; ++slot) {
		bkr = spleaf_subref_at(sl, slot);
		bkr_other = spleaf_subref_at(sl_other, slot);
		bkr_clone_from(bkr, bkr_other);
	}
}

static void spleaf_clone_rivs(struct silofs_spmap_leaf *sl,
                              const struct silofs_spmap_leaf *sl_other)
{
	const size_t nslots_max = ARRAY_SIZE(sl->sl_rivs);

	for (size_t slot = 0; slot < nslots_max; ++slot) {
		spleaf_set_riv_at(sl, slot, spleaf_riv_at(sl_other, slot));
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_unode_info *sli_ui(struct silofs_spleaf_info *sli)
{
	return &sli->sl_ui;
}

const struct silofs_ulink *
silofs_sli_ulink(const struct silofs_spleaf_info *sli)
{
	return silofs_ui_ulink(&sli->sl_ui);
}

const struct silofs_uaddr *
silofs_sli_uaddr(const struct silofs_spleaf_info *sli)
{
	return silofs_ui_uaddr(&sli->sl_ui);
}

void silofs_sli_incref(struct silofs_spleaf_info *sli)
{
	if (likely(sli != NULL)) {
		ui_incref(sli_ui(sli));
	}
}

void silofs_sli_decref(struct silofs_spleaf_info *sli)
{
	if (likely(sli != NULL)) {
		ui_decref(sli_ui(sli));
	}
}

static void sli_dirtify(struct silofs_spleaf_info *sli)
{
	ui_dirtify(sli_ui(sli));
}

void silofs_sli_vspace_range(const struct silofs_spleaf_info *sli,
                             struct silofs_vrange *out_vrange)
{
	spleaf_vrange(sli->sl, out_vrange);
}

void silofs_sli_setup_spawned(struct silofs_spleaf_info *sli,
                              const struct silofs_uaddr *parent, loff_t voff)
{
	struct silofs_vrange vrange;
	struct silofs_spmap_leaf *sl = sli->sl;

	vrange_of_spleaf(&vrange, voff);
	spleaf_init(sl, &vrange);
	spleaf_set_parent(sl, parent);
	spleaf_set_self(sl, sli_uaddr(sli));
	spleaf_gen_rivs(sl);
	sli_dirtify(sli);
}

static loff_t sli_start_voff(const struct silofs_spleaf_info *sli)
{
	struct silofs_vrange vrange;
	struct silofs_spmap_leaf *sl = sli->sl;

	spleaf_vrange(sl, &vrange);
	return vrange.beg;
}

void silofs_sli_update_staged(struct silofs_spleaf_info *sli)
{
	const struct silofs_spmap_leaf *sl = sli->sl;

	sli->sl_nused_bytes = spleaf_sum_nbytes_used(sl);
	silofs_assert_le(sli->sl_nused_bytes, SILOFS_LEXT_SIZE_MAX);
}

loff_t silofs_sli_base_voff(const struct silofs_spleaf_info *sli)
{
	struct silofs_vrange vrange;

	sli_vrange(sli, &vrange);
	return vrange.beg;
}

static bool sli_is_inrange(const struct silofs_spleaf_info *sli, loff_t voff)
{
	struct silofs_vrange vrange;

	sli_vrange(sli, &vrange);
	return (vrange.beg <= voff) && (voff < vrange.end);
}

static size_t sli_voff_to_bn(const struct silofs_spleaf_info *sli, loff_t voff)
{
	const loff_t beg = sli_start_voff(sli);
	const size_t bn = (size_t)off_to_lba(voff - beg);

	return bn;
}

static void sli_vaddr_at(const struct silofs_spleaf_info *sli,
                         enum silofs_stype stype, size_t bn, size_t kbn,
                         struct silofs_vaddr *out_vaddr)
{
	const loff_t beg = sli_start_voff(sli);

	silofs_vaddr_by_spleaf(out_vaddr, stype, beg, bn, kbn);
}

static int sli_find_free_space_from(const struct silofs_spleaf_info *sli,
                                    loff_t voff_from, enum silofs_stype stype,
                                    struct silofs_vaddr *out_vaddr)
{
	struct silofs_vrange vrange;
	loff_t voff_beg;
	size_t bn_beg;
	size_t bn_end;
	size_t bn;
	size_t kbn;
	int err;

	sli_vrange(sli, &vrange);
	voff_beg = off_max(voff_from, vrange.beg);
	if (voff_beg >= vrange.end) {
		return -SILOFS_ENOSPC;
	}
	bn_beg = sli_voff_to_bn(sli, voff_beg);
	bn_end = sli_voff_to_bn(sli, vrange.end);
	err = spleaf_find_free(sli->sl, stype, bn_beg, bn_end, &bn, &kbn);
	if (err) {
		return err;
	}
	sli_vaddr_at(sli, stype, bn, kbn, out_vaddr);
	return 0;
}

static int sli_cap_allocate(const struct silofs_spleaf_info *sli,
                            enum silofs_stype stype)
{
	struct silofs_vrange vrange;
	size_t nlimit;
	size_t nbytes;

	sli_vrange(sli, &vrange);
	nlimit = vrange.len;
	nbytes = stype_size(stype);

	return ((sli->sl_nused_bytes + nbytes) <= nlimit) ? 0 : -SILOFS_ENOSPC;
}

int silofs_sli_find_free_space(const struct silofs_spleaf_info *sli,
                               loff_t voff_from, enum silofs_stype stype,
                               struct silofs_vaddr *out_vaddr)
{
	int err;

	err = sli_cap_allocate(sli, stype);
	if (err) {
		return err;
	}
	err = sli_find_free_space_from(sli, voff_from, stype, out_vaddr);
	if (err) {
		return err;
	}
	return 0;
}

void silofs_sli_mark_allocated_space(struct silofs_spleaf_info *sli,
                                     const struct silofs_vaddr *vaddr)
{
	struct silofs_spmap_leaf *sl = sli->sl;

	sli->sl_nused_bytes += vaddr->len;
	silofs_assert_le(sli->sl_nused_bytes, SILOFS_LEXT_SIZE_MAX);

	spleaf_ref_allocated_at(sl, vaddr);
	if (vaddr_isdata(vaddr)) {
		spleaf_set_unwritten_at(sl, vaddr);
	}
	sli_dirtify(sli);
}

void silofs_sli_reref_allocated_space(struct silofs_spleaf_info *sli,
                                      const struct silofs_vaddr *vaddr)
{
	silofs_assert_eq(vaddr->stype, SILOFS_STYPE_DATABK);
	silofs_assert_ge(sli->sl_nused_bytes, SILOFS_LBK_SIZE);
	silofs_assert_le(sli->sl_nused_bytes, SILOFS_LEXT_SIZE_MAX);

	spleaf_ref_allocated_at(sli->sl, vaddr);
	sli_dirtify(sli);
}

void silofs_sli_unref_allocated_space(struct silofs_spleaf_info *sli,
                                      const struct silofs_vaddr *vaddr)
{
	struct silofs_spmap_leaf *sl = sli->sl;
	const bool last = spleaf_is_last_allocated(sl, vaddr);

	spleaf_unref_allocated_at(sl, vaddr);
	if (!spleaf_is_allocated_at(sl, vaddr)) {
		silofs_assert_ge(sli->sl_nused_bytes, vaddr->len);
		sli->sl_nused_bytes -= vaddr->len;
	}
	if (last) {
		spleaf_renew_bk_at(sl, vaddr);
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
                          enum silofs_stype stype, silofs_lba_t lba,
                          struct silofs_vaddrs *vas)
{
	spleaf_make_vaddrs(sli->sl, stype, lba, vas);
}

void silofs_sli_main_blob(const struct silofs_spleaf_info *sli,
                          struct silofs_lextid *out_lextid)
{
	spleaf_main_lextid(sli->sl, out_lextid);
}

void silofs_sli_bind_main_blob(struct silofs_spleaf_info *sli,
                               const struct silofs_lextid *lextid)
{
	spleaf_set_main_lextid(sli->sl, lextid);
	spleaf_bind_bks_to_main(sli->sl);
	sli_dirtify(sli);
}

void silofs_sli_clone_from(struct silofs_spleaf_info *sli,
                           const struct silofs_spleaf_info *sli_other)
{
	spleaf_clone_subrefs(sli->sl, sli_other->sl);
	spleaf_clone_rivs(sli->sl, sli_other->sl);
	sli->sl_nused_bytes = sli_other->sl_nused_bytes;
	sli_dirtify(sli);
}

void silofs_sli_resolve_main(const struct silofs_spleaf_info *sli,
                             loff_t voff, struct silofs_blink *out_blink)
{
	spleaf_resolve_main_ubk(sli->sl, voff, &out_blink->bka);
	spleaf_riv_of(sli->sl, voff, &out_blink->riv);
}

int silofs_sli_resolve_child(const struct silofs_spleaf_info *sli,
                             loff_t voff, struct silofs_blink *out_blink)
{
	if (!sli_is_inrange(sli, voff)) {
		return -SILOFS_ERANGE;
	}
	spleaf_resolve_blink(sli->sl, voff, out_blink);
	if (bkaddr_isnull(&out_blink->bka)) {
		return -SILOFS_ENOENT;
	}
	return 0;
}

void silofs_sli_bind_child(struct silofs_spleaf_info *sli, loff_t voff,
                           const struct silofs_blink *blink)
{
	spleaf_bind_child(sli->sl, voff, &blink->bka.laddr);
	spleaf_set_riv_of(sli->sl, voff, &blink->riv);
	sli_dirtify(sli);
}

void silofs_sli_childrens(const struct silofs_spleaf_info *sli,
                          struct silofs_spleaf_urefs *out_urefs)
{
	const struct silofs_spmap_leaf *sl = sli->sl;
	const struct silofs_bk_ref *bkr = NULL;

	STATICASSERT_EQ(ARRAY_SIZE(out_urefs->subs),
	                ARRAY_SIZE(sl->sl_subrefs));

	for (size_t slot = 0; slot < ARRAY_SIZE(sl->sl_subrefs); ++slot) {
		bkr = spleaf_subref_at(sl, slot);
		bkr_uref(bkr, &out_urefs->subs[slot]);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_unode_info *sni_ui(const struct silofs_spnode_info *sni)
{
	return silofs_unconst(&sni->sn_ui);
}

static void sni_dirtify(struct silofs_spnode_info *sni)
{
	ui_dirtify(sni_ui(sni));
}

const struct silofs_ulink *
silofs_sni_ulink(const struct silofs_spnode_info *sni)
{
	return silofs_ui_ulink(&sni->sn_ui);
}

const struct silofs_uaddr *
silofs_sni_uaddr(const struct silofs_spnode_info *sni)
{
	return silofs_ui_uaddr(&sni->sn_ui);
}

void silofs_sni_incref(struct silofs_spnode_info *sni)
{
	if (likely(sni != NULL)) {
		ui_incref(sni_ui(sni));
	}
}

void silofs_sni_decref(struct silofs_spnode_info *sni)
{
	if (likely(sni != NULL)) {
		ui_decref(sni_ui(sni));
	}
}

void silofs_sni_setup_spawned(struct silofs_spnode_info *sni,
                              const struct silofs_uaddr *parent, loff_t voff)
{
	struct silofs_vrange vrange = { .beg = -1, .end = -1, .len = 0 };
	const enum silofs_height parent_height = uaddr_height(parent);

	vrange_of_spnode(&vrange, parent_height - 1, voff);
	spnode_init(sni->sn, &vrange);
	spnode_set_parent(sni->sn, parent);
	spnode_set_self(sni->sn, sni_uaddr(sni));
	spnode_gen_rivs(sni->sn);
	sni_dirtify(sni);
}

void silofs_sni_update_staged(struct silofs_spnode_info *sni)
{
	sni->sn_nactive_subs = spnode_count_nactive(sni->sn);
}

enum silofs_height silofs_sni_height(const struct silofs_spnode_info *sni)
{
	return uaddr_height(sni_uaddr(sni));
}

static enum silofs_height sni_sub_height(const struct silofs_spnode_info *sni)
{
	return silofs_sni_height(sni) - 1;
}

void silofs_sni_bind_child(struct silofs_spnode_info *sni, loff_t voff,
                           const struct silofs_ulink *ulink)
{
	/* either we set new ulink or override upon clone */
	const bool bind_override = spnode_has_child_at(sni->sn, voff);

	spnode_set_uaddr_of(sni->sn, voff, &ulink->uaddr);
	spnode_set_riv_of(sni->sn, voff, &ulink->riv);
	if (!bind_override) {
		sni->sn_nactive_subs++;
	}
	sni_dirtify(sni);
}

static bool sni_is_inrange(const struct silofs_spnode_info *sni, loff_t voff)
{
	struct silofs_vrange vrange;

	sni_vrange(sni, &vrange);
	return (vrange.beg <= voff) && (voff < vrange.end);
}

void silofs_sni_vspace_range(const struct silofs_spnode_info *sni,
                             struct silofs_vrange *out_vrange)
{
	spnode_vrange(sni->sn, out_vrange);
}

void silofs_sni_active_vrange(const struct silofs_spnode_info *sni,
                              struct silofs_vrange *out_vrange)
{
	struct silofs_vrange vrange;
	size_t nform_size;
	ssize_t span;

	sni_vrange(sni, &vrange);
	span = silofs_height_to_space_span(vrange.height - 1);
	nform_size = sni->sn_nactive_subs * (size_t)span;
	silofs_vrange_setup(out_vrange, vrange.height, vrange.beg,
	                    off_end(vrange.beg, nform_size));
}

loff_t silofs_sni_base_voff(const struct silofs_spnode_info *sni)
{
	struct silofs_vrange vrange;

	sni_vrange(sni, &vrange);
	return vrange.beg;
}

static enum silofs_stype sni_child_stype(const struct silofs_spnode_info *sni)
{
	enum silofs_stype child_stype;
	const size_t child_height = sni_sub_height(sni);

	if (child_height == SILOFS_HEIGHT_SPLEAF) {
		child_stype = SILOFS_STYPE_SPLEAF;
	} else {
		child_stype = SILOFS_STYPE_SPNODE;
	}
	return child_stype;
}

static void sni_get_riv_of(const struct silofs_spnode_info *sni,
                           loff_t voff, struct silofs_iv *out_riv)
{
	spnode_riv_of(sni->sn, voff, out_riv);
}

static void sni_get_ulink_of(const struct silofs_spnode_info *sni,
                             loff_t voff, struct silofs_ulink *out_ulink)
{
	spnode_uaddr_of(sni->sn, voff, &out_ulink->uaddr);
	spnode_riv_of(sni->sn, voff, &out_ulink->riv);
}

int silofs_sni_resolve_child(const struct silofs_spnode_info *sni,
                             loff_t voff, struct silofs_ulink *out_ulink)
{
	silofs_assert(sni_is_inrange(sni, voff));
	if (!sni_is_inrange(sni, voff)) {
		return -SILOFS_ERANGE;
	}
	sni_get_ulink_of(sni, voff, out_ulink);
	if (uaddr_isnull(&out_ulink->uaddr)) {
		return -SILOFS_ENOENT;
	}
	return 0;
}

void silofs_sni_main_blob(const struct silofs_spnode_info *sni,
                          struct silofs_lextid *out_lextid)
{
	spnode_main_lextid(sni->sn, out_lextid);
}

void silofs_sni_bind_main_blob(struct silofs_spnode_info *sni,
                               const struct silofs_lextid *lextid)
{
	spnode_set_main_lextid(sni->sn, lextid);
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
	struct silofs_vrange vrange;
	const enum silofs_height child_height = sni_sub_height(sni);

	silofs_vrange_of_spmap(&vrange, child_height, voff);
	return vrange.beg;
}

void silofs_sni_resolve_main(const struct silofs_spnode_info *sni,
                             loff_t voff, struct silofs_ulink *out_ulink)
{
	struct silofs_lextid lextid;
	const loff_t bpos = sni_bpos_of_child(sni, voff);
	const loff_t base = sni_base_voff_of_child(sni, voff);
	enum silofs_stype child_stype = sni_child_stype(sni);

	silofs_sni_main_blob(sni, &lextid);
	uaddr_setup(&out_ulink->uaddr, &lextid, bpos, child_stype, base);
	sni_get_riv_of(sni, voff, &out_ulink->riv);
}

void silofs_sni_clone_from(struct silofs_spnode_info *sni,
                           const struct silofs_spnode_info *sni_other)
{
	spnode_clone_subrefs(sni->sn, sni_other->sn);
	spnode_clone_rivs(sni->sn, sni_other->sn);
	sni->sn_nactive_subs = sni_other->sn_nactive_subs;
	sni_dirtify(sni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
bk_state_mask_of_view(struct silofs_bk_state *bk_mask, loff_t off, size_t len)
{
	const loff_t roff = silofs_off_in_lbk(off);
	const size_t ki = (size_t)(roff / SILOFS_KB_SIZE);
	const size_t nk = div_round_up(len, SILOFS_KB_SIZE);

	bk_state_mask_of(bk_mask, ki, nk);
}

bool silofs_lbki_has_view_at(const struct silofs_lbk_info *lbki,
                             loff_t view_pos, size_t view_len)
{
	struct silofs_bk_state bk_mask;

	bk_state_mask_of_view(&bk_mask, view_pos, view_len);
	return bk_state_has_mask(&lbki->lbk_view, &bk_mask);
}

void silofs_lbki_set_view_at(struct silofs_lbk_info *lbki,
                             loff_t view_pos, size_t view_len)
{
	struct silofs_bk_state bk_mask;

	bk_state_mask_of_view(&bk_mask, view_pos, view_len);
	bk_state_set_mask(&lbki->lbk_view, &bk_mask);
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

static int verify_bk_ref(const struct silofs_bk_ref *bkr)
{
	size_t val;

	val = bkr_dbkref(bkr);
	if (val >= INT_MAX) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int verify_spmap_leaf_parent(const struct silofs_spmap_leaf *sl)
{
	struct silofs_uaddr uaddr;

	spleaf_parent(sl, &uaddr);
	if (uaddr_isnull(&uaddr)) {
		return -SILOFS_EFSCORRUPTED;
	}
	if (uaddr.stype != SILOFS_STYPE_SPNODE) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int verify_spmap_leaf_self(const struct silofs_spmap_leaf *sl)
{
	struct silofs_uaddr uaddr;

	spleaf_self(sl, &uaddr);
	if (uaddr_isnull(&uaddr)) {
		return -SILOFS_EFSCORRUPTED;
	}
	if (uaddr.stype != SILOFS_STYPE_SPLEAF) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

int silofs_verify_spmap_leaf(const struct silofs_spmap_leaf *sl)
{
	const struct silofs_bk_ref *bkr;
	int err;

	err = verify_spmap_leaf_parent(sl);
	if (err) {
		return err;
	}
	err = verify_spmap_leaf_self(sl);
	if (err) {
		return err;
	}
	for (size_t i = 0; i < ARRAY_SIZE(sl->sl_subrefs); ++i) {
		bkr = spleaf_subref_at(sl, i);
		err = verify_bk_ref(bkr);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int verify_ulink(const struct silofs_uaddr *uaddr)
{
	return laddr_isvalid(&uaddr->laddr) ? 0 : -SILOFS_EFSCORRUPTED;
}

static int verify_spmap_ref(const struct silofs_spmap_ref *spr)
{
	struct silofs_uaddr uaddr;
	int err;

	spr_uaddr(spr, &uaddr);
	if (uaddr_isnull(&uaddr)) {
		return 0;
	}
	err = verify_ulink(&uaddr);
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
	int parent_height;

	spnode_parent(sn, &parent_uaddr);
	if (uaddr_isnull(&parent_uaddr)) {
		return -SILOFS_EFSCORRUPTED;
	}
	parent_height = uaddr_height(&parent_uaddr);
	if (parent_height != ((int)height + 1)) {
		return -SILOFS_EFSCORRUPTED;
	}
	if ((height == height_max) && !stype_issuper(parent_uaddr.stype)) {
		return -SILOFS_EFSCORRUPTED;
	}
	if ((height < height_max) && !stype_isspnode(parent_uaddr.stype)) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int verify_spmap_node_self(const struct silofs_spmap_node *sn)
{
	struct silofs_uaddr uaddr;
	enum silofs_height height;
	int err;

	spnode_self(sn, &uaddr);
	if (uaddr_isnull(&uaddr)) {
		return -SILOFS_EFSCORRUPTED;
	}
	if (!stype_isspnode(uaddr.stype)) {
		return -SILOFS_EFSCORRUPTED;
	}
	height = uaddr_height(&uaddr);
	err = verify_spnode_height(height);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_verify_spmap_node(const struct silofs_spmap_node *sn)
{
	struct silofs_vrange vrange;
	enum silofs_height height;
	ssize_t vrange_len;
	ssize_t height_len;
	int err;

	height = spnode_heigth(sn);
	err = verify_spnode_height(height);
	if (err) {
		log_err("bad spnode height: height=%lu", height);
		return err;
	}
	spnode_vrange(sn, &vrange);
	vrange_len = off_len(vrange.beg, vrange.end);
	height_len = silofs_height_to_space_span(height);
	if (vrange_len != height_len) {
		log_err("bad spmap-node vrange: height=%lu "
		        "beg=0x%lx end=0x%lx", height, vrange.beg, vrange.end);
		return -SILOFS_EFSCORRUPTED;
	}
	err = verify_spmap_node_self(sn);
	if (err) {
		log_err("illegal spmap-node self: height=%lu "
		        "beg=0x%lx end=0x%lx", height, vrange.beg, vrange.end);
		return err;
	}
	err = verify_spmap_node_parent(sn);
	if (err) {
		log_err("illegal spmap-node parent: height=%lu "
		        "beg=0x%lx end=0x%lx", height, vrange.beg, vrange.end);
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

