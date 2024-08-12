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
#include <silofs/fs.h>
#include <silofs/fs-private.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>


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
	return ltype_nkbs(vaddr->ltype);
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

static void spnode_vrange(const struct silofs_spmap_node *spn,
                          struct silofs_vrange *out_vrange)
{
	silofs_vrange128_xtoh(&spn->sn_vrange, out_vrange);
}

static void spnode_set_vrange(struct silofs_spmap_node *spn,
                              const struct silofs_vrange *vrange)
{
	silofs_vrange128_htox(&spn->sn_vrange, vrange);
}

static enum silofs_height spnode_heigth(const struct silofs_spmap_node *spn)
{
	struct silofs_uaddr self_uaddr;

	spnode_self(spn, &self_uaddr);
	return uaddr_height(&self_uaddr);
}

static void spnode_main_lsegid(const struct silofs_spmap_node *spn,
                               struct silofs_lsegid *out_lsegid)
{
	silofs_lsegid32b_xtoh(&spn->sn_main_lsegid, out_lsegid);
}

static void spnode_set_main_lsegid(struct silofs_spmap_node *spn,
                                   const struct silofs_lsegid *lsegid)
{
	silofs_lsegid32b_htox(&spn->sn_main_lsegid, lsegid);
}

static void spnode_init(struct silofs_spmap_node *spn,
                        const struct silofs_vrange *vrange)
{
	spnode_set_vrange(spn, vrange);
	silofs_lsegid32b_reset(&spn->sn_main_lsegid);
	silofs_uaddr64b_reset(&spn->sn_parent);
	silofs_uaddr64b_reset(&spn->sn_self);
	spr_initn(spn->sn_subrefs, ARRAY_SIZE(spn->sn_subrefs));
}

static size_t spnode_slot_of(const struct silofs_spmap_node *spn, loff_t voff)
{
	const size_t nslots = SILOFS_SPMAP_NCHILDS;
	struct silofs_vrange vrange;
	size_t len;
	size_t slot;
	ssize_t roff;

	STATICASSERT_EQ(ARRAY_SIZE(spn->sn_subrefs), SILOFS_SPMAP_NCHILDS);
	STATICASSERT_EQ(ARRAY_SIZE(spn->sn_rivs), SILOFS_SPMAP_NCHILDS);

	spnode_vrange(spn, &vrange);
	len = vrange.len;
	roff = off_diff(vrange.beg, voff);
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

static void spnode_gen_rivs(struct silofs_spmap_node *spn)
{
	silofs_gen_random_ivs(spn->sn_rivs, ARRAY_SIZE(spn->sn_rivs));
}

static struct silofs_iv *
spnode_riv_at(const struct silofs_spmap_node *spn, size_t slot)
{
	const struct silofs_iv *riv = &spn->sn_rivs[slot];

	silofs_assert_lt(slot, ARRAY_SIZE(spn->sn_rivs));

	return unconst(riv);
}

static void spnode_set_riv_at(struct silofs_spmap_node *spn, size_t slot,
                              const struct silofs_iv *iv)
{
	struct silofs_iv *riv = &spn->sn_rivs[slot];

	silofs_iv_assign(riv, iv);
}

static void spnode_riv_of(const struct silofs_spmap_node *spn, loff_t voff,
                          struct silofs_iv *out_riv)
{
	const size_t slot = spnode_slot_of(spn, voff);

	silofs_iv_assign(out_riv, spnode_riv_at(spn, slot));
}

static void spnode_set_riv_of(struct silofs_spmap_node *spn, loff_t voff,
                              const struct silofs_iv *iv)
{
	spnode_set_riv_at(spn, spnode_slot_of(spn, voff), iv);
}

static void spnode_clone_rivs(struct silofs_spmap_node *spn,
                              const struct silofs_spmap_node *spn_other)
{
	const size_t nslots_max = ARRAY_SIZE(spn->sn_rivs);

	for (size_t slot = 0; slot < nslots_max; ++slot) {
		spnode_set_riv_at(spn, slot, spnode_riv_at(spn_other, slot));
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

static size_t bkr_usecnt_nbytes(const struct silofs_bk_ref *bkr)
{
	return SILOFS_KB_SIZE * bkr_usecnt(bkr);
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
                            enum silofs_ltype ltype, loff_t voff_base,
                            struct silofs_vaddrs *vas)
{
	struct silofs_bk_state bk_st;
	struct silofs_bk_state bk_mask;
	const size_t nkb = ltype_nkbs(ltype);
	const size_t nkb_in_bk = SILOFS_NKB_IN_LBK;
	loff_t voff;

	bkr_allocated(bkr, &bk_st);
	vas->count = 0;
	for (size_t kbn = 0; (kbn + nkb) <= nkb_in_bk; kbn += nkb) {
		bk_state_mask_of(&bk_mask, kbn, nkb);
		if (bk_state_has_mask(&bk_st, &bk_mask)) {
			voff = off_end(voff_base, kbn * SILOFS_KB_SIZE);
			vaddr_setup(&vas->vaddr[vas->count++], ltype, voff);
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

static void spleaf_init(struct silofs_spmap_leaf *spl,
                        const struct silofs_vrange *vrange)
{
	silofs_vrange128_htox(&spl->sl_vrange, vrange);
	silofs_lsegid32b_reset(&spl->sl_main_lsegid);
	silofs_uaddr64b_reset(&spl->sl_parent);
	silofs_uaddr64b_reset(&spl->sl_self);
	bkr_init_arr(spl->sl_subrefs, ARRAY_SIZE(spl->sl_subrefs));
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

static enum silofs_ltype spleaf_vspace(const struct silofs_spmap_leaf *spl)
{
	struct silofs_uaddr uaddr;

	spleaf_self(spl, &uaddr);
	return uaddr.laddr.lsid.vspace;
}

static void spleaf_vrange(const struct silofs_spmap_leaf *spl,
                          struct silofs_vrange *vrange)
{
	silofs_vrange128_xtoh(&spl->sl_vrange, vrange);
}

static struct silofs_bk_ref *
spleaf_subref_at(const struct silofs_spmap_leaf *spl, size_t slot)
{
	const struct silofs_bk_ref *bkr = &(spl->sl_subrefs[slot]);

	return bkr_unconst(bkr);
}

static size_t
spleaf_lba_slot(const struct silofs_spmap_leaf *spl, silofs_lba_t lba)
{
	return (size_t)lba % ARRAY_SIZE(spl->sl_subrefs);
}

static size_t
spleaf_slot_of(const struct silofs_spmap_leaf *spl, loff_t voff)
{
	return spleaf_lba_slot(spl, off_to_lba(voff));
}

static struct silofs_bk_ref *
spleaf_bkr_by_lba(const struct silofs_spmap_leaf *spl, silofs_lba_t lba)
{
	return spleaf_subref_at(spl, spleaf_lba_slot(spl, lba));
}

static struct silofs_bk_ref *
spleaf_bkr_by_voff(const struct silofs_spmap_leaf *spl, loff_t voff)
{
	return spleaf_subref_at(spl, spleaf_slot_of(spl, voff));
}

static struct silofs_bk_ref *
spleaf_bkr_by_vaddr(const struct silofs_spmap_leaf *spl,
                    const struct silofs_vaddr *vaddr)
{
	return spleaf_bkr_by_voff(spl, vaddr->off);
}

static bool spleaf_is_allocated_at(const struct silofs_spmap_leaf *spl,
                                   const struct silofs_vaddr *vaddr)
{
	const size_t kbn = kbn_of(vaddr);
	const size_t nkb = nkbs_of(vaddr);
	const struct silofs_bk_ref *bkr;
	bool ret;

	bkr = spleaf_bkr_by_vaddr(spl, vaddr);
	if (vaddr_isdatabk(vaddr)) {
		ret = (bkr_dbkref(bkr) > 0);
	} else {
		ret = bkr_test_allocated_at(bkr, kbn, nkb);
	}
	return ret;
}

static bool spleaf_has_allocated_with(const struct silofs_spmap_leaf *spl,
                                      const struct silofs_vaddr *vaddr)
{
	const size_t kbn = kbn_of(vaddr);
	const size_t nkb = nkbs_of(vaddr);
	const struct silofs_bk_ref *bkr;
	bool ret;

	bkr = spleaf_bkr_by_vaddr(spl, vaddr);
	if (vaddr_isdatabk(vaddr)) {
		ret = (bkr_dbkref(bkr) > 0);
	} else {
		ret = bkr_test_allocated_other(bkr, kbn, nkb);
	}
	return ret;
}

static bool spleaf_is_last_allocated(const struct silofs_spmap_leaf *spl,
                                     const struct silofs_vaddr *vaddr)
{
	const size_t kbn = kbn_of(vaddr);
	const size_t nkb = nkbs_of(vaddr);
	const struct silofs_bk_ref *bkr;
	bool ret;

	bkr = spleaf_bkr_by_vaddr(spl, vaddr);
	if (vaddr_isdatabk(vaddr)) {
		ret = (bkr_dbkref(bkr) == 1);
	} else {
		ret = !bkr_test_allocated_other(bkr, kbn, nkb);
	}
	return ret;
}

static bool spleaf_test_unwritten_at(const struct silofs_spmap_leaf *spl,
                                     const struct silofs_vaddr *vaddr)
{
	const struct silofs_bk_ref *bkr = spleaf_bkr_by_vaddr(spl, vaddr);

	return bkr_test_unwritten_at(bkr, kbn_of(vaddr), nkbs_of(vaddr));
}

static void spleaf_set_unwritten_at(struct silofs_spmap_leaf *spl,
                                    const struct silofs_vaddr *vaddr)
{
	struct silofs_bk_ref *bkr = spleaf_bkr_by_vaddr(spl, vaddr);

	bkr_set_unwritten_at(bkr, kbn_of(vaddr), nkbs_of(vaddr));
}

static void spleaf_clear_unwritten_at(struct silofs_spmap_leaf *spl,
                                      const struct silofs_vaddr *vaddr)
{
	struct silofs_bk_ref *bkr = spleaf_bkr_by_vaddr(spl, vaddr);

	bkr_clear_unwritten_at(bkr, kbn_of(vaddr), nkbs_of(vaddr));
}

static size_t spleaf_dbkref_at(const struct silofs_spmap_leaf *spl,
                               const struct silofs_vaddr *vaddr)
{
	const struct silofs_bk_ref *bkr = spleaf_bkr_by_vaddr(spl, vaddr);

	silofs_assert_eq(vaddr->ltype, SILOFS_LTYPE_DATABK);

	return bkr_dbkref(bkr);
}

static void spleaf_ref_allocated_at(struct silofs_spmap_leaf *spl,
                                    const struct silofs_vaddr *vaddr)
{
	const size_t kbn = kbn_of(vaddr);
	const size_t nkb = nkbs_of(vaddr);
	struct silofs_bk_ref *bkr = spleaf_bkr_by_vaddr(spl, vaddr);

	bkr_set_allocated_at(bkr, kbn, nkb);
	if (vaddr_isdatabk(vaddr)) {
		bkr_inc_dbkref(bkr);
	}
}

static void spleaf_unref_allocated_at(struct silofs_spmap_leaf *spl,
                                      const struct silofs_vaddr *vaddr)
{
	const size_t kbn = kbn_of(vaddr);
	const size_t nkb = nkbs_of(vaddr);
	struct silofs_bk_ref *bkr = spleaf_bkr_by_vaddr(spl, vaddr);

	if (vaddr_isdatabk(vaddr)) {
		bkr_dec_dbkref(bkr);
	}
	if (!bkr_dbkref(bkr) || (nkb < SILOFS_NKB_IN_LBK)) {
		bkr_clear_allocated_at(bkr, kbn, nkb);
	}
}

static void spleaf_renew_bk_at(struct silofs_spmap_leaf *spl,
                               const struct silofs_vaddr *vaddr)
{
	struct silofs_bk_ref *bkr = spleaf_bkr_by_vaddr(spl, vaddr);

	silofs_assert(bkr_isunused(bkr));
	bkr_clear_alloc_state(bkr);
}

static int
spleaf_find_nfree_at(const struct silofs_spmap_leaf *spl,
                     enum silofs_ltype ltype, size_t bn, size_t *out_kbn)
{
	const size_t nkb = ltype_nkbs(ltype);
	const struct silofs_bk_ref *bkr = spleaf_subref_at(spl, bn);
	int err = -SILOFS_ENOSPC;

	if (bkr_may_alloc(bkr, nkb)) {
		err = bkr_find_free(bkr, nkb, out_kbn);
	}
	return err;
}

static int
spleaf_find_free(const struct silofs_spmap_leaf *spl, enum silofs_ltype ltype,
                 size_t bn_beg, size_t bn_end, size_t *out_bn, size_t *out_kbn)
{
	size_t kbn = 0;
	int err = -SILOFS_ENOSPC;

	for (size_t bn = bn_beg; bn < bn_end; ++bn) {
		err = spleaf_find_nfree_at(spl, ltype, bn, &kbn);
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
	const struct silofs_bk_ref *bkr = spleaf_bkr_by_lba(spl, lba);
	const loff_t off = silofs_lba_to_off(lba);

	bkr_make_vaddrs(bkr, ltype, off, vas);
}

static void spleaf_main_lsegid(const struct silofs_spmap_leaf *spl,
                               struct silofs_lsegid *out_lsegid)
{
	silofs_lsegid32b_xtoh(&spl->sl_main_lsegid, out_lsegid);
}

static void spleaf_set_main_lsegid(struct silofs_spmap_leaf *spl,
                                   const struct silofs_lsegid *lsegid)
{
	silofs_lsegid32b_htox(&spl->sl_main_lsegid, lsegid);
}

static void spleaf_main_uref_at(const struct silofs_spmap_leaf *spl,
                                size_t slot, struct silofs_laddr *out_laddr)
{
	struct silofs_lsegid lsegid = { .height = SILOFS_HEIGHT_NONE };
	const loff_t pos = silofs_lba_to_off((silofs_lba_t)slot);

	spleaf_main_lsegid(spl, &lsegid);
	silofs_laddr_setup_lbk(out_laddr, &lsegid, spleaf_vspace(spl), pos);
}

static void spleaf_bind_bks_to_main(struct silofs_spmap_leaf *spl)
{
	struct silofs_laddr laddr;
	struct silofs_bk_ref *bkr = NULL;
	const size_t nslots = ARRAY_SIZE(spl->sl_subrefs);

	for (size_t slot = 0; slot < nslots; ++slot) {
		bkr = spleaf_subref_at(spl, slot);
		spleaf_main_uref_at(spl, slot, &laddr);
		bkr_set_uref(bkr, &laddr);
	}
}

static size_t spleaf_calc_total_usecnt(const struct silofs_spmap_leaf *spl)
{
	const struct silofs_bk_ref *bkr = NULL;
	const size_t nslots = ARRAY_SIZE(spl->sl_subrefs);
	size_t usecnt_sum = 0;

	for (size_t slot = 0; slot < nslots; ++slot) {
		bkr = spleaf_subref_at(spl, slot);
		usecnt_sum += bkr_usecnt(bkr);
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
	struct silofs_lsegid lsegid;

	spleaf_main_lsegid(spl, &lsegid);
	silofs_laddr_setup_lbk(out_laddr, &lsegid, spleaf_vspace(spl), voff);
}

static void spleaf_child_of(const struct silofs_spmap_leaf *spl,
                            loff_t voff, struct silofs_laddr *out_laddr)
{
	const struct silofs_bk_ref *bkr = spleaf_bkr_by_voff(spl, voff);

	bkr_uref(bkr, out_laddr);
}

static void spleaf_bind_child(struct silofs_spmap_leaf *spl, loff_t voff,
                              const struct silofs_laddr *laddr)
{
	struct silofs_bk_ref *bkr = spleaf_bkr_by_voff(spl, voff);

	silofs_assert_gt(bkr_usecnt(bkr), 0);
	if (!laddr_isnull(laddr)) {
		silofs_assert_eq(laddr->len, SILOFS_LBK_SIZE);
	}
	bkr_set_uref(bkr, laddr);
}

static void spleaf_gen_rivs(struct silofs_spmap_leaf *spl)
{
	silofs_gen_random_ivs(spl->sl_rivs, ARRAY_SIZE(spl->sl_rivs));
}

static const struct silofs_iv *
spleaf_riv_at(const struct silofs_spmap_leaf *spl, size_t slot)
{
	const struct silofs_iv *riv = &spl->sl_rivs[slot];

	silofs_assert_lt(slot, ARRAY_SIZE(spl->sl_rivs));

	return riv;
}

static struct silofs_iv *
spleaf_riv_at2(struct silofs_spmap_leaf *spl, size_t slot)
{
	struct silofs_iv *riv = &spl->sl_rivs[slot];

	silofs_assert_lt(slot, ARRAY_SIZE(spl->sl_rivs));

	return riv;
}

static void spleaf_riv_of(const struct silofs_spmap_leaf *spl, loff_t voff,
                          struct silofs_iv *out_riv)
{
	const size_t slot = spleaf_slot_of(spl, voff);

	silofs_iv_assign(out_riv, spleaf_riv_at(spl, slot));
}

static void spleaf_set_riv_at(struct silofs_spmap_leaf *spl, size_t slot,
                              const struct silofs_iv *riv)
{
	silofs_iv_assign(spleaf_riv_at2(spl, slot), riv);
}

static void spleaf_set_riv_of(struct silofs_spmap_leaf *spl, loff_t voff,
                              const struct silofs_iv *riv)
{
	spleaf_set_riv_at(spl, spleaf_slot_of(spl, voff), riv);
}

static void spleaf_renew_riv_of(struct silofs_spmap_leaf *spl, loff_t voff)
{
	struct silofs_iv riv;

	silofs_gen_random_iv(&riv);
	spleaf_set_riv_of(spl, voff, &riv);
}

static void spleaf_resolve_child(const struct silofs_spmap_leaf *spl,
                                 loff_t voff, struct silofs_llink *out_llink)
{
	spleaf_child_of(spl, voff, &out_llink->laddr);
	spleaf_riv_of(spl, voff, &out_llink->riv);
}

static void spleaf_clone_subrefs(struct silofs_spmap_leaf *spl,
                                 const struct silofs_spmap_leaf *sl_other)
{
	struct silofs_bk_ref *bkr;
	const struct silofs_bk_ref *bkr_other;
	const size_t nslots = ARRAY_SIZE(spl->sl_subrefs);

	for (size_t slot = 0; slot < nslots; ++slot) {
		bkr = spleaf_subref_at(spl, slot);
		bkr_other = spleaf_subref_at(sl_other, slot);
		bkr_clone_from(bkr, bkr_other);
	}
}

static void spleaf_clone_rivs(struct silofs_spmap_leaf *spl,
                              const struct silofs_spmap_leaf *spl_other)
{
	const size_t nslots_max = ARRAY_SIZE(spl->sl_rivs);

	for (size_t slot = 0; slot < nslots_max; ++slot) {
		spleaf_set_riv_at(spl, slot, spleaf_riv_at(spl_other, slot));
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

	spleaf_vrange(sli->sl, &vrange);
	return vrange.beg;
}

void silofs_sli_update_nused(struct silofs_spleaf_info *sli)
{
	sli->sl_nused_bytes = spleaf_sum_nbytes_used(sli->sl);
	silofs_assert_le(sli->sl_nused_bytes, SILOFS_LSEG_SIZE_MAX);
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
                         enum silofs_ltype ltype, size_t bn, size_t kbn,
                         struct silofs_vaddr *out_vaddr)
{
	const loff_t beg = sli_start_voff(sli);

	silofs_vaddr_by_spleaf(out_vaddr, ltype, beg, bn, kbn);
}

static int sli_find_free_space_from(const struct silofs_spleaf_info *sli,
                                    loff_t voff_from, enum silofs_ltype ltype,
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
	err = spleaf_find_free(sli->sl, ltype, bn_beg, bn_end, &bn, &kbn);
	if (err) {
		return err;
	}
	sli_vaddr_at(sli, ltype, bn, kbn, out_vaddr);
	return 0;
}

static size_t sli_vrange_len(const struct silofs_spleaf_info *sli)
{
	struct silofs_vrange vrange;

	sli_vrange(sli, &vrange);
	return vrange.len;
}

static int sli_cap_allocate(const struct silofs_spleaf_info *sli,
                            enum silofs_ltype ltype)
{
	const size_t nlimit = sli_vrange_len(sli);
	const size_t nbytes_want = ltype_size(ltype);
	const size_t nbytes_used = sli->sl_nused_bytes;

	silofs_assert_le(nlimit, SILOFS_LSEG_SIZE_MAX);
	silofs_assert_le(nbytes_used, SILOFS_LSEG_SIZE_MAX);

	return ((nbytes_used + nbytes_want) <= nlimit) ? 0 : -SILOFS_ENOSPC;
}

int silofs_sli_find_free_space(const struct silofs_spleaf_info *sli,
                               loff_t voff_from, enum silofs_ltype ltype,
                               struct silofs_vaddr *out_vaddr)
{
	int err;

	err = sli_cap_allocate(sli, ltype);
	if (err) {
		return err;
	}
	err = sli_find_free_space_from(sli, voff_from, ltype, out_vaddr);
	if (err) {
		return err;
	}
	return 0;
}

void silofs_sli_mark_allocated_space(struct silofs_spleaf_info *sli,
                                     const struct silofs_vaddr *vaddr)
{
	silofs_assert_lt(sli->sl_nused_bytes, SILOFS_LSEG_SIZE_MAX);
	silofs_assert_le(sli->sl_nused_bytes + vaddr->len,
	                 SILOFS_LSEG_SIZE_MAX);

	sli->sl_nused_bytes += vaddr->len;

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
	const loff_t voff = vaddr->off;
	const bool last = spleaf_is_last_allocated(sl, vaddr);

	spleaf_unref_allocated_at(sl, vaddr);
	if (!spleaf_is_allocated_at(sl, vaddr)) {
		silofs_assert_ge(sli->sl_nused_bytes, vaddr->len);
		sli->sl_nused_bytes -= vaddr->len;
	}
	if (last) {
		spleaf_renew_bk_at(sl, vaddr);
		spleaf_renew_riv_of(sl, voff);
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
                          struct silofs_lsegid *out_lsegid)
{
	spleaf_main_lsegid(sli->sl, out_lsegid);
}

void silofs_sli_bind_main_lseg(struct silofs_spleaf_info *sli,
                               const struct silofs_lsegid *lsegid)
{
	spleaf_set_main_lsegid(sli->sl, lsegid);
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

void silofs_sli_resolve_main_lbk(const struct silofs_spleaf_info *sli,
                                 loff_t voff, struct silofs_llink *out_llink)
{
	spleaf_resolve_main_lbk(sli->sl, voff, &out_llink->laddr);
	spleaf_riv_of(sli->sl, voff, &out_llink->riv);
}

int silofs_sli_resolve_child(const struct silofs_spleaf_info *sli,
                             loff_t voff, struct silofs_llink *out_llink)
{
	if (!sli_is_inrange(sli, voff)) {
		return -SILOFS_ERANGE;
	}
	spleaf_resolve_child(sli->sl, voff, out_llink);
	if (laddr_isnull(&out_llink->laddr)) {
		return -SILOFS_ENOENT;
	}
	return 0;
}

void silofs_sli_bind_child(struct silofs_spleaf_info *sli, loff_t voff,
                           const struct silofs_llink *llink)
{
	spleaf_bind_child(sli->sl, voff, &llink->laddr);
	spleaf_set_riv_of(sli->sl, voff, &llink->riv);
	sli_dirtify(sli);
}

static void lmap_append_entry(struct silofs_spmap_lmap *lmap,
                              const struct silofs_laddr *laddr)
{
	silofs_assert_lt(lmap->cnt, ARRAY_SIZE(lmap->laddr));

	laddr_assign(&lmap->laddr[lmap->cnt++], laddr);
}

static void lmap_append_length(struct silofs_spmap_lmap *lmap,
                               const struct silofs_laddr *laddr)
{
	struct silofs_laddr *laddr_prev = &lmap->laddr[lmap->cnt - 1];

	silofs_assert_lt(lmap->cnt, ARRAY_SIZE(lmap->laddr));
	silofs_assert_gt(lmap->cnt, 0);

	laddr_prev->len += laddr->len;
}

static bool lmap_may_append_length(const struct silofs_spmap_lmap *lmap,
                                   const struct silofs_laddr *laddr)
{
	const struct silofs_laddr *laddr_prev = NULL;
	bool ret = false;

	if (lmap->cnt > 0) {
		laddr_prev = &lmap->laddr[lmap->cnt - 1];
		ret = laddr_isnext(laddr_prev, laddr);
	}
	return ret;
}

static void lmap_append(struct silofs_spmap_lmap *lmap,
                        const struct silofs_laddr *laddr)
{
	silofs_assert_le(lmap->cnt, ARRAY_SIZE(lmap->laddr));

	if (!laddr_isnull(laddr)) {
		if (lmap_may_append_length(lmap, laddr)) {
			lmap_append_length(lmap, laddr);
		} else {
			lmap_append_entry(lmap, laddr);
		}
	}
}

void silofs_sli_resolve_lmap(const struct silofs_spleaf_info *sli,
                             struct silofs_spmap_lmap *out_lmap)
{
	struct silofs_laddr laddr = { .pos = -1 };
	const struct silofs_spmap_leaf *sl = sli->sl;
	const struct silofs_bk_ref *bkr = NULL;
	const size_t nslots = ARRAY_SIZE(sl->sl_subrefs);
	const size_t nused = sli->sl_nused_bytes;
	size_t nused_at_slot = 0;
	size_t nbytes = 0;

	STATICASSERT_EQ(ARRAY_SIZE(out_lmap->laddr),
	                ARRAY_SIZE(sl->sl_subrefs));

	out_lmap->cnt = 0;
	for (size_t slot = 0; (slot < nslots) && (nbytes < nused); ++slot) {
		bkr = spleaf_subref_at(sl, slot);
		nused_at_slot = bkr_usecnt_nbytes(bkr);
		if (nused_at_slot > 0) {
			bkr_uref(bkr, &laddr);
			lmap_append(out_lmap, &laddr);
			nbytes += nused_at_slot;
		}
	}

	silofs_assert_eq(nbytes, nused);
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

void silofs_sni_update_nactive(struct silofs_spnode_info *sni)
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

void silofs_sni_main_lseg(const struct silofs_spnode_info *sni,
                          struct silofs_lsegid *out_lsegid)
{
	spnode_main_lsegid(sni->sn, out_lsegid);
}

void silofs_sni_bind_main_lseg(struct silofs_spnode_info *sni,
                               const struct silofs_lsegid *lsegid)
{
	spnode_set_main_lsegid(sni->sn, lsegid);
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
	struct silofs_lsegid lsegid;
	const loff_t bpos = sni_bpos_of_child(sni, voff);
	const loff_t base = sni_base_voff_of_child(sni, voff);
	enum silofs_ltype child_ltype = sni_child_ltype(sni);

	silofs_sni_main_lseg(sni, &lsegid);
	uaddr_setup(&out_ulink->uaddr, &lsegid, bpos, child_ltype, base);
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

void silofs_sni_resolve_lmap(const struct silofs_spnode_info *sni,
                             struct silofs_spmap_lmap *out_lmap)
{
	struct silofs_uaddr uaddr = { .voff = -1 };
	const struct silofs_spmap_node *sn = sni->sn;
	const struct silofs_spmap_ref *spr = NULL;

	STATICASSERT_EQ(ARRAY_SIZE(out_lmap->laddr),
	                ARRAY_SIZE(sn->sn_subrefs));

	out_lmap->cnt = 0;
	for (size_t slot = 0; slot < ARRAY_SIZE(sn->sn_subrefs); ++slot) {
		spr = spnode_subref_at(sn, slot);
		spr_uaddr(spr, &uaddr);
		lmap_append(out_lmap, &uaddr.laddr);
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
	if (uaddr_ltype(&uaddr) != SILOFS_LTYPE_SPNODE) {
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
	if (uaddr_ltype(&uaddr) != SILOFS_LTYPE_SPLEAF) {
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
	enum silofs_ltype parent_ltype;
	enum silofs_height parent_height;

	spnode_parent(sn, &parent_uaddr);
	if (uaddr_isnull(&parent_uaddr)) {
		return -SILOFS_EFSCORRUPTED;
	}
	parent_height = uaddr_height(&parent_uaddr);
	if (parent_height != (height + 1)) {
		return -SILOFS_EFSCORRUPTED;
	}
	parent_ltype = uaddr_ltype(&parent_uaddr);
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
	if (uaddr_isnull(&uaddr)) {
		return -SILOFS_EFSCORRUPTED;
	}
	ltype = uaddr_ltype(&uaddr);
	if (!ltype_isspnode(ltype)) {
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
