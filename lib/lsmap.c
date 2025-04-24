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
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <silofs/errors.h>
#include <silofs/panic.h>
#include "infra.h"
#include "addr.h"
#include "private.h"
#include "lnodes.h"
#include "lsmap.h"

static size_t nkbs_of(const struct silofs_vaddr *vaddr)
{
	return silofs_ltype_nkbs(vaddr->ltype);
}

static size_t kbn_of(const struct silofs_vaddr *vaddr)
{
	return (size_t)((vaddr->off / SILOFS_KB_SIZE) % SILOFS_NKB_IN_LBK);
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

static size_t lbm_refcnt(const struct silofs_lbk_meta *lbm)
{
	return silofs_le64_to_cpu(lbm->lbm_refcnt);
}

static void lbm_set_refcnt(struct silofs_lbk_meta *lbm, size_t n)
{
	lbm->lbm_refcnt = silofs_cpu_to_le64(n);
}

static inline void lbm_inc_refcnt(struct silofs_lbk_meta *lbm)
{
	lbm_set_refcnt(lbm, lbm_refcnt(lbm) + 1);
}

static inline void lbm_dec_refcnt(struct silofs_lbk_meta *lbm)
{
	const size_t cur = lbm_refcnt(lbm);

	silofs_expect_ge(cur, 1);

	lbm_set_refcnt(lbm, cur - 1);
}

static void lbm_allocated(const struct silofs_lbk_meta *lbm,
			  struct silofs_lbk_state *lbk_st)
{
	lbk_state_xtoh(&lbm->lbm_allocated, lbk_st);
}

static void lbm_set_allocated(struct silofs_lbk_meta *lbm,
			      const struct silofs_lbk_state *lbk_st)
{
	lbk_state_htox(&lbm->lbm_allocated, lbk_st);
}

static bool lbm_test_allocated_at(const struct silofs_lbk_meta *lbm,
				  size_t kbn, size_t nkb)
{
	struct silofs_lbk_state lbk_st;
	struct silofs_lbk_state bk_mask;

	lbm_allocated(lbm, &lbk_st);
	lbk_state_mask_of(&bk_mask, kbn, nkb);
	return lbk_state_has_mask(&lbk_st, &bk_mask);
}

static bool lbm_test_allocated_bk(const struct silofs_lbk_meta *lbm)
{
	return lbm_test_allocated_at(lbm, 0, SILOFS_NKB_IN_LBK);
}

static bool lbm_test_allocated_other(const struct silofs_lbk_meta *lbm,
				     size_t kbn, size_t nkb)
{
	struct silofs_lbk_state lbk_st;
	struct silofs_lbk_state bk_mask;

	lbm_allocated(lbm, &lbk_st);
	lbk_state_mask_of_other(&bk_mask, kbn, nkb);
	return lbk_state_has_mask_any(&lbk_st, &bk_mask);
}

static inline void
lbm_set_allocated_at(struct silofs_lbk_meta *lbm, size_t kbn, size_t nkb)
{
	struct silofs_lbk_state lbk_st;
	struct silofs_lbk_state bk_mask;

	lbm_allocated(lbm, &lbk_st);
	lbk_state_mask_of(&bk_mask, kbn, nkb);
	lbk_state_set_mask(&lbk_st, &bk_mask);
	lbm_set_allocated(lbm, &lbk_st);
}

static inline void
lbm_clear_allocated_at(struct silofs_lbk_meta *lbm, size_t kbn, size_t nkb)
{
	struct silofs_lbk_state lbk_st;
	struct silofs_lbk_state bk_mask;

	lbm_allocated(lbm, &lbk_st);
	lbk_state_mask_of(&bk_mask, kbn, nkb);
	lbk_state_unset_mask(&lbk_st, &bk_mask);
	lbm_set_allocated(lbm, &lbk_st);
}

static size_t lbm_usecnt(const struct silofs_lbk_meta *lbm)
{
	struct silofs_lbk_state lbk_st;

	lbm_allocated(lbm, &lbk_st);
	return lbk_state_popcount(&lbk_st);
}

static size_t lbm_freecnt(const struct silofs_lbk_meta *lbm)
{
	return SILOFS_NKB_IN_LBK - lbm_usecnt(lbm);
}

static bool lbm_isfull(const struct silofs_lbk_meta *lbm)
{
	return lbm_test_allocated_bk(lbm);
}

static inline bool lbm_isunused(const struct silofs_lbk_meta *lbm)
{
	struct silofs_lbk_state lbk_st;

	lbm_allocated(lbm, &lbk_st);
	return !lbk_state_has_any(&lbk_st);
}

static void lbm_unwritten(const struct silofs_lbk_meta *lbm,
			  struct silofs_lbk_state *lbk_st)
{
	lbk_state_xtoh(&lbm->lbm_unwritten, lbk_st);
}

static void lbm_set_unwritten(struct silofs_lbk_meta *lbm,
			      const struct silofs_lbk_state *lbk_st)
{
	lbk_state_htox(&lbm->lbm_unwritten, lbk_st);
}

static inline bool lbm_test_unwritten_at(const struct silofs_lbk_meta *lbm,
					 size_t kbn, size_t nkb)
{
	struct silofs_lbk_state lbk_st;
	struct silofs_lbk_state bk_mask;

	lbm_unwritten(lbm, &lbk_st);
	lbk_state_mask_of(&bk_mask, kbn, nkb);
	return lbk_state_has_mask(&lbk_st, &bk_mask);
}

static inline void
lbm_set_unwritten_at(struct silofs_lbk_meta *lbm, size_t kbn, size_t nkb)
{
	struct silofs_lbk_state lbk_st;
	struct silofs_lbk_state bk_mask;

	lbm_unwritten(lbm, &lbk_st);
	lbk_state_mask_of(&bk_mask, kbn, nkb);
	lbk_state_set_mask(&lbk_st, &bk_mask);
	lbm_set_unwritten(lbm, &lbk_st);
}

static inline void
lbm_clear_unwritten_at(struct silofs_lbk_meta *lbm, size_t kbn, size_t nkb)
{
	struct silofs_lbk_state lbk_st;
	struct silofs_lbk_state bk_mask;

	lbm_unwritten(lbm, &lbk_st);
	lbk_state_mask_of(&bk_mask, kbn, nkb);
	lbk_state_unset_mask(&lbk_st, &bk_mask);
	lbm_set_unwritten(lbm, &lbk_st);
}

static void lbm_clear_alloc_state(struct silofs_lbk_meta *lbm)
{
	struct silofs_lbk_state lbk_st;

	lbk_state_none(&lbk_st);
	lbm_set_allocated(lbm, &lbk_st);
	lbm_set_unwritten(lbm, &lbk_st);
	lbm_set_refcnt(lbm, 0);
}

static void lbm_reset(struct silofs_lbk_meta *lbm)
{
	memset(lbm, 0, sizeof(*lbm));
	lbm_clear_alloc_state(lbm);
}

static void lbm_init(struct silofs_lbk_meta *lbm)
{
	lbm_reset(lbm);
}

static void lbm_init_arr(struct silofs_lbk_meta *arr, size_t cnt)
{
	for (size_t i = 0; i < cnt; ++i) {
		lbm_init(&arr[i]);
	}
}

static bool lbm_may_alloc(const struct silofs_lbk_meta *lbm, size_t nkb)
{
	return !lbm_isfull(lbm) && (nkb <= lbm_freecnt(lbm));
}

static int
lbm_find_free(const struct silofs_lbk_meta *lbm, size_t nkb, size_t *out_kbn)
{
	struct silofs_lbk_state lbk_st;
	struct silofs_lbk_state bk_mask;
	const size_t nkb_in_bk = SILOFS_NKB_IN_LBK;

	lbm_allocated(lbm, &lbk_st);
	for (size_t kbn = 0; (kbn + nkb) <= nkb_in_bk; kbn += nkb) {
		lbk_state_mask_of(&bk_mask, kbn, nkb);
		if (lbk_state_has_mask_none(&lbk_st, &bk_mask)) {
			*out_kbn = kbn;
			return 0;
		}
	}
	return -SILOFS_ENOSPC;
}

static inline void
lbm_make_vaddrs(const struct silofs_lbk_meta *lbm, enum silofs_ltype ltype,
		loff_t voff_base, struct silofs_vaddrs *vas)
{
	struct silofs_lbk_state lbk_st;
	struct silofs_lbk_state bk_mask;
	const size_t nkb = silofs_ltype_nkbs(ltype);
	const size_t nkb_in_bk = SILOFS_NKB_IN_LBK;
	loff_t voff;

	lbm_allocated(lbm, &lbk_st);
	vas->count = 0;
	for (size_t kbn = 0; (kbn + nkb) <= nkb_in_bk; kbn += nkb) {
		lbk_state_mask_of(&bk_mask, kbn, nkb);
		if (!lbk_state_has_mask(&lbk_st, &bk_mask)) {
			continue;
		}
		voff = off_end(voff_base, kbn * SILOFS_KB_SIZE);
		silofs_vaddr_setup(&vas->vaddr[vas->count++], ltype, voff);
	}
}

static inline void lbm_clone_from(struct silofs_lbk_meta *lbm,
				  const struct silofs_lbk_meta *lbm_other)
{
	struct silofs_lbk_state lbk_st;

	lbm_allocated(lbm_other, &lbk_st);
	lbm_set_allocated(lbm, &lbk_st);

	lbm_unwritten(lbm_other, &lbk_st);
	lbm_set_unwritten(lbm, &lbk_st);

	lbm_set_refcnt(lbm, lbm_refcnt(lbm_other));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
lsmap_lrange(const struct silofs_lsmap *lsm, struct silofs_lrange *out_lrange)
{
	silofs_lrange128_xtoh(&lsm->lsm_lrange, out_lrange);
}

static void
lsmap_set_lrange(struct silofs_lsmap *lsm, const struct silofs_lrange *lrange)
{
	silofs_lrange128_htox(&lsm->lsm_lrange, lrange);
}

static enum silofs_ltype lsmap_refltype(const struct silofs_lsmap *lsm)
{
	return (enum silofs_ltype)lsm->lsm_refltype;
}

static void
lsmap_set_refltype(struct silofs_lsmap *lsm, enum silofs_ltype ltype)
{
	lsm->lsm_refltype = (uint8_t)ltype;
}

static void
lsmap_init(struct silofs_lsmap *lsm, const struct silofs_lrange *lrange,
	   enum silofs_ltype refltype)
{
	lsmap_set_lrange(lsm, lrange);
	lsmap_set_refltype(lsm, refltype);
	lbm_init_arr(lsm->lsm_lbms, ARRAY_SIZE(lsm->lsm_lbms));
}

static inline struct silofs_lbk_meta *
lsmap_lbm_at(struct silofs_lsmap *lsm, size_t slot)
{
	return &lsm->lsm_lbms[slot];
}

static const struct silofs_lbk_meta *
lsmap_lbm_at2(const struct silofs_lsmap *lsm, size_t slot)
{
	return &lsm->lsm_lbms[slot];
}

static size_t
lsmap_slot_by_lba(const struct silofs_lsmap *lsm, silofs_lba_t lba)
{
	STATICASSERT_EQ(ARRAY_SIZE(lsm->lsm_lbms), ARRAY_SIZE(lsm->lsm_keys));

	return (size_t)lba % ARRAY_SIZE(lsm->lsm_lbms);
}

static size_t lsmap_slot_by_voff(const struct silofs_lsmap *lsm, loff_t voff)
{
	return lsmap_slot_by_lba(lsm, silofs_off_to_lba(voff));
}

static const struct silofs_lbk_meta *
lsmpa_lbm_by_voff2(const struct silofs_lsmap *lsm, loff_t voff)
{
	return lsmap_lbm_at2(lsm, lsmap_slot_by_voff(lsm, voff));
}

static const struct silofs_lbk_meta *
lsmpa_lbm_by_vaddr2(const struct silofs_lsmap *lsm,
		    const struct silofs_vaddr *vaddr)
{
	return lsmpa_lbm_by_voff2(lsm, vaddr->off);
}

static inline const struct silofs_key *
lsmap_key_at(const struct silofs_lsmap *lsm, size_t slot)
{
	silofs_assert_lt(slot, ARRAY_SIZE(lsm->lsm_keys));
	return &lsm->lsm_keys[slot];
}

static void lsmap_gen_keys(struct silofs_lsmap *lsm)
{
	silofs_generate_keys(lsm->lsm_keys, ARRAY_SIZE(lsm->lsm_keys), true);
}

static size_t lsmap_calc_total_usecnt(const struct silofs_lsmap *lsm)
{
	size_t usecnt_sum = 0;

	for (size_t slot = 0; slot < ARRAY_SIZE(lsm->lsm_keys); ++slot) {
		usecnt_sum += lbm_usecnt(lsmap_lbm_at2(lsm, slot));
	}
	return usecnt_sum;
}

static bool lsmap_has_allocated_with(const struct silofs_lsmap *lsm,
				     const struct silofs_vaddr *vaddr)
{
	const struct silofs_lbk_meta *lbm = lsmpa_lbm_by_vaddr2(lsm, vaddr);

	if (silofs_vaddr_isdatabk(vaddr)) {
		return lbm_refcnt(lbm) > 0;
	}
	return lbm_test_allocated_other(lbm, kbn_of(vaddr), nkbs_of(vaddr));
}

static size_t lsmap_refltype_nkb(const struct silofs_lsmap *lsm)
{
	return silofs_ltype_nkbs(lsmap_refltype(lsm));
}

static int
lsmap_find_free_at(const struct silofs_lsmap *lsm, size_t bn, size_t *out_kbn)
{
	const size_t nkb = lsmap_refltype_nkb(lsm);
	const struct silofs_lbk_meta *lbm = lsmap_lbm_at2(lsm, bn);
	int err = -SILOFS_ENOSPC;

	if (lbm_may_alloc(lbm, nkb)) {
		err = lbm_find_free(lbm, nkb, out_kbn);
	}
	return err;
}

static int lsmap_find_free(const struct silofs_lsmap *lsm, size_t bn_beg,
			   size_t bn_end, size_t *out_bn, size_t *out_kbn)
{
	size_t kbn = 0;
	int err;

	for (size_t bn = bn_beg; bn < bn_end; ++bn) {
		err = lsmap_find_free_at(lsm, bn, &kbn);
		if (!err) {
			*out_bn = bn;
			*out_kbn = kbn;
			return 0;
		}
	}
	return -SILOFS_ENOSPC;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void lrange_of(struct silofs_lrange *lrange, loff_t beg, size_t nlbk)
{
	const loff_t end = silofs_off_end(beg, nlbk * SILOFS_LBK_SIZE);

	silofs_lrange_setup(lrange, SILOFS_HEIGHT_SPLEAF, beg, end);
}

static void lsi_dirtify(struct silofs_lsmap_info *lsi)
{
	silofs_vni_dirtify(&lsi->ls_vni, NULL);
}

static void lsi_lrange(const struct silofs_lsmap_info *lsi,
		       struct silofs_lrange *out_lrange)
{
	lsmap_lrange(lsi->lsm, out_lrange);
}

static size_t lsi_lrange_len(const struct silofs_lsmap_info *lsi)
{
	struct silofs_lrange lrange;

	lsi_lrange(lsi, &lrange);
	return silofs_lrange_len(&lrange);
}

static loff_t lsi_start_off(const struct silofs_lsmap_info *lsi)
{
	struct silofs_lrange lrange;

	lsi_lrange(lsi, &lrange);
	return lrange.beg;
}

static inline size_t
lsi_off_to_bn(const struct silofs_lsmap_info *lsi, loff_t off)
{
	const loff_t beg = lsi_start_off(lsi);

	return (size_t)silofs_off_to_lba(off - beg);
}

void silofs_lsi_get_lrange(const struct silofs_lsmap_info *lsi,
			   struct silofs_lrange *out_lrange)
{
	lsi_lrange(lsi, out_lrange);
}

void silofs_lsi_setup_spawned(struct silofs_lsmap_info *lsi,
			      enum silofs_ltype refltype, loff_t beg)
{
	struct silofs_lrange lrange;

	lrange_of(&lrange, beg, ARRAY_SIZE(lsi->lsm->lsm_lbms));
	lsmap_init(lsi->lsm, &lrange, refltype);
	lsmap_gen_keys(lsi->lsm);
	lsi_dirtify(lsi);
}

void silofs_lsi_update_nused(struct silofs_lsmap_info *lsi)
{
	const size_t usecnt = lsmap_calc_total_usecnt(lsi->lsm);

	lsi->ls_nused_bytes = usecnt * SILOFS_KB_SIZE;
	silofs_assert_le(lsi->ls_nused_bytes, SILOFS_LSEG_SIZE_MAX);
}

static bool lsi_is_subref(const struct silofs_lsmap_info *lsi,
			  const struct silofs_vaddr *vaddr)
{
	struct silofs_lrange lrange;

	if (vaddr->ltype != lsmap_refltype(lsi->lsm)) {
		return false;
	}
	lsmap_lrange(lsi->lsm, &lrange);
	if (!silofs_lrange_within(&lrange, vaddr->off)) {
		return false;
	}
	return true;
}

bool silofs_lsi_has_allocated_with(const struct silofs_lsmap_info *lsi,
				   const struct silofs_vaddr *vaddr)
{
	bool ret = false;

	if (lsi_is_subref(lsi, vaddr)) {
		ret = lsmap_has_allocated_with(lsi->lsm, vaddr);
	}
	return ret;
}

static enum silofs_ltype lsi_refltype(const struct silofs_lsmap_info *lsi)
{
	return lsmap_refltype(lsi->lsm);
}

static size_t lsi_refltype_size(const struct silofs_lsmap_info *lsi)
{
	return silofs_ltype_size(lsi_refltype(lsi));
}

static void lsi_vaddr_at(const struct silofs_lsmap_info *lsi, size_t bn,
			 size_t kbn, struct silofs_vaddr *out_vaddr)
{
	const loff_t beg = lsi_start_off(lsi);

	silofs_vaddr_by_spleaf(out_vaddr, lsi_refltype(lsi), beg, bn, kbn);
}

static size_t lsi_start_bn(const struct silofs_lsmap_info *lsi)
{
	struct silofs_lrange lrange;
	loff_t off_beg = lsi->ls_off_hint;

	lsi_lrange(lsi, &lrange);
	if (!silofs_lrange_within(&lrange, off_beg)) {
		off_beg = lrange.beg;
	}
	return lsi_off_to_bn(lsi, off_beg);
}

static size_t lsi_finish_bn(const struct silofs_lsmap_info *lsi)
{
	struct silofs_lrange lrange;

	lsi_lrange(lsi, &lrange);
	return lsi_off_to_bn(lsi, lrange.end);
}

static int lsi_find_free_space(const struct silofs_lsmap_info *lsi,
			       struct silofs_vaddr *out_vaddr)
{
	size_t bn_beg = lsi_start_bn(lsi);
	size_t bn_end = lsi_finish_bn(lsi);
	size_t bn = 0;
	size_t kbn = 0;
	int err;

	/* fast search based on cached last-allocated hint */
	err = lsmap_find_free(lsi->lsm, bn_beg, bn_end, &bn, &kbn);
	if (!err) {
		goto out_ok;
	}
	if (bn_beg == 0) {
		goto out_err;
	}
	/* slow search on unchecked slots */
	err = lsmap_find_free(lsi->lsm, 0, bn_beg, &bn, &kbn);
	if (err) {
		goto out_err;
	}
out_ok:
	lsi_vaddr_at(lsi, bn, kbn, out_vaddr);
	return 0;
out_err:
	return err;
}

static bool lsi_cap_allocate(const struct silofs_lsmap_info *lsi)
{
	const size_t nlimit = lsi_lrange_len(lsi);
	const size_t nbytes_want = lsi_refltype_size(lsi);
	const size_t nbytes_used = lsi->ls_nused_bytes;

	silofs_assert_le(nlimit, SILOFS_LSEG_SIZE_MAX);
	silofs_assert_le(nbytes_used, SILOFS_LSEG_SIZE_MAX);

	return ((nbytes_used + nbytes_want) <= nlimit);
}

int silofs_lsi_find_free_space(const struct silofs_lsmap_info *lsi,
			       struct silofs_vaddr *out_vaddr)
{
	int ret = -SILOFS_ENOSPC;

	if (lsi_cap_allocate(lsi)) {
		ret = lsi_find_free_space(lsi, out_vaddr);
	}
	return ret;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int verify_lsmap_lrange(const struct silofs_lsmap *lsm)
{
	struct silofs_lrange lrange;
	size_t len;

	lsmap_lrange(lsm, &lrange);
	if (!silofs_lrange_isvalid(&lrange)) {
		return -SILOFS_EFSCORRUPTED;
	}
	len = silofs_lrange_len(&lrange);
	if (len != SILOFS_LSEG_SIZE_MAX) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int verify_lsmap_refltype(const struct silofs_lsmap *lsm)
{
	const enum silofs_ltype ltype = lsmap_refltype(lsm);

	return silofs_ltype_isvnode(ltype) ? 0 : -SILOFS_EFSCORRUPTED;
}

static int verify_lbk_meta(const struct silofs_lbk_meta *lbm)
{
	size_t val;

	val = lbm_refcnt(lbm);
	if (val >= INT_MAX) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

int silofs_verify_lsmap(const struct silofs_lsmap *lsm)
{
	const struct silofs_lbk_meta *lbm;
	int err = 0;

	err = verify_lsmap_lrange(lsm);
	if (err) {
		return err;
	}
	err = verify_lsmap_refltype(lsm);
	if (err) {
		return err;
	}
	for (size_t i = 0; i < ARRAY_SIZE(lsm->lsm_lbms); ++i) {
		lbm = lsmap_lbm_at2(lsm, i);
		err = verify_lbk_meta(lbm);
		if (err) {
			return err;
		}
	}
	return 0;
}
