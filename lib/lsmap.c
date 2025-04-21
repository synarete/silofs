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
#include "infra/utility.h"
#include "addr/htox.h"
#include "addr/ltype.h"
#include "addr/laddr.h"
#include "addr/vaddr.h"
#include "private.h"
#include "lnodes.h"
#include "lsmap.h"

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

static inline void lbr_inc_refcnt(struct silofs_lbk_ref *lbr)
{
	lbr_set_refcnt(lbr, lbr_refcnt(lbr) + 1);
}

static inline void lbr_dec_refcnt(struct silofs_lbk_ref *lbr)
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

static inline bool lbr_test_allocated_other(const struct silofs_lbk_ref *lbr,
                                            size_t kbn, size_t nkb)
{
	struct silofs_lbk_state lbk_st;
	struct silofs_lbk_state bk_mask;

	lbr_allocated(lbr, &lbk_st);
	lbk_state_mask_of_other(&bk_mask, kbn, nkb);
	return lbk_state_has_mask_any(&lbk_st, &bk_mask);
}

static inline void
lbr_set_allocated_at(struct silofs_lbk_ref *lbr, size_t kbn, size_t nkb)
{
	struct silofs_lbk_state lbk_st;
	struct silofs_lbk_state bk_mask;

	lbr_allocated(lbr, &lbk_st);
	lbk_state_mask_of(&bk_mask, kbn, nkb);
	lbk_state_set_mask(&lbk_st, &bk_mask);
	lbr_set_allocated(lbr, &lbk_st);
}

static inline void
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

static inline size_t lbr_usecnt_nbytes(const struct silofs_lbk_ref *lbr)
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

static inline bool lbr_isunused(const struct silofs_lbk_ref *lbr)
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

static inline bool
lbr_test_unwritten_at(const struct silofs_lbk_ref *lbr, size_t kbn, size_t nkb)
{
	struct silofs_lbk_state lbk_st;
	struct silofs_lbk_state bk_mask;

	lbr_unwritten(lbr, &lbk_st);
	lbk_state_mask_of(&bk_mask, kbn, nkb);
	return lbk_state_has_mask(&lbk_st, &bk_mask);
}

static inline void
lbr_set_unwritten_at(struct silofs_lbk_ref *lbr, size_t kbn, size_t nkb)
{
	struct silofs_lbk_state lbk_st;
	struct silofs_lbk_state bk_mask;

	lbr_unwritten(lbr, &lbk_st);
	lbk_state_mask_of(&bk_mask, kbn, nkb);
	lbk_state_set_mask(&lbk_st, &bk_mask);
	lbr_set_unwritten(lbr, &lbk_st);
}

static inline void
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

static inline bool lbr_may_alloc(const struct silofs_lbk_ref *lbr, size_t nkb)
{
	return !lbr_isfull(lbr) && (nkb <= lbr_freecnt(lbr));
}

static inline int
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

static inline void
lbr_make_vaddrs(const struct silofs_lbk_ref *lbr, enum silofs_ltype ltype,
                loff_t voff_base, struct silofs_vaddrs *vas)
{
	struct silofs_lbk_state lbk_st;
	struct silofs_lbk_state bk_mask;
	const size_t nkb = ltype_nkbs(ltype);
	const size_t nkb_in_bk = SILOFS_NKB_IN_LBK;
	loff_t voff;

	lbr_allocated(lbr, &lbk_st);
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

static inline void lbr_clone_from(struct silofs_lbk_ref *lbr,
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

static void
lsmap_init(struct silofs_lsmap *lsm, const struct silofs_lrange *lrange)
{
	silofs_lrange128_htox(&lsm->lsm_lrange, lrange);
	lbr_init_arr(lsm->lsm_lbrs, SILOFS_ARRAY_SIZE(lsm->lsm_lbrs));
}

static void
lsmap_lrange(const struct silofs_lsmap *lsm, struct silofs_lrange *out_lrange)
{
	silofs_lrange128_xtoh(&lsm->lsm_lrange, out_lrange);
}

static struct silofs_lbk_ref *
lsmap_lbr_at(struct silofs_lsmap *lsm, size_t slot)
{
	return &lsm->lsm_lbrs[slot];
}

static const struct silofs_lbk_ref *
lsmap_lbr_at2(const struct silofs_lsmap *lsm, size_t slot)
{
	return &lsm->lsm_lbrs[slot];
}

static void lsmap_gen_keys(struct silofs_lsmap *lsm)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(lsm->lsm_lbrs); ++slot) {
		lbr_gen_key(lsmap_lbr_at(lsm, slot));
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void lrange_of(struct silofs_lrange *lrange, loff_t beg, size_t nlbk)
{
	const loff_t end = silofs_off_end(beg, nlbk * SILOFS_LBK_SIZE);

	silofs_lrange_setup(lrange, SILOFS_HEIGHT_SPLEAF, beg, end);
}

static void lsi_dirtify(struct silofs_lsmap_info *lsi)
{
	silofs_vni_dirtify(&lsi->ls_vni, NULL);
}

void silofs_lsi_get_lrange(const struct silofs_lsmap_info *lsi,
                           struct silofs_lrange *out_lrange)
{
	lsmap_lrange(lsi->lsm, out_lrange);
}

void silofs_lsi_setup_spawned(struct silofs_lsmap_info *lsi, loff_t beg)
{
	struct silofs_lrange lrange;

	lrange_of(&lrange, beg, ARRAY_SIZE(lsi->lsm->lsm_lbrs));
	lsmap_init(lsi->lsm, &lrange);
	lsmap_gen_keys(lsi->lsm);
	lsi_dirtify(lsi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int verify_lbk_ref(const struct silofs_lbk_ref *lbr)
{
	size_t val;

	val = lbr_refcnt(lbr);
	if (val >= INT_MAX) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

int silofs_verify_lsmap(const struct silofs_lsmap *lsm)
{
	const struct silofs_lbk_ref *lbr;
	int err = 0;

	for (size_t i = 0; i < ARRAY_SIZE(lsm->lsm_lbrs) && !err; ++i) {
		lbr = lsmap_lbr_at2(lsm, i);
		err = verify_lbk_ref(lbr);
	}
	return err;
}
