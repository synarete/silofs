/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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
#include <silofs/fs/types.h>
#include <silofs/fs/address.h>
#include <silofs/fs/nodes.h>
#include <silofs/fs/cache.h>
#include <silofs/fs/spmaps.h>
#include <silofs/fs/private.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t nkb_of(const struct silofs_vaddr *vaddr)
{
	return stype_nkbs(vaddr_stype(vaddr));
}

static size_t kbn_of(const struct silofs_vaddr *vaddr)
{
	const loff_t kb_size = SILOFS_KB_SIZE;
	const loff_t nkb_in_bk = SILOFS_NKB_IN_BK;
	const loff_t off = vaddr_off(vaddr);

	return (size_t)((off / kb_size) % nkb_in_bk);
}

static ssize_t sum_vspace_used_bytes(const struct silofs_space_stat *sp_st)
{
	return sp_st->vspace_ndata + sp_st->vspace_nmeta;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static enum silofs_spmapf spr_flags(const struct silofs_spmap_ref *spr)
{
	const uint32_t f = silofs_le32_to_cpu(spr->sr_flags);

	return (enum silofs_spmapf)f;
}

static void spr_set_flags(struct silofs_spmap_ref *spr, enum silofs_spmapf f)
{
	spr->sr_flags = silofs_cpu_to_le32((uint32_t)f);
}

static void spr_add_flags(struct silofs_spmap_ref *spr, enum silofs_spmapf f)
{
	spr_set_flags(spr, f | spr_flags(spr));
}

static bool spr_has_flags(const struct silofs_spmap_ref *spr,
                          enum silofs_spmapf f)
{
	return ((spr_flags(spr) & f) > 0);
}

static bool spr_isactive(const struct silofs_spmap_ref *spr)
{
	return spr_has_flags(spr, SILOFS_SPMAPF_ACTIVE);
}

static void spr_reset_flags(struct silofs_spmap_ref *spr)
{
	spr_set_flags(spr, SILOFS_SPMAPF_NONE);
}

static enum silofs_stype spr_stype_sub(const struct silofs_spmap_ref *spr)
{
	return spr->sr_stype_sub;
}

static void spr_set_stype_sub(struct silofs_spmap_ref *spr,
                              enum silofs_stype stype_sub)
{
	spr->sr_stype_sub = (uint8_t)stype_sub;
}

static bool spr_has_stype_sub(const struct silofs_spmap_ref *spr,
                              enum silofs_stype stype_sub)
{
	return stype_isequal(spr_stype_sub(spr), stype_sub);
}

void silofs_spr_ulink(const struct silofs_spmap_ref *spr,
                      struct silofs_ulink *out_ulink)
{
	if (spr_isactive(spr)) {
		silofs_ulink128b_parse(&spr->sr_ulink, out_ulink);
	} else {
		silofs_ulink_reset(out_ulink);
	}
}

void silofs_spr_set_ulink(struct silofs_spmap_ref *spr,
                          const struct silofs_ulink *ulink,
                          enum silofs_stype stype_sub)
{
	silofs_ulink128b_set(&spr->sr_ulink, ulink);
	spr_set_stype_sub(spr, stype_sub);
	spr_add_flags(spr, SILOFS_SPMAPF_ACTIVE);
}

static void spr_reset(struct silofs_spmap_ref *spr)
{
	silofs_ulink128b_reset(&spr->sr_ulink);
	spr_set_stype_sub(spr, SILOFS_STYPE_NONE);
	spr_reset_flags(spr);
}

static void spr_init(struct silofs_spmap_ref *spr)
{
	spr_reset(spr);
	memset(spr->sr_reserved, 0, sizeof(spr->sr_reserved));
}

void silofs_spr_initn(struct silofs_spmap_ref *spr, size_t n)
{
	for (size_t i = 0; i < n; ++i) {
		spr_init(&spr[i]);
	}
}

static bool spr_may_alloc_stype(const struct silofs_spmap_ref *spr,
                                enum silofs_stype stype)
{
	return spr_has_stype_sub(spr, stype) && spr_isactive(spr);
}

static void spr_clone_from(struct silofs_spmap_ref *spr,
                           const struct silofs_spmap_ref *spr_other)
{
	struct silofs_ulink ulink;

	silofs_spr_ulink(spr_other, &ulink);
	silofs_spr_set_ulink(spr, &ulink, spr_stype_sub(spr_other));
	spr_set_flags(spr, spr_flags(spr_other));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t spnode_heigth(const struct silofs_spmap_node *sn)
{
	return sn->sn_height;
}

static void spnode_set_heigth(struct silofs_spmap_node *sn, size_t height)
{
	silofs_assert_ge(height, 2);
	silofs_assert_le(height, 5);

	sn->sn_height = (uint8_t)height;
}

static void spnode_vrange(const struct silofs_spmap_node *sn,
                          struct silofs_vrange *out_vrange)
{
	silofs_vrange128_parse(&sn->sn_vrange, out_vrange);
}

static void spnode_set_vrange(struct silofs_spmap_node *sn,
                              const struct silofs_vrange *vrange)
{
	silofs_vrange128_set(&sn->sn_vrange, vrange);
}

static void spnode_main_blobid(const struct silofs_spmap_node *sn,
                               struct silofs_blobid *out_bid)
{
	silofs_blobid40b_parse(&sn->sn_main_blobid, out_bid);
}

static void spnode_set_main_blobid(struct silofs_spmap_node *sn,
                                   const struct silofs_blobid *bid)
{
	silofs_blobid40b_set(&sn->sn_main_blobid, bid);
}

static void spnode_init(struct silofs_spmap_node *sn, size_t height,
                        const struct silofs_vrange *vrange)
{
	spnode_set_vrange(sn, vrange);
	spnode_set_heigth(sn, height);
	silofs_blobid40b_reset(&sn->sn_main_blobid);
	silofs_uaddr64b_reset(&sn->sn_parent);
	silofs_spr_initn(sn->sn_subref, ARRAY_SIZE(sn->sn_subref));
}

static ssize_t spnode_span(const struct silofs_spmap_node *sn)
{
	struct silofs_vrange vrange;

	spnode_vrange(sn, &vrange);
	return off_len(vrange.beg, vrange.end);
}

static loff_t spnode_beg(const struct silofs_spmap_node *sn)
{
	struct silofs_vrange vrange;

	spnode_vrange(sn, &vrange);
	return vrange.beg;
}

static size_t spnode_slot_of(const struct silofs_spmap_node *sn, loff_t voff)
{
	size_t slot;
	loff_t beg;
	ssize_t roff;
	const loff_t span = spnode_span(sn);
	const size_t nslots = ARRAY_SIZE(sn->sn_subref);

	beg = spnode_beg(sn);
	silofs_assert_le(beg, voff);
	roff = off_diff(beg, voff);
	slot = (size_t)((roff * (long)nslots) / span);
	return slot;
}

static void spnode_parent(const struct silofs_spmap_node *sn,
                          struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr64b_parse(&sn->sn_parent, out_uaddr);
}

static void spnode_set_parent(struct silofs_spmap_node *sn,
                              const struct silofs_uaddr *uaddr)
{
	silofs_uaddr64b_set(&sn->sn_parent, uaddr);
}

static struct silofs_spmap_ref *
spnode_subref_at(const struct silofs_spmap_node *sn, size_t slot)
{
	const struct silofs_spmap_ref *spr = &sn->sn_subref[slot];

	return unconst(spr);
}

static struct silofs_spmap_ref *
spnode_child_ref_of(const struct silofs_spmap_node *sn, loff_t voff)
{
	return spnode_subref_at(sn, spnode_slot_of(sn, voff));
}

static void spnode_child_of(const struct silofs_spmap_node *sn, loff_t voff,
                            struct silofs_ulink *out_ulink)
{
	const struct silofs_spmap_ref *spr = spnode_child_ref_of(sn, voff);

	silofs_spr_ulink(spr, out_ulink);
}

static void spnode_set_ulink_of(struct silofs_spmap_node *sn, loff_t voff,
                                const struct silofs_ulink *ulink,
                                enum silofs_stype stype_sub)
{
	struct silofs_spmap_ref *spr = spnode_child_ref_of(sn, voff);

	silofs_spr_set_ulink(spr, ulink, stype_sub);
}

static bool spnode_has_subref(const struct silofs_spmap_node *sn, loff_t voff)
{
	const struct silofs_spmap_ref *spr = spnode_child_ref_of(sn, voff);

	return spr_has_flags(spr, SILOFS_SPMAPF_ACTIVE);
}

static bool spnode_find_avail_spleaf(const struct silofs_spmap_node *sn,
                                     const struct silofs_vrange *range,
                                     enum silofs_stype stype, loff_t *out_voff)
{
	loff_t voff;
	const struct silofs_spmap_ref *spr = NULL;
	bool ret = false;

	voff = range->beg;
	while (voff < range->end) {
		spr = spnode_child_ref_of(sn, voff);
		if (!spr_isactive(spr)) {
			break;
		}
		if (spr_may_alloc_stype(spr, stype)) {
			ret = true;
			break;
		}
		voff = silofs_off_to_vsec_next(voff, 1);
	}
	*out_voff = voff;
	return ret;
}

static size_t spnode_count_nform(const struct silofs_spmap_node *sn)
{
	size_t count = 0;
	const struct silofs_spmap_ref *spr = NULL;
	const size_t nslots_max = ARRAY_SIZE(sn->sn_subref);

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
	const size_t nslots_max = ARRAY_SIZE(sn->sn_subref);

	for (size_t slot = 0; slot < nslots_max; ++slot) {
		spr = spnode_subref_at(sn, slot);
		spr_other = spnode_subref_at(sn_other, slot);
		spr_clone_from(spr, spr_other);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint64_t mask_of(size_t kbn, size_t nkb)
{
	uint64_t mask;
	const size_t nkb_in_bk = SILOFS_NKB_IN_BK;

	silofs_assert_lt(kbn, nkb_in_bk);
	silofs_assert_le(nkb, nkb_in_bk);
	silofs_assert_le(kbn + nkb, nkb_in_bk);

	mask = (nkb < nkb_in_bk) ? (((1UL << nkb) - 1UL) << kbn) : ~0UL;
	silofs_assert_ne(mask, 0);

	return mask;
}

static void bkr_set_flags(struct silofs_bk_ref *bkr, enum silofs_spmapf f)
{
	bkr->br_flags = silofs_cpu_to_le32((uint32_t)f);
}

static void bkr_ulink(const struct silofs_bk_ref *bkr,
                      struct silofs_ulink *out_ulink)
{
	silofs_ulink128b_parse(&bkr->br_ulink, out_ulink);
}

static void bkr_set_ulink(struct silofs_bk_ref *bkr,
                          const struct silofs_ulink *ulink)
{
	silofs_ulink128b_set(&bkr->br_ulink, ulink);
}

static size_t bkr_refcnt(const struct silofs_bk_ref *bkr)
{
	return silofs_le64_to_cpu(bkr->br_refcnt);
}

static void bkr_set_refcnt(struct silofs_bk_ref *bkr, size_t refcnt)
{
	silofs_assert_le(refcnt, SILOFS_NKB_IN_BK);

	bkr->br_refcnt = silofs_cpu_to_le64(refcnt);
}

static void bkr_inc_refcnt(struct silofs_bk_ref *bkr, size_t n)
{
	bkr_set_refcnt(bkr, bkr_refcnt(bkr) + n);
}

static void bkr_dec_refcnt(struct silofs_bk_ref *bkr, size_t n)
{
	silofs_assert_ge(bkr_refcnt(bkr), n);

	bkr_set_refcnt(bkr, bkr_refcnt(bkr) - n);
}

static uint64_t bkr_allocated(const struct silofs_bk_ref *bkr)
{
	return silofs_le64_to_cpu(bkr->br_allocated);
}

static void bkr_set_allocated(struct silofs_bk_ref *bkr, uint64_t allocated)
{
	bkr->br_allocated = silofs_cpu_to_le64(allocated);
}

static bool bkr_test_allocated_at(const struct silofs_bk_ref *bkr,
                                  size_t kbn, size_t nkb)
{
	const uint64_t mask = mask_of(kbn, nkb);

	return ((bkr_allocated(bkr) & mask) == mask);
}

static bool bkr_test_allocated_bk(const struct silofs_bk_ref *bkr)
{
	return bkr_test_allocated_at(bkr, 0, SILOFS_NKB_IN_BK);
}

static void bkr_set_allocated_at(struct silofs_bk_ref *bkr,
                                 size_t kbn, size_t nkb)
{
	const uint64_t mask = mask_of(kbn, nkb);
	const uint64_t allocated = bkr_allocated(bkr);

	silofs_assert_eq(allocated & mask, 0);
	bkr_set_allocated(bkr, allocated | mask);
	silofs_assert_ne(bkr_allocated(bkr), 0);
}

static void bkr_clear_allocated_at(struct silofs_bk_ref *bkr,
                                   size_t kbn, size_t nkb)
{
	const uint64_t mask = mask_of(kbn, nkb);
	const uint64_t allocated = bkr_allocated(bkr);

	silofs_assert_eq(allocated & mask, mask);
	bkr_set_allocated(bkr, allocated & ~mask);
}

static size_t bkr_usecnt(const struct silofs_bk_ref *bkr)
{
	const uint64_t allocated = bkr_allocated(bkr);

	return silofs_popcount64(allocated);
}

static size_t bkr_freecnt(const struct silofs_bk_ref *bkr)
{
	return SILOFS_NKB_IN_BK - bkr_usecnt(bkr);
}

static bool bkr_isfull(const struct silofs_bk_ref *bkr)
{
	return bkr_test_allocated_bk(bkr);
}

static bool bkr_isunused(const struct silofs_bk_ref *bkr)
{
	return (bkr_usecnt(bkr) == 0);
}

static uint64_t bkr_unwritten(const struct silofs_bk_ref *bkr)
{
	return silofs_le64_to_cpu(bkr->br_unwritten);
}

static void bkr_set_unwritten(struct silofs_bk_ref *bkr, uint64_t unwritten)
{
	bkr->br_unwritten = silofs_cpu_to_le64(unwritten);
}

static bool bkr_test_unwritten_at(const struct silofs_bk_ref *bkr,
                                  size_t kbn, size_t nkb)
{
	const uint64_t mask = mask_of(kbn, nkb);
	const uint64_t unwritten = bkr_unwritten(bkr);

	silofs_assert(((unwritten & mask) == mask) ||
	              ((unwritten & mask) == 0));

	return (unwritten & mask) == mask;
}

static void bkr_set_unwritten_at(struct silofs_bk_ref *bkr,
                                 size_t kbn, size_t nkb)
{
	const uint64_t mask = mask_of(kbn, nkb);
	const uint64_t unwritten = bkr_unwritten(bkr);

	silofs_assert(!bkr_test_unwritten_at(bkr, kbn, nkb));

	bkr_set_unwritten(bkr, unwritten | mask);
}

static void bkr_clear_unwritten_at(struct silofs_bk_ref *bkr,
                                   size_t kbn, size_t nkb)
{
	const uint64_t mask = mask_of(kbn, nkb);
	const uint64_t unwritten = bkr_unwritten(bkr);

	silofs_assert(bkr_test_unwritten_at(bkr, kbn, nkb));

	bkr_set_unwritten(bkr, unwritten & ~mask);
}

static void bkr_set_offset(struct silofs_bk_ref *bkr, loff_t off)
{
	bkr->br_off = silofs_cpu_to_off(off);
}

static void bkr_clear_alloc_state(struct silofs_bk_ref *bkr)
{
	bkr_set_refcnt(bkr, 0);
	bkr_set_allocated(bkr, 0);
	bkr_set_unwritten(bkr, 0);
}

static void bkr_reset(struct silofs_bk_ref *bkr)
{
	bkr_clear_alloc_state(bkr);
	silofs_ulink128b_reset(&bkr->br_ulink);
	bkr_set_flags(bkr, SILOFS_SPMAPF_NONE);
}

static void bkr_init(struct silofs_bk_ref *bkr, loff_t off)
{
	bkr_reset(bkr);
	bkr_set_offset(bkr, off);
}

static void bkr_init_arr(struct silofs_bk_ref *arr,
                         size_t cnt, loff_t base_off)
{
	const ssize_t bk_size = SILOFS_BK_SIZE;

	for (int i = 0; i < (int)cnt; ++i) {
		bkr_init(&arr[i], base_off + (i * bk_size));
	}
}

static bool bkr_may_alloc(const struct silofs_bk_ref *bkr, size_t nkb)
{
	return !bkr_isfull(bkr) && (nkb <= bkr_freecnt(bkr));
}

static int bkr_find_free(const struct silofs_bk_ref *bkr,
                         size_t nkb, size_t *out_kbn)
{
	uint64_t mask;
	const size_t nkb_in_bk = SILOFS_NKB_IN_BK;
	const uint64_t allocated = bkr_allocated(bkr);

	for (size_t kbn = 0; (kbn + nkb) <= nkb_in_bk; kbn += nkb) {
		mask = mask_of(kbn, nkb);
		if ((allocated & mask) == 0) {
			*out_kbn = kbn;
			return 0;
		}
	}
	return -ENOSPC;
}

static void bkr_accum_space_stat(const struct silofs_bk_ref *bkr,
                                 enum silofs_stype stype_sub,
                                 struct silofs_space_stat *sp_st)
{
	const bool isdata = stype_isdata(stype_sub);
	const bool isinode = stype_isinode(stype_sub);
	const ssize_t kb_size = (ssize_t)(SILOFS_KB_SIZE);
	const ssize_t usecnt = (ssize_t)bkr_usecnt(bkr);

	if (isdata) {
		sp_st->vspace_ndata += (usecnt * kb_size);
	} else {
		sp_st->vspace_nmeta += (usecnt * kb_size);
		if (isinode) {
			sp_st->vspace_nfiles += usecnt;
		}
	}
}

static void bkr_clone_from(struct silofs_bk_ref *bkr,
                           const struct silofs_bk_ref *bkr_other)
{
	struct silofs_ulink ulink;

	bkr_ulink(bkr_other, &ulink);
	bkr_set_ulink(bkr, &ulink);
	bkr_set_allocated(bkr, bkr_allocated(bkr_other));
	bkr_set_unwritten(bkr, bkr_unwritten(bkr_other));
	bkr_set_refcnt(bkr, bkr_refcnt(bkr_other));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static enum silofs_stype spleaf_stype_sub(const struct silofs_spmap_leaf *sl)
{
	return (enum silofs_stype)(sl->sl_stype_sub);
}

static void spleaf_set_stype_sub(struct silofs_spmap_leaf *sl,
                                 enum silofs_stype stype)
{
	sl->sl_stype_sub = (uint8_t)stype;
}

static void spleaf_init(struct silofs_spmap_leaf *sl,
                        const struct silofs_vrange *vrange,
                        enum silofs_stype stype_sub)
{
	silofs_vrange128_set(&sl->sl_vrange, vrange);
	spleaf_set_stype_sub(sl, stype_sub);
	silofs_blobid40b_reset(&sl->sl_main_blobid);
	silofs_uaddr64b_reset(&sl->sl_parent);
	bkr_init_arr(sl->sl_subref, ARRAY_SIZE(sl->sl_subref), vrange->beg);
}

static void spleaf_parent(const struct silofs_spmap_leaf *sl,
                          struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr64b_parse(&sl->sl_parent, out_uaddr);
}

static void spleaf_set_parent(struct silofs_spmap_leaf *sl,
                              const struct silofs_uaddr *uaddr)
{
	silofs_uaddr64b_set(&sl->sl_parent, uaddr);
}

static void spleaf_vrange(const struct silofs_spmap_leaf *sl,
                          struct silofs_vrange *vrange)
{
	silofs_vrange128_parse(&sl->sl_vrange, vrange);
}

static loff_t spleaf_voff_base(const struct silofs_spmap_leaf *sl)
{
	struct silofs_vrange vrange;

	spleaf_vrange(sl, &vrange);
	return vrange.beg;
}

static struct silofs_bk_ref *
spleaf_subref_at(const struct silofs_spmap_leaf *sl, size_t slot)
{
	const struct silofs_bk_ref *bkr = &(sl->sl_subref[slot]);

	return unconst(bkr);
}

static size_t spleaf_nsubrefs_max(const struct silofs_spmap_leaf *sl)
{
	return ARRAY_SIZE(sl->sl_subref);
}

static size_t spleaf_lba_slot(const struct silofs_spmap_leaf *sl,
                              silofs_lba_t lba)
{
	return (size_t)lba % spleaf_nsubrefs_max(sl);
}

static struct silofs_bk_ref *
spleaf_bkr_by_lba(const struct silofs_spmap_leaf *sl, silofs_lba_t lba)
{
	return spleaf_subref_at(sl, spleaf_lba_slot(sl, lba));
}

static struct silofs_bk_ref *
spleaf_bkr_by_voff(const struct silofs_spmap_leaf *sl, loff_t voff)
{
	return spleaf_bkr_by_lba(sl, off_to_lba(voff));
}

static struct silofs_bk_ref *
spleaf_bkr_by_vaddr(const struct silofs_spmap_leaf *sl,
                    const struct silofs_vaddr *vaddr)
{
	return spleaf_bkr_by_voff(sl, vaddr->voff);
}

static bool spleaf_is_allocated_at(const struct silofs_spmap_leaf *sl,
                                   const struct silofs_vaddr *vaddr)
{
	const size_t kbn = kbn_of(vaddr);
	const size_t nkb = nkb_of(vaddr);
	const struct silofs_bk_ref *bkr;

	bkr = spleaf_bkr_by_vaddr(sl, vaddr);
	return bkr_test_allocated_at(bkr, kbn, nkb);
}

static bool spleaf_test_unwritten_at(const struct silofs_spmap_leaf *sl,
                                     const struct silofs_vaddr *vaddr)
{
	const struct silofs_bk_ref *bkr = spleaf_bkr_by_vaddr(sl, vaddr);

	return bkr_test_unwritten_at(bkr, kbn_of(vaddr), nkb_of(vaddr));
}

static void spleaf_set_unwritten_at(struct silofs_spmap_leaf *sl,
                                    const struct silofs_vaddr *vaddr)
{
	struct silofs_bk_ref *bkr = spleaf_bkr_by_vaddr(sl, vaddr);

	bkr_set_unwritten_at(bkr, kbn_of(vaddr), nkb_of(vaddr));
}

static void spleaf_clear_unwritten_at(struct silofs_spmap_leaf *sl,
                                      const struct silofs_vaddr *vaddr)
{
	struct silofs_bk_ref *bkr = spleaf_bkr_by_vaddr(sl, vaddr);

	bkr_clear_unwritten_at(bkr, kbn_of(vaddr), nkb_of(vaddr));
}

static size_t spleaf_refcnt_at(const struct silofs_spmap_leaf *sl, loff_t voff)
{
	const struct silofs_bk_ref *bkr = spleaf_bkr_by_voff(sl, voff);

	return bkr_refcnt(bkr);
}

static bool spleaf_has_allocated_at(const struct silofs_spmap_leaf *sl,
                                    const struct silofs_vaddr *vaddr)
{
	const struct silofs_bk_ref *bkr = spleaf_bkr_by_vaddr(sl, vaddr);

	return (bkr_allocated(bkr) > 0);
}

static void spleaf_set_allocated_at(struct silofs_spmap_leaf *sl,
                                    const struct silofs_vaddr *vaddr)
{
	const size_t kbn = kbn_of(vaddr);
	const size_t nkb = nkb_of(vaddr);
	struct silofs_bk_ref *bkr = spleaf_bkr_by_vaddr(sl, vaddr);

	bkr_inc_refcnt(bkr, nkb);
	bkr_set_allocated_at(bkr, kbn, nkb);
}

static void spleaf_clear_allocated_at(struct silofs_spmap_leaf *sl,
                                      const struct silofs_vaddr *vaddr)
{
	const size_t kbn = kbn_of(vaddr);
	const size_t nkb = nkb_of(vaddr);
	const size_t nkb_in_bk = SILOFS_NKB_IN_BK;
	struct silofs_bk_ref *bkr = spleaf_bkr_by_vaddr(sl, vaddr);

	bkr_dec_refcnt(bkr, nkb);
	if (!bkr_refcnt(bkr) || (nkb < nkb_in_bk)) {
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
	int err = -ENOSPC;

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
	int err = -ENOSPC;

	for (size_t bn = bn_beg; bn < bn_end; ++ bn) {
		err = spleaf_find_nfree_at(sl, stype, bn, &kbn);
		if (!err) {
			*out_bn = bn;
			*out_kbn = kbn;
			break;
		}
	}
	return err;
}

static void spleaf_main_blobid(const struct silofs_spmap_leaf *sl,
                               struct silofs_blobid *out_bid)
{
	silofs_blobid40b_parse(&sl->sl_main_blobid, out_bid);
}

static void spleaf_set_main_blobid(struct silofs_spmap_leaf *sl,
                                   const struct silofs_blobid *bid)
{
	silofs_blobid40b_set(&sl->sl_main_blobid, bid);
}

static void spleaf_make_ulink_at(struct silofs_spmap_leaf *sl, size_t slot,
                                 const struct silofs_uaddr *owner,
                                 struct silofs_ulink *out_ulink)
{
	struct silofs_blobid bid;
	struct silofs_uaddr child;
	const enum silofs_stype stype = spleaf_stype_sub(sl);
	const size_t bk_size = SILOFS_BK_SIZE;
	const loff_t bpos = (loff_t)(slot * bk_size);
	const loff_t voff = spleaf_voff_base(sl) + bpos;

	spleaf_main_blobid(sl, &bid);
	silofs_uaddr_setup(&child, &bid, stype, bpos, voff);
	silofs_ulink_setup(out_ulink, owner, &child);
}

static void spleaf_bind_bks_to_main(struct silofs_spmap_leaf *sl,
                                    const struct silofs_uaddr *owner)
{
	struct silofs_ulink ulink;
	struct silofs_bk_ref *bkr = NULL;
	const size_t nslots = spleaf_nsubrefs_max(sl);

	for (size_t slot = 0; slot < nslots; ++slot) {
		spleaf_make_ulink_at(sl, slot, owner, &ulink);

		bkr = spleaf_subref_at(sl, slot);
		bkr_set_ulink(bkr, &ulink);
	}
}

static void spleaf_calc_space_stat(const struct silofs_spmap_leaf *sl,
                                   struct silofs_space_stat *sp_st)
{
	const struct silofs_bk_ref *bkr;
	const size_t nslots = spleaf_nsubrefs_max(sl);
	const enum silofs_stype stype_sub = spleaf_stype_sub(sl);

	silofs_memzero(sp_st, sizeof(*sp_st));
	for (size_t slot = 0; slot < nslots; ++slot) {
		bkr = spleaf_subref_at(sl, slot);
		if (bkr_refcnt(bkr)) {
			bkr_accum_space_stat(bkr, stype_sub, sp_st);
		}
	}
}

static size_t spleaf_sum_nbytes_used(const struct silofs_spmap_leaf *sl)
{
	struct silofs_space_stat sp_st = { .uspace_nmeta = 0 };

	spleaf_calc_space_stat(sl, &sp_st);
	return (size_t)sum_vspace_used_bytes(&sp_st);
}

static void spleaf_clone_childs(struct silofs_spmap_leaf *sl,
                                const struct silofs_spmap_leaf *sl_other)
{
	struct silofs_bk_ref *bkr;
	const struct silofs_bk_ref *bkr_other;
	const size_t nslots = spleaf_nsubrefs_max(sl);

	for (size_t slot = 0; slot < nslots; ++slot) {
		bkr = spleaf_subref_at(sl, slot);
		bkr_other = spleaf_subref_at(sl_other, slot);
		bkr_clone_from(bkr, bkr_other);
	}
}

static void spleaf_resolve_child(struct silofs_spmap_leaf *sl, loff_t voff,
                                 struct silofs_uaddr *out_uaddr)
{
	struct silofs_ulink ulink;
	const struct silofs_bk_ref *bkr;

	bkr = spleaf_bkr_by_voff(sl, voff);
	bkr_ulink(bkr, &ulink);
	uaddr_assign(out_uaddr, &ulink.child);
}

static void spleaf_resolve_main_at(struct silofs_spmap_leaf *sl, loff_t voff,
                                   struct silofs_uaddr *out_uaddr)
{
	struct silofs_blobid bid;
	const loff_t bk_voff = off_align_to_bk(voff);
	const enum silofs_stype stype = SILOFS_STYPE_ANONBK;

	spleaf_main_blobid(sl, &bid);
	silofs_uaddr_setup_by2(out_uaddr, &bid, bk_voff, stype);
}

static void spleaf_rebind_child(struct silofs_spmap_leaf *sl, loff_t voff,
                                const struct silofs_ulink *ulink)
{
	struct silofs_bk_ref *bkr;

	bkr = spleaf_bkr_by_voff(sl, voff);
	bkr_set_ulink(bkr, ulink);
}


/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_unode_info *sli_ui(struct silofs_spleaf_info *sli)
{
	silofs_assert_not_null(sli);

	return &sli->sl_ui;
}

const struct silofs_uaddr *
silofs_sli_uaddr(const struct silofs_spleaf_info *sli)
{
	return &sli->sl_ui.u_uaddr;
}

void silofs_sli_incref(struct silofs_spleaf_info *sli)
{
	ui_incref(sli_ui(sli));
}

void silofs_sli_decref(struct silofs_spleaf_info *sli)
{
	ui_decref(sli_ui(sli));
}

static void sli_dirtify(struct silofs_spleaf_info *sli)
{
	ui_dirtify(sli_ui(sli));
}

void silofs_sli_setup_spawned(struct silofs_spleaf_info *sli,
                              const struct silofs_vrange *vrange,
                              enum silofs_stype stype_sub)
{
	spleaf_init(sli->sl, vrange, stype_sub);
	sli->sl_voff_last = vrange->beg;
	sli_dirtify(sli);
}

void silofs_sli_setup_parent(struct silofs_spleaf_info *sli,
                             const struct silofs_spnode_info *sni)
{
	spleaf_set_parent(sli->sl, sni_uaddr(sni));
	sli_dirtify(sli);
}

static void sli_formatted_vrange(const struct silofs_spleaf_info *sli,
                                 struct silofs_vrange *out_vrange)
{
	spleaf_vrange(sli->sl, out_vrange);
}

void silofs_sli_update_voff_last(struct silofs_spleaf_info *sli, loff_t voff)
{
	struct silofs_vrange vrange;

	sli_formatted_vrange(sli, &vrange);
	if (!off_isnull(voff) && (voff < vrange.end)) {
		sli->sl_voff_last = off_align_to_bk(voff);
		silofs_assert_ge(sli->sl_voff_last, vrange.beg);
	} else {
		sli->sl_voff_last = vrange.beg;
	}
}

static loff_t sli_start_voff(const struct silofs_spleaf_info *sli)
{
	struct silofs_vrange vrange;

	spleaf_vrange(sli->sl, &vrange);
	return vrange.beg;
}

void silofs_sli_update_staged(struct silofs_spleaf_info *sli)
{
	loff_t voff;

	sli->sl_nused_bytes = spleaf_sum_nbytes_used(sli->sl);
	voff = off_end(sli_start_voff(sli), sli->sl_nused_bytes);
	silofs_sli_update_voff_last(sli, voff);
}

void silofs_sli_vspace_range(const struct silofs_spleaf_info *sli,
                             struct silofs_vrange *out_vrange)
{
	spleaf_vrange(sli->sl, out_vrange);
}

enum silofs_stype silofs_sli_stype_sub(const struct silofs_spleaf_info *sli)
{
	return spleaf_stype_sub(sli->sl);
}

static bool sli_has_stype_sub(const struct silofs_spleaf_info *sli,
                              enum silofs_stype stype)
{
	return (silofs_sli_stype_sub(sli) == stype);
}

loff_t silofs_sli_base_voff(const struct silofs_spleaf_info *sli)
{
	struct silofs_vrange vrange;

	silofs_sli_vspace_range(sli, &vrange);
	return vrange.beg;
}

loff_t silofs_sli_last_voff(const struct silofs_spleaf_info *sli)
{
	struct silofs_vrange vrange;

	silofs_sli_vspace_range(sli, &vrange);
	return vrange.end;
}

static bool sli_is_inrange(const struct silofs_spleaf_info *sli, loff_t voff)
{
	struct silofs_vrange vrange;

	silofs_sli_vspace_range(sli, &vrange);
	return (vrange.beg <= voff) && (voff < vrange.end);
}

static size_t sli_voff_to_bn(const struct silofs_spleaf_info *sli, loff_t voff)
{
	size_t bn;
	const loff_t beg = sli_start_voff(sli);

	silofs_assert_ge(voff, beg);

	bn = (size_t)off_to_lba(voff - beg);
	silofs_assert_le(bn, ARRAY_SIZE(sli->sl->sl_subref));
	return bn;
}

static void sli_vaddr_at(const struct silofs_spleaf_info *sli,
                         enum silofs_stype stype, size_t bn, size_t kbn,
                         struct silofs_vaddr *out_vaddr)
{
	const loff_t beg = sli_start_voff(sli);

	silofs_vaddr_by_spleaf(out_vaddr, stype, beg, bn, kbn);
}

static int sli_find_free_space_within(const struct silofs_spleaf_info *sli,
                                      enum silofs_stype stype,
                                      const struct silofs_vrange *vrange,
                                      struct silofs_vaddr *out_vaddr)
{
	int err;
	size_t bn;
	size_t kbn;
	const size_t bn_beg = sli_voff_to_bn(sli, vrange->beg);
	const size_t bn_end = sli_voff_to_bn(sli, vrange->end);

	err = spleaf_find_free(sli->sl, stype, bn_beg, bn_end, &bn, &kbn);
	if (err) {
		return err;
	}
	sli_vaddr_at(sli, stype, bn, kbn, out_vaddr);
	return 0;
}

static void sli_calc_vrange(const struct silofs_spleaf_info *sli,
                            bool from_last, struct silofs_vrange *out_vrange)
{
	struct silofs_vrange sl_vrange;
	const loff_t voff_last = sli->sl_voff_last;

	sli_formatted_vrange(sli, &sl_vrange);
	silofs_assert_le(voff_last, sl_vrange.end);
	silofs_assert_ge(voff_last, sl_vrange.beg);
	if (from_last) {
		silofs_vrange_setup(out_vrange, voff_last, sl_vrange.end);
	} else {
		silofs_vrange_setup(out_vrange, sl_vrange.beg, voff_last);
	}
}

static int sli_cap_allocate(const struct silofs_spleaf_info *sli,
                            enum silofs_stype stype)
{
	const size_t nbytes = stype_size(stype);
	const size_t nbytes_max = SILOFS_VSEC_SIZE;

	return ((sli->sl_nused_bytes + nbytes) <= nbytes_max) ? 0 : -ENOSPC;
}

int silofs_sli_find_free_space(const struct silofs_spleaf_info *sli,
                               enum silofs_stype stype,
                               struct silofs_vaddr *out_vaddr)
{
	int err;
	struct silofs_vrange vrange;

	err = sli_cap_allocate(sli, stype);
	if (err) {
		return err;
	}
	sli_calc_vrange(sli, true, &vrange);
	err = sli_find_free_space_within(sli, stype, &vrange, out_vaddr);
	if (err != -ENOSPC) {
		return err;
	}
	sli_calc_vrange(sli, false, &vrange);
	err = sli_find_free_space_within(sli, stype, &vrange, out_vaddr);
	if (err != -ENOSPC) {
		return err;
	}
	return -ENOSPC;
}

void silofs_sli_mark_allocated_space(struct silofs_spleaf_info *sli,
                                     const struct silofs_vaddr *vaddr)
{
	struct silofs_spmap_leaf *sl = sli->sl;

	spleaf_set_allocated_at(sl, vaddr);
	if (vaddr_isdata(vaddr)) {
		spleaf_set_unwritten_at(sl, vaddr);
	}
	sli_dirtify(sli);
}

void silofs_sli_clear_allocated_space(struct silofs_spleaf_info *sli,
                                      const struct silofs_vaddr *vaddr)
{
	struct silofs_spmap_leaf *sl = sli->sl;

	spleaf_clear_allocated_at(sl, vaddr);
	if (!spleaf_has_allocated_at(sl, vaddr)) {
		spleaf_renew_bk_at(sl, vaddr);
	}
	sli_dirtify(sli);
}

bool silofs_sli_has_refs_at(const struct silofs_spleaf_info *sli, loff_t voff)
{
	silofs_assert(sli_is_inrange(sli, voff));

	return spleaf_refcnt_at(sli->sl, voff) > 0;
}

bool silofs_sli_has_last_refcnt(const struct silofs_spleaf_info *sli,
                                const struct silofs_vaddr *vaddr)
{
	const size_t nkb = nkb_of(vaddr);
	const size_t cnt = spleaf_refcnt_at(sli->sl, vaddr->voff);

	return (nkb == cnt);
}

static bool sli_is_allocated_at(const struct silofs_spleaf_info *sli,
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
	if (spleaf_test_unwritten_at(sli->sl, vaddr)) {
		spleaf_clear_unwritten_at(sli->sl, vaddr);
		sli_dirtify(sli);
	}
}

void silofs_sli_mark_unwritten_at(struct silofs_spleaf_info *sli,
                                  const struct silofs_vaddr *vaddr)
{
	if (!spleaf_test_unwritten_at(sli->sl, vaddr)) {
		spleaf_set_unwritten_at(sli->sl, vaddr);
		sli_dirtify(sli);
	}
}

void silofs_sli_main_blob(const struct silofs_spleaf_info *sli,
                          struct silofs_blobid *out_bid)
{
	spleaf_main_blobid(sli->sl, out_bid);
}

void silofs_sli_bind_main_blob(struct silofs_spleaf_info *sli,
                               const struct silofs_blobid *bid)
{
	spleaf_set_main_blobid(sli->sl, bid);
	spleaf_bind_bks_to_main(sli->sl, sli_uaddr(sli));
	sli_dirtify(sli);
}

bool silofs_sli_has_main_blob(const struct silofs_spleaf_info *sli,
                              const struct silofs_metaid *tree_id)
{
	struct silofs_blobid bid;

	silofs_sli_main_blob(sli, &bid);
	if (blobid_size(&bid) == 0) {
		return false;
	}
	if (!metaid_isequal(tree_id, &bid.tree_id)) {
		return false;
	}
	return true;
}

int silofs_sli_check_stable_at(const struct silofs_spleaf_info *sli,
                               const struct silofs_vaddr *vaddr)
{
	if (!sli_has_stype_sub(sli, vaddr_stype(vaddr))) {
		return -EFSCORRUPTED;
	}
	if (!sli_is_allocated_at(sli, vaddr)) {
		return -EFSCORRUPTED;
	}
	return 0;
}

void silofs_sli_clone_childs(struct silofs_spleaf_info *sli,
                             const struct silofs_spleaf_info *sli_other)
{
	sli->sl_nused_bytes = sli_other->sl_nused_bytes;
	sli->sl_voff_last = sli_other->sl_voff_last;
	spleaf_clone_childs(sli->sl, sli_other->sl);
}

void silofs_sli_resolve_child(const struct silofs_spleaf_info *sli,
                              loff_t voff, struct silofs_uaddr *out_uaddr)
{
	spleaf_resolve_child(sli->sl, voff, out_uaddr);
}

void silofs_sli_resolve_main_at(const struct silofs_spleaf_info *sli,
                                loff_t voff, struct silofs_uaddr *out_uaddr)
{
	spleaf_resolve_main_at(sli->sl, voff, out_uaddr);
}

void silofs_sli_rebind_main_at(struct silofs_spleaf_info *sli, loff_t voff)
{
	struct silofs_uaddr uaddr;
	struct silofs_ulink ulink;

	silofs_assert(sli_is_inrange(sli, voff));
	silofs_sli_resolve_main_at(sli, voff, &uaddr);
	silofs_ulink_setup(&ulink, sli_uaddr(sli), &uaddr);
	spleaf_rebind_child(sli->sl, voff, &ulink);
	sli_dirtify(sli);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_unode_info *sni_ui(const struct silofs_spnode_info *sni)
{
	silofs_assert_not_null(sni);

	return silofs_unconst(&sni->sn_ui);
}

static void sni_dirtify(struct silofs_spnode_info *sni)
{
	ui_dirtify(sni_ui(sni));
}

const struct silofs_uaddr *
silofs_sni_uaddr(const struct silofs_spnode_info *sni)
{
	return &sni->sn_ui.u_uaddr;
}

void silofs_sni_incref(struct silofs_spnode_info *sni)
{
	if (sni != NULL) {
		ui_incref(sni_ui(sni));
	}
}

void silofs_sni_decref(struct silofs_spnode_info *sni)
{
	if (sni != NULL) {
		ui_decref(sni_ui(sni));
	}
}

void silofs_sni_setup_spawned(struct silofs_spnode_info *sni, size_t sn_height,
                              const struct silofs_vrange *vrange)
{
	silofs_assert_gt(sn_height, SILOFS_SPLEAF_HEIGHT);
	silofs_assert_le(sn_height, SILOFS_SPNODE_HEIGHT_MAX);

	spnode_init(sni->sn, sn_height, vrange);
	sni_dirtify(sni);
}

void silofs_sni_update_staged(struct silofs_spnode_info *sni)
{
	sni->sn_nchild_form = spnode_count_nform(sni->sn);
	sni->sn_nused_bytes = 0; /* heuristic */
}

size_t silofs_sni_height(const struct silofs_spnode_info *sni)
{
	return spnode_heigth(sni->sn);
}

size_t silofs_sni_child_height(const struct silofs_spnode_info *sni)
{
	return silofs_sni_height(sni) - 1;
}

enum silofs_stype silofs_sni_child_stype(const struct silofs_spnode_info *sni)
{
	const size_t height = silofs_sni_height(sni);

	return ((height - 1) > SILOFS_SPLEAF_HEIGHT) ?
	       SILOFS_STYPE_SPNODE : SILOFS_STYPE_SPLEAF;
}


int silofs_sni_search_spleaf(const struct silofs_spnode_info *sni,
                             const struct silofs_vrange *vrange,
                             enum silofs_stype stype, loff_t *out_voff)
{
	bool ok;

	silofs_assert_eq(silofs_sni_height(sni), 2);

	ok = spnode_find_avail_spleaf(sni->sn, vrange, stype, out_voff);
	silofs_assert_ge(*out_voff, vrange->beg);
	if (ok) {
		silofs_assert_lt(*out_voff, vrange->end);
	}
	return ok ? 0 : -ENOSPC;
}

static void sni_bind_subref(struct silofs_spnode_info *sni, loff_t voff,
                            const struct silofs_uaddr *uaddr,
                            enum silofs_stype stype_sub)
{
	struct silofs_ulink ulink;
	struct silofs_spmap_node *sn = sni->sn;

	if (!spnode_has_subref(sn, voff)) {
		sni->sn_nchild_form++;
	}
	silofs_ulink_setup(&ulink, sni_uaddr(sni), uaddr);
	spnode_set_ulink_of(sn, voff, &ulink, stype_sub);
	sni_dirtify(sni);
}

bool silofs_sni_has_child_at(const struct silofs_spnode_info *sni, loff_t voff)
{
	return spnode_has_subref(sni->sn, voff);
}

void silofs_sni_bind_child_spleaf(struct silofs_spnode_info *sni,
                                  const struct silofs_spleaf_info *sli)
{
	struct silofs_vrange vrange;

	silofs_assert_eq(silofs_sni_height(sni), 2);

	silofs_sli_vspace_range(sli, &vrange);
	sni_bind_subref(sni, vrange.beg, sli_uaddr(sli),
	                silofs_sli_stype_sub(sli));
}

void silofs_sni_bind_child_spnode(struct silofs_spnode_info *sni,
                                  const struct silofs_spnode_info *sni_child)
{
	struct silofs_vrange vrange;
	const struct silofs_uaddr *uaddr;
	enum silofs_stype stype_sub;

	silofs_sni_vspace_range(sni_child, &vrange);

	uaddr = silofs_sni_uaddr(sni_child);
	stype_sub = silofs_sni_child_stype(sni_child);
	sni_bind_subref(sni, vrange.beg, uaddr, stype_sub);
}

void silofs_sni_setup_parent(struct silofs_spnode_info *sni,
                             const struct silofs_unode_info *ui)
{
	spnode_set_parent(sni->sn, ui_uaddr(ui));
	sni_dirtify(sni);
}

void silofs_sni_vspace_range(const struct silofs_spnode_info *sni,
                             struct silofs_vrange *out_vrange)
{
	spnode_vrange(sni->sn, out_vrange);
}

void silofs_sni_formatted_vrange(const struct silofs_spnode_info *sni,
                                 struct silofs_vrange *out_vrange)
{
	loff_t voff_form_end;
	size_t nform_size;
	const size_t vsec_size = SILOFS_VSEC_SIZE;
	struct silofs_vrange vrange_full;

	silofs_sni_vspace_range(sni, &vrange_full);
	nform_size = sni->sn_nchild_form * vsec_size;
	voff_form_end = off_end(vrange_full.beg, nform_size);
	silofs_vrange_setup(out_vrange, vrange_full.beg, voff_form_end);
}

loff_t silofs_sni_base_voff(const struct silofs_spnode_info *sni)
{
	struct silofs_vrange vrange;

	silofs_sni_vspace_range(sni, &vrange);
	return vrange.beg;
}

loff_t silofs_sni_last_voff(const struct silofs_spnode_info *sni)
{
	struct silofs_vrange vrange;

	silofs_sni_vspace_range(sni, &vrange);
	return vrange.end;
}

int silofs_sni_check_may_alloc(const struct silofs_spnode_info *sni,
                               const enum silofs_stype stype)
{
	const size_t nbytes = stype_size(stype);
	const size_t nbytes_max = SILOFS_SPNODE_VRANGE_SIZE;
	const size_t nbytes_cur = sni->sn_nused_bytes;

	silofs_assert_le(nbytes_cur, nbytes_max);

	return ((nbytes_cur + nbytes) <= nbytes_max) ? 0 : -ENOSPC;
}

static size_t sni_child_height(const struct silofs_spnode_info *sni)
{
	return silofs_sni_height(sni) - 1;
}

static size_t sni_child_objsize(const struct silofs_spnode_info *sni)
{
	const size_t child_height = sni_child_height(sni);

	return (child_height == SILOFS_SPLEAF_HEIGHT) ?
	       SILOFS_SPLEAF_SIZE : SILOFS_SPNODE_SIZE;
}

static enum silofs_stype sni_child_stype(const struct silofs_spnode_info *sni)
{
	enum silofs_stype child_stype;
	const size_t child_height = sni_child_height(sni);

	if (child_height == SILOFS_SPLEAF_HEIGHT) {
		child_stype = SILOFS_STYPE_SPLEAF;
	} else {
		child_stype = SILOFS_STYPE_SPNODE;
	}
	return child_stype;
}

int silofs_sni_resolve_subref(const struct silofs_spnode_info *sni,
                              loff_t voff, struct silofs_ulink *out_ulink)
{
	spnode_child_of(sni->sn, voff, out_ulink);
	return silofs_ulink_isnull(out_ulink) ? -ENOENT : 0;
}

void silofs_sni_main_blob(const struct silofs_spnode_info *sni,
                          struct silofs_blobid *out_bid)
{
	spnode_main_blobid(sni->sn, out_bid);

	silofs_assert(!blobid_isequal(out_bid, &sni->sn_ui.u_uaddr.oaddr.bid));
}

void silofs_sni_bind_main_blob(struct silofs_spnode_info *sni,
                               const struct silofs_blobid *bid)
{
	silofs_assert(!blobid_isequal(bid, &sni->sn_ui.u_uaddr.oaddr.bid));

	spnode_set_main_blobid(sni->sn, bid);
	sni_dirtify(sni);
}

bool silofs_sni_has_main_blob(const struct silofs_spnode_info *sni)
{
	struct silofs_blobid bid;

	silofs_sni_main_blob(sni, &bid);
	return (blobid_size(&bid) > 0);
}

static loff_t
sni_bpos_of_child(const struct silofs_spnode_info *sni, loff_t voff)
{
	const size_t slot = spnode_slot_of(sni->sn, voff);

	return (loff_t)(slot * sni_child_objsize(sni));
}

static loff_t
sni_base_voff_of_child(const struct silofs_spnode_info *sni, loff_t voff)
{
	struct silofs_vrange vrange;
	const size_t child_height = sni_child_height(sni);

	silofs_vrange_setup_by(&vrange, child_height, voff);
	return vrange.beg;
}

void silofs_sni_resolve_main_child(const struct silofs_spnode_info *sni,
                                   loff_t voff, struct silofs_uaddr *out_uaddr)
{
	loff_t base;
	loff_t bpos;
	struct silofs_blobid bid;
	const size_t child_height = sni_child_height(sni);
	const enum silofs_stype child_stype = sni_child_stype(sni);

	silofs_sni_main_blob(sni, &bid);
	silofs_assert_eq(bid.height, child_height);

	base = sni_base_voff_of_child(sni, voff);
	bpos = sni_bpos_of_child(sni, voff);
	silofs_uaddr_setup(out_uaddr, &bid, child_stype, bpos, base);
}

void silofs_sni_update_nused(struct silofs_spnode_info *sni,
                             const struct silofs_vaddr *vaddr, int take)
{
	if (take > 0) {
		sni->sn_nused_bytes += vaddr->len;
	} else if (take < 0) {
		if (sni->sn_nused_bytes > vaddr->len) {
			sni->sn_nused_bytes -= vaddr->len;
		} else {
			sni->sn_nused_bytes = 0;
		}
	}
}

void silofs_sni_clone_subrefs(struct silofs_spnode_info *sni,
                              const struct silofs_spnode_info *sni_other)
{
	sni->sn_nused_bytes = sni_other->sn_nused_bytes;
	sni->sn_nchild_form = sni_other->sn_nchild_form;
	spnode_clone_subrefs(sni->sn, sni_other->sn);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int verify_stype(enum silofs_stype stype)
{
	switch (stype) {
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_ANONBK:
	case SILOFS_STYPE_DATA1K:
	case SILOFS_STYPE_DATA4K:
	case SILOFS_STYPE_DATABK:
	case SILOFS_STYPE_SUPER:
	case SILOFS_STYPE_SPNODE:
	case SILOFS_STYPE_SPLEAF:
	case SILOFS_STYPE_ITNODE:
	case SILOFS_STYPE_INODE:
	case SILOFS_STYPE_XANODE:
	case SILOFS_STYPE_DTNODE:
	case SILOFS_STYPE_FTNODE:
	case SILOFS_STYPE_SYMVAL:
		return 0;
	case SILOFS_STYPE_MAX:
	default:
		break;
	}
	return -EFSCORRUPTED;
}

static int verify_spnode_height(size_t height)
{
	if (height <= SILOFS_SPLEAF_HEIGHT) {
		return -EFSCORRUPTED;
	}
	if (height > SILOFS_SPNODE_HEIGHT_MAX) {
		return -EFSCORRUPTED;
	}
	return 0;
}

static int verify_bk_ref(const struct silofs_bk_ref *bkr)
{
	size_t refcnt;

	refcnt = bkr_refcnt(bkr);
	if (refcnt >= INT_MAX) {
		return -EFSCORRUPTED;
	}
	return 0;
}

static int verify_spmap_leaf_parent(const struct silofs_spmap_leaf *sl)
{
	struct silofs_uaddr uaddr;

	spleaf_parent(sl, &uaddr);
	if (uaddr_isnull(&uaddr)) {
		return -EFSCORRUPTED;
	}
	if (uaddr.stype != SILOFS_STYPE_SPNODE) {
		return -EFSCORRUPTED;
	}
	return 0;
}

int silofs_verify_spmap_leaf(const struct silofs_spmap_leaf *sl)
{
	int err;
	const struct silofs_bk_ref *bkr;

	for (size_t i = 0; i < ARRAY_SIZE(sl->sl_subref); ++i) {
		bkr = spleaf_subref_at(sl, i);
		err = verify_bk_ref(bkr);
		if (err) {
			return err;
		}
	}
	err = verify_spmap_leaf_parent(sl);
	if (err) {
		return err;
	}
	return 0;
}

static int verify_ulink(const struct silofs_ulink *ulink)
{
	if (uaddr_isnull(&ulink->owner) && uaddr_isnull(&ulink->child)) {
		return 0;
	}
	if (!oaddr_isvalid(&ulink->owner.oaddr)) {
		return -EFSCORRUPTED;
	}
	if (!oaddr_isvalid(&ulink->child.oaddr)) {
		return -EFSCORRUPTED;
	}
	return 0;
}

static int verify_spmap_ref(const struct silofs_spmap_ref *spr, size_t height)
{
	struct silofs_ulink ulink;
	const size_t spleaf_height = SILOFS_SPLEAF_HEIGHT;
	enum silofs_stype stype_sub;
	int err;

	silofs_spr_ulink(spr, &ulink);
	err = verify_ulink(&ulink);
	if (err) {
		return err;
	}
	if (uaddr_isnull(&ulink.child)) {
		return 0;
	}
	stype_sub = spr_stype_sub(spr);
	err = verify_stype(stype_sub);
	if (err) {
		log_err("non valid spmap: sub_type=%d", stype_sub);
		return err;
	}
	if (stype_isnone(stype_sub) && (height == spleaf_height + 1)) {
		return -EFSCORRUPTED;
	}
	return 0;
}

static int verify_spmap_node_parent(const struct silofs_spmap_node *sn)
{
	struct silofs_uaddr uaddr;
	const size_t height = spnode_heigth(sn);

	spnode_parent(sn, &uaddr);
	if (uaddr_isnull(&uaddr)) {
		return -EFSCORRUPTED;
	}
	if (height == SILOFS_SPNODE_HEIGHT_MAX) {
		if (uaddr.stype != SILOFS_STYPE_SUPER) {
			return -EFSCORRUPTED;
		}
	} else {
		if (uaddr.stype != SILOFS_STYPE_SPNODE) {
			return -EFSCORRUPTED;
		}
	}
	return 0;
}

int silofs_verify_spmap_node(const struct silofs_spmap_node *sn)
{
	struct silofs_vrange vrange;
	size_t height;
	ssize_t len;
	int err;

	height = spnode_heigth(sn);
	err = verify_spnode_height(height);
	if (err) {
		log_err("bad spnode height: height=%lu", height);
		return err;
	}
	spnode_vrange(sn, &vrange);
	len = off_len(vrange.beg, vrange.end);
	if (len < SILOFS_VSEC_SIZE) {
		log_err("bad spmap-node vrange: height=%lu "
		        "beg=0x%lx end=0x%lx", height, vrange.beg, vrange.end);
		return -EFSCORRUPTED;
	}
	for (size_t i = 0; i < ARRAY_SIZE(sn->sn_subref); ++i) {
		err = verify_spmap_ref(&sn->sn_subref[i], height);
		if (err) {
			return err;
		}
	}
	err = verify_spmap_node_parent(sn);
	if (err) {
		log_err("illegal spmap-node parent: height=%lu "
		        "beg=0x%lx end=0x%lx", height, vrange.beg, vrange.end);
		return err;
	}
	return 0;
}

