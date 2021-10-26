/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2021 Shachar Sharon
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

static void spr_child(const struct silofs_spmap_ref *spr,
                      struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr56b_parse(&spr->sr_child.uor_uadr, out_uaddr);
}

static void spr_set_child(struct silofs_spmap_ref *spr,
                          const struct silofs_uaddr *uaddr,
                          enum silofs_stype stype_sub)
{
	silofs_uaddr56b_set(&spr->sr_child.uor_uadr, uaddr);
	spr_set_stype_sub(spr, stype_sub);
}

static bool spr_has_child(const struct silofs_spmap_ref *spr)
{
	struct silofs_uaddr uaddr;

	spr_child(spr, &uaddr);
	return !uaddr_isnull(&uaddr);
}

static void spr_reset_child(struct silofs_spmap_ref *spr)
{
	silofs_uaddr56b_reset(&spr->sr_child.uor_uadr);
}

static void spr_init(struct silofs_spmap_ref *spr)
{
	spr_set_stype_sub(spr, SILOFS_STYPE_NONE);
	spr_reset_child(spr);
	spr->sr_flags = 0 ;
	memset(spr->sr_reserved, 0, sizeof(spr->sr_reserved));
}

static void spr_initn(struct silofs_spmap_ref *spr, size_t n)
{
	for (size_t i = 0; i < n; ++i) {
		spr_init(&spr[i]);
	}
}

static bool spr_may_alloc_stype(const struct silofs_spmap_ref *spr,
                                enum silofs_stype stype)
{
	return spr_has_stype_sub(spr, stype) && spr_has_child(spr);
}

static void spr_clone_from(struct silofs_spmap_ref *spr,
                           const struct silofs_spmap_ref *spr_other)
{
	struct silofs_uaddr uaddr;

	spr_child(spr_other, &uaddr);
	spr_set_child(spr, &uaddr, spr_stype_sub(spr_other));
	spr->sr_stype_sub = spr_other->sr_stype_sub;
	spr->sr_flags = spr_other->sr_flags;
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
	silofs_blobid40b_reset(&sn->sn_arch_blobid);
	spr_initn(sn->sn_child, ARRAY_SIZE(sn->sn_child));
}

static struct silofs_spmap_ref *
spnode_child_ref_at(const struct silofs_spmap_node *sn, size_t slot)
{
	const struct silofs_spmap_ref *spr = &sn->sn_child[slot];

	silofs_assert_lt(slot, ARRAY_SIZE(sn->sn_child));
	return unconst(spr);
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

static size_t spnode_nchilds_max(const struct silofs_spmap_node *sn)
{
	return ARRAY_SIZE(sn->sn_child);
}

static size_t spnode_slot_of(const struct silofs_spmap_node *sn, loff_t voff)
{
	size_t slot;
	loff_t beg;
	ssize_t roff;
	const loff_t span = spnode_span(sn);
	const size_t nslots = spnode_nchilds_max(sn);

	beg = spnode_beg(sn);
	silofs_assert_le(beg, voff);
	roff = off_diff(beg, voff);
	slot = (size_t)((roff * (long)nslots) / span);
	return slot;
}

static struct silofs_spmap_ref *
spnode_child_ref_of(const struct silofs_spmap_node *sn, loff_t voff)
{
	return spnode_child_ref_at(sn, spnode_slot_of(sn, voff));
}

static void spnode_child_of(const struct silofs_spmap_node *sn, loff_t voff,
                            struct silofs_uaddr *out_uaddr)
{
	const struct silofs_spmap_ref *spr = spnode_child_ref_of(sn, voff);

	spr_child(spr, out_uaddr);
}

static void spnode_set_child_of(struct silofs_spmap_node *sn, loff_t voff,
                                const struct silofs_uaddr *uaddr,
                                enum silofs_stype stype_sub)
{
	struct silofs_spmap_ref *spr = spnode_child_ref_of(sn, voff);

	spr_set_child(spr, uaddr, stype_sub);
}

static bool spnode_has_child(const struct silofs_spmap_node *sn, loff_t voff)
{
	const struct silofs_spmap_ref *spr = spnode_child_ref_of(sn, voff);

	return spr_has_child(spr);
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
		if (!spr_has_child(spr)) {
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

static size_t spnode_count_nchild_form(const struct silofs_spmap_node *sn)
{
	size_t count = 0;
	const struct silofs_spmap_ref *spr = NULL;
	const size_t nslots_max = spnode_nchilds_max(sn);

	for (size_t slot = 0; slot < nslots_max; ++slot) {
		spr = spnode_child_ref_at(sn, slot);
		if (!spr_has_child(spr)) {
			break;
		}
		++count;
	}
	return count;
}

static void spnode_clone_childs(struct silofs_spmap_node *sn,
                                const struct silofs_spmap_node *sn_other)
{
	struct silofs_spmap_ref *spr = NULL;
	const struct silofs_spmap_ref *spr_other = NULL;
	const size_t nslots_max = spnode_nchilds_max(sn);

	for (size_t slot = 0; slot < nslots_max; ++slot) {
		spr = spnode_child_ref_at(sn, slot);
		spr_other = spnode_child_ref_at(sn_other, slot);
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

static void bkr_set_flags(struct silofs_bk_ref *bkr, enum silofs_bkrf f)
{
	bkr->br_flags = silofs_cpu_to_le32((uint32_t)f);
}

static void bkr_blobid(const struct silofs_bk_ref *bkr,
                       struct silofs_blobid *out_bid)
{
	silofs_blobid40b_parse(&bkr->br_blobid, out_bid);
}

static void bkr_set_blobid(struct silofs_bk_ref *bkr,
                           const struct silofs_blobid *bid)
{
	silofs_blobid40b_set(&bkr->br_blobid, bid);
}

static void bkr_reset_blobid(struct silofs_bk_ref *bkr)
{
	silofs_blobid40b_reset(&bkr->br_blobid);
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

static void bkr_init(struct silofs_bk_ref *bkr, loff_t off)
{
	bkr_clear_alloc_state(bkr);
	bkr_reset_blobid(bkr);
	bkr_set_flags(bkr, SILOFS_BKRF_NONE);
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
	struct silofs_blobid bid;

	bkr_blobid(bkr_other, &bid);
	bkr_set_blobid(bkr, &bid);
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
	silofs_blobid40b_reset(&sl->sl_arch_blobid);
	bkr_init_arr(sl->sl_bkr, ARRAY_SIZE(sl->sl_bkr), vrange->beg);
}

static void spleaf_vrange(const struct silofs_spmap_leaf *sl,
                          struct silofs_vrange *vrange)
{
	silofs_vrange128_parse(&sl->sl_vrange, vrange);
}

static struct silofs_bk_ref *
spleaf_bkr_at(const struct silofs_spmap_leaf *sl, size_t slot)
{
	const struct silofs_bk_ref *bkr = &(sl->sl_bkr[slot]);

	silofs_assert_lt(slot, ARRAY_SIZE(sl->sl_bkr));
	return unconst(bkr);
}

static size_t spleaf_nchilds_max(const struct silofs_spmap_leaf *sl)
{
	return ARRAY_SIZE(sl->sl_bkr);
}

static size_t spleaf_lba_slot(const struct silofs_spmap_leaf *sl,
                              silofs_lba_t lba)
{
	return (size_t)lba % spleaf_nchilds_max(sl);
}

static struct silofs_bk_ref *
spleaf_bkr_by_lba(const struct silofs_spmap_leaf *sl, silofs_lba_t lba)
{
	return spleaf_bkr_at(sl, spleaf_lba_slot(sl, lba));
}

static struct silofs_bk_ref *
spleaf_bkr_by_vaddr(const struct silofs_spmap_leaf *sl,
                    const struct silofs_vaddr *vaddr)
{
	return spleaf_bkr_by_lba(sl, vaddr_lba(vaddr));
}

static bool spleaf_is_allocated_at(const struct silofs_spmap_leaf *sl,
                                   const struct silofs_vaddr *vaddr)
{
	const size_t kbn = kbn_of(vaddr);
	const size_t nkb = nkb_of(vaddr);
	const struct silofs_bk_ref *bkr;

	bkr = spleaf_bkr_by_lba(sl, vaddr_lba(vaddr));
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

static size_t spleaf_refcnt_at(const struct silofs_spmap_leaf *sl,
                               const struct silofs_vaddr *vaddr)
{
	const struct silofs_bk_ref *bkr = spleaf_bkr_by_vaddr(sl, vaddr);

	return bkr_refcnt(bkr);
}

static bool spleaf_last_refcnt_at(const struct silofs_spmap_leaf *sl,
                                  const struct silofs_vaddr *vaddr)
{
	const size_t nkb = nkb_of(vaddr);

	return (nkb == spleaf_refcnt_at(sl, vaddr));
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
	int err = -ENOSPC;
	const size_t nkb = stype_nkbs(stype);
	const struct silofs_bk_ref *bkr = spleaf_bkr_at(sl, bn);

	if (bkr_may_alloc(bkr, nkb)) {
		err = bkr_find_free(bkr, nkb, out_kbn);
	}
	return err;
}

static int
spleaf_find_free(const struct silofs_spmap_leaf *sl, enum silofs_stype stype,
                 size_t bn_beg, size_t bn_end, size_t *out_bn, size_t *out_kbn)
{
	int err = -ENOSPC;
	size_t kbn;

	silofs_assert_le(bn_beg, ARRAY_SIZE(sl->sl_bkr));
	silofs_assert_le(bn_beg, bn_end);
	silofs_assert_le(bn_beg - bn_end, ARRAY_SIZE(sl->sl_bkr));

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

static void spleaf_reassign_bks_blobid(struct silofs_spmap_leaf *sl,
                                       const struct silofs_blobid *bid)
{
	struct silofs_bk_ref *bkr;
	struct silofs_blobid bid_cur;
	const size_t nslots = spleaf_nchilds_max(sl);

	for (size_t slot = 0; slot < nslots; ++slot) {
		bkr = spleaf_bkr_at(sl, slot);
		bkr_blobid(bkr, &bid_cur);
		if (bid_cur.size == 0) {
			bkr_set_blobid(bkr, bid);
		}
	}
}

static void spleaf_calc_space_stat(const struct silofs_spmap_leaf *sl,
                                   struct silofs_space_stat *sp_st)
{
	const struct silofs_bk_ref *bkr;
	const size_t nslots = spleaf_nchilds_max(sl);
	const enum silofs_stype stype_sub = spleaf_stype_sub(sl);

	silofs_memzero(sp_st, sizeof(*sp_st));
	for (size_t slot = 0; slot < nslots; ++slot) {
		bkr = spleaf_bkr_at(sl, slot);
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
	const size_t nslots = spleaf_nchilds_max(sl);

	for (size_t slot = 0; slot < nslots; ++slot) {
		bkr = spleaf_bkr_at(sl, slot);
		bkr_other = spleaf_bkr_at(sl_other, slot);
		bkr_clone_from(bkr, bkr_other);
	}
}

static void spleaf_bind_to_main(struct silofs_spmap_leaf *sl,
                                const struct silofs_vaddr *vaddr)
{
	struct silofs_blobid bid_main;
	struct silofs_blobid bid_curr;
	struct silofs_bk_ref *bkr = spleaf_bkr_by_vaddr(sl, vaddr);

	silofs_assert(!bkr_isunused(bkr));

	spleaf_main_blobid(sl, &bid_main);

	bkr_blobid(bkr, &bid_curr);
	silofs_assert(!blobid_isequal(&bid_main, &bid_curr));

	bkr_set_blobid(bkr, &bid_main);
}


/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_unode_info *sli_ui(struct silofs_spleaf_info *sli)
{
	silofs_assert_not_null(sli);

	return &sli->sl_ui;
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

static const struct silofs_uaddr *
sli_uaddr(const struct silofs_spleaf_info *sli)
{
	return &sli->sl_ui.u_uaddr;
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

static bool sli_is_inrange(const struct silofs_spleaf_info *sli, loff_t voff)
{
	struct silofs_vrange vrange;

	silofs_sli_vspace_range(sli, &vrange);
	return (vrange.beg <= voff) && (voff < vrange.end);
}

void silofs_sli_resolve_oaddr(const struct silofs_spleaf_info *sli,
                              const struct silofs_vaddr *vaddr,
                              struct silofs_oaddr *out_oaddr)
{
	struct silofs_blobid bid;

	silofs_sli_main_blob(sli, &bid);

	silofs_assert(sli_is_inrange(sli, vaddr_off(vaddr)));
	silofs_assert_eq(bid.size, SILOFS_VSEC_SIZE);

	silofs_oaddr_setup(out_oaddr, &bid, vaddr->len, vaddr_off(vaddr));
}

void silofs_sli_resolve_ova(const struct silofs_spleaf_info *sli,
                            const struct silofs_vaddr *vaddr,
                            struct silofs_ovaddr *out_ova)
{
	struct silofs_oaddr oaddr;

	silofs_sli_resolve_oaddr(sli, vaddr, &oaddr);
	silofs_ovaddr_setup(out_ova, &oaddr, vaddr);
}

static size_t sli_voff_to_bn(const struct silofs_spleaf_info *sli, loff_t voff)
{
	size_t bn;
	const loff_t beg = sli_start_voff(sli);

	silofs_assert_ge(voff, beg);

	bn = (size_t)off_to_lba(voff - beg);
	silofs_assert_le(bn, ARRAY_SIZE(sli->sl->sl_bkr));
	return bn;
}

static void sli_resolve_vaddr(const struct silofs_spleaf_info *sli,
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
	sli_resolve_vaddr(sli, stype, bn, kbn, out_vaddr);
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

bool silofs_sli_has_last_refcnt(const struct silofs_spleaf_info *sli,
                                const struct silofs_vaddr *vaddr)
{
	return spleaf_last_refcnt_at(sli->sl, vaddr);
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
	silofs_assert_eq(bid->size, SILOFS_VSEC_SIZE);

	spleaf_set_main_blobid(sli->sl, bid);
	spleaf_reassign_bks_blobid(sli->sl, bid);
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

void silofs_sli_bind_to_main_at(struct silofs_spleaf_info *sli,
                                const struct silofs_vaddr *vaddr)
{
	spleaf_bind_to_main(sli->sl, vaddr);
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
	silofs_assert_not_null(sni);
	ui_incref(sni_ui(sni));
}

void silofs_sni_decref(struct silofs_spnode_info *sni)
{
	silofs_assert_not_null(sni);
	ui_decref(sni_ui(sni));
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
	sni->sn_nchild_form = spnode_count_nchild_form(sni->sn);
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

static void sni_bind_child(struct silofs_spnode_info *sni, loff_t voff,
                           const struct silofs_uaddr *uaddr,
                           enum silofs_stype stype_sub)
{
	struct silofs_blobid bid;
	struct silofs_spmap_node *sn = sni->sn;

	spnode_main_blobid(sn, &bid);
	silofs_assert(!blobid_isequal(&bid, &sni->sn_ui.u_uaddr.oaddr.bid));
	silofs_assert_lt(sni->sn_nchild_form, SILOFS_SPMAP_NODE_NCHILDS);

	if (!spnode_has_child(sn, voff)) {
		sni->sn_nchild_form++;
	}
	spnode_set_child_of(sn, voff, uaddr, stype_sub);
	sni_dirtify(sni);
}

bool silofs_sni_has_child_at(const struct silofs_spnode_info *sni, loff_t voff)
{
	return spnode_has_child(sni->sn, voff);
}

void silofs_sni_bind_child_spleaf(struct silofs_spnode_info *sni,
                                  const struct silofs_spleaf_info *sli)
{
	struct silofs_vrange vrange;

	silofs_assert_eq(silofs_sni_height(sni), 2);

	silofs_sli_vspace_range(sli, &vrange);
	sni_bind_child(sni, vrange.beg, sli_uaddr(sli),
	               silofs_sli_stype_sub(sli));
}

void silofs_sni_bind_child_spnode(struct silofs_spnode_info *sni,
                                  const struct silofs_spnode_info *sni_child)
{
	struct silofs_vrange vrange;
	enum silofs_stype stype_sub = SILOFS_STYPE_NONE;
	const struct silofs_uaddr *uaddr = silofs_sni_uaddr(sni_child);

	silofs_sni_vspace_range(sni_child, &vrange);
	sni_bind_child(sni, vrange.beg, uaddr, stype_sub);
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

int silofs_sni_resolve_child(const struct silofs_spnode_info *sni,
                             loff_t voff, struct silofs_uaddr *out_uaddr)
{
	struct silofs_uaddr uaddr;

	spnode_child_of(sni->sn, voff, &uaddr);
	if (uaddr_isnull(&uaddr)) {
		return -ENOENT;
	}
	uaddr_assign(out_uaddr, &uaddr);
	return 0;
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

void silofs_sni_main_child_uaddr(const struct silofs_spnode_info *sni,
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

void silofs_sni_clone_childs(struct silofs_spnode_info *sni,
                             const struct silofs_spnode_info *sni_other)
{
	sni->sn_nused_bytes = sni_other->sn_nused_bytes;
	sni->sn_nchild_form = sni_other->sn_nchild_form;
	spnode_clone_childs(sni->sn, sni_other->sn);
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

int silofs_verify_spmap_leaf(const struct silofs_spmap_leaf *sl)
{
	int err;
	const struct silofs_bk_ref *bkr;

	for (size_t i = 0; i < ARRAY_SIZE(sl->sl_bkr); ++i) {
		bkr = spleaf_bkr_at(sl, i);
		err = verify_bk_ref(bkr);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int verify_spmap_ref(const struct silofs_spmap_ref *spr, size_t height)
{
	int err;
	enum silofs_stype stype_sub;
	struct silofs_uaddr uaddr;
	const size_t spleaf_height = SILOFS_SPLEAF_HEIGHT;

	spr_child(spr, &uaddr);
	if (uaddr_isnull(&uaddr)) {
		return 0;
	}
	if (!oaddr_isvalid(&uaddr.oaddr)) {
		return -EFSCORRUPTED;
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

int silofs_verify_spmap_node(const struct silofs_spmap_node *sn)
{
	int err;
	ssize_t len;
	size_t height;
	struct silofs_vrange vrange;

	height = spnode_heigth(sn);
	err = verify_spnode_height(height);
	if (err) {
		log_err("bad spnode height: height=%lu", height);
		return err;
	}
	spnode_vrange(sn, &vrange);
	len = off_len(vrange.beg, vrange.end);
	if (len < SILOFS_VSEC_SIZE) {
		log_err("bad spmap-node vrange: "
		        "beg=0x%lx end=0x%lx", vrange.beg, vrange.end);
		return -EFSCORRUPTED;
	}
	for (size_t i = 0; i < ARRAY_SIZE(sn->sn_child); ++i) {
		err = verify_spmap_ref(&sn->sn_child[i], height);
		if (err) {
			return err;
		}
	}
	return 0;
}

