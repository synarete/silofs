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
	return (size_t)((vaddr->off / SILOFS_KB_SIZE) % SILOFS_NKB_IN_BK);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void spr_ulink(const struct silofs_spmap_ref *spr,
                      struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr64b_parse(&spr->sr_ulink, out_uaddr);
}

static void spr_set_ulink(struct silofs_spmap_ref *spr,
                          const struct silofs_uaddr *uaddr)
{
	silofs_uaddr64b_set(&spr->sr_ulink, uaddr);
}

static void spr_reset(struct silofs_spmap_ref *spr)
{
	silofs_uaddr64b_reset(&spr->sr_ulink);
}

static bool spr_isactive(const struct silofs_spmap_ref *spr)
{
	struct silofs_uaddr uaddr;

	spr_ulink(spr, &uaddr);
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

	spr_ulink(spr_other, &uaddr);
	spr_set_ulink(spr, &uaddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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

static void spnode_self(const struct silofs_spmap_node *sn,
                        struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr64b_parse(&sn->sn_self, out_uaddr);
}

static void spnode_set_self(struct silofs_spmap_node *sn,
                            const struct silofs_uaddr *uaddr)
{
	silofs_uaddr64b_set(&sn->sn_self, uaddr);
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

static enum silofs_height spnode_heigth(const struct silofs_spmap_node *sn)
{
	struct silofs_uaddr self_uaddr;

	spnode_self(sn, &self_uaddr);
	return self_uaddr.height;
}

static void spnode_main_blobid(const struct silofs_spmap_node *sn,
                               struct silofs_blobid *out_blobid)
{
	silofs_blobid40b_parse(&sn->sn_main_blobid, out_blobid);
}

static void spnode_set_main_blobid(struct silofs_spmap_node *sn,
                                   const struct silofs_blobid *blobid)
{
	silofs_blobid40b_set(&sn->sn_main_blobid, blobid);
}

static void spnode_init(struct silofs_spmap_node *sn,
                        const struct silofs_vrange *vrange)
{
	spnode_set_vrange(sn, vrange);
	silofs_blobid40b_reset(&sn->sn_main_blobid);
	silofs_uaddr64b_reset(&sn->sn_parent);
	silofs_uaddr64b_reset(&sn->sn_self);
	spr_initn(sn->sn_subref, ARRAY_SIZE(sn->sn_subref));
}

static size_t spnode_slot_of(const struct silofs_spmap_node *sn, loff_t voff)
{
	const size_t nslots = ARRAY_SIZE(sn->sn_subref);
	struct silofs_vrange vrange;
	size_t len;
	size_t slot;
	ssize_t roff;

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
	const struct silofs_spmap_ref *spr = &sn->sn_subref[slot];

	silofs_assert_lt(slot, ARRAY_SIZE(sn->sn_subref));

	return unconst(spr);
}

static struct silofs_spmap_ref *
spnode_subref_of(const struct silofs_spmap_node *sn, loff_t voff)
{
	return spnode_subref_at(sn, spnode_slot_of(sn, voff));
}

static void spnode_ulink_of(const struct silofs_spmap_node *sn, loff_t voff,
                            struct silofs_uaddr *out_uaddr)
{
	const struct silofs_spmap_ref *spr = spnode_subref_of(sn, voff);

	spr_ulink(spr, out_uaddr);
}

static void spnode_set_ulink_of(struct silofs_spmap_node *sn, loff_t voff,
                                const struct silofs_uaddr *uaddr)
{
	struct silofs_spmap_ref *spr = spnode_subref_of(sn, voff);

	spr_set_ulink(spr, uaddr);
}

static size_t spnode_count_nactive(const struct silofs_spmap_node *sn)
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

static bool
spnode_has_child_at(const struct silofs_spmap_node *sn, loff_t voff)
{
	const struct silofs_spmap_ref *spr = spnode_subref_of(sn, voff);

	return spr_isactive(spr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint64_t mask_of(size_t kbn, size_t nkb)
{
	uint64_t mask;
	const size_t nkb_in_bk = SILOFS_NKB_IN_BK;

	mask = (nkb < nkb_in_bk) ? (((1UL << nkb) - 1UL) << kbn) : ~0UL;
	return mask;
}

static struct silofs_bk_ref *bkr_unconst(const struct silofs_bk_ref *bkr)
{
	return unconst(bkr);
}

static void bkr_uref_blobid(const struct silofs_bk_ref *bkr,
                            struct silofs_blobid *out_blobid)
{
	silofs_blobid40b_parse(&bkr->br_uref_blobid, out_blobid);
}

static void bkr_set_uref_blobid(struct silofs_bk_ref *bkr,
                                const struct silofs_blobid *blobid)
{
	silofs_blobid40b_set(&bkr->br_uref_blobid, blobid);
}

static size_t bkr_refcnt(const struct silofs_bk_ref *bkr)
{
	return silofs_le64_to_cpu(bkr->br_refcnt);
}

static void bkr_set_refcnt(struct silofs_bk_ref *bkr, size_t refcnt)
{
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

	bkr_set_allocated(bkr, allocated | mask);
}

static void bkr_clear_allocated_at(struct silofs_bk_ref *bkr,
                                   size_t kbn, size_t nkb)
{
	const uint64_t mask = mask_of(kbn, nkb);
	const uint64_t allocated = bkr_allocated(bkr);

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

static void bkr_clear_alloc_state(struct silofs_bk_ref *bkr)
{
	bkr_set_refcnt(bkr, 0);
	bkr_set_allocated(bkr, 0);
	bkr_set_unwritten(bkr, 0);
}

static void bkr_reset(struct silofs_bk_ref *bkr)
{
	memset(bkr, 0, sizeof(*bkr));
	bkr_clear_alloc_state(bkr);
	silofs_blobid40b_reset(&bkr->br_uref_blobid);
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

static void bkr_make_vaddrs(const struct silofs_bk_ref *bkr,
                            enum silofs_stype stype, loff_t voff_base,
                            struct silofs_vaddrs *vas)
{
	const size_t nkb = stype_nkbs(stype);
	const size_t nkb_in_bk = SILOFS_NKB_IN_BK;
	const uint64_t allocated = bkr_allocated(bkr);
	uint64_t mask;
	loff_t voff;

	vas->count = 0;
	for (size_t kbn = 0; (kbn + nkb) <= nkb_in_bk; kbn += nkb) {
		mask = mask_of(kbn, nkb);
		if ((allocated & mask) == mask) {
			voff = off_end(voff_base, kbn * SILOFS_KB_SIZE);
			vaddr_setup(&vas->vaddr[vas->count++], stype, voff);
		}
	}
}

static void bkr_clone_from(struct silofs_bk_ref *bkr,
                           const struct silofs_bk_ref *bkr_other)
{
	struct silofs_blobid blobid;

	bkr_uref_blobid(bkr_other, &blobid);
	bkr_set_uref_blobid(bkr, &blobid);
	bkr_set_allocated(bkr, bkr_allocated(bkr_other));
	bkr_set_unwritten(bkr, bkr_unwritten(bkr_other));
	bkr_set_refcnt(bkr, bkr_refcnt(bkr_other));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void spleaf_init(struct silofs_spmap_leaf *sl,
                        const struct silofs_vrange *vrange)
{
	silofs_vrange128_set(&sl->sl_vrange, vrange);
	silofs_blobid40b_reset(&sl->sl_main_blobid);
	silofs_uaddr64b_reset(&sl->sl_parent);
	silofs_uaddr64b_reset(&sl->sl_self);
	bkr_init_arr(sl->sl_subref, ARRAY_SIZE(sl->sl_subref));
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

static void spleaf_self(const struct silofs_spmap_leaf *sl,
                        struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr64b_parse(&sl->sl_self, out_uaddr);
}

static void spleaf_set_self(struct silofs_spmap_leaf *sl,
                            const struct silofs_uaddr *uaddr)
{
	silofs_uaddr64b_set(&sl->sl_self, uaddr);
}

static void spleaf_vrange(const struct silofs_spmap_leaf *sl,
                          struct silofs_vrange *vrange)
{
	silofs_vrange128_parse(&sl->sl_vrange, vrange);
}

static struct silofs_bk_ref *
spleaf_subref_at(const struct silofs_spmap_leaf *sl, size_t slot)
{
	const struct silofs_bk_ref *bkr = &(sl->sl_subref[slot]);

	return bkr_unconst(bkr);
}

static size_t
spleaf_lba_slot(const struct silofs_spmap_leaf *sl, silofs_lba_t lba)
{
	return (size_t)lba % ARRAY_SIZE(sl->sl_subref);
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
	return spleaf_bkr_by_voff(sl, vaddr->off);
}

static bool spleaf_is_allocated_at(const struct silofs_spmap_leaf *sl,
                                   const struct silofs_vaddr *vaddr)
{
	const size_t kbn = kbn_of(vaddr);
	const size_t nkb = nkbs_of(vaddr);
	const struct silofs_bk_ref *bkr;

	bkr = spleaf_bkr_by_vaddr(sl, vaddr);
	return bkr_test_allocated_at(bkr, kbn, nkb);
}

static bool spleaf_has_allocated_with(const struct silofs_spmap_leaf *sl,
                                      const struct silofs_vaddr *vaddr)
{
	const struct silofs_bk_ref *bkr = spleaf_bkr_by_vaddr(sl, vaddr);

	return bkr_allocated(bkr) > 0;
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

static size_t spleaf_refcnt_at(const struct silofs_spmap_leaf *sl, loff_t voff)
{
	const struct silofs_bk_ref *bkr = spleaf_bkr_by_voff(sl, voff);

	return bkr_refcnt(bkr);
}

static size_t
spleaf_allocated_at(const struct silofs_spmap_leaf *sl, silofs_lba_t lba)
{
	const struct silofs_bk_ref *bkr = spleaf_bkr_by_lba(sl, lba);

	return bkr_allocated(bkr);
}

static void spleaf_set_allocated_at(struct silofs_spmap_leaf *sl,
                                    const struct silofs_vaddr *vaddr)
{
	const size_t kbn = kbn_of(vaddr);
	const size_t nkb = nkbs_of(vaddr);
	struct silofs_bk_ref *bkr = spleaf_bkr_by_vaddr(sl, vaddr);

	bkr_inc_refcnt(bkr, nkb);
	bkr_set_allocated_at(bkr, kbn, nkb);
}

static void spleaf_add_allocated_at(struct silofs_spmap_leaf *sl,
                                    const struct silofs_vaddr *vaddr)
{
	const size_t kbn = kbn_of(vaddr);
	const size_t nkb = nkbs_of(vaddr);
	struct silofs_bk_ref *bkr = spleaf_bkr_by_vaddr(sl, vaddr);

	silofs_assert(bkr_test_allocated_at(bkr, kbn, nkb));
	bkr_inc_refcnt(bkr, nkb);
}

static void spleaf_dec_allocated_at(struct silofs_spmap_leaf *sl,
                                    const struct silofs_vaddr *vaddr)
{
	const size_t kbn = kbn_of(vaddr);
	const size_t nkb = nkbs_of(vaddr);
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

static void spleaf_main_blobid(const struct silofs_spmap_leaf *sl,
                               struct silofs_blobid *out_blobid)
{
	silofs_blobid40b_parse(&sl->sl_main_blobid, out_blobid);
}

static void spleaf_set_main_blobid(struct silofs_spmap_leaf *sl,
                                   const struct silofs_blobid *blobid)
{
	silofs_blobid40b_set(&sl->sl_main_blobid, blobid);
}

static void spleaf_bind_bks_to_main(struct silofs_spmap_leaf *sl)
{
	struct silofs_blobid blobid;
	struct silofs_bk_ref *bkr = NULL;
	const size_t nslots = ARRAY_SIZE(sl->sl_subref);

	spleaf_main_blobid(sl, &blobid);
	for (size_t slot = 0; slot < nslots; ++slot) {
		bkr = spleaf_subref_at(sl, slot);
		bkr_set_uref_blobid(bkr, &blobid);
	}
}

static size_t spleaf_calc_total_usecnt(const struct silofs_spmap_leaf *sl)
{
	const struct silofs_bk_ref *bkr = NULL;
	const size_t nslots = ARRAY_SIZE(sl->sl_subref);
	size_t usecnt_sum = 0;

	for (size_t slot = 0; slot < nslots; ++slot) {
		bkr = spleaf_subref_at(sl, slot);
		if (bkr_refcnt(bkr)) {
			usecnt_sum += bkr_usecnt(bkr);
		}
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
	struct silofs_blobid blobid;

	spleaf_main_blobid(sl, &blobid);
	silofs_bkaddr_by_off(out_bkaddr, &blobid, voff);
}

static void spleaf_clone_subrefs(struct silofs_spmap_leaf *sl,
                                 const struct silofs_spmap_leaf *sl_other)
{
	struct silofs_bk_ref *bkr;
	const struct silofs_bk_ref *bkr_other;
	const size_t nslots = ARRAY_SIZE(sl->sl_subref);

	for (size_t slot = 0; slot < nslots; ++slot) {
		bkr = spleaf_subref_at(sl, slot);
		bkr_other = spleaf_subref_at(sl_other, slot);
		bkr_clone_from(bkr, bkr_other);
	}
}

static void spleaf_resolve_ubk(const struct silofs_spmap_leaf *sl, loff_t voff,
                               struct silofs_bkaddr *out_bkaddr)
{
	struct silofs_blobid blobid;
	const struct silofs_bk_ref *bkr = spleaf_bkr_by_voff(sl, voff);

	bkr_uref_blobid(bkr, &blobid);
	if (blobid_isnull(&blobid)) {
		bkaddr_reset(out_bkaddr);
	} else {
		silofs_bkaddr_by_off(out_bkaddr, &blobid, voff);
	}
}

static void spleaf_rebind_ubk(struct silofs_spmap_leaf *sl, loff_t voff,
                              const struct silofs_bkaddr *bkaddr)
{
	struct silofs_bk_ref *bkr = spleaf_bkr_by_voff(sl, voff);

	bkr_set_uref_blobid(bkr, &bkaddr->blobid);

	silofs_assert_gt(bkr_refcnt(bkr), 0);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_unode_info *sli_ui(struct silofs_spleaf_info *sli)
{
	return &sli->sl_ui;
}

const struct silofs_uaddr *
silofs_sli_uaddr(const struct silofs_spleaf_info *sli)
{
	return &sli->sl_ui.u_uaddr;
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
		return -ENOSPC;
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
	size_t nbytes_max;
	size_t nbytes;

	sli_vrange(sli, &vrange);
	nbytes_max = vrange.len;
	nbytes = stype_size(stype);

	return ((sli->sl_nused_bytes + nbytes) <= nbytes_max) ? 0 : -ENOSPC;
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
	spleaf_set_allocated_at(sl, vaddr);
	if (vaddr_isdata(vaddr)) {
		spleaf_set_unwritten_at(sl, vaddr);
	}
	sli_dirtify(sli);
}

void silofs_sli_reref_allocated_space(struct silofs_spleaf_info *sli,
                                      const struct silofs_vaddr *vaddr)
{
	spleaf_add_allocated_at(sli->sl, vaddr);
	sli_dirtify(sli);
}

void silofs_sli_unref_allocated_space(struct silofs_spleaf_info *sli,
                                      const struct silofs_vaddr *vaddr)
{
	struct silofs_spmap_leaf *sl = sli->sl;

	spleaf_dec_allocated_at(sl, vaddr);
	if (!spleaf_is_allocated_at(sl, vaddr)) {
		sli->sl_nused_bytes -= vaddr->len;
	}
	if (!spleaf_has_allocated_with(sl, vaddr)) {
		spleaf_renew_bk_at(sl, vaddr);
	}
	sli_dirtify(sli);
}

bool silofs_sli_has_shared_refcnt(const struct silofs_spleaf_info *sli,
                                  const struct silofs_vaddr *vaddr)
{
	const size_t refcnt = spleaf_refcnt_at(sli->sl, vaddr->off);

	return (refcnt > SILOFS_NKB_IN_BK);
}

bool silofs_sli_has_refs_at(const struct silofs_spleaf_info *sli,
                            const struct silofs_vaddr *vaddr)
{
	const size_t refcnt = spleaf_refcnt_at(sli->sl, vaddr->off);

	return (refcnt > 0);
}

bool silofs_sli_has_last_refcnt(const struct silofs_spleaf_info *sli,
                                const struct silofs_vaddr *vaddr)
{
	const size_t cnt = spleaf_refcnt_at(sli->sl, vaddr->off);
	const size_t nkb = nkbs_of(vaddr);

	return (nkb == cnt);
}

size_t silofs_sli_nallocated_at(const struct silofs_spleaf_info *sli,
                                const silofs_lba_t lba)
{
	return spleaf_allocated_at(sli->sl, lba);
}

static bool sli_is_allocated_at(const struct silofs_spleaf_info *sli,
                                const struct silofs_vaddr *vaddr)
{
	return spleaf_is_allocated_at(sli->sl, vaddr);
}

bool silofs_sli_has_allocated_space(const struct silofs_spleaf_info *sli,
                                    const struct silofs_vaddr *vaddr)
{
	return sli_is_allocated_at(sli, vaddr);
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
                          struct silofs_blobid *out_blobid)
{
	spleaf_main_blobid(sli->sl, out_blobid);
}

void silofs_sli_bind_main_blob(struct silofs_spleaf_info *sli,
                               const struct silofs_blobid *blobid)
{
	struct silofs_spmap_leaf *sl = sli->sl;

	spleaf_set_main_blobid(sl, blobid);
	spleaf_bind_bks_to_main(sl);
	sli_dirtify(sli);
}

bool silofs_sli_has_main_blob(const struct silofs_spleaf_info *sli,
                              const struct silofs_treeid *treeid)
{
	struct silofs_blobid blobid;

	silofs_sli_main_blob(sli, &blobid);
	if (blobid_size(&blobid) == 0) {
		return false;
	}
	if (!blobid_has_treeid(&blobid, treeid)) {
		return false;
	}
	return true;
}

void silofs_sli_clone_subrefs(struct silofs_spleaf_info *sli,
                              const struct silofs_spleaf_info *sli_other)
{
	sli->sl_nused_bytes = sli_other->sl_nused_bytes;
	spleaf_clone_subrefs(sli->sl, sli_other->sl);
}

void silofs_sli_resolve_main_ubk(const struct silofs_spleaf_info *sli,
                                 loff_t voff, struct silofs_bkaddr *out_bkaddr)
{
	spleaf_resolve_main_ubk(sli->sl, voff, out_bkaddr);
}

int silofs_sli_resolve_ubk(const struct silofs_spleaf_info *sli,
                           loff_t voff, struct silofs_bkaddr *out_bkaddr)
{
	if (!sli_is_inrange(sli, voff)) {
		return -SILOFS_ERANGE;
	}
	spleaf_resolve_ubk(sli->sl, voff, out_bkaddr);
	if (bkaddr_isnull(out_bkaddr)) {
		return -ENOENT;
	}
	return 0;
}

void silofs_sli_rebind_ubk(struct silofs_spleaf_info *sli, loff_t voff,
                           const struct silofs_bkaddr *bkaddr)
{
	spleaf_rebind_ubk(sli->sl, voff, bkaddr);
	sli_dirtify(sli);
}

void silofs_sli_seal_meta(struct silofs_spleaf_info *sli)
{
	silofs_ui_seal_meta(&sli->sl_ui);
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

const struct silofs_uaddr *
silofs_sni_uaddr(const struct silofs_spnode_info *sni)
{
	return &sni->sn_ui.u_uaddr;
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
	struct silofs_vrange vrange;

	vrange_of_spnode(&vrange, parent->height - 1, voff);
	spnode_init(sni->sn, &vrange);
	spnode_set_parent(sni->sn, parent);
	spnode_set_self(sni->sn, sni_uaddr(sni));
	sni_dirtify(sni);
}

void silofs_sni_update_staged(struct silofs_spnode_info *sni)
{
	sni->sn_nactive_subs = spnode_count_nactive(sni->sn);
}

enum silofs_height silofs_sni_height(const struct silofs_spnode_info *sni)
{
	const struct silofs_uaddr *uaddr = sni_uaddr(sni);

	return uaddr->height;
}

static enum silofs_height
sni_child_height(const struct silofs_spnode_info *sni) {
	return silofs_sni_height(sni) - 1;
}

static void sni_bind_subref(struct silofs_spnode_info *sni, loff_t voff,
                            const struct silofs_uaddr *uaddr)
{
	/* either we set new ulink or override upon clone */
	const bool bind_override = spnode_has_child_at(sni->sn, voff);

	spnode_set_ulink_of(sni->sn, voff, uaddr);
	sni_dirtify(sni);

	if (!bind_override) {
		silofs_assert_lt(sni->sn_nactive_subs, SILOFS_SPMAP_NCHILDS);
		sni->sn_nactive_subs++;
	}
}

void silofs_sni_bind_child_spleaf(struct silofs_spnode_info *sni,
                                  const struct silofs_spleaf_info *sli)
{
	struct silofs_vrange vrange;

	sli_vrange(sli, &vrange);
	sni_bind_subref(sni, vrange.beg, sli_uaddr(sli));
}

void silofs_sni_bind_child_spnode(struct silofs_spnode_info *sni,
                                  const struct silofs_spnode_info *sni_child)
{
	struct silofs_vrange vrange;
	const struct silofs_uaddr *uaddr;

	silofs_sni_vspace_range(sni_child, &vrange);

	uaddr = silofs_sni_uaddr(sni_child);
	sni_bind_subref(sni, vrange.beg, uaddr);
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
	const size_t child_height = sni_child_height(sni);

	if (child_height == SILOFS_HEIGHT_SPLEAF) {
		child_stype = SILOFS_STYPE_SPLEAF;
	} else {
		child_stype = SILOFS_STYPE_SPNODE;
	}
	return child_stype;
}

bool silofs_sni_has_child_at(const struct silofs_spnode_info *sni, loff_t voff)
{
	return spnode_has_child_at(sni->sn, voff);
}

int silofs_sni_subref_of(const struct silofs_spnode_info *sni, loff_t voff,
                         struct silofs_uaddr *out_uaddr)
{
	silofs_assert(sni_is_inrange(sni, voff));
	if (!sni_is_inrange(sni, voff)) {
		return -SILOFS_ERANGE;
	}
	spnode_ulink_of(sni->sn, voff, out_uaddr);
	if (uaddr_isnull(out_uaddr)) {
		return -ENOENT;
	}
	return 0;
}

void silofs_sni_main_blob(const struct silofs_spnode_info *sni,
                          struct silofs_blobid *out_blobid)
{
	spnode_main_blobid(sni->sn, out_blobid);
}

void silofs_sni_bind_main_blob(struct silofs_spnode_info *sni,
                               const struct silofs_blobid *blobid)
{
	spnode_set_main_blobid(sni->sn, blobid);
	sni_dirtify(sni);
}

bool silofs_sni_has_main_blob(const struct silofs_spnode_info *sni)
{
	struct silofs_blobid blobid;

	silofs_sni_main_blob(sni, &blobid);
	return (blobid_size(&blobid) > 0);
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
	const enum silofs_height child_height = sni_child_height(sni);

	silofs_vrange_of_spmap(&vrange, child_height, voff);
	return vrange.beg;
}

void silofs_sni_resolve_main_at(const struct silofs_spnode_info *sni,
                                loff_t voff, struct silofs_uaddr *out_uaddr)
{
	struct silofs_blobid blobid;
	const loff_t bpos = sni_bpos_of_child(sni, voff);
	const loff_t base = sni_base_voff_of_child(sni, voff);

	silofs_assert(sni_is_inrange(sni, voff));

	silofs_sni_main_blob(sni, &blobid);
	uaddr_setup(out_uaddr, &blobid, bpos,
	            sni_child_stype(sni), sni_child_height(sni), base);
}

void silofs_sni_clone_subrefs(struct silofs_spnode_info *sni,
                              const struct silofs_spnode_info *sni_other)
{
	spnode_clone_subrefs(sni->sn, sni_other->sn);
	sni->sn_nactive_subs = sni_other->sn_nactive_subs;
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
	size_t refcnt;

	refcnt = bkr_refcnt(bkr);
	if (refcnt >= INT_MAX) {
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
	for (size_t i = 0; i < ARRAY_SIZE(sl->sl_subref); ++i) {
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
	return oaddr_isvalid(&uaddr->oaddr) ? 0 : -SILOFS_EFSCORRUPTED;
}

static int verify_spmap_ref(const struct silofs_spmap_ref *spr)
{
	struct silofs_uaddr uaddr;
	int err;

	spr_ulink(spr, &uaddr);
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
	size_t parent_height;

	spnode_parent(sn, &parent_uaddr);
	if (uaddr_isnull(&parent_uaddr)) {
		return -SILOFS_EFSCORRUPTED;
	}
	parent_height = parent_uaddr.height;
	if (parent_height != (height + 1)) {
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
	height = uaddr.height;
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
	for (size_t i = 0; i < ARRAY_SIZE(sn->sn_subref); ++i) {
		err = verify_spmap_ref(&sn->sn_subref[i]);
		if (err) {
			return err;
		}
	}
	return 0;
}

