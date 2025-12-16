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
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include "infra.h"
#include "nodes.h"
#include "spmaps.h"

static void lrange_of_spleaf(struct silofs_lrange *lrange, off_t voff)
{
	silofs_lrange_of_spmap(lrange, SILOFS_HEIGHT_SPLEAF, voff);
}

static void lrange_of_spnode(struct silofs_lrange *lrange,
                             enum silofs_height height, off_t voff)
{
	silofs_lrange_of_spmap(lrange, height, voff);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
spr_uaddr(const struct silofs_spmap_ref *spr, struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr128b_xtoh(&spr->sr_uaddr, out_uaddr);
}

static void
spr_set_uaddr(struct silofs_spmap_ref *spr, const struct silofs_uaddr *uaddr)
{
	silofs_uaddr128b_htox(&spr->sr_uaddr, uaddr);
}

static void spr_reset(struct silofs_spmap_ref *spr)
{
	silofs_uaddr128b_reset(&spr->sr_uaddr);
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

static void spr_clone_from(struct silofs_spmap_ref       *spr,
                           const struct silofs_spmap_ref *spr_other)
{
	struct silofs_uaddr uaddr;

	spr_uaddr(spr_other, &uaddr);
	spr_set_uaddr(spr, &uaddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void spnode_parent(const struct silofs_spmap_node *spn,
                          struct silofs_uaddr            *out_uaddr)
{
	silofs_uaddr128b_xtoh(&spn->sn_parent, out_uaddr);
}

static void spnode_set_parent(struct silofs_spmap_node  *spn,
                              const struct silofs_uaddr *uaddr)
{
	silofs_uaddr128b_htox(&spn->sn_parent, uaddr);
}

static void spnode_self(const struct silofs_spmap_node *spn,
                        struct silofs_uaddr            *out_uaddr)
{
	silofs_uaddr128b_xtoh(&spn->sn_self, out_uaddr);
}

static void spnode_set_self(struct silofs_spmap_node  *spn,
                            const struct silofs_uaddr *uaddr)
{
	silofs_uaddr128b_htox(&spn->sn_self, uaddr);
}

static void spnode_lrange(const struct silofs_spmap_node *spn,
                          struct silofs_lrange           *out_lrange)
{
	silofs_lrange128_xtoh(&spn->sn_lrange, out_lrange);
}

static void spnode_set_lrange(struct silofs_spmap_node   *spn,
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
                             struct silofs_lsid             *out_lsid)
{
	silofs_lsid64b_xtoh(&spn->sn_main_lsid, out_lsid);
}

static void spnode_set_main_lsid(struct silofs_spmap_node *spn,
                                 const struct silofs_lsid *lsid)
{
	silofs_lsid64b_htox(&spn->sn_main_lsid, lsid);
}

static void
spnode_init(struct silofs_spmap_node *spn, const struct silofs_lrange *lrange)
{
	spnode_set_lrange(spn, lrange);
	silofs_lsid64b_reset(&spn->sn_main_lsid);
	silofs_uaddr128b_reset(&spn->sn_parent);
	silofs_uaddr128b_reset(&spn->sn_self);
	spr_initn(spn->sn_subrefs, ARRAY_SIZE(spn->sn_subrefs));
}

static size_t spnode_slot_of(const struct silofs_spmap_node *spn, off_t voff)
{
	const size_t         nslots = SILOFS_SPMAP_NCHILDS;
	struct silofs_lrange lrange;
	size_t               len;
	size_t               slot;
	ssize_t              roff;

	STATICASSERT_EQ(ARRAY_SIZE(spn->sn_subrefs), SILOFS_SPMAP_NCHILDS);

	spnode_lrange(spn, &lrange);
	len  = silofs_lrange_len(&lrange);
	roff = silofs_off_diff(lrange.beg, voff);
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
spnode_subref_of(const struct silofs_spmap_node *spn, off_t voff)
{
	return spnode_subref_at(spn, spnode_slot_of(spn, voff));
}

static void spnode_uaddr_of(const struct silofs_spmap_node *spn, off_t voff,
                            struct silofs_uaddr *out_uaddr)
{
	const struct silofs_spmap_ref *spr = spnode_subref_of(spn, voff);

	spr_uaddr(spr, out_uaddr);
}

static void spnode_set_uaddr_of(struct silofs_spmap_node *spn, off_t voff,
                                const struct silofs_uaddr *uaddr)
{
	struct silofs_spmap_ref *spr = spnode_subref_of(spn, voff);

	spr_set_uaddr(spr, uaddr);
}

static size_t spnode_count_nactive(const struct silofs_spmap_node *spn)
{
	const struct silofs_spmap_ref *spr = nullptr;
	const size_t nslots_max            = ARRAY_SIZE(spn->sn_subrefs);
	size_t       count                 = 0;

	for (size_t slot = 0; slot < nslots_max; ++slot) {
		spr = spnode_subref_at(spn, slot);
		if (!spr_isactive(spr)) {
			break;
		}
		++count;
	}
	return count;
}

static void spnode_clone_subrefs(struct silofs_spmap_node       *spn,
                                 const struct silofs_spmap_node *sn_other)
{
	struct silofs_spmap_ref       *spr       = nullptr;
	const struct silofs_spmap_ref *spr_other = nullptr;
	const size_t nslots_max                  = ARRAY_SIZE(spn->sn_subrefs);

	for (size_t slot = 0; slot < nslots_max; ++slot) {
		spr       = spnode_subref_at(spn, slot);
		spr_other = spnode_subref_at(sn_other, slot);
		spr_clone_from(spr, spr_other);
	}
}

static bool
spnode_has_child_at(const struct silofs_spmap_node *spn, off_t voff)
{
	const struct silofs_spmap_ref *spr = spnode_subref_of(spn, voff);

	return spr_isactive(spr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_lbk_ref *lbr_unconst(const struct silofs_lbk_ref *lbr)
{
	return unconst(lbr);
}

static void
lbr_subref(const struct silofs_lbk_ref *lbr, struct silofs_laddr *out_laddr)
{
	silofs_laddr96b_xtoh(&lbr->lbr_subref, out_laddr);
}

static void
lbr_set_subref(struct silofs_lbk_ref *lbr, const struct silofs_laddr *laddr)
{
	silofs_laddr96b_htox(&lbr->lbr_subref, laddr);
}

static void lbr_reset(struct silofs_lbk_ref *lbr)
{
	memset(lbr, 0, sizeof(*lbr));
	silofs_laddr96b_reset(&lbr->lbr_subref);
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

static void
lbr_make_lbk_vaddrs(const struct silofs_lbk_ref *lbr, enum silofs_mtype mtype,
                    off_t voff_base, struct silofs_vaddrs *out_vaddrs)
{
	struct silofs_laddr  laddr;
	struct silofs_vaddr *vaddr;
	size_t               sz;

	sz = silofs_mtype_size(mtype);
	silofs_assert_eq(sz, SILOFS_LBK_SIZE);

	out_vaddrs->count = 0;
	lbr_subref(lbr, &laddr);
	if (!silofs_laddr_isnull(&laddr)) {
		vaddr = &out_vaddrs->vaddr[out_vaddrs->count++];
		silofs_vaddr_setup(vaddr, mtype, voff_base);
	}
}

static void lbr_clone_from(struct silofs_lbk_ref       *lbr,
                           const struct silofs_lbk_ref *lbr_other)
{
	struct silofs_laddr laddr;

	lbr_subref(lbr_other, &laddr);
	lbr_set_subref(lbr, &laddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void spleaf_lrange(const struct silofs_spmap_leaf *spl,
                          struct silofs_lrange           *out_lrange)
{
	silofs_lrange128_xtoh(&spl->sl_lrange, out_lrange);
}

static void spleaf_set_lrange(struct silofs_spmap_leaf   *spl,
                              const struct silofs_lrange *lrange)
{
	silofs_lrange128_htox(&spl->sl_lrange, lrange);
}

static enum silofs_mtype spleaf_refmtype(const struct silofs_spmap_leaf *spl)
{
	const uint16_t refmtype = silofs_le16_to_cpu(spl->sl_refmtype);

	return (enum silofs_mtype)refmtype;
}

static void
spleaf_set_refmtype(struct silofs_spmap_leaf *spl, enum silofs_mtype refmtype)
{
	spl->sl_refmtype = silofs_cpu_to_le16((uint16_t)refmtype);
}

static void
spleaf_init(struct silofs_spmap_leaf *spl, const struct silofs_lrange *lrange,
            enum silofs_mtype refmtype)
{
	spleaf_set_lrange(spl, lrange);
	spleaf_set_refmtype(spl, refmtype);
	silofs_lsid64b_reset(&spl->sl_main_lsid);
	silofs_uaddr128b_reset(&spl->sl_parent);
	silofs_uaddr128b_reset(&spl->sl_self);
	lbr_init_arr(spl->sl_lbrs, ARRAY_SIZE(spl->sl_lbrs));
}

static void spleaf_parent(const struct silofs_spmap_leaf *spl,
                          struct silofs_uaddr            *out_uaddr)
{
	silofs_uaddr128b_xtoh(&spl->sl_parent, out_uaddr);
}

static void spleaf_set_parent(struct silofs_spmap_leaf  *spl,
                              const struct silofs_uaddr *uaddr)
{
	silofs_uaddr128b_htox(&spl->sl_parent, uaddr);
}

static void spleaf_self(const struct silofs_spmap_leaf *spl,
                        struct silofs_uaddr            *out_uaddr)
{
	silofs_uaddr128b_xtoh(&spl->sl_self, out_uaddr);
}

static void spleaf_set_self(struct silofs_spmap_leaf  *spl,
                            const struct silofs_uaddr *uaddr)
{
	silofs_uaddr128b_htox(&spl->sl_self, uaddr);
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

static size_t spleaf_slot_of(const struct silofs_spmap_leaf *spl, off_t voff)
{
	return spleaf_lba_slot(spl, silofs_off_to_lba(voff));
}

static struct silofs_lbk_ref *
spleaf_lbr_by_voff(const struct silofs_spmap_leaf *spl, off_t voff)
{
	return spleaf_lbr_at(spl, spleaf_slot_of(spl, voff));
}

static void spleaf_make_lbk_vaddrs(const struct silofs_spmap_leaf *spl,
                                   enum silofs_mtype mtype, off_t voff,
                                   struct silofs_vaddrs *out_vaddrs)
{
	const struct silofs_lbk_ref *lbr       = spleaf_lbr_by_voff(spl, voff);
	const off_t                  voff_base = silofs_off_align_to_lbk(voff);

	lbr_make_lbk_vaddrs(lbr, mtype, voff_base, out_vaddrs);
}

static void spleaf_main_lsid(const struct silofs_spmap_leaf *spl,
                             struct silofs_lsid             *out_lsid)
{
	silofs_lsid64b_xtoh(&spl->sl_main_lsid, out_lsid);
}

static void spleaf_set_main_lsid(struct silofs_spmap_leaf *spl,
                                 const struct silofs_lsid *lsid)
{
	silofs_lsid64b_htox(&spl->sl_main_lsid, lsid);
}

static void spleaf_main_child_at(const struct silofs_spmap_leaf *spl,
                                 size_t slot, struct silofs_laddr *out_laddr)
{
	struct silofs_lsid lsid = { .lsize = 0 };
	const off_t        pos  = silofs_lba_to_off((silofs_lba_t)slot);

	spleaf_main_lsid(spl, &lsid);
	silofs_laddr_setup_lbk(out_laddr, &lsid, pos);
}

static void spleaf_bind_lbk_to_main(struct silofs_spmap_leaf *spl, off_t voff)
{
	struct silofs_laddr    laddr;
	const size_t           slot = spleaf_slot_of(spl, voff);
	struct silofs_lbk_ref *lbr  = spleaf_lbr_at(spl, slot);

	spleaf_main_child_at(spl, slot, &laddr);
	lbr_set_subref(lbr, &laddr);
}

static void spleaf_resolve_main_lbk(const struct silofs_spmap_leaf *spl,
                                    off_t voff, struct silofs_laddr *out_laddr)
{
	struct silofs_lsid lsid;

	spleaf_main_lsid(spl, &lsid);
	silofs_laddr_setup_lbk(out_laddr, &lsid, voff);
}

static void spleaf_child_of(const struct silofs_spmap_leaf *spl, off_t voff,
                            struct silofs_laddr *out_laddr)
{
	const struct silofs_lbk_ref *lbr = spleaf_lbr_by_voff(spl, voff);

	lbr_subref(lbr, out_laddr);
}

static void spleaf_set_child_of(struct silofs_spmap_leaf *spl, off_t voff,
                                const struct silofs_laddr *laddr)
{
	struct silofs_lbk_ref *lbr = spleaf_lbr_by_voff(spl, voff);

	lbr_set_subref(lbr, laddr);
}

static void spleaf_clone_subrefs(struct silofs_spmap_leaf       *spl,
                                 const struct silofs_spmap_leaf *sl_other)
{
	struct silofs_lbk_ref       *lbr;
	const struct silofs_lbk_ref *lbr_other;

	for (size_t slot = 0; slot < ARRAY_SIZE(spl->sl_lbrs); ++slot) {
		lbr       = spleaf_lbr_at(spl, slot);
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

static enum silofs_mtype sli_refmtype(const struct silofs_spleaf_info *sli)
{
	return spleaf_refmtype(sli->sl);
}

enum silofs_mtype silofs_sli_refmtype(const struct silofs_spleaf_info *sli)
{
	return sli_refmtype(sli);
}

void silofs_sli_incref(struct silofs_spleaf_info *sli)
{
	if (likely(sli != nullptr)) {
		silofs_uni_incref(sli_uni(sli));
	}
}

void silofs_sli_decref(struct silofs_spleaf_info *sli)
{
	if (likely(sli != nullptr)) {
		silofs_uni_decref(sli_uni(sli));
	}
}

static void sli_dirtify(struct silofs_spleaf_info *sli)
{
	silofs_uni_dirtify(sli_uni(sli));
}

void silofs_sli_get_lrange(const struct silofs_spleaf_info *sli,
                           struct silofs_lrange            *out_lrange)
{
	spleaf_lrange(sli->sl, out_lrange);
}

void silofs_sli_setup_spawned(struct silofs_spleaf_info *sli,
                              const struct silofs_uaddr *parent,
                              enum silofs_mtype refmtype, off_t voff)
{
	struct silofs_lrange      lrange;
	struct silofs_spmap_leaf *sl = sli->sl;

	lrange_of_spleaf(&lrange, voff);
	spleaf_init(sl, &lrange, refmtype);
	spleaf_set_parent(sl, parent);
	spleaf_set_self(sl, silofs_sli_uaddr(sli));
	sli_dirtify(sli);
}

off_t silofs_sli_base_voff(const struct silofs_spleaf_info *sli)
{
	struct silofs_lrange lrange;

	silofs_sli_get_lrange(sli, &lrange);
	return lrange.beg;
}

static bool sli_is_inrange(const struct silofs_spleaf_info *sli, off_t voff)
{
	struct silofs_lrange lrange;

	silofs_sli_get_lrange(sli, &lrange);
	return (lrange.beg <= voff) && (voff < lrange.end);
}

void silofs_sli_lbk_vaddrs_at(const struct silofs_spleaf_info *sli,
                              const struct silofs_vaddr       *vaddr,
                              struct silofs_vaddrs            *out_vaddrs)
{
	const enum silofs_mtype refmtype = silofs_sli_refmtype(sli);

	silofs_assert_eq(refmtype, vaddr->mtype);

	spleaf_make_lbk_vaddrs(sli->sl, vaddr->mtype, vaddr->off, out_vaddrs);
}

void silofs_sli_main_lseg(const struct silofs_spleaf_info *sli,
                          struct silofs_lsid              *out_lsid)
{
	spleaf_main_lsid(sli->sl, out_lsid);
}

void silofs_sli_bind_main_lseg(struct silofs_spleaf_info *sli,
                               const struct silofs_lsid  *lsid)
{
	spleaf_set_main_lsid(sli->sl, lsid);
	sli_dirtify(sli);
}

void silofs_sli_clone_from(struct silofs_spleaf_info       *sli,
                           const struct silofs_spleaf_info *sli_other)
{
	spleaf_clone_subrefs(sli->sl, sli_other->sl);
	sli_dirtify(sli);
}

int silofs_sli_resolve_main_lbk(const struct silofs_spleaf_info *sli,
                                off_t voff, struct silofs_laddr *out_laddr)
{
	if (!sli_is_inrange(sli, voff)) {
		return -SILOFS_ERANGE;
	}
	spleaf_resolve_main_lbk(sli->sl, voff, out_laddr);
	return 0;
}

static int sli_resolve_child_lbk(const struct silofs_spleaf_info *sli,
                                 off_t voff, struct silofs_laddr *out_laddr)
{
	spleaf_child_of(sli->sl, voff, out_laddr);
	return !silofs_laddr_isnull(out_laddr) ? 0 : -SILOFS_ENOENT;
}

static bool sli_has_child_lbk_at(const struct silofs_spleaf_info *sli,
                                 const struct silofs_vaddr       *vaddr)
{
	struct silofs_laddr laddr;

	return (sli_resolve_child_lbk(sli, vaddr->off, &laddr) == 0);
}

bool silofs_sli_has_child_lbk_at(const struct silofs_spleaf_info *sli,
                                 const struct silofs_vaddr       *vaddr)
{
	bool ret = false;

	if (sli_is_inrange(sli, vaddr->off)) {
		ret = sli_has_child_lbk_at(sli, vaddr);
	}
	return ret;
}

int silofs_sli_resolve_child(const struct silofs_spleaf_info *sli, off_t voff,
                             struct silofs_laddr *out_laddr)
{
	int err;

	if (!sli_is_inrange(sli, voff)) {
		return -SILOFS_ERANGE;
	}
	err = sli_resolve_child_lbk(sli, voff, out_laddr);
	if (err) {
		return err;
	}
	silofs_laddr_setpos(out_laddr, voff);
	return 0;
}

int silofs_sli_require_child(struct silofs_spleaf_info *sli,
                             const struct silofs_vaddr *vaddr, bool *out_new)
{
	*out_new = false;
	if (!sli_is_inrange(sli, vaddr->off)) {
		return -SILOFS_ERANGE;
	}
	if (sli_has_child_lbk_at(sli, vaddr)) {
		return 0;
	}
	spleaf_bind_lbk_to_main(sli->sl, vaddr->off);
	sli_dirtify(sli);
	*out_new = true;
	return 0;
}

void silofs_sli_bind_child(struct silofs_spleaf_info *sli, off_t voff,
                           const struct silofs_laddr *laddr)
{
	spleaf_set_child_of(sli->sl, voff, laddr);
	sli_dirtify(sli);
}

static void lmap_append_entry(struct silofs_spmap_lmap  *lmap,
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
	off_t end1;

	if (!silofs_lsid_isequal(&laddr1->lsid, &laddr2->lsid)) {
		return false;
	}
	end1 = silofs_off_end(laddr1->pos, len1);
	if (end1 != laddr2->pos) {
		return false;
	}
	if (end1 > (ssize_t)laddr2->lsid.lsize) {
		return false;
	}
	return true;
}

static bool lmap_may_append_length(const struct silofs_spmap_lmap *lmap,
                                   const struct silofs_laddr      *laddr2)
{
	const struct silofs_laddr *laddr1;
	size_t                     len1;
	bool                       ret = false;

	if (lmap->cnt > 0) {
		laddr1 = &lmap->laddr[lmap->cnt - 1];
		len1   = lmap->len[lmap->cnt - 1];
		ret    = is_consecutive_laddrs(laddr1, len1, laddr2);
	}
	return ret;
}

static void lmap_append(struct silofs_spmap_lmap  *lmap,
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
                             struct silofs_spmap_lmap        *out_lmap)
{
	struct silofs_laddr             laddr  = { .pos = -1 };
	const struct silofs_spmap_leaf *sl     = sli->sl;
	const struct silofs_lbk_ref    *lbr    = nullptr;
	const size_t                    nslots = ARRAY_SIZE(sl->sl_lbrs);

	STATICASSERT_EQ(ARRAY_SIZE(out_lmap->laddr), ARRAY_SIZE(sl->sl_lbrs));

	out_lmap->cnt = 0;
	for (size_t slot = 0; slot < nslots; ++slot) {
		lbr = spleaf_lbr_at(sl, slot);
		lbr_subref(lbr, &laddr);
		if (silofs_laddr_isnull(&laddr)) {
			continue;
		}
		lmap_append(out_lmap, &laddr, SILOFS_LBK_SIZE);
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_unode_info *sni_uni(const struct silofs_spnode_info *sni)
{
	return silofs_unconst(&sni->sn_uni);
}

static void sni_dirtify(struct silofs_spnode_info *sni)
{
	silofs_uni_dirtify(sni_uni(sni));
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
	if (likely(sni != nullptr)) {
		silofs_uni_incref(sni_uni(sni));
	}
}

void silofs_sni_decref(struct silofs_spnode_info *sni)
{
	if (likely(sni != nullptr)) {
		silofs_uni_decref(sni_uni(sni));
	}
}

void silofs_sni_setup_spawned(struct silofs_spnode_info *sni,
                              const struct silofs_uaddr *parent, off_t voff)
{
	struct silofs_lrange     lrange        = { .beg = -1, .end = -1 };
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

void silofs_sni_bind_child(struct silofs_spnode_info *sni, off_t voff,
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

static bool sni_is_inrange(const struct silofs_spnode_info *sni, off_t voff)
{
	struct silofs_lrange lrange;

	silofs_sni_vspace_range(sni, &lrange);
	return (lrange.beg <= voff) && (voff < lrange.end);
}

void silofs_sni_vspace_range(const struct silofs_spnode_info *sni,
                             struct silofs_lrange            *out_lrange)
{
	spnode_lrange(sni->sn, out_lrange);
}

void silofs_sni_active_lrange(const struct silofs_spnode_info *sni,
                              struct silofs_lrange            *out_lrange)
{
	struct silofs_lrange lrange;
	size_t               nform_size;
	ssize_t              span;

	silofs_sni_vspace_range(sni, &lrange);
	span       = silofs_height_to_space_span(lrange.height - 1);
	nform_size = sni->sn_nactive_subs * (size_t)span;
	silofs_lrange_setup(out_lrange, lrange.height, lrange.beg,
	                    silofs_off_end(lrange.beg, nform_size));
}

off_t silofs_sni_base_voff(const struct silofs_spnode_info *sni)
{
	struct silofs_lrange lrange;

	silofs_sni_vspace_range(sni, &lrange);
	return lrange.beg;
}

static enum silofs_mtype sni_child_mtype(const struct silofs_spnode_info *sni)
{
	enum silofs_mtype child_mtype;
	const size_t      child_height = sni_sub_height(sni);

	if (child_height == SILOFS_HEIGHT_SPLEAF) {
		child_mtype = SILOFS_MTYPE_SPLEAF;
	} else {
		child_mtype = SILOFS_MTYPE_SPNODE;
	}
	return child_mtype;
}

static void sni_get_uaddr_of(const struct silofs_spnode_info *sni, off_t voff,
                             struct silofs_uaddr *out_uaddr)
{
	spnode_uaddr_of(sni->sn, voff, out_uaddr);
}

int silofs_sni_resolve_child(const struct silofs_spnode_info *sni, off_t voff,
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
                          struct silofs_lsid              *out_lsid)
{
	spnode_main_lsid(sni->sn, out_lsid);
}

void silofs_sni_bind_main_lseg(struct silofs_spnode_info *sni,
                               const struct silofs_lsid  *lsid)
{
	spnode_set_main_lsid(sni->sn, lsid);
	sni_dirtify(sni);
}

static off_t
sni_bpos_of_child(const struct silofs_spnode_info *sni, off_t voff)
{
	const size_t spmap_size = SILOFS_SPMAP_SIZE;
	const size_t slot       = spnode_slot_of(sni->sn, voff);

	return (off_t)(slot * spmap_size);
}

static off_t
sni_base_voff_of_child(const struct silofs_spnode_info *sni, off_t voff)
{
	struct silofs_lrange     lrange;
	const enum silofs_height child_height = sni_sub_height(sni);

	silofs_lrange_of_spmap(&lrange, child_height, voff);
	return lrange.beg;
}

void silofs_sni_resolve_main(const struct silofs_spnode_info *sni, off_t voff,
                             struct silofs_uaddr *out_uaddr)
{
	struct silofs_lsid lsid;
	const off_t        bpos        = sni_bpos_of_child(sni, voff);
	const off_t        base        = sni_base_voff_of_child(sni, voff);
	enum silofs_mtype  child_mtype = sni_child_mtype(sni);

	silofs_sni_main_lseg(sni, &lsid);

	silofs_uaddr_setup(out_uaddr, &lsid, bpos, base);

	silofs_unused(child_mtype);
}

void silofs_sni_clone_from(struct silofs_spnode_info       *sni,
                           const struct silofs_spnode_info *sni_other)
{
	spnode_clone_subrefs(sni->sn, sni_other->sn);
	sni->sn_nactive_subs = sni_other->sn_nactive_subs;
	sni_dirtify(sni);
}

void silofs_sni_resolve_lmap(const struct silofs_spnode_info *sni,
                             struct silofs_spmap_lmap        *out_lmap)
{
	struct silofs_uaddr             uaddr = { .voff = -1 };
	const struct silofs_spmap_node *sn    = sni->sn;
	const struct silofs_spmap_ref  *spr   = nullptr;
	size_t                          len;

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

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

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
	struct silofs_laddr laddr;

	lbr_subref(lbr, &laddr);
	if (silofs_laddr_isnull(&laddr)) {
		return 0;
	}
	if (laddr.pos > INT_MAX) {
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
	if (silofs_uaddr_mtype(&uaddr) != SILOFS_MTYPE_SPNODE) {
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
	if (silofs_uaddr_mtype(&uaddr) != SILOFS_MTYPE_SPLEAF) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

int silofs_verify_spmap_leaf(const struct silofs_spmap_leaf *sl)
{
	const struct silofs_lbk_ref *lbr;
	int                          err;

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
	int                 err;

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
	struct silofs_uaddr      parent_uaddr;
	const enum silofs_height height_max = SILOFS_HEIGHT_SUPER - 1;
	const enum silofs_height height     = spnode_heigth(sn);
	enum silofs_mtype        parent_mtype;
	enum silofs_height       parent_height;

	spnode_parent(sn, &parent_uaddr);
	if (silofs_uaddr_isnull(&parent_uaddr)) {
		return -SILOFS_EFSCORRUPTED;
	}
	parent_height = silofs_uaddr_height(&parent_uaddr);
	if (parent_height != (height + 1)) {
		return -SILOFS_EFSCORRUPTED;
	}
	parent_mtype = silofs_uaddr_mtype(&parent_uaddr);
	if ((height == height_max) && !silofs_mtype_issuper(parent_mtype)) {
		return -SILOFS_EFSCORRUPTED;
	}
	if ((height < height_max) && !silofs_mtype_isspnode(parent_mtype)) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int verify_spmap_node_self(const struct silofs_spmap_node *sn)
{
	struct silofs_uaddr uaddr;
	enum silofs_height  height;
	enum silofs_mtype   mtype;
	int                 err;

	spnode_self(sn, &uaddr);
	if (silofs_uaddr_isnull(&uaddr)) {
		return -SILOFS_EFSCORRUPTED;
	}
	mtype = silofs_uaddr_mtype(&uaddr);
	if (!silofs_mtype_isspnode(mtype)) {
		return -SILOFS_EFSCORRUPTED;
	}
	height = silofs_uaddr_height(&uaddr);
	err    = verify_spnode_height(height);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_verify_spmap_node(const struct silofs_spmap_node *sn)
{
	struct silofs_lrange lrange;
	enum silofs_height   height;
	ssize_t              lrange_len;
	ssize_t              height_len;
	int                  err;

	height = spnode_heigth(sn);
	err    = verify_spnode_height(height);
	if (err) {
		log_err("bad spnode height: height=%d", height);
		return err;
	}
	spnode_lrange(sn, &lrange);
	lrange_len = silofs_off_len(lrange.beg, lrange.end);
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
