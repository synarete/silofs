/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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
#include <stdlib.h>
#include <stdio.h>
#include "infra.h"
#include "str.h"
#include "offlba.h"
#include "htox.h"
#include "stype.h"
#include "blobid.h"
#include "laddr.h"

static size_t height_to_lseg_size(enum silofs_height height)
{
	size_t elemsz = 0;
	size_t nelems = 1;

	switch (height) {
	case SILOFS_HEIGHT_VDATA:
		elemsz = SILOFS_LBK_SIZE;
		nelems = SILOFS_SPMAP_NCHILDS;
		break;
	case SILOFS_HEIGHT_SPLEAF:
	case SILOFS_HEIGHT_SPNODE1:
	case SILOFS_HEIGHT_SPNODE2:
	case SILOFS_HEIGHT_SPNODE3:
	case SILOFS_HEIGHT_SPNODE4:
		elemsz = SILOFS_SPMAP_SIZE;
		nelems = SILOFS_SPMAP_NCHILDS;
		break;
	case SILOFS_HEIGHT_SUPER:
		elemsz = SILOFS_SB_SIZE;
		break;
	case SILOFS_HEIGHT_BOOT:
		elemsz = SILOFS_MBR_SIZE;
		break;
	case SILOFS_HEIGHT_NONE:
	case SILOFS_HEIGHT_LAST:
	default:
		elemsz = 0;
		break;
	}
	return silofs_min(elemsz * nelems, SILOFS_LSEG_SIZE_MAX);
}

static uint32_t lseg_vindex_of(off_t voff, ssize_t lseg_size)
{
	int64_t lseg_index = 0;

	if (lseg_size > 0) {
		lseg_index = silofs_off_align(voff, lseg_size) / lseg_size;
	}
	silofs_assert_lt(lseg_index, INT32_MAX);
	silofs_assert_ge(lseg_index, 0);
	return (uint32_t)lseg_index;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_lsid s_silofs_lsid_none = {
	.lsize  = 0,
	.vindex = UINT32_MAX,
};

const struct silofs_lsid *silofs_lsid_none(void)
{
	return &s_silofs_lsid_none;
}

size_t silofs_lsid_size(const struct silofs_lsid *lsid)
{
	return lsid->lsize;
}

bool silofs_lsid_isnull(const struct silofs_lsid *lsid)
{
	return (lsid->lsize == 0) || (lsid->vindex == UINT32_MAX);
}

bool silofs_lsid_has_blobid(const struct silofs_lsid *lsid,
                            const struct silofs_blobid *blobid)
{
	return silofs_blobid_isequal(&lsid->blobid, blobid);
}

bool silofs_lsid_has_layerid(const struct silofs_lsid *lsid,
                             const struct silofs_layerid *layerid)
{
	return silofs_layerid_isequal(&lsid->blobid.layerid, layerid);
}

off_t silofs_lsid_pos(const struct silofs_lsid *lsid, off_t off)
{
	const size_t size = silofs_lsid_size(lsid);

	return size ? silofs_off_remainder(off, size) : 0;
}

void silofs_lsid_reset(struct silofs_lsid *lsid)
{
	memset(lsid, 0, sizeof(*lsid));
	lsid->vindex = UINT32_MAX;
	lsid->lsize  = 0;
}

void silofs_lsid_assign(struct silofs_lsid *lsid,
                        const struct silofs_lsid *other)
{
	silofs_blobid_assign(&lsid->blobid, &other->blobid);
	lsid->vindex = other->vindex;
	lsid->lsize  = other->lsize;
}

static long silofs_lsid_compare(const struct silofs_lsid *lsid1,
                                const struct silofs_lsid *lsid2)
{
	long cmp;

	cmp = silofs_blobid_compare(&lsid1->blobid, &lsid2->blobid);
	if (cmp) {
		return cmp;
	}
	cmp = (long)(lsid2->vindex) - (long)(lsid1->vindex);
	if (cmp) {
		return cmp;
	}
	cmp = (long)(lsid2->lsize) - (long)(lsid1->lsize);
	if (cmp) {
		return cmp;
	}
	return 0;
}

bool silofs_lsid_isequal(const struct silofs_lsid *lsid,
                         const struct silofs_lsid *other)
{
	return silofs_lsid_compare(lsid, other) == 0;
}

uint64_t silofs_lsid_hash64(const struct silofs_lsid *lsid)
{
	struct silofs_lsid64b lsid64b = { .lsize = 0 };

	silofs_lsid64b_htox(&lsid64b, lsid);
	return silofs_xxh64(&lsid64b, sizeof(lsid64b), 0);
}

void silofs_lsid_setup(struct silofs_lsid *lsid,
                       const struct silofs_blobid *blobid, off_t off)
{
	const size_t lseg_size = height_to_lseg_size(blobid->height);

	silofs_blobid_assign(&lsid->blobid, blobid);
	lsid->lsize  = lseg_size;
	lsid->vindex = lseg_vindex_of(off, (ssize_t)lseg_size);
}

void silofs_lsid64b_reset(struct silofs_lsid64b *lsid64)
{
	memset(lsid64, 0, sizeof(*lsid64));
	lsid64->vindex = UINT32_MAX;
	lsid64->lsize  = 0;
}

void silofs_lsid64b_htox(struct silofs_lsid64b *lsid64,
                         const struct silofs_lsid *lsid)
{
	memset(lsid64, 0, sizeof(*lsid64));
	silofs_blobid56b_htox(&lsid64->blobid56b, &lsid->blobid);
	lsid64->vindex = silofs_cpu_to_le32(lsid->vindex);
	lsid64->lsize  = silofs_cpu_to_le32((uint32_t)lsid->lsize);
}

void silofs_lsid64b_xtoh(const struct silofs_lsid64b *lsid64,
                         struct silofs_lsid *lsid)
{
	silofs_blobid56b_xtoh(&lsid64->blobid56b, &lsid->blobid);
	lsid->vindex = silofs_le32_to_cpu(lsid64->vindex);
	lsid->lsize  = silofs_le32_to_cpu(lsid64->lsize);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_laddr s_laddr_none = {
	.pos = SILOFS_OFF_NULL,
};

const struct silofs_laddr *silofs_laddr_none(void)
{
	return &s_laddr_none;
}

void silofs_laddr_setpos(struct silofs_laddr *laddr, off_t off)
{
	const struct silofs_lsid *lsid = &laddr->lsid;

	if (lsid->lsize && !silofs_off_isnull(off)) {
		laddr->pos = silofs_lsid_pos(lsid, off);
	} else {
		laddr->pos = SILOFS_OFF_NULL;
	}
}

void silofs_laddr_setup(struct silofs_laddr *laddr,
                        const struct silofs_lsid *lsid, off_t off)
{
	silofs_lsid_assign(&laddr->lsid, lsid);
	silofs_laddr_setpos(laddr, off);
}

void silofs_laddr_setup_lbk(struct silofs_laddr *laddr,
                            const struct silofs_lsid *lsid, off_t off)
{
	const off_t lbk_off =
		!silofs_off_isnull(off) ? silofs_off_align_to_lbk(off) : off;

	silofs_laddr_setup(laddr, lsid, lbk_off);
}

void silofs_laddr_reset(struct silofs_laddr *laddr)
{
	silofs_lsid_reset(&laddr->lsid);
	laddr->pos = SILOFS_OFF_NULL;
}

void silofs_laddr_assign(struct silofs_laddr *laddr,
                         const struct silofs_laddr *other)
{
	silofs_lsid_assign(&laddr->lsid, &other->lsid);
	laddr->pos = other->pos;
}

enum silofs_vtype silofs_laddr_vtype(const struct silofs_laddr *laddr)
{
	return laddr->lsid.blobid.stype.vtype;
}

size_t silofs_laddr_len(const struct silofs_laddr *laddr)
{
	return silofs_vtype_size(silofs_laddr_vtype(laddr));
}

off_t silofs_laddr_end(const struct silofs_laddr *laddr)
{
	return silofs_off_end(laddr->pos, silofs_laddr_len(laddr));
}

long silofs_laddr_compare(const struct silofs_laddr *laddr1,
                          const struct silofs_laddr *laddr2)
{
	long cmp;

	cmp = silofs_lsid_compare(&laddr1->lsid, &laddr2->lsid);
	if (cmp) {
		return cmp;
	}
	cmp = (long)laddr1->pos - (long)laddr2->pos;
	if (cmp) {
		return cmp;
	}
	return 0;
}

bool silofs_laddr_isnull(const struct silofs_laddr *laddr)
{
	return silofs_off_isnull(laddr->pos) ||
	       silofs_lsid_isnull(&laddr->lsid);
}

bool silofs_laddr_isvalid(const struct silofs_laddr *laddr)
{
	const ssize_t lsid_size = (ssize_t)(laddr->lsid.lsize);

	return !silofs_laddr_isnull(laddr) && (laddr->pos <= lsid_size);
}

bool silofs_laddr_isequal(const struct silofs_laddr *laddr,
                          const struct silofs_laddr *other)
{
	return (laddr->pos == other->pos) &&
	       silofs_lsid_isequal(&laddr->lsid, &other->lsid);
}

void silofs_laddr96b_reset(struct silofs_laddr96b *laddr96)
{
	memset(laddr96, 0, sizeof(*laddr96));
	silofs_lsid64b_reset(&laddr96->lsid);
	laddr96->pos = 0;
}

void silofs_laddr96b_htox(struct silofs_laddr96b *laddr96,
                          const struct silofs_laddr *laddr)
{
	memset(laddr96, 0, sizeof(*laddr96));
	silofs_lsid64b_htox(&laddr96->lsid, &laddr->lsid);
	laddr96->pos = silofs_cpu_to_off(laddr->pos);
}

void silofs_laddr96b_xtoh(const struct silofs_laddr96b *laddr96,
                          struct silofs_laddr *laddr)
{
	silofs_lsid64b_xtoh(&laddr96->lsid, &laddr->lsid);
	laddr->pos = silofs_off_to_cpu(laddr96->pos);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void laddr_to_hash(const struct silofs_laddr *laddr,
                          const struct silofs_mdigest_hd *md,
                          struct silofs_hash256 *out_hash)
{
	struct silofs_laddr96b laddr96 = {};

	silofs_laddr96b_htox(&laddr96, laddr);
	silofs_sha3_256_of(md, &laddr96, sizeof(laddr96), out_hash);
}

static void
derive_iv_by_hash256(struct silofs_civ *iv, const struct silofs_hash256 *hash)
{
	STATICASSERT_LE(ARRAY_SIZE(iv->iv), ARRAY_SIZE(hash->hash));

	silofs_civ_reset(iv);
	for (size_t i = 0; i < ARRAY_SIZE(hash->hash); ++i) {
		const size_t j = i % ARRAY_SIZE(iv->iv);

		iv->iv[j] ^= (hash->hash[i] ^ (uint8_t)i);
	}
}

void silofs_derive_iv_by_laddr(const struct silofs_mdigest_hd *md,
                               const struct silofs_laddr *laddr,
                               struct silofs_civ *out_iv)
{
	struct silofs_hash256 hash = {};

	laddr_to_hash(laddr, md, &hash);
	derive_iv_by_hash256(out_iv, &hash);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_llink_setup(struct silofs_llink *llink,
                        const struct silofs_laddr *laddr,
                        const struct silofs_ckey *key,
                        const struct silofs_civ *iv)
{
	silofs_laddr_assign(&llink->laddr, laddr);
	silofs_civkey_setup(&llink->civkey, key, iv);
}

void silofs_llink_assign(struct silofs_llink *llink,
                         const struct silofs_llink *other)
{
	silofs_laddr_assign(&llink->laddr, &other->laddr);
	silofs_civkey_assign(&llink->civkey, &other->civkey);
}

void silofs_llink_reset(struct silofs_llink *llink)
{
	silofs_laddr_reset(&llink->laddr);
	silofs_civkey_reset(&llink->civkey);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint64_t cpu_to_len_height(size_t len, enum silofs_height height)
{
	uint64_t val;

	silofs_assert_le(len, (1L << 58));
	silofs_assert_lt(height, 0xF);
	silofs_assert_le(height, SILOFS_HEIGHT_SUPER);

	val = ((uint64_t)len << 4) | (height & 0xF);
	return silofs_cpu_to_le64(val);
}

static void len_height_to_cpu(uint64_t len_height, size_t *out_len,
                              enum silofs_height *out_height)
{
	const uint64_t val = silofs_le64_to_cpu(len_height);

	*out_len    = val >> 4;
	*out_height = (enum silofs_height)(val & 0xF);

	silofs_assert_le(*out_len, (1L << 58));
	silofs_assert_lt(*out_height, 0xF);
	silofs_assert_le(*out_height, SILOFS_HEIGHT_SUPER);
}

bool silofs_lrange_isvalid(const struct silofs_lrange *lrange)
{
	return ((lrange->beg >= 0) && (lrange->end >= 0) &&
	        (lrange->beg < lrange->end));
}

size_t silofs_lrange_len(const struct silofs_lrange *lrange)
{
	return silofs_off_ulen(lrange->beg, lrange->end);
}

bool silofs_lrange_within(const struct silofs_lrange *lrange, off_t off)
{
	return (lrange->beg <= off) && (off < lrange->end);
}

void silofs_lrange_setup(struct silofs_lrange *lrange,
                         enum silofs_height height, off_t beg, off_t end)
{
	lrange->beg    = beg;
	lrange->end    = end;
	lrange->height = height;
}

void silofs_lrange_setup_sub(struct silofs_lrange *lrange,
                             const struct silofs_lrange *other, off_t beg)
{
	silofs_lrange_setup(lrange, other->height, beg, other->end);
}

void silofs_lrange_of_space(struct silofs_lrange *lrange,
                            enum silofs_height height, off_t voff_base)
{
	const ssize_t span = silofs_height_to_space_span(height);
	const off_t beg    = silofs_off_align(voff_base, span);

	silofs_lrange_setup(lrange, height, beg, silofs_off_next(beg, span));
}

void silofs_lrange_of_spmap(struct silofs_lrange *lrange,
                            enum silofs_height height, off_t voff_base)
{
	const ssize_t span = silofs_height_to_space_span(height);
	const off_t beg    = silofs_off_align(voff_base, span);

	silofs_lrange_setup(lrange, height, beg, silofs_off_next(beg, span));
}

static off_t silofs_off_next_n(off_t off, ssize_t len, size_t n)
{
	return silofs_off_align(off + ((ssize_t)n * len), len);
}

off_t silofs_lrange_voff_at(const struct silofs_lrange *lrange, size_t slot)
{
	ssize_t span;
	off_t voff;

	span = silofs_height_to_space_span(lrange->height - 1);
	voff = silofs_off_next_n(lrange->beg, span, slot);
	silofs_assert_le(voff, lrange->end);
	return voff;
}

off_t silofs_lrange_next(const struct silofs_lrange *lrange, off_t voff)
{
	ssize_t span;
	off_t vnxt;

	if (unlikely(voff < lrange->beg)) {
		vnxt = lrange->beg;
	} else if (unlikely(voff >= lrange->end)) {
		vnxt = voff;
	} else {
		span = silofs_height_to_space_span(lrange->height - 1);
		vnxt = silofs_off_next(voff, span);
	}
	return vnxt;
}

void silofs_lrange128_reset(struct silofs_lrange128 *vrng)
{
	struct silofs_lrange lrange = {
		.beg    = SILOFS_OFF_NULL,
		.end    = SILOFS_OFF_NULL,
		.height = SILOFS_HEIGHT_VDATA,
	};

	silofs_lrange128_htox(vrng, &lrange);
}

void silofs_lrange128_htox(struct silofs_lrange128 *lrange128,
                           const struct silofs_lrange *lrange)
{
	const size_t len = silofs_lrange_len(lrange);

	lrange128->beg        = silofs_cpu_to_off(lrange->beg);
	lrange128->len_height = cpu_to_len_height(len, lrange->height);
}

void silofs_lrange128_xtoh(const struct silofs_lrange128 *lrange128,
                           struct silofs_lrange *lrange)
{
	off_t beg;
	size_t len;
	enum silofs_height height;

	beg = silofs_off_to_cpu(lrange128->beg);
	len_height_to_cpu(lrange128->len_height, &len, &height);
	silofs_lrange_setup(lrange, height, beg, silofs_off_end(beg, len));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

ssize_t silofs_height_to_space_span(enum silofs_height height)
{
	ssize_t shift_fac;
	ssize_t span;

	switch (height) {
	default:
	case SILOFS_HEIGHT_NONE:
	case SILOFS_HEIGHT_VDATA:
		shift_fac = 0;
		break;
	case SILOFS_HEIGHT_SPLEAF:
		shift_fac = 1;
		break;
	case SILOFS_HEIGHT_SPNODE1:
		shift_fac = 2;
		break;
	case SILOFS_HEIGHT_SPNODE2:
		shift_fac = 3;
		break;
	case SILOFS_HEIGHT_SPNODE3:
		shift_fac = 4;
		break;
	case SILOFS_HEIGHT_SPNODE4:
	case SILOFS_HEIGHT_SUPER:
	case SILOFS_HEIGHT_BOOT:
	case SILOFS_HEIGHT_LAST:
		shift_fac = 5;
		break;
	}
	span = (1L << (SILOFS_SPMAP_SHIFT * shift_fac)) * SILOFS_LBK_SIZE;
	silofs_assert_ge(span, SILOFS_LBK_SIZE);
	silofs_assert_le(span, SILOFS_VSPACE_SIZE_MAX);

	return span;
}
