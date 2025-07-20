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
#include <stdio.h>
#include "infra.h"
#include "str.h"
#include "crypt.h"
#include "offlba.h"
#include "htox.h"
#include "mtype.h"
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

static uint32_t lseg_vindex_of(loff_t voff, ssize_t lseg_size)
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
	.lsize = 0,
	.vindex = UINT32_MAX,
	.vspace = SILOFS_MTYPE_NONE,
	.height = SILOFS_HEIGHT_LAST,
	.mtype = SILOFS_MTYPE_NONE,
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
	return silofs_mtype_isnone(lsid->mtype) || (lsid->lsize == 0) ||
	       (lsid->vindex == UINT32_MAX);
}

bool silofs_lsid_has_blobid(const struct silofs_lsid *lsid,
                            const struct silofs_blobid *blobid)
{
	return silofs_blobid_isequal(&lsid->blobid, blobid);
}

loff_t silofs_lsid_pos(const struct silofs_lsid *lsid, loff_t off)
{
	const size_t size = silofs_lsid_size(lsid);

	return size ? silofs_off_remainder(off, size) : 0;
}

void silofs_lsid_reset(struct silofs_lsid *lsid)
{
	memset(lsid, 0, sizeof(*lsid));
	lsid->vindex = UINT32_MAX;
	lsid->lsize = 0;
	lsid->vspace = SILOFS_MTYPE_NONE;
	lsid->height = SILOFS_HEIGHT_NONE;
	lsid->mtype = SILOFS_MTYPE_NONE;
}

void silofs_lsid_assign(struct silofs_lsid *lsid,
                        const struct silofs_lsid *other)
{
	silofs_blobid_assign(&lsid->blobid, &other->blobid);
	lsid->vindex = other->vindex;
	lsid->lsize = other->lsize;
	lsid->vspace = other->vspace;
	lsid->height = other->height;
	lsid->mtype = other->mtype;
}

static long silofs_lsid_compare(const struct silofs_lsid *lsid1,
                                const struct silofs_lsid *lsid2)
{
	long cmp;

	cmp = silofs_blobid_compare(&lsid1->blobid, &lsid2->blobid);
	if (cmp) {
		return cmp;
	}
	cmp = (long)(lsid2->height) - (long)(lsid1->height);
	if (cmp) {
		return cmp;
	}
	cmp = (long)(lsid2->vindex) - (long)(lsid1->vindex);
	if (cmp) {
		return cmp;
	}
	cmp = (long)(lsid2->vspace) - (long)(lsid1->vspace);
	if (cmp) {
		return cmp;
	}
	cmp = (long)(lsid2->mtype) - (long)(lsid1->mtype);
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
	struct silofs_lsid48b lsid48b = { .lsize = 0 };
	const uint64_t seed1 = ((uint64_t)lsid->vspace) << 11;
	const uint64_t seed2 = (uint64_t)lsid->mtype;

	silofs_lsid48b_htox(&lsid48b, lsid);
	return silofs_hash_xxh64(&lsid48b, sizeof(lsid48b), seed1 | seed2);
}

void silofs_lsid_setup(struct silofs_lsid *lsid,
                       const struct silofs_blobid *blobid, loff_t voff,
                       enum silofs_mtype vspace, enum silofs_height height,
                       enum silofs_mtype mtype)
{
	const size_t lseg_size = height_to_lseg_size(height);

	silofs_blobid_assign(&lsid->blobid, blobid);
	lsid->lsize = lseg_size;
	lsid->vindex = lseg_vindex_of(voff, (ssize_t)lseg_size);
	lsid->height = height;
	lsid->vspace = vspace;
	lsid->mtype = mtype;
}

void silofs_lsid48b_reset(struct silofs_lsid48b *lsid48)
{
	memset(lsid48, 0, sizeof(*lsid48));
	lsid48->vindex = UINT32_MAX;
	lsid48->lsize = 0;
	lsid48->vspace = SILOFS_MTYPE_NONE;
	lsid48->height = SILOFS_HEIGHT_LAST;
	lsid48->mtype = SILOFS_MTYPE_NONE;
}

void silofs_lsid48b_htox(struct silofs_lsid48b *lsid48,
                         const struct silofs_lsid *lsid)
{
	memset(lsid48, 0, sizeof(*lsid48));
	silofs_blobid_assign(&lsid48->blobid, &lsid->blobid);
	lsid48->vindex = silofs_cpu_to_le32(lsid->vindex);
	lsid48->lsize = silofs_cpu_to_le32((uint32_t)lsid->lsize);
	lsid48->vspace = (uint8_t)lsid->vspace;
	lsid48->height = (uint8_t)lsid->height;
	lsid48->mtype = (uint8_t)lsid->mtype;
}

void silofs_lsid48b_xtoh(const struct silofs_lsid48b *lsid48,
                         struct silofs_lsid *lsid)
{
	silofs_blobid_assign(&lsid->blobid, &lsid48->blobid);
	lsid->vindex = silofs_le32_to_cpu(lsid48->vindex);
	lsid->lsize = silofs_le32_to_cpu(lsid48->lsize);
	lsid->vspace = (enum silofs_mtype)lsid48->vspace;
	lsid->height = (enum silofs_height)lsid48->height;
	lsid->mtype = (enum silofs_mtype)lsid48->mtype;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_laddr s_laddr_none = {
	.pos = SILOFS_OFF_NULL,
};

const struct silofs_laddr *silofs_laddr_none(void)
{
	return &s_laddr_none;
}

void silofs_laddr_setpos(struct silofs_laddr *laddr, loff_t off)
{
	const struct silofs_lsid *lsid = &laddr->lsid;

	if (lsid->lsize && !silofs_off_isnull(off)) {
		laddr->pos = silofs_lsid_pos(lsid, off);
	} else {
		laddr->pos = SILOFS_OFF_NULL;
	}
}

void silofs_laddr_setup(struct silofs_laddr *laddr,
                        const struct silofs_lsid *lsid, loff_t off)
{
	silofs_lsid_assign(&laddr->lsid, lsid);
	silofs_laddr_setpos(laddr, off);
}

void silofs_laddr_setup_lbk(struct silofs_laddr *laddr,
                            const struct silofs_lsid *lsid, loff_t off)
{
	const loff_t lbk_off =
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

enum silofs_mtype silofs_laddr_mtype(const struct silofs_laddr *laddr)
{
	return laddr->lsid.mtype;
}

size_t silofs_laddr_len(const struct silofs_laddr *laddr)
{
	return silofs_mtype_size(silofs_laddr_mtype(laddr));
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

void silofs_laddr_as_iv(const struct silofs_laddr *laddr,
                        struct silofs_iv *out_iv)
{
	union {
		struct silofs_laddr64b laddr64;
		uint8_t d[64];
	} u;

	STATICASSERT_EQ(sizeof(u), 64);
	STATICASSERT_EQ(4 * sizeof(out_iv->iv), sizeof(u.laddr64));
	STATICASSERT_EQ(4 * sizeof(out_iv->iv), sizeof(u));
	STATICASSERT_EQ(4 * ARRAY_SIZE(out_iv->iv), sizeof(u));

	silofs_laddr64b_htox(&u.laddr64, laddr);
	for (size_t i = 0; i < ARRAY_SIZE(out_iv->iv); ++i) {
		const size_t j = i % 8;

		out_iv->iv[i] = //
			u.d[j] ^ u.d[j + 16] ^ u.d[j + 32] ^ u.d[j + 48];
	}
}

void silofs_laddr64b_reset(struct silofs_laddr64b *laddr64)
{
	memset(laddr64, 0, sizeof(*laddr64));
	silofs_lsid48b_reset(&laddr64->lsid);
	laddr64->pos = 0;
}

void silofs_laddr64b_htox(struct silofs_laddr64b *laddr64,
                          const struct silofs_laddr *laddr)
{
	memset(laddr64, 0, sizeof(*laddr64));
	silofs_lsid48b_htox(&laddr64->lsid, &laddr->lsid);
	laddr64->pos = silofs_cpu_to_le32((uint32_t)(laddr->pos));
}

void silofs_laddr64b_xtoh(const struct silofs_laddr64b *laddr64,
                          struct silofs_laddr *laddr)
{
	silofs_lsid48b_xtoh(&laddr64->lsid, &laddr->lsid);
	laddr->pos = (loff_t)silofs_le32_to_cpu(laddr64->pos);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_laddr_repr {
	struct silofs_blobid blobid;
	uint32_t lsize;
	int32_t pos;
	uint32_t vindex;
	uint8_t vspace;
	uint8_t height;
	uint8_t mtype;
	uint8_t version;
};

static void
laddr_to_repr(const struct silofs_laddr *laddr, struct silofs_laddr_repr *repr)
{
	silofs_memzero(repr, sizeof(*repr));
	silofs_blobid_assign(&repr->blobid, &laddr->lsid.blobid);
	repr->lsize = (uint32_t)laddr->lsid.lsize;
	repr->pos = (int32_t)laddr->pos;
	repr->vindex = laddr->lsid.vindex;
	repr->vspace = (uint8_t)laddr->lsid.vspace;
	repr->height = (uint8_t)laddr->lsid.height;
	repr->mtype = (uint8_t)laddr->lsid.mtype;
	repr->version = 1;
}

static int laddr_from_repr(struct silofs_laddr *laddr,
                           const struct silofs_laddr_repr *repr)
{
	if (repr->version != 1) {
		return -SILOFS_EINVAL;
	}
	silofs_laddr_reset(laddr);
	silofs_blobid_assign(&laddr->lsid.blobid, &repr->blobid);
	laddr->lsid.lsize = repr->lsize;
	laddr->pos = repr->pos;
	laddr->lsid.vindex = repr->vindex;
	laddr->lsid.vspace = repr->vspace;
	laddr->lsid.height = repr->height;
	laddr->lsid.mtype = repr->mtype;
	if (!silofs_laddr_isvalid(laddr)) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

static void laddr_repr_blobid_to_str(const struct silofs_laddr_repr *repr,
                                     struct silofs_strbuf *sbuf)
{
	silofs_blobid_to_sbuf(&repr->blobid, sbuf);
}

static int laddr_repr_blobid_from_str(struct silofs_laddr_repr *repr,
                                      const struct silofs_strbuf *sbuf)
{
	struct silofs_strview sv;

	silofs_strview_init(&sv, sbuf->str);
	return silofs_blobid_from_str(&repr->blobid, &sv);
}

static void laddr_repr_meta_to_str(const struct silofs_laddr_repr *repr,
                                   struct silofs_strbuf *sbuf)
{
	sbuf->str[0] = silofs_nibble_to_ascii((int)repr->version);
	sbuf->str[1] = silofs_nibble_to_ascii((int)repr->height);
	silofs_byte_to_ascii(repr->vspace, &sbuf->str[2]);
	silofs_byte_to_ascii(repr->mtype, &sbuf->str[4]);
	sbuf->str[6] = '\0';
}

static void laddr_repr_meta_from_str(struct silofs_laddr_repr *repr,
                                     const struct silofs_strbuf *sbuf)
{
	repr->version = (uint8_t)silofs_ascii_to_nibble(sbuf->str[0]);
	repr->height = (uint8_t)silofs_ascii_to_nibble(sbuf->str[1]);
	silofs_ascii_to_byte(&sbuf->str[2], &repr->vspace);
	silofs_ascii_to_byte(&sbuf->str[4], &repr->mtype);
}

static void laddr_repr_to_str(const struct silofs_laddr_repr *repr,
                              struct silofs_strbuf *sbuf)
{
	struct silofs_strbuf blobid;
	struct silofs_strbuf meta;
	const size_t lim = sizeof(sbuf->str) - 1;
	int n;

	silofs_strbuf_reset(&blobid);
	silofs_strbuf_reset(&meta);

	laddr_repr_blobid_to_str(repr, &blobid);
	laddr_repr_meta_to_str(repr, &meta);
	n = snprintf(sbuf->str, lim, "%s:%s-%08x-%08x-%08x", blobid.str,
	             meta.str, repr->lsize, repr->vindex, repr->pos);
	if (n >= (int)lim) {
		n = (int)lim;
	}
	sbuf->str[n] = '\0';
}

static int laddr_repr_from_str(struct silofs_laddr_repr *repr,
                               const struct silofs_strbuf *sbuf)
{
	struct silofs_strbuf blobid;
	struct silofs_strbuf meta;
	uint32_t pos;
	int nscan;
	int err;

	silofs_strbuf_reset(&blobid);
	silofs_strbuf_reset(&meta);
	nscan = sscanf(sbuf->str, "%36s:%6s-%08x-%08x-%08x", blobid.str,
	               meta.str, &repr->lsize, &repr->vindex, &pos);
	if (nscan != 6) {
		return -SILOFS_EINVAL;
	}
	repr->pos = (int32_t)pos;
	err = laddr_repr_blobid_from_str(repr, &blobid);
	if (err) {
		return err;
	}
	laddr_repr_meta_from_str(repr, &meta);

	if (err) {
		return err;
	}
	return 0;
}

void silofs_laddr_to_ascii(const struct silofs_laddr *laddr,
                           struct silofs_strbuf *sbuf)
{
	struct silofs_laddr_repr repr = { .version = 1 };

	laddr_to_repr(laddr, &repr);
	laddr_repr_to_str(&repr, sbuf);
}

int silofs_laddr_from_ascii(struct silofs_laddr *laddr,
                            const struct silofs_strbuf *sbuf)
{
	struct silofs_laddr_repr repr = { .version = 0xFF };
	int err;

	err = laddr_repr_from_str(&repr, sbuf);
	if (err) {
		return err;
	}
	err = laddr_from_repr(laddr, &repr);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

union silofs_laddr_repr_u {
	struct silofs_laddr64b laddr64;
	uint8_t d[64];
} silofs_attr_aligned16;

void silofs_laddr_to_base64(const struct silofs_laddr *laddr,
                            struct silofs_strbuf *sbuf)
{
	union silofs_laddr_repr_u repr;
	size_t len = 0;

	STATICASSERT_EQ(sizeof(repr), 64);

	silofs_memzero(&repr, sizeof(repr));
	silofs_laddr64b_htox(&repr.laddr64, laddr);
	silofs_base64_encode(repr.d, sizeof(repr.d), sbuf->str,
	                     sizeof(sbuf->str) - 1, &len);
	sbuf->str[len] = '\0';
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_llink_setup(struct silofs_llink *llink,
                        const struct silofs_laddr *laddr,
                        const struct silofs_key *key)
{
	struct silofs_iv iv;

	silofs_laddr_as_iv(laddr, &iv);
	silofs_llink_setup2(llink, laddr, key, &iv);
}

void silofs_llink_setup2(struct silofs_llink *llink,
                         const struct silofs_laddr *laddr,
                         const struct silofs_key *key,
                         const struct silofs_iv *iv)
{
	silofs_laddr_assign(&llink->laddr, laddr);
	silofs_ivkey_setup(&llink->ivkey, key, iv);
}

void silofs_llink_assign(struct silofs_llink *llink,
                         const struct silofs_llink *other)
{
	silofs_laddr_assign(&llink->laddr, &other->laddr);
	silofs_ivkey_assign(&llink->ivkey, &other->ivkey);
}

void silofs_llink_reset(struct silofs_llink *llink)
{
	silofs_laddr_reset(&llink->laddr);
	silofs_ivkey_reset(&llink->ivkey);
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

	*out_len = val >> 4;
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

bool silofs_lrange_within(const struct silofs_lrange *lrange, loff_t off)
{
	return (lrange->beg <= off) && (off < lrange->end);
}

void silofs_lrange_setup(struct silofs_lrange *lrange,
                         enum silofs_height height, loff_t beg, loff_t end)
{
	lrange->beg = beg;
	lrange->end = end;
	lrange->height = height;
}

void silofs_lrange_setup_sub(struct silofs_lrange *lrange,
                             const struct silofs_lrange *other, loff_t beg)
{
	silofs_lrange_setup(lrange, other->height, beg, other->end);
}

void silofs_lrange_of_space(struct silofs_lrange *lrange,
                            enum silofs_height height, loff_t voff_base)
{
	const ssize_t span = silofs_height_to_space_span(height);
	const loff_t beg = silofs_off_align(voff_base, span);

	silofs_lrange_setup(lrange, height, beg, silofs_off_next(beg, span));
}

void silofs_lrange_of_spmap(struct silofs_lrange *lrange,
                            enum silofs_height height, loff_t voff_base)
{
	const ssize_t span = silofs_height_to_space_span(height);
	const loff_t beg = silofs_off_align(voff_base, span);

	silofs_lrange_setup(lrange, height, beg, silofs_off_next(beg, span));
}

static loff_t silofs_off_next_n(loff_t off, ssize_t len, size_t n)
{
	return silofs_off_align(off + ((ssize_t)n * len), len);
}

loff_t silofs_lrange_voff_at(const struct silofs_lrange *lrange, size_t slot)
{
	ssize_t span;
	loff_t voff;

	span = silofs_height_to_space_span(lrange->height - 1);
	voff = silofs_off_next_n(lrange->beg, span, slot);
	silofs_assert_le(voff, lrange->end);
	return voff;
}

loff_t silofs_lrange_next(const struct silofs_lrange *lrange, loff_t voff)
{
	ssize_t span;
	loff_t vnxt;

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
		.beg = SILOFS_OFF_NULL,
		.end = SILOFS_OFF_NULL,
		.height = SILOFS_HEIGHT_VDATA,
	};

	silofs_lrange128_htox(vrng, &lrange);
}

void silofs_lrange128_htox(struct silofs_lrange128 *lrange128,
                           const struct silofs_lrange *lrange)
{
	const size_t len = silofs_lrange_len(lrange);

	lrange128->beg = silofs_cpu_to_off(lrange->beg);
	lrange128->len_height = cpu_to_len_height(len, lrange->height);
}

void silofs_lrange128_xtoh(const struct silofs_lrange128 *lrange128,
                           struct silofs_lrange *lrange)
{
	loff_t beg;
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
