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
#include <silofs/addr.h>

void silofs_lvid_generate(struct silofs_lvid *lvid)
{
	silofs_uuid_generate(&lvid->uuid);
}

void silofs_lvid_assign(struct silofs_lvid *lvid,
                        const struct silofs_lvid *other)
{
	silofs_uuid_assign(&lvid->uuid, &other->uuid);
}

static long lvid_compare(const struct silofs_lvid *lvid1,
                         const struct silofs_lvid *lvid2)
{
	return silofs_uuid_compare(&lvid1->uuid, &lvid2->uuid);
}

bool silofs_lvid_isequal(const struct silofs_lvid *lvid1,
                         const struct silofs_lvid *lvid2)
{
	return (lvid_compare(lvid1, lvid2) == 0);
}

void silofs_lvid_by_uuid(struct silofs_lvid *lvid,
                         const struct silofs_uuid *uuid)
{
	STATICASSERT_EQ(sizeof(lvid->uuid.uu), 16);

	silofs_uuid_assign(&lvid->uuid, uuid);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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
		elemsz = SILOFS_BOOTREC_SIZE;
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
		lseg_index = off_align(voff, lseg_size) / lseg_size;
	}
	silofs_assert_lt(lseg_index, INT32_MAX);
	silofs_assert_ge(lseg_index, 0);
	return (uint32_t)lseg_index;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_lsegid s_lsegid_none = {
	.size = 0,
	.vindex = 0,
	.vspace = SILOFS_LTYPE_NONE,
	.height = SILOFS_HEIGHT_LAST,
};

const struct silofs_lsegid *silofs_lsegid_none(void)
{
	return &s_lsegid_none;
}

size_t silofs_lsegid_size(const struct silofs_lsegid *lsegid)
{
	return lsegid->size;
}

bool silofs_lsegid_isnull(const struct silofs_lsegid *lsegid)
{
	return (lsegid->size == 0) || (lsegid->vindex == UINT32_MAX);
}

bool silofs_lsegid_has_lvid(const struct silofs_lsegid *lsegid,
                            const struct silofs_lvid *lvid)
{
	return silofs_lvid_isequal(&lsegid->lvid, lvid);
}

loff_t silofs_lsegid_pos(const struct silofs_lsegid *lsegid, loff_t off)
{
	const size_t size = silofs_lsegid_size(lsegid);

	return size ? silofs_off_remainder(off, size) : 0;
}

void silofs_lsegid_reset(struct silofs_lsegid *lsegid)
{
	memset(lsegid, 0, sizeof(*lsegid));
	lsegid->vindex = UINT32_MAX;
	lsegid->size = 0;
	lsegid->vspace = SILOFS_LTYPE_NONE;
	lsegid->height = SILOFS_HEIGHT_NONE;
}

void silofs_lsegid_assign(struct silofs_lsegid *lsegid,
                          const struct silofs_lsegid *other)
{
	silofs_lvid_assign(&lsegid->lvid, &other->lvid);
	lsegid->vindex = other->vindex;
	lsegid->size = other->size;
	lsegid->vspace = other->vspace;
	lsegid->height = other->height;
}

static long lsegid_compare(const struct silofs_lsegid *lsegid1,
                           const struct silofs_lsegid *lsegid2)
{
	long cmp;

	cmp = lvid_compare(&lsegid1->lvid, &lsegid2->lvid);
	if (cmp) {
		return cmp;
	}
	cmp = (long)(lsegid2->height) - (long)(lsegid1->height);
	if (cmp) {
		return cmp;
	}
	cmp = (long)(lsegid2->vindex) - (long)(lsegid1->vindex);
	if (cmp) {
		return cmp;
	}
	cmp = (long)(lsegid2->vspace) - (long)(lsegid1->vspace);
	if (cmp) {
		return cmp;
	}
	cmp = (long)(lsegid2->size) - (long)(lsegid1->size);
	if (cmp) {
		return cmp;
	}
	return 0;
}

bool silofs_lsegid_isequal(const struct silofs_lsegid *lsegid,
                           const struct silofs_lsegid *other)
{
	return lsegid_compare(lsegid, other) == 0;
}

uint64_t silofs_lsegid_hash64(const struct silofs_lsegid *lsegid)
{
	struct silofs_lsegid32b lsegid32b = { .size = 0 };
	const uint64_t seed = lsegid->vspace;

	silofs_lsegid32b_htox(&lsegid32b, lsegid);
	return silofs_hash_xxh64(&lsegid32b, sizeof(lsegid32b), seed);
}

void silofs_lsegid_setup(struct silofs_lsegid *lsegid,
                         const struct silofs_lvid *lvid,
                         loff_t voff, enum silofs_ltype vspace,
                         enum silofs_height height)
{
	const size_t lseg_size = height_to_lseg_size(height);

	silofs_lvid_assign(&lsegid->lvid, lvid);
	lsegid->size = lseg_size;
	lsegid->vindex = lseg_vindex_of(voff, (ssize_t)lseg_size);
	lsegid->height = height;
	lsegid->vspace = vspace;
}

void silofs_lsegid32b_reset(struct silofs_lsegid32b *lsegid32)
{
	memset(lsegid32, 0, sizeof(*lsegid32));
	lsegid32->vindex = UINT32_MAX;
	lsegid32->size = 0;
	lsegid32->vspace = SILOFS_LTYPE_NONE;
	lsegid32->height = SILOFS_HEIGHT_LAST;
}

void silofs_lsegid32b_htox(struct silofs_lsegid32b *lsegid32,
                           const struct silofs_lsegid *lsegid)
{
	memset(lsegid32, 0, sizeof(*lsegid32));
	silofs_lvid_assign(&lsegid32->lvid, &lsegid->lvid);
	lsegid32->vindex = silofs_cpu_to_le32(lsegid->vindex);
	lsegid32->size = silofs_cpu_to_le32((uint32_t)lsegid->size);
	lsegid32->vspace = (uint8_t)lsegid->vspace;
	lsegid32->height = (uint8_t)lsegid->height;
}

void silofs_lsegid32b_xtoh(const struct silofs_lsegid32b *lsegid32,
                           struct silofs_lsegid *lsegid)
{
	silofs_lvid_assign(&lsegid->lvid, &lsegid32->lvid);
	lsegid->vindex = silofs_le32_to_cpu(lsegid32->vindex);
	lsegid->size = silofs_le32_to_cpu(lsegid32->size);
	lsegid->vspace = (enum silofs_ltype)lsegid32->vspace;
	lsegid->height = (enum silofs_height)lsegid32->height;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_laddr s_laddr_none = {
	.pos = SILOFS_OFF_NULL,
	.ltype = SILOFS_LTYPE_NONE,
};

const struct silofs_laddr *silofs_laddr_none(void)
{
	return &s_laddr_none;
}

void silofs_laddr_setup(struct silofs_laddr *laddr,
                        const struct silofs_lsegid *lsegid,
                        enum silofs_ltype ltype, loff_t off, size_t len)
{
	silofs_lsegid_assign(&laddr->lsegid, lsegid);
	laddr->ltype = ltype;
	if (lsegid->size && !off_isnull(off)) {
		laddr->len = len;
		laddr->pos = silofs_lsegid_pos(lsegid, off);
	} else {
		laddr->len = 0;
		laddr->pos = SILOFS_OFF_NULL;
	}
}

void silofs_laddr_setup_lbk(struct silofs_laddr *laddr,
                            const struct silofs_lsegid *lsegid,
                            enum silofs_ltype ltype, loff_t off)
{
	const loff_t lbk_off = !off_isnull(off) ? off_align_to_lbk(off) : off;

	silofs_laddr_setup(laddr, lsegid, ltype, lbk_off, SILOFS_LBK_SIZE);
}

void silofs_laddr_reset(struct silofs_laddr *laddr)
{
	silofs_lsegid_reset(&laddr->lsegid);
	laddr->len = 0;
	laddr->pos = SILOFS_OFF_NULL;
	laddr->ltype = SILOFS_LTYPE_NONE;
}

void silofs_laddr_assign(struct silofs_laddr *laddr,
                         const struct silofs_laddr *other)
{
	silofs_lsegid_assign(&laddr->lsegid, &other->lsegid);
	laddr->len = other->len;
	laddr->pos = other->pos;
	laddr->ltype = other->ltype;
}

long silofs_laddr_compare(const struct silofs_laddr *laddr1,
                          const struct silofs_laddr *laddr2)
{
	long cmp;

	cmp = lsegid_compare(&laddr1->lsegid, &laddr2->lsegid);
	if (cmp) {
		return cmp;
	}
	cmp = (long)laddr1->ltype - (long)laddr2->ltype;
	if (cmp) {
		return cmp;
	}
	cmp = (long)laddr1->pos - (long)laddr2->pos;
	if (cmp) {
		return cmp;
	}
	cmp = (long)laddr1->len - (long)laddr2->len;
	if (cmp) {
		return cmp;
	}
	return 0;
}

bool silofs_laddr_isnull(const struct silofs_laddr *laddr)
{
	return silofs_ltype_isnone(laddr->ltype) ||
	       silofs_off_isnull(laddr->pos) ||
	       silofs_lsegid_isnull(&laddr->lsegid);
}

bool silofs_laddr_isvalid(const struct silofs_laddr *laddr)
{
	const loff_t end = off_end(laddr->pos, laddr->len);
	const ssize_t lsegid_size = (ssize_t)(laddr->lsegid.size);

	return !silofs_laddr_isnull(laddr) && (end <= lsegid_size);
}

bool silofs_laddr_isequal(const struct silofs_laddr *laddr,
                          const struct silofs_laddr *other)
{
	return ((laddr->ltype == other->ltype) &&
	        (laddr->len == other->len) &&
	        (laddr->pos == other->pos) &&
	        lsegid_isequal(&laddr->lsegid, &other->lsegid));
}

bool silofs_laddr_isnext(const struct silofs_laddr *laddr,
                         const struct silofs_laddr *other)
{
	loff_t end;

	if (laddr->ltype != other->ltype) {
		return false;
	}
	end = off_end(laddr->pos, laddr->len);
	if (other->pos != end) {
		return false;
	}
	if (end > (ssize_t)other->lsegid.size) {
		return false;
	}
	if (!lsegid_isequal(&laddr->lsegid, &other->lsegid)) {
		return false;
	}
	return true;
}

void silofs_laddr_as_iv(const struct silofs_laddr *laddr,
                        struct silofs_iv *out_iv)
{
	union {
		struct silofs_laddr48b laddr48;
		uint8_t d[48];
	} u;

	STATICASSERT_EQ(sizeof(u), 48);
	STATICASSERT_EQ(3 * sizeof(out_iv->iv), sizeof(u.laddr48));
	STATICASSERT_EQ(3 * sizeof(out_iv->iv), sizeof(u));
	STATICASSERT_EQ(3 * ARRAY_SIZE(out_iv->iv), sizeof(u));

	silofs_laddr48b_htox(&u.laddr48, laddr);
	for (size_t i = 0; i < ARRAY_SIZE(out_iv->iv); ++i) {
		out_iv->iv[i] = u.d[i] ^ u.d[i + 16] ^ u.d[i + 32];
	}
}

void silofs_laddr48b_reset(struct silofs_laddr48b *laddr48)
{
	memset(laddr48, 0, sizeof(*laddr48));
	silofs_lsegid32b_reset(&laddr48->lsegid);
	laddr48->pos = 0;
	laddr48->len = 0;
	laddr48->ltype = 0;
}

void silofs_laddr48b_htox(struct silofs_laddr48b *laddr48,
                          const struct silofs_laddr *laddr)
{
	memset(laddr48, 0, sizeof(*laddr48));
	silofs_lsegid32b_htox(&laddr48->lsegid, &laddr->lsegid);
	laddr48->pos = silofs_cpu_to_le32((uint32_t)(laddr->pos));
	laddr48->len = silofs_cpu_to_le32((uint32_t)(laddr->len));
	laddr48->ltype = (uint8_t)laddr->ltype;
}

void silofs_laddr48b_xtoh(const struct silofs_laddr48b *laddr48,
                          struct silofs_laddr *laddr)
{
	silofs_lsegid32b_xtoh(&laddr48->lsegid, &laddr->lsegid);
	laddr->pos = (loff_t)silofs_le32_to_cpu(laddr48->pos);
	laddr->len = (size_t)silofs_le32_to_cpu(laddr48->len);
	laddr->ltype = (enum silofs_ltype)laddr48->ltype;
}

union silofs_laddr_data_u {
	struct silofs_laddr48b laddr48;
	uint8_t d[48];
};

int silofs_laddr_to_base64(const struct silofs_laddr *laddr,
                           struct silofs_nbuf *nbuf)
{
	union silofs_laddr_data_u u;
	size_t len = 0;
	int err;

	STATICASSERT_EQ(sizeof(u), 48);
	STATICASSERT_LT(2 * sizeof(u), sizeof(nbuf->b));

	silofs_memzero(&u, sizeof(u));
	silofs_laddr48b_htox(&u.laddr48, laddr);

	err = silofs_base64_encode(u.d, sizeof(u.d), nbuf->b,
	                           sizeof(nbuf->b) - 1, &len);
	if (err) {
		return err;
	}
	nbuf->b[len] = '\0';
	return 0;
}

int silofs_laddr_from_base64(struct silofs_laddr *laddr,
                             const struct silofs_nbuf *nbuf)
{
	union silofs_laddr_data_u u;
	size_t nrd = 0;
	size_t inlen = 0;
	size_t outlen = 0;
	int err;

	STATICASSERT_EQ(sizeof(u), 48);
	STATICASSERT_LT(2 * sizeof(u), sizeof(nbuf->b));

	silofs_memzero(&u, sizeof(u));

	inlen = strlen(nbuf->b);
	err = silofs_base64_decode(nbuf->b, inlen,
	                           u.d, sizeof(u.d), &outlen, &nrd);
	if (err) {
		return err;
	}
	if ((outlen != sizeof(u.d)) || (nrd != inlen)) {
		return -SILOFS_EINVAL;
	}
	silofs_laddr48b_xtoh(&u.laddr48, laddr);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_llink_setup(struct silofs_llink *llink,
                        const struct silofs_laddr *laddr,
                        const struct silofs_iv *riv)
{
	silofs_laddr_assign(&llink->laddr, laddr);
	silofs_iv_assign(&llink->riv, riv);
}

void silofs_llink_assign(struct silofs_llink *llink,
                         const struct silofs_llink *other)
{
	silofs_llink_setup(llink, &other->laddr, &other->riv);
}

void silofs_llink_reset(struct silofs_llink *llink)
{
	silofs_laddr_reset(&llink->laddr);
	silofs_iv_reset(&llink->riv);
}
