/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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
#include <stdlib.h>
#include <stdint.h>
#include <endian.h>
#include <errno.h>
#include <ctype.h>

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t height_to_lext_size(enum silofs_height height)
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
	case SILOFS_HEIGHT_UBER:
		elemsz = SILOFS_BOOTREC_SIZE;
		break;
	case SILOFS_HEIGHT_NONE:
	case SILOFS_HEIGHT_LAST:
	default:
		elemsz = 0;
		break;
	}
	return silofs_min(elemsz * nelems, SILOFS_LEXT_SIZE_MAX);
}

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
	case SILOFS_HEIGHT_UBER:
	case SILOFS_HEIGHT_LAST:
		shift_fac = 5;
		break;
	}
	span = (1L << (SILOFS_SPMAP_SHIFT * shift_fac)) * SILOFS_LBK_SIZE;
	silofs_assert_ge(span, SILOFS_LBK_SIZE);
	silofs_assert_le(span, SILOFS_VSPACE_SIZE_MAX);

	return span;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void byte_to_ascii(unsigned int b, char *a)
{
	a[0] = silofs_nibble_to_ascii((int)(b >> 4));
	a[1] = silofs_nibble_to_ascii((int)b);
}

static uint8_t ascii_to_byte(const char *a)
{
	int nib[2];

	nib[0] = silofs_ascii_to_nibble(a[0]);
	nib[1] = silofs_ascii_to_nibble(a[1]);
	return (uint8_t)(nib[0] << 4 | nib[1]);
}

void silofs_uint64_to_ascii(uint64_t u, char *a)
{
	int shift;
	unsigned int b;

	shift = 64;
	while (shift > 0) {
		shift -= 8;
		b = (unsigned int)((u >> shift) & 0xFF);
		byte_to_ascii(b, a);
		a += 2;
	}
}

uint64_t silofs_ascii_to_uint64(const char *a)
{
	uint64_t u = 0;

	for (size_t i = 0; i < 8; ++i) {
		u = u << 8;
		u |= ascii_to_byte(a);
		a += 2;
	}
	return u;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint64_t u64_of(const uint8_t p[8])
{
	uint64_t u = 0;

	u |= (uint64_t)(p[0]) << 56;
	u |= (uint64_t)(p[1]) << 48;
	u |= (uint64_t)(p[2]) << 40;
	u |= (uint64_t)(p[3]) << 32;
	u |= (uint64_t)(p[4]) << 24;
	u |= (uint64_t)(p[5]) << 16;
	u |= (uint64_t)(p[6]) << 8;
	u |= (uint64_t)(p[7]);

	return u;
}

void silofs_hash256_assign(struct silofs_hash256 *hash,
                           const struct silofs_hash256 *other)
{
	memcpy(hash, other, sizeof(*hash));
}

bool silofs_hash256_isequal(const struct silofs_hash256 *hash,
                            const struct silofs_hash256 *other)
{
	return (memcmp(hash, other, sizeof(*hash)) == 0);
}

static uint64_t hash256_to_u64(const uint8_t *h)
{
	return u64_of(h) ^ u64_of(h + 8) ^ u64_of(h + 16) ^ u64_of(h + 24);
}

uint64_t silofs_hash256_to_u64(const struct silofs_hash256 *hash)
{
	STATICASSERT_EQ(ARRAY_SIZE(hash->hash), 4 * sizeof(uint64_t));

	return hash256_to_u64(hash->hash);
}

size_t silofs_hash256_to_name(const struct silofs_hash256 *hash,
                              char *buf, size_t bsz)
{
	size_t cnt = 0;

	for (size_t i = 0; i < ARRAY_SIZE(hash->hash); ++i) {
		if ((cnt + 2) > bsz) {
			break;
		}
		byte_to_ascii(hash->hash[i], buf + cnt);
		cnt += 2;
	}
	return cnt;
}

void silofs_hash512_assign(struct silofs_hash512 *hash,
                           const struct silofs_hash512 *other)
{
	memcpy(hash, other, sizeof(*hash));
}

bool silofs_hash512_isequal(const struct silofs_hash512 *hash,
                            const struct silofs_hash512 *other)
{
	return (memcmp(hash, other, sizeof(*hash)) == 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint64_t cpu_to_voff_stype(loff_t voff, enum silofs_stype stype)
{
	uint64_t voff_stype;
	const uint64_t mask = 0xFF;
	const uint64_t uoff = (uint64_t)voff;
	const uint64_t ustype = (uint64_t)stype;

	if (!stype_isnone(stype)) {
		silofs_assert_eq(uoff & mask, 0);

		voff_stype = ((uoff & ~mask) | (ustype & mask));
		voff_stype = silofs_cpu_to_le64(voff_stype);
	} else {
		voff_stype = 0;
	}
	return voff_stype;
}

static void voff_stype_to_cpu(uint64_t voff_stype, loff_t *out_voff,
                              enum silofs_stype *out_stype)
{
	const uint64_t mask = 0xFF;
	const uint64_t uoff = voff_stype & ~mask;
	const uint64_t ustype = voff_stype & mask;

	if (voff_stype > 0) {
		*out_voff = (loff_t)uoff;
		*out_stype = (enum silofs_stype)ustype;
	} else {
		*out_voff = SILOFS_OFF_NULL;
		*out_stype = SILOFS_STYPE_NONE;
	}
}

static uint64_t cpu_to_len_height(size_t len, enum silofs_height height)
{
	uint64_t val;

	silofs_assert_le(len, (1L << 58));
	silofs_assert_lt(height, 0xF);
	silofs_assert_le(height, SILOFS_HEIGHT_SUPER);

	val = ((uint64_t)len << 4) | (height & 0xF);
	return silofs_cpu_to_le64(val);
}

static void len_height_to_cpu(uint64_t len_height,
                              size_t *out_len, enum silofs_height *out_height)
{
	const uint64_t val = silofs_le64_to_cpu(len_height);

	*out_len = val >> 4;
	*out_height = (enum silofs_height)(val & 0xF);

	silofs_assert_le(*out_len, (1L << 58));
	silofs_assert_lt(*out_height, 0xF);
	silofs_assert_le(*out_height, SILOFS_HEIGHT_SUPER);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

loff_t silofs_lba_to_off(silofs_lba_t lba)
{
	return !silofs_lba_isnull(lba) ?
	       (lba * SILOFS_LBK_SIZE) : SILOFS_OFF_NULL;
}

silofs_lba_t silofs_lba_plus(silofs_lba_t lba, size_t nbk)
{
	return lba + (silofs_lba_t)nbk;
}

static silofs_lba_t lba_kbn_to_off(silofs_lba_t lba, size_t kbn)
{
	return lba_to_off(lba) + (silofs_lba_t)(kbn * SILOFS_KB_SIZE);
}

static loff_t off_within(loff_t off, size_t bsz)
{
	const size_t uoff = (size_t)off;

	return (loff_t)(uoff % bsz);
}

silofs_lba_t silofs_off_to_lba(loff_t off)
{
	return !silofs_off_isnull(off) ?
	       (off / SILOFS_LBK_SIZE) : SILOFS_LBA_NULL;
}

loff_t silofs_off_in_lbk(loff_t off)
{
	STATICASSERT_LT(SILOFS_OFF_NULL, 0);

	return off_within(off, SILOFS_LBK_SIZE);
}

static size_t spleaf_span(void)
{
	return SILOFS_SPMAP_NCHILDS * SILOFS_LBK_SIZE;
}

loff_t silofs_off_to_spleaf_start(loff_t voff)
{
	return off_align(voff, (long)spleaf_span());
}

loff_t silofs_off_to_spleaf_next(loff_t voff)
{
	const loff_t voff_next = off_end(voff, spleaf_span());

	return silofs_off_to_spleaf_start(voff_next);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_stype_isunode(enum silofs_stype stype)
{
	bool ret;

	switch (stype) {
	case SILOFS_STYPE_BOOTREC:
	case SILOFS_STYPE_SUPER:
	case SILOFS_STYPE_SPNODE:
	case SILOFS_STYPE_SPLEAF:
		ret = true;
		break;
	case SILOFS_STYPE_INODE:
	case SILOFS_STYPE_XANODE:
	case SILOFS_STYPE_SYMVAL:
	case SILOFS_STYPE_DTNODE:
	case SILOFS_STYPE_FTNODE:
	case SILOFS_STYPE_DATA1K:
	case SILOFS_STYPE_DATA4K:
	case SILOFS_STYPE_DATABK:
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_LAST:
	default:
		ret = false;
		break;
	}
	return ret;
}

bool silofs_stype_isvnode(enum silofs_stype stype)
{
	bool ret;

	switch (stype) {
	case SILOFS_STYPE_INODE:
	case SILOFS_STYPE_XANODE:
	case SILOFS_STYPE_SYMVAL:
	case SILOFS_STYPE_DTNODE:
	case SILOFS_STYPE_FTNODE:
	case SILOFS_STYPE_DATA1K:
	case SILOFS_STYPE_DATA4K:
	case SILOFS_STYPE_DATABK:
		ret = true;
		break;
	case SILOFS_STYPE_BOOTREC:
	case SILOFS_STYPE_SUPER:
	case SILOFS_STYPE_SPNODE:
	case SILOFS_STYPE_SPLEAF:
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_LAST:
	default:
		ret = false;
		break;
	}
	return ret;
}

bool silofs_stype_isdata(enum silofs_stype stype)
{
	bool ret;

	switch (stype) {
	case SILOFS_STYPE_DATA1K:
	case SILOFS_STYPE_DATA4K:
	case SILOFS_STYPE_DATABK:
		ret = true;
		break;
	case SILOFS_STYPE_BOOTREC:
	case SILOFS_STYPE_SUPER:
	case SILOFS_STYPE_SPNODE:
	case SILOFS_STYPE_SPLEAF:
	case SILOFS_STYPE_INODE:
	case SILOFS_STYPE_XANODE:
	case SILOFS_STYPE_DTNODE:
	case SILOFS_STYPE_FTNODE:
	case SILOFS_STYPE_SYMVAL:
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_LAST:
	default:
		ret = false;
		break;
	}
	return ret;
}

uint32_t silofs_stype_size(enum silofs_stype stype)
{
	switch (stype) {
	case SILOFS_STYPE_BOOTREC:
		return sizeof(struct silofs_bootrec1k);
	case SILOFS_STYPE_SUPER:
		return sizeof(struct silofs_super_block);
	case SILOFS_STYPE_SPNODE:
		return sizeof(struct silofs_spmap_node);
	case SILOFS_STYPE_SPLEAF:
		return sizeof(struct silofs_spmap_leaf);
	case SILOFS_STYPE_INODE:
		return sizeof(struct silofs_inode);
	case SILOFS_STYPE_XANODE:
		return sizeof(struct silofs_xattr_node);
	case SILOFS_STYPE_DTNODE:
		return sizeof(struct silofs_dtree_node);
	case SILOFS_STYPE_FTNODE:
		return sizeof(struct silofs_ftree_node);
	case SILOFS_STYPE_SYMVAL:
		return sizeof(struct silofs_symlnk_value);
	case SILOFS_STYPE_DATA1K:
		return sizeof(struct silofs_data_block1);
	case SILOFS_STYPE_DATA4K:
		return sizeof(struct silofs_data_block4);
	case SILOFS_STYPE_DATABK:
		return sizeof(struct silofs_data_block64);
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_LAST:
	default:
		break;
	}
	return 0;
}

ssize_t silofs_stype_ssize(enum silofs_stype stype)
{
	return (ssize_t)silofs_stype_size(stype);
}

size_t silofs_stype_nkbs(enum silofs_stype stype)
{
	const size_t size = silofs_stype_size(stype);

	return div_round_up(size, SILOFS_KB_SIZE);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void treeid_reset(struct silofs_treeid *treeid)
{
	memset(treeid, 0, sizeof(*treeid));
}

void silofs_treeid_generate(struct silofs_treeid *treeid)
{
	silofs_uuid_generate(&treeid->uuid);
}

void silofs_treeid_assign(struct silofs_treeid *treeid,
                          const struct silofs_treeid *other)
{
	silofs_uuid_assign(&treeid->uuid, &other->uuid);
}

static long treeid_compare(const struct silofs_treeid *treeid1,
                           const struct silofs_treeid *treeid2)
{
	const struct silofs_uuid *uu1 = &treeid1->uuid;
	const struct silofs_uuid *uu2 = &treeid2->uuid;

	return memcmp(uu1->uu, uu2->uu, sizeof(uu1->uu));
}

static bool treeid_isequal(const struct silofs_treeid *treeid1,
                           const struct silofs_treeid *treeid2)
{
	return (treeid_compare(treeid1, treeid2) == 0);
}

bool silofs_treeid_isequal(const struct silofs_treeid *treeid1,
                           const struct silofs_treeid *treeid2)
{
	return treeid_isequal(treeid1, treeid2);
}

void silofs_treeid_as_uuid(const struct silofs_treeid *treeid,
                           struct silofs_uuid *out_uuid)
{
	STATICASSERT_EQ(sizeof(treeid->uuid.uu), 16);

	silofs_uuid_assign(out_uuid, &treeid->uuid);
}

void silofs_treeid_by_uuid(struct silofs_treeid *treeid,
                           const struct silofs_uuid *uuid)
{
	STATICASSERT_EQ(sizeof(treeid->uuid.uu), 16);

	silofs_uuid_assign(&treeid->uuid, uuid);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_lextid s_lextid_none = {
	.size = 0,
	.vspace = SILOFS_STYPE_NONE,
	.height = SILOFS_HEIGHT_LAST,
};

const struct silofs_lextid *silofs_lextid_none(void)
{
	return &s_lextid_none;
}

size_t silofs_lextid_size(const struct silofs_lextid *lextid)
{
	return lextid->size;
}

bool silofs_lextid_isnull(const struct silofs_lextid *lextid)
{
	return (lextid->size == 0);
}

bool silofs_lextid_has_treeid(const struct silofs_lextid *lextid,
                              const struct silofs_treeid *treeid)
{
	return treeid_isequal(&lextid->treeid, treeid);
}

static loff_t
silofs_lextid_pos(const struct silofs_lextid *lextid, loff_t off)
{
	const size_t size = silofs_lextid_size(lextid);

	return size ? off_within(off, size) : 0;
}

void silofs_lextid_reset(struct silofs_lextid *lextid)
{
	treeid_reset(&lextid->treeid);
	lextid->voff = SILOFS_OFF_NULL;
	lextid->size = 0;
	lextid->vspace = SILOFS_STYPE_NONE;
	lextid->height = SILOFS_HEIGHT_NONE;
}

void silofs_lextid_assign(struct silofs_lextid *lextid,
                          const struct silofs_lextid *other)
{
	silofs_treeid_assign(&lextid->treeid, &other->treeid);
	lextid->voff = other->voff;
	lextid->size = other->size;
	lextid->vspace = other->vspace;
	lextid->height = other->height;
}

long silofs_lextid_compare(const struct silofs_lextid *lextid1,
                           const struct silofs_lextid *lextid2)
{
	long cmp;

	cmp = (long)(lextid2->vspace) - (long)(lextid1->vspace);
	if (cmp) {
		return cmp;
	}
	cmp = (long)(lextid2->height) - (long)(lextid1->height);
	if (cmp) {
		return cmp;
	}
	cmp = (long)(lextid2->size) - (long)(lextid1->size);
	if (cmp) {
		return cmp;
	}
	cmp = (long)(lextid2->voff) - (long)(lextid1->voff);
	if (cmp) {
		return cmp;
	}
	cmp = treeid_compare(&lextid1->treeid, &lextid2->treeid);
	if (cmp) {
		return cmp;
	}
	return 0;
}

bool silofs_lextid_isequal(const struct silofs_lextid *lextid,
                           const struct silofs_lextid *other)
{
	return silofs_lextid_compare(lextid, other) == 0;
}

uint64_t silofs_lextid_hash64(const struct silofs_lextid *lextid)
{
	struct silofs_lextid32b bid = { .size = 0 };

	silofs_lextid32b_htox(&bid, lextid);
	return silofs_hash_xxh64(&bid, sizeof(bid), lextid->vspace);
}

void silofs_lextid_setup(struct silofs_lextid *lextid,
                         const struct silofs_treeid *treeid,
                         loff_t voff, enum silofs_stype vspace,
                         enum silofs_height height)
{
	const size_t sz = height_to_lext_size(height);

	silofs_treeid_assign(&lextid->treeid, treeid);
	lextid->size = sz;
	lextid->voff = sz ? off_align(voff, (ssize_t)sz) : SILOFS_OFF_NULL;
	lextid->height = height;
	lextid->vspace = vspace;
}

static void lextid_as_iv(const struct silofs_lextid *lextid,
                         struct silofs_iv *out_iv)
{
	STATICASSERT_EQ(sizeof(lextid->treeid), sizeof(*out_iv));
	STATICASSERT_EQ(sizeof(lextid->treeid.uuid), sizeof(out_iv->iv));
	STATICASSERT_GE(ARRAY_SIZE(out_iv->iv), 16);

	memcpy(out_iv->iv, &lextid->treeid.uuid, sizeof(out_iv->iv));
	out_iv->iv[0] ^= (uint8_t)(lextid->voff & 0xFF);
	out_iv->iv[1] ^= (uint8_t)((lextid->voff >> 8) & 0xFF);
	out_iv->iv[2] ^= (uint8_t)((lextid->voff >> 16) & 0xFF);
	out_iv->iv[3] ^= (uint8_t)((lextid->voff >> 24) & 0xFF);
	out_iv->iv[4] ^= (uint8_t)((lextid->voff >> 32) & 0xFF);
	out_iv->iv[5] ^= (uint8_t)((lextid->voff >> 40) & 0xFF);
	out_iv->iv[6] ^= (uint8_t)((lextid->voff >> 48) & 0xFF);
	out_iv->iv[7] ^= (uint8_t)((lextid->voff >> 56) & 0xFF);

	out_iv->iv[14] ^= (uint8_t)lextid->vspace;
	out_iv->iv[15] ^= (uint8_t)lextid->height;
}

void silofs_lextid32b_reset(struct silofs_lextid32b *lextid32)
{
	memset(lextid32, 0, sizeof(*lextid32));
	lextid32->voff = SILOFS_OFF_NULL;
	lextid32->size = 0;
	lextid32->vspace = SILOFS_STYPE_NONE;
	lextid32->height = SILOFS_HEIGHT_LAST;
}

void silofs_lextid32b_htox(struct silofs_lextid32b *lextid32,
                           const struct silofs_lextid *lextid)
{
	memset(lextid32, 0, sizeof(*lextid32));
	silofs_treeid_assign(&lextid32->treeid, &lextid->treeid);
	lextid32->voff = silofs_cpu_to_off(lextid->voff);
	lextid32->size = silofs_cpu_to_le32((uint32_t)lextid->size);
	lextid32->vspace = (uint8_t)lextid->vspace;
	lextid32->height = (uint8_t)lextid->height;
}

void silofs_lextid32b_xtoh(const struct silofs_lextid32b *lextid32,
                           struct silofs_lextid *lextid)
{
	silofs_treeid_assign(&lextid->treeid, &lextid32->treeid);
	lextid->voff = silofs_off_to_cpu(lextid32->voff);
	lextid->size = silofs_le32_to_cpu(lextid32->size);
	lextid->vspace = (enum silofs_stype)lextid32->vspace;
	lextid->height = (enum silofs_height)lextid32->height;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_laddr s_laddr_none = {
	.pos = SILOFS_OFF_NULL,
};

const struct silofs_laddr *silofs_laddr_none(void)
{
	return &s_laddr_none;
}

void silofs_laddr_setup(struct silofs_laddr *laddr,
                        const struct silofs_lextid *lextid,
                        loff_t off, size_t len)
{
	silofs_lextid_assign(&laddr->lextid, lextid);
	if (lextid->size && !off_isnull(off)) {
		laddr->len = len;
		laddr->pos = silofs_lextid_pos(lextid, off);
	} else {
		laddr->len = 0;
		laddr->pos = SILOFS_OFF_NULL;
	}
}

void silofs_laddr_reset(struct silofs_laddr *laddr)
{
	silofs_lextid_reset(&laddr->lextid);
	laddr->len = 0;
	laddr->pos = SILOFS_OFF_NULL;
}

void silofs_laddr_assign(struct silofs_laddr *laddr,
                         const struct silofs_laddr *other)
{
	silofs_lextid_assign(&laddr->lextid, &other->lextid);
	laddr->len = other->len;
	laddr->pos = other->pos;
}

long silofs_laddr_compare(const struct silofs_laddr *laddr1,
                          const struct silofs_laddr *laddr2)
{
	long cmp;

	cmp = laddr1->pos - laddr2->pos;
	if (cmp) {
		return cmp;
	}
	cmp = (int)laddr1->len - (int)laddr2->len;
	if (cmp) {
		return cmp;
	}
	cmp = silofs_lextid_compare(&laddr1->lextid, &laddr2->lextid);
	if (cmp) {
		return cmp;
	}
	return 0;
}

bool silofs_laddr_isnull(const struct silofs_laddr *laddr)
{
	return silofs_off_isnull(laddr->pos) ||
	       silofs_lextid_isnull(&laddr->lextid);
}

bool silofs_laddr_isvalid(const struct silofs_laddr *laddr)
{
	const loff_t end = off_end(laddr->pos, laddr->len);
	const ssize_t lextid_size = (ssize_t)(laddr->lextid.size);

	return !silofs_laddr_isnull(laddr) && (end <= lextid_size);
}

bool silofs_laddr_isequal(const struct silofs_laddr *laddr,
                          const struct silofs_laddr *other)
{
	return ((laddr->len == other->len) && (laddr->pos == other->pos) &&
	        silofs_lextid_isequal(&laddr->lextid, &other->lextid));
}

void silofs_laddr_as_iv(const struct silofs_laddr *laddr,
                        struct silofs_iv *out_iv)
{
	STATICASSERT_GE(ARRAY_SIZE(out_iv->iv), 16);

	memset(out_iv, 0, sizeof(*out_iv));
	lextid_as_iv(&laddr->lextid, out_iv);
	out_iv->iv[8] ^= (uint8_t)(laddr->pos & 0xFF);
	out_iv->iv[9] ^= (uint8_t)((laddr->pos >> 8) & 0xFF);
	out_iv->iv[10] ^= (uint8_t)((laddr->pos >> 16) & 0xFF);
	out_iv->iv[11] ^= (uint8_t)((laddr->pos >> 24) & 0xFF);
	out_iv->iv[12] ^= (uint8_t)((laddr->pos >> 32) & 0xFF);
	out_iv->iv[13] ^= (uint8_t)((laddr->pos >> 40) & 0xFF);
	out_iv->iv[14] ^= (uint8_t)((laddr->pos >> 48) & 0xFF);
	out_iv->iv[15] ^= (uint8_t)((laddr->pos >> 56) & 0xFF);
}

void silofs_laddr48b_reset(struct silofs_laddr48b *laddr48)
{
	silofs_lextid32b_reset(&laddr48->lextid);
	laddr48->pos = 0;
	laddr48->len = 0;
}

void silofs_laddr48b_htox(struct silofs_laddr48b *laddr48,
                          const struct silofs_laddr *laddr)
{
	silofs_lextid32b_htox(&laddr48->lextid, &laddr->lextid);
	laddr48->pos = silofs_cpu_to_le32((uint32_t)(laddr->pos));
	laddr48->len = silofs_cpu_to_le32((uint32_t)(laddr->len));
}

void silofs_laddr48b_xtoh(const struct silofs_laddr48b *laddr48,
                          struct silofs_laddr *laddr)
{
	silofs_lextid32b_xtoh(&laddr48->lextid, &laddr->lextid);
	laddr->pos = (loff_t)silofs_le32_to_cpu(laddr48->pos);
	laddr->len = (size_t)silofs_le32_to_cpu(laddr48->len);
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

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const struct silofs_bkaddr s_bkaddr_none = {
	.lba = SILOFS_LBA_NULL,
};

const struct silofs_bkaddr *silofs_bkaddr_none(void)
{
	return &s_bkaddr_none;
}

void silofs_bkaddr_setup(struct silofs_bkaddr *bkaddr,
                         const struct silofs_lextid *lextid,
                         silofs_lba_t abs_lba)
{
	loff_t pos;
	silofs_lba_t lba;

	if (lba_isnull(abs_lba)) {
		pos = SILOFS_OFF_NULL;
		lba = SILOFS_LBA_NULL;
	} else {
		pos = silofs_lextid_pos(lextid, lba_to_off(abs_lba));
		lba = off_to_lba(pos);
	}

	silofs_laddr_setup(&bkaddr->laddr, lextid, pos, SILOFS_LBK_SIZE);
	bkaddr->lba = lba;
}

void silofs_bkaddr_reset(struct silofs_bkaddr *bkaddr)
{
	silofs_laddr_reset(&bkaddr->laddr);
	bkaddr->lba = SILOFS_LBA_NULL;
}

void silofs_bkaddr_by_off(struct silofs_bkaddr *bkaddr,
                          const struct silofs_lextid *lextid, loff_t off)
{
	silofs_bkaddr_setup(bkaddr, lextid, off_to_lba(off));
}

void silofs_bkaddr_by_laddr(struct silofs_bkaddr *bkaddr,
                            const struct silofs_laddr *laddr)
{
	const silofs_lba_t lba = off_to_lba(laddr->pos);

	silofs_bkaddr_setup(bkaddr, &laddr->lextid, lba);
}

bool silofs_bkaddr_isequal(const struct silofs_bkaddr *bkaddr,
                           const struct silofs_bkaddr *other)
{
	return ((bkaddr->lba == other->lba) &&
	        silofs_laddr_isequal(&bkaddr->laddr, &other->laddr));
}

long silofs_bkaddr_compare(const struct silofs_bkaddr *bkaddr1,
                           const struct silofs_bkaddr *bkaddr2)
{
	long cmp;

	cmp = bkaddr1->lba - bkaddr2->lba;
	if (cmp) {
		return cmp;
	}
	cmp = silofs_laddr_compare(&bkaddr1->laddr, &bkaddr2->laddr);
	if (cmp) {
		return cmp;
	}
	return 0;
}

void silofs_bkaddr_assign(struct silofs_bkaddr *bkaddr,
                          const struct silofs_bkaddr *other)
{
	silofs_laddr_assign(&bkaddr->laddr, &other->laddr);
	bkaddr->lba = other->lba;
}

bool silofs_bkaddr_isnull(const struct silofs_bkaddr *bkaddr)
{
	return lba_isnull(bkaddr->lba) ||
	       silofs_laddr_isnull(&bkaddr->laddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_uaddr s_uaddr_none = {
	.laddr.lextid.size = 0,
	.laddr.pos = SILOFS_OFF_NULL,
	.voff = SILOFS_OFF_NULL,
	.stype = SILOFS_STYPE_NONE,
};

const struct silofs_uaddr *silofs_uaddr_none(void)
{
	return &s_uaddr_none;
}

bool silofs_uaddr_isnull(const struct silofs_uaddr *uaddr)
{
	return stype_isnone(uaddr->stype) || off_isnull(uaddr->voff) ||
	       silofs_laddr_isnull(&uaddr->laddr);
}

void silofs_uaddr_setup(struct silofs_uaddr *uaddr,
                        const struct silofs_lextid *lextid,
                        loff_t bpos, enum silofs_stype stype, loff_t voff)
{
	silofs_laddr_setup(&uaddr->laddr, lextid, bpos, stype_size(stype));
	uaddr->voff = voff;
	uaddr->stype = stype;
}

void silofs_uaddr_reset(struct silofs_uaddr *uaddr)
{
	silofs_laddr_reset(&uaddr->laddr);
	uaddr->voff = SILOFS_OFF_NULL;
	uaddr->stype = SILOFS_STYPE_NONE;
}

void silofs_uaddr_assign(struct silofs_uaddr *uaddr,
                         const struct silofs_uaddr *other)
{
	silofs_laddr_assign(&uaddr->laddr, &other->laddr);
	uaddr->voff = other->voff;
	uaddr->stype = other->stype;
}

long silofs_uaddr_compare(const struct silofs_uaddr *uaddr1,
                          const struct silofs_uaddr *uaddr2)
{
	long cmp;

	cmp = (long)uaddr1->stype - (long)uaddr2->stype;
	if (cmp) {
		return cmp;
	}
	cmp = uaddr1->voff - uaddr2->voff;
	if (cmp) {
		return cmp;
	}
	cmp = silofs_laddr_compare(&uaddr1->laddr, &uaddr2->laddr);
	if (cmp) {
		return cmp;
	}
	return 0;
}

bool silofs_uaddr_isequal(const struct silofs_uaddr *uaddr1,
                          const struct silofs_uaddr *uaddr2)
{
	return (silofs_uaddr_compare(uaddr1, uaddr2) == 0);
}

const struct silofs_treeid *
silofs_uaddr_treeid(const struct silofs_uaddr *uaddr)
{
	return &uaddr->laddr.lextid.treeid;
}

const struct silofs_lextid *
silofs_uaddr_lextid(const struct silofs_uaddr *uaddr)
{
	return &uaddr->laddr.lextid;
}

enum silofs_height silofs_uaddr_height(const struct silofs_uaddr *uaddr)
{
	return uaddr->laddr.lextid.height;
}

void silofs_uaddr64b_reset(struct silofs_uaddr64b *uaddr64)
{
	silofs_laddr48b_reset(&uaddr64->laddr);
	uaddr64->voff = silofs_off_to_cpu(SILOFS_OFF_NULL);
	uaddr64->stype = SILOFS_STYPE_NONE;
}

void silofs_uaddr64b_htox(struct silofs_uaddr64b *uaddr64,
                          const struct silofs_uaddr *uaddr)
{
	silofs_laddr48b_htox(&uaddr64->laddr, &uaddr->laddr);
	uaddr64->voff = silofs_cpu_to_off(uaddr->voff);
	uaddr64->stype = (uint8_t)uaddr->stype;
}

void silofs_uaddr64b_xtoh(const struct silofs_uaddr64b *uaddr64,
                          struct silofs_uaddr *uaddr)
{
	silofs_laddr48b_xtoh(&uaddr64->laddr, &uaddr->laddr);
	uaddr->voff = silofs_off_to_cpu(uaddr64->voff);
	uaddr->stype = (enum silofs_stype)(uaddr64->stype);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_ulink_assign(struct silofs_ulink *ulink,
                         const struct silofs_ulink *other)
{
	silofs_ulink_assign2(ulink, &other->uaddr, &other->riv);
}

void silofs_ulink_assign2(struct silofs_ulink *ulink,
                          const struct silofs_uaddr *uaddr,
                          const struct silofs_iv *iv)
{
	silofs_uaddr_assign(&ulink->uaddr, uaddr);
	silofs_iv_assign(&ulink->riv, iv);
}

void silofs_ulink_reset(struct silofs_ulink *ulink)
{
	silofs_uaddr_reset(&ulink->uaddr);
	silofs_iv_reset(&ulink->riv);
}

void silofs_ulink_as_llink(const struct silofs_ulink *ulink,
                           struct silofs_llink *out_llink)
{
	silofs_llink_setup(out_llink, &ulink->uaddr.laddr, &ulink->riv);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_vaddr s_vaddr_none = {
	.off = SILOFS_OFF_NULL,
	.stype = SILOFS_STYPE_NONE,
	.len = 0,
};

const struct silofs_vaddr *silofs_vaddr_none(void)
{
	return &s_vaddr_none;
}

long silofs_vaddr_compare(const struct silofs_vaddr *vaddr1,
                          const struct silofs_vaddr *vaddr2)
{
	long cmp;

	cmp = (long)vaddr1->len - (long)vaddr2->len;
	if (cmp) {
		return cmp;
	}
	cmp = vaddr1->off - vaddr2->off;
	if (cmp) {
		return cmp;
	}
	cmp = vaddr1->stype - vaddr2->stype;
	if (cmp) {
		return cmp;
	}
	return 0;
}

bool silofs_vaddr_isequal(const struct silofs_vaddr *vaddr1,
                          const struct silofs_vaddr *vaddr2)
{
	return (silofs_vaddr_compare(vaddr1, vaddr2) == 0);
}

void silofs_vaddr_setup(struct silofs_vaddr *vaddr,
                        enum silofs_stype stype, loff_t voff)
{
	vaddr->stype = stype;
	vaddr->off = voff;
	vaddr->len = (unsigned int)stype_size(stype);
}

void silofs_vaddr_setup2(struct silofs_vaddr *vaddr,
                         enum silofs_stype stype, silofs_lba_t lba)
{
	silofs_vaddr_setup(vaddr, stype, lba_to_off(lba));
}

void silofs_vaddr_assign(struct silofs_vaddr *vaddr,
                         const struct silofs_vaddr *other)
{
	vaddr->stype = other->stype;
	vaddr->off = other->off;
	vaddr->len = other->len;
}

void silofs_vaddr_reset(struct silofs_vaddr *vaddr)
{
	vaddr->stype = SILOFS_STYPE_NONE;
	vaddr->off = SILOFS_OFF_NULL;
	vaddr->len = 0;
}

bool silofs_vaddr_isnull(const struct silofs_vaddr *vaddr)
{
	return !vaddr->len || off_isnull(vaddr->off) ||
	       stype_isnone(vaddr->stype);
}

bool silofs_vaddr_isdata(const struct silofs_vaddr *vaddr)
{
	return stype_isdata(vaddr->stype);
}

bool silofs_vaddr_isdatabk(const struct silofs_vaddr *vaddr)
{
	return stype_isequal(vaddr->stype, SILOFS_STYPE_DATABK);
}

bool silofs_vaddr_isinode(const struct silofs_vaddr *vaddr)
{
	return stype_isequal(vaddr->stype, SILOFS_STYPE_INODE);
}

void silofs_vaddr_by_spleaf(struct silofs_vaddr *vaddr,
                            enum silofs_stype stype,
                            loff_t voff_base, size_t bn, size_t kbn)
{
	const silofs_lba_t lba = lba_plus(off_to_lba(voff_base), bn);
	const loff_t off = lba_kbn_to_off(lba, kbn);

	silofs_vaddr_setup(vaddr, stype, off);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_vaddr56 s_vaddr56_null = {
	.b = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
};

void silofs_vaddr56_htox(struct silofs_vaddr56 *vadr, loff_t off)
{
	const uint64_t uoff = (uint64_t)off;

	if (!off_isnull(off)) {
		silofs_assert_eq(uoff & 0xFFL, 0);

		vadr->b[0] = (uint8_t)((uoff >> 8) & 0xFF);
		vadr->b[1] = (uint8_t)((uoff >> 16) & 0xFF);
		vadr->b[2] = (uint8_t)((uoff >> 24) & 0xFF);
		vadr->b[3] = (uint8_t)((uoff >> 32) & 0xFF);
		vadr->b[4] = (uint8_t)((uoff >> 40) & 0xFF);
		vadr->b[5] = (uint8_t)((uoff >> 48) & 0xFF);
		vadr->b[6] = (uint8_t)((uoff >> 56) & 0xFF);
	} else {
		memcpy(vadr, &s_vaddr56_null, sizeof(*vadr));
	}
}

void silofs_vaddr56_xtoh(const struct silofs_vaddr56 *vadr, loff_t *out_off)
{
	int cmp;
	loff_t off = 0;

	cmp = memcmp(vadr, &s_vaddr56_null, sizeof(*vadr));
	if (cmp) {
		off |= (loff_t)(vadr->b[0]) << 8;
		off |= (loff_t)(vadr->b[1]) << 16;
		off |= (loff_t)(vadr->b[2]) << 24;
		off |= (loff_t)(vadr->b[3]) << 32;
		off |= (loff_t)(vadr->b[4]) << 40;
		off |= (loff_t)(vadr->b[5]) << 48;
		off |= (loff_t)(vadr->b[6]) << 56;
	} else {
		off = SILOFS_OFF_NULL;
	}
	*out_off = off;
}

void silofs_vaddr64_htox(struct silofs_vaddr64 *vadr,
                         const struct silofs_vaddr *vaddr)
{
	vadr->voff_stype = cpu_to_voff_stype(vaddr->off, vaddr->stype);
}

void silofs_vaddr64_xtoh(const struct silofs_vaddr64 *vadr,
                         struct silofs_vaddr *vaddr)
{
	loff_t voff;
	enum silofs_stype stype;

	voff_stype_to_cpu(vadr->voff_stype, &voff, &stype);
	silofs_vaddr_setup(vaddr, stype, voff);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_vrange_within(const struct silofs_vrange *vrange, loff_t off)
{
	return (vrange->beg <= off) && (off < vrange->end);
}

void silofs_vrange_setup(struct silofs_vrange *vrange,
                         enum silofs_height height, loff_t beg, loff_t end)
{
	vrange->beg = beg;
	vrange->end = end;
	vrange->len = off_ulen(beg, end);
	vrange->height = height;
}

void silofs_vrange_setup_sub(struct silofs_vrange *vrange,
                             const struct silofs_vrange *other, loff_t beg)
{
	silofs_vrange_setup(vrange, other->height, beg, other->end);
}

void silofs_vrange_of_space(struct silofs_vrange *vrange,
                            enum silofs_height height, loff_t voff_base)
{
	const ssize_t span = silofs_height_to_space_span(height);
	const loff_t beg = off_align(voff_base, span);

	silofs_vrange_setup(vrange, height, beg, off_next(beg, span));
}

void silofs_vrange_of_spmap(struct silofs_vrange *vrange,
                            enum silofs_height height, loff_t voff_base)
{
	const ssize_t span = silofs_height_to_space_span(height);
	const loff_t beg = off_align(voff_base, span);

	silofs_vrange_setup(vrange, height, beg, off_next(beg, span));
}

loff_t silofs_vrange_voff_at(const struct silofs_vrange *vrange, size_t slot)
{
	ssize_t span;
	loff_t voff;

	span = silofs_height_to_space_span(vrange->height - 1);
	voff = silofs_off_next_n(vrange->beg, span, slot);
	silofs_assert_le(voff, vrange->end);
	return voff;
}

loff_t silofs_vrange_next(const struct silofs_vrange *vrange, loff_t voff)
{
	ssize_t span;
	loff_t vnxt;

	if (unlikely(voff < vrange->beg)) {
		vnxt = vrange->beg;
	} else if (unlikely(voff >= vrange->end)) {
		vnxt = voff;
	} else {
		span = silofs_height_to_space_span(vrange->height - 1);
		vnxt = off_next(voff, span);
	}
	return vnxt;
}


void silofs_vrange128_reset(struct silofs_vrange128 *vrng)
{
	struct silofs_vrange vrange = {
		.beg = SILOFS_OFF_NULL,
		.end = SILOFS_OFF_NULL,
		.height = SILOFS_HEIGHT_VDATA,
	};

	silofs_vrange128_htox(vrng, &vrange);
}

void silofs_vrange128_htox(struct silofs_vrange128 *vrng,
                           const struct silofs_vrange *vrange)
{
	vrng->beg = silofs_cpu_to_off(vrange->beg);
	vrng->len_height = cpu_to_len_height(vrange->len, vrange->height);
}

void silofs_vrange128_xtoh(const struct silofs_vrange128 *vrng,
                           struct silofs_vrange *vrange)
{
	loff_t beg;
	size_t len;
	enum silofs_height height;

	beg = silofs_off_to_cpu(vrng->beg);
	len_height_to_cpu(vrng->len_height, &len, &height);
	silofs_vrange_setup(vrange, height, beg, off_end(beg, len));
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_check_fs_capacity(size_t cap_size)
{
	if (cap_size < SILOFS_CAPACITY_SIZE_MIN) {
		return -SILOFS_EINVAL;
	}
	if (cap_size > SILOFS_CAPACITY_SIZE_MAX) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

int silofs_calc_fs_capacity(size_t capcity_want, size_t *out_capacity)
{
	const size_t align_size = SILOFS_LEXT_SIZE_MAX;
	int err;

	err = silofs_check_fs_capacity(capcity_want);
	if (err) {
		return err;
	}
	*out_capacity = (capcity_want / align_size) * align_size;
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_uuid_generate(struct silofs_uuid *uu)
{
	uuid_generate_random(uu->uu);
}

void silofs_uuid_assign(struct silofs_uuid *uu1, const struct silofs_uuid *uu2)
{
	uuid_copy(uu1->uu, uu2->uu);
}

void silofs_uuid_name(const struct silofs_uuid *uu, struct silofs_namebuf *nb)
{
	char buf[40] = "";

	STATICASSERT_GT(sizeof(nb->name), sizeof(buf));

	uuid_unparse_lower(uu->uu, buf);
	strncpy(nb->name, buf, sizeof(nb->name));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_verify_ino(ino_t ino)
{
	return !ino_isnull(ino) ? 0 : -SILOFS_EFSCORRUPTED;
}

int silofs_verify_off(loff_t off)
{
	return (off_isnull(off) || (off >= 0)) ? 0 : -SILOFS_EFSCORRUPTED;
}

