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

ssize_t silofs_height_to_blob_size(enum silofs_height height)
{
	const ssize_t blob_size_max = SILOFS_BLOB_SIZE_MAX;
	ssize_t elemsz;
	ssize_t nelems;
	ssize_t factor;

	switch (height) {
	default:
	case SILOFS_HEIGHT_NONE:
	case SILOFS_HEIGHT_VDATA:
		elemsz = SILOFS_BK_SIZE;
		nelems = SILOFS_SPMAP_NCHILDS;
		factor = blob_size_max / (elemsz * nelems);
		break;
	case SILOFS_HEIGHT_SPLEAF:
	case SILOFS_HEIGHT_SPNODE1:
	case SILOFS_HEIGHT_SPNODE2:
	case SILOFS_HEIGHT_SPNODE3:
	case SILOFS_HEIGHT_SPNODE4:
	case SILOFS_HEIGHT_SPNODE5:
	case SILOFS_HEIGHT_SUPER:
	case SILOFS_HEIGHT_LAST:
		elemsz = SILOFS_SPMAP_SIZE;
		nelems = SILOFS_SPMAP_NCHILDS;
		factor = 1;
		break;
	}
	return elemsz * nelems * factor;
}

ssize_t silofs_height_to_space_span(enum silofs_height height)
{
	const ssize_t bk_size = SILOFS_BK_SIZE;
	const ssize_t shift = SILOFS_SPMAP_SHIFT;
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
		shift_fac = 5;
		break;
	case SILOFS_HEIGHT_SPNODE5:
	case SILOFS_HEIGHT_SUPER:
	case SILOFS_HEIGHT_LAST:
		shift_fac = 6;
		break;
	}
	span = (1L << (shift * shift_fac)) * bk_size;
	silofs_assert_ge(span, SILOFS_BK_SIZE);
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
	       (lba * SILOFS_BK_SIZE) : SILOFS_OFF_NULL;
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
	       (off / SILOFS_BK_SIZE) : SILOFS_LBA_NULL;
}

loff_t silofs_off_in_bk(loff_t off)
{
	STATICASSERT_LT(SILOFS_OFF_NULL, 0);

	return off_within(off, SILOFS_BK_SIZE);
}

static size_t spleaf_span(void)
{
	return SILOFS_SPMAP_NCHILDS * SILOFS_BK_SIZE;
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
	case SILOFS_STYPE_SUPER:
	case SILOFS_STYPE_SPNODE:
	case SILOFS_STYPE_SPLEAF:
		ret = true;
		break;
	case SILOFS_STYPE_RESERVED:
	case SILOFS_STYPE_INODE:
	case SILOFS_STYPE_XANODE:
	case SILOFS_STYPE_SYMVAL:
	case SILOFS_STYPE_DTNODE:
	case SILOFS_STYPE_FTNODE:
	case SILOFS_STYPE_DATA1K:
	case SILOFS_STYPE_DATA4K:
	case SILOFS_STYPE_DATABK:
	case SILOFS_STYPE_ANONBK:
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
	case SILOFS_STYPE_SUPER:
	case SILOFS_STYPE_SPNODE:
	case SILOFS_STYPE_SPLEAF:
	case SILOFS_STYPE_ANONBK:
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_RESERVED:
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
	case SILOFS_STYPE_ANONBK:
	case SILOFS_STYPE_SUPER:
	case SILOFS_STYPE_SPNODE:
	case SILOFS_STYPE_SPLEAF:
	case SILOFS_STYPE_RESERVED:
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

size_t silofs_stype_size(enum silofs_stype stype)
{
	switch (stype) {
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
	case SILOFS_STYPE_ANONBK:
		return sizeof(struct silofs_data_block);
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_RESERVED:
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

void silofs_treeid_generate(struct silofs_treeid *treeid)
{
	silofs_uuid_generate(&treeid->uuid);
}

static void treeid_assign(struct silofs_treeid *treeid,
                          const struct silofs_treeid *other)
{
	silofs_uuid_assign(&treeid->uuid, &other->uuid);
}

static long treeid_compare(const struct silofs_treeid *treeid1,
                           const struct silofs_treeid *treeid2)
{
	return silofs_uuid_compare(&treeid1->uuid, &treeid2->uuid);
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

static void treeid_as_u64(const struct silofs_treeid *treeid,
                          uint64_t *out_u1, uint64_t *out_u2)
{
	STATICASSERT_EQ(sizeof(treeid->uuid.uu), 16);

	*out_u1 = u64_of(&treeid->uuid.uu[0]);
	*out_u2 = u64_of(&treeid->uuid.uu[8]);
}

void silofs_treeid128_set(struct silofs_treeid128 *treeid128,
                          const struct silofs_treeid *treeid)
{
	silofs_uuid_assign(&treeid128->uuid, &treeid->uuid);
}

void silofs_treeid128_parse(const struct silofs_treeid128 *treeid128,
                            struct silofs_treeid *treeid)
{
	silofs_uuid_assign(&treeid->uuid, &treeid128->uuid);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_blobid s_blobid_none = {
	.size = 0,
	.vspace = SILOFS_STYPE_NONE,
	.height = SILOFS_HEIGHT_LAST,
};

const struct silofs_blobid *silofs_blobid_none(void)
{
	return &s_blobid_none;
}

size_t silofs_blobid_size(const struct silofs_blobid *blobid)
{
	return blobid->size;
}

bool silofs_blobid_isnull(const struct silofs_blobid *blobid)
{
	return (blobid->size == 0);
}

bool silofs_blobid_has_treeid(const struct silofs_blobid *blobid,
                              const struct silofs_treeid *treeid)
{
	return treeid_isequal(&blobid->treeid, treeid);
}

loff_t silofs_blobid_pos(const struct silofs_blobid *blobid, loff_t off)
{
	const size_t blob_size = silofs_blobid_size(blobid);

	return blob_size ? off_within(off, blob_size) : 0;
}

static silofs_lba_t
blobid_off_to_lba_within(const struct silofs_blobid *blobid, loff_t off)
{
	silofs_lba_t lba = SILOFS_LBA_NULL;

	if (!off_isnull(off) && blobid->size) {
		lba = off_to_lba(silofs_blobid_pos(blobid, off));
	}
	return lba;
}

static silofs_lba_t
blobid_lba_within(const struct silofs_blobid *blobid, silofs_lba_t lba)
{
	return lba_isnull(lba) ? SILOFS_LBA_NULL :
	       blobid_off_to_lba_within(blobid, lba_to_off(lba));
}

void silofs_blobid_reset(struct silofs_blobid *blobid)
{
	memset(blobid, 0, sizeof(*blobid));
}

static void blobid_assign_ta(struct silofs_blobid *blobid,
                             const struct silofs_blobid *other)
{
	treeid_assign(&blobid->treeid, &other->treeid);
	blobid->voff = other->voff;
}

void silofs_blobid_assign(struct silofs_blobid *blobid,
                          const struct silofs_blobid *other)
{
	blobid->size = other->size;
	blobid->vspace = other->vspace;
	blobid->height = other->height;
	blobid_assign_ta(blobid, other);
}

static long blobid_compare_ta(const struct silofs_blobid *blobid1,
                              const struct silofs_blobid *blobid2)
{
	long cmp;

	cmp = (long)(blobid2->voff) - (long)(blobid1->voff);
	if (cmp) {
		return cmp;
	}
	cmp = treeid_compare(&blobid1->treeid, &blobid2->treeid);
	if (cmp) {
		return cmp;
	}
	return 0;
}

long silofs_blobid_compare(const struct silofs_blobid *blobid1,
                           const struct silofs_blobid *blobid2)
{
	long cmp;

	cmp = (int)(blobid2->vspace) - (int)(blobid1->vspace);
	if (cmp) {
		return cmp;
	}
	cmp = (int)(blobid2->height) - (int)(blobid1->height);
	if (cmp) {
		return cmp;
	}
	cmp = (long)(blobid2->size) - (long)(blobid1->size);
	if (cmp) {
		return cmp;
	}
	return blobid_compare_ta(blobid1, blobid2);
}

bool silofs_blobid_isequal(const struct silofs_blobid *blobid,
                           const struct silofs_blobid *other)
{
	return silofs_blobid_compare(blobid, other) == 0;
}

static uint64_t blobid_as_u64_ta(const struct silofs_blobid *blobid)
{
	uint64_t u1;
	uint64_t u2;
	const uint64_t uoff = (uint64_t)(blobid->voff);

	treeid_as_u64(&blobid->treeid, &u1, &u2);
	return uoff ^ u1 ^ u2;
}

static uint64_t blobid_as_u64_by_meta(const struct silofs_blobid *blobid)
{
	return blobid->size ^
	       (((uint64_t)blobid->height << 8) | ((uint64_t)blobid->vspace));
}

void silofs_blobid_as_u128(const struct silofs_blobid *blobid, uint64_t h[2])
{
	h[0] = blobid_as_u64_ta(blobid);
	h[1] = blobid_as_u64_by_meta(blobid);
}

uint64_t silofs_blobid_hash(const struct silofs_blobid *blobid)
{
	uint64_t h[2];

	silofs_blobid_as_u128(blobid, h);
	return silofs_hash_xxh64(h, sizeof(h), blobid->vspace);
}

void silofs_blobid_setup(struct silofs_blobid *blobid,
                         const struct silofs_treeid *treeid,
                         loff_t voff, enum silofs_stype vspace,
                         enum silofs_height height)
{
	const ssize_t blob_size = silofs_height_to_blob_size(height);

	treeid_assign(&blobid->treeid, treeid);
	blobid->voff = off_align(voff, blob_size);
	blobid->size = (size_t)blob_size;
	blobid->height = height;
	blobid->vspace = vspace;
}

static void blobid_as_iv(const struct silofs_blobid *blobid,
                         struct silofs_iv *out_iv)
{
	STATICASSERT_EQ(sizeof(blobid->treeid), sizeof(*out_iv));
	STATICASSERT_EQ(sizeof(blobid->treeid.uuid), sizeof(out_iv->iv));
	STATICASSERT_GE(ARRAY_SIZE(out_iv->iv), 16);

	memcpy(out_iv->iv, &blobid->treeid.uuid, sizeof(out_iv->iv));
	out_iv->iv[0] ^= (uint8_t)(blobid->voff & 0xFF);
	out_iv->iv[1] ^= (uint8_t)((blobid->voff >> 8) & 0xFF);
	out_iv->iv[2] ^= (uint8_t)((blobid->voff >> 16) & 0xFF);
	out_iv->iv[3] ^= (uint8_t)((blobid->voff >> 24) & 0xFF);
	out_iv->iv[4] ^= (uint8_t)((blobid->voff >> 32) & 0xFF);
	out_iv->iv[5] ^= (uint8_t)((blobid->voff >> 40) & 0xFF);
	out_iv->iv[6] ^= (uint8_t)((blobid->voff >> 48) & 0xFF);
	out_iv->iv[7] ^= (uint8_t)((blobid->voff >> 56) & 0xFF);

	out_iv->iv[14] ^= (uint8_t)blobid->vspace;
	out_iv->iv[15] ^= (uint8_t)blobid->height;
}

void silofs_blobid40b_reset(struct silofs_blobid40b *blobid40)
{
	memset(blobid40, 0, sizeof(*blobid40));
	blobid40->size = 0;
	blobid40->vspace = SILOFS_STYPE_NONE;
	blobid40->height = SILOFS_HEIGHT_LAST;
}

static void blobid40b_set_ta(struct silofs_blobid40b *blobid40,
                             const struct silofs_blobid *blobid)
{
	silofs_treeid128_set(&blobid40->treeid, &blobid->treeid);
	blobid40->voff = silofs_cpu_to_off(blobid->voff);
}

void silofs_blobid40b_set(struct silofs_blobid40b *blobid40,
                          const struct silofs_blobid *blobid)
{
	memset(blobid40, 0, sizeof(*blobid40));
	blobid40->size = silofs_cpu_to_le32((uint32_t)blobid->size);
	blobid40->vspace = (uint8_t)blobid->vspace;
	blobid40->height = (uint8_t)blobid->height;
	blobid40b_set_ta(blobid40, blobid);
}

static void blobid40b_parse_ta(const struct silofs_blobid40b *blobid40,
                               struct silofs_blobid *blobid)
{
	silofs_treeid128_parse(&blobid40->treeid, &blobid->treeid);
	blobid->voff = silofs_off_to_cpu(blobid40->voff);
}

void silofs_blobid40b_parse(const struct silofs_blobid40b *blobid40,
                            struct silofs_blobid *blobid)
{
	blobid->size = silofs_le32_to_cpu(blobid40->size);
	blobid->vspace = (enum silofs_stype)blobid40->vspace;
	blobid->height = (enum silofs_height)blobid40->height;
	blobid40b_parse_ta(blobid40, blobid);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_bkaddr s_bkaddr_none = {
	.lba = SILOFS_LBA_NULL,
};

const struct silofs_bkaddr *silofs_bkaddr_none(void)
{
	return &s_bkaddr_none;
}

void silofs_bkaddr_setup(struct silofs_bkaddr *bkaddr,
                         const struct silofs_blobid *blobid, silofs_lba_t lba)
{
	silofs_blobid_assign(&bkaddr->blobid, blobid);
	bkaddr->lba = blobid_lba_within(blobid, lba);
}

void silofs_bkaddr_reset(struct silofs_bkaddr *bkaddr)
{
	silofs_blobid_reset(&bkaddr->blobid);
	bkaddr->lba = SILOFS_LBA_NULL;
}

void silofs_bkaddr_by_off(struct silofs_bkaddr *bkaddr,
                          const struct silofs_blobid *blobid, loff_t off)
{
	const silofs_lba_t lba = blobid_off_to_lba_within(blobid, off);

	silofs_bkaddr_setup(bkaddr, blobid, lba);
}

bool silofs_bkaddr_isequal(const struct silofs_bkaddr *bkaddr,
                           const struct silofs_bkaddr *other)
{
	return ((bkaddr->lba == other->lba) &&
	        silofs_blobid_isequal(&bkaddr->blobid, &other->blobid));
}

long silofs_bkaddr_compare(const struct silofs_bkaddr *bkaddr1,
                           const struct silofs_bkaddr *bkaddr2)
{
	long cmp;

	cmp = bkaddr1->lba - bkaddr2->lba;
	if (cmp) {
		return cmp;
	}
	cmp = silofs_blobid_compare(&bkaddr1->blobid, &bkaddr2->blobid);
	if (cmp) {
		return cmp;
	}
	return 0;
}

void silofs_bkaddr_assign(struct silofs_bkaddr *bkaddr,
                          const struct silofs_bkaddr *other)
{
	silofs_bkaddr_setup(bkaddr, &other->blobid, other->lba);
}

bool silofs_bkaddr_isnull(const struct silofs_bkaddr *bkaddr)
{
	return lba_isnull(bkaddr->lba) ||
	       silofs_blobid_isnull(&bkaddr->blobid);
}

void silofs_bkaddr48b_reset(struct silofs_bkaddr48b *bkaddr48)
{
	silofs_blobid40b_reset(&bkaddr48->blobid);
	bkaddr48->lba = silofs_cpu_to_le32(UINT32_MAX);
	bkaddr48->pad = 0;
}

void silofs_bkaddr48b_set(struct silofs_bkaddr48b *bkaddr48,
                          const struct silofs_bkaddr *bkaddr)
{
	silofs_blobid40b_set(&bkaddr48->blobid, &bkaddr->blobid);
	bkaddr48->pad = 0;
	if (!lba_isnull(bkaddr->lba)) {
		bkaddr48->lba = silofs_cpu_to_le32((uint32_t)bkaddr->lba);
	} else {
		bkaddr48->lba = silofs_cpu_to_le32(UINT32_MAX);
	}
}

void silofs_bkaddr48b_parse(const struct silofs_bkaddr48b *bkaddr48,
                            struct silofs_bkaddr *bkaddr)
{
	struct silofs_blobid blobid;
	silofs_lba_t lba;

	silofs_blobid40b_parse(&bkaddr48->blobid, &blobid);
	lba = silofs_le32_to_cpu(bkaddr48->lba);
	if (lba_to_off(lba) < (ssize_t)blobid.size) {
		silofs_bkaddr_setup(bkaddr, &blobid, lba);
	} else {
		silofs_bkaddr_reset(bkaddr);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_oaddr s_oaddr_none = {
	.bka.lba = SILOFS_LBA_NULL,
	.pos = SILOFS_OFF_NULL,
};

const struct silofs_oaddr *silofs_oaddr_none(void)
{
	return &s_oaddr_none;
}

void silofs_oaddr_setup(struct silofs_oaddr *oaddr,
                        const struct silofs_blobid *blobid,
                        loff_t off, size_t len)
{
	silofs_bkaddr_by_off(&oaddr->bka, blobid, off);
	if (blobid->size && !off_isnull(off)) {
		oaddr->len = len;
		oaddr->pos = silofs_blobid_pos(blobid, off);
	} else {
		oaddr->len = 0;
		oaddr->pos = SILOFS_OFF_NULL;
	}
}

void silofs_oaddr_setup_bk(struct silofs_oaddr *oaddr,
                           const struct silofs_bkaddr *bkaddr)
{
	const loff_t off = lba_to_off(bkaddr->lba);

	silofs_oaddr_setup(oaddr, &bkaddr->blobid, off, SILOFS_BK_SIZE);
}

static void oaddr_setup_by(struct silofs_oaddr *oaddr,
                           const struct silofs_blobid *blobid,
                           const struct silofs_vaddr *vaddr)
{
	const loff_t bpos = silofs_blobid_pos(blobid, vaddr->off);

	silofs_oaddr_setup(oaddr, blobid, bpos, vaddr->len);
}

void silofs_oaddr_reset(struct silofs_oaddr *oaddr)
{
	silofs_bkaddr_reset(&oaddr->bka);
	oaddr->len = 0;
	oaddr->pos = SILOFS_OFF_NULL;
}

void silofs_oaddr_assign(struct silofs_oaddr *oaddr,
                         const struct silofs_oaddr *other)
{
	silofs_bkaddr_assign(&oaddr->bka, &other->bka);
	oaddr->len = other->len;
	oaddr->pos = other->pos;
}

long silofs_oaddr_compare(const struct silofs_oaddr *oaddr1,
                          const struct silofs_oaddr *oaddr2)
{
	long cmp;

	cmp = oaddr1->pos - oaddr2->pos;
	if (cmp) {
		return cmp;
	}
	cmp = (int)oaddr1->len - (int)oaddr2->len;
	if (cmp) {
		return cmp;
	}
	cmp = silofs_bkaddr_compare(&oaddr1->bka, &oaddr2->bka);
	if (cmp) {
		return cmp;
	}
	return 0;
}

bool silofs_oaddr_isnull(const struct silofs_oaddr *oaddr)
{
	return off_isnull(oaddr->pos) || silofs_bkaddr_isnull(&oaddr->bka);
}

bool silofs_oaddr_isvalid(const struct silofs_oaddr *oaddr)
{
	const loff_t end = off_end(oaddr->pos, oaddr->len);
	const ssize_t blobid_size = (ssize_t)(oaddr->bka.blobid.size);

	return !silofs_oaddr_isnull(oaddr) && (end <= blobid_size);
}

bool silofs_oaddr_isequal(const struct silofs_oaddr *oaddr,
                          const struct silofs_oaddr *other)
{
	return ((oaddr->len == other->len) && (oaddr->pos == other->pos) &&
	        silofs_bkaddr_isequal(&oaddr->bka, &other->bka));
}

void silofs_oaddr_of_bk(struct silofs_oaddr *oaddr,
                        const struct silofs_blobid *blobid, silofs_lba_t lba)
{
	silofs_oaddr_setup(oaddr, blobid, lba_to_off(lba), SILOFS_BK_SIZE);
}


void silofs_oaddr48b_reset(struct silofs_oaddr48b *oaddr48)
{
	silofs_blobid40b_reset(&oaddr48->blobid);
	oaddr48->pos = 0;
	oaddr48->len = 0;
}

void silofs_oaddr48b_set(struct silofs_oaddr48b *oaddr48,
                         const struct silofs_oaddr *oaddr)
{
	silofs_blobid40b_set(&oaddr48->blobid, &oaddr->bka.blobid);
	oaddr48->pos = silofs_cpu_to_le32((uint32_t)(oaddr->pos));
	oaddr48->len = silofs_cpu_to_le32((uint32_t)(oaddr->len));
}

void silofs_oaddr48b_parse(const struct silofs_oaddr48b *oaddr48,
                           struct silofs_oaddr *oaddr)
{
	struct silofs_blobid blobid;
	loff_t pos;
	size_t len;

	silofs_blobid40b_parse(&oaddr48->blobid, &blobid);
	pos = (loff_t)silofs_le32_to_cpu(oaddr48->pos);
	len = (size_t)silofs_le32_to_cpu(oaddr48->len);
	silofs_oaddr_setup(oaddr, &blobid, pos, len);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_voaddr_setup(struct silofs_voaddr *voa,
                         const struct silofs_vaddr *vaddr,
                         const struct silofs_oaddr *oaddr)
{
	vaddr_assign(&voa->vaddr, vaddr);
	oaddr_assign(&voa->oaddr, oaddr);
}

void silofs_voaddr_setup_by(struct silofs_voaddr *voa,
                            const struct silofs_blobid *blobid,
                            const struct silofs_vaddr *vaddr)
{
	vaddr_assign(&voa->vaddr, vaddr);
	oaddr_setup_by(&voa->oaddr, blobid, vaddr);
}

void silofs_voaddr_assign(struct silofs_voaddr *voa,
                          const struct silofs_voaddr *other)
{
	silofs_voaddr_setup(voa, &other->vaddr, &other->oaddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_uaddr s_uaddr_none = {
	.oaddr.bka.blobid.size = 0,
	.oaddr.bka.lba = SILOFS_LBA_NULL,
	.oaddr.pos = SILOFS_OFF_NULL,
	.voff = SILOFS_OFF_NULL,
	.stype = SILOFS_STYPE_NONE,
	.height = UINT32_MAX,
};

const struct silofs_uaddr *silofs_uaddr_none(void)
{
	return &s_uaddr_none;
}

bool silofs_uaddr_isnull(const struct silofs_uaddr *uaddr)
{
	return stype_isnone(uaddr->stype) || off_isnull(uaddr->voff) ||
	       silofs_oaddr_isnull(&uaddr->oaddr);
}

void silofs_uaddr_setup(struct silofs_uaddr *uaddr,
                        const struct silofs_blobid *blobid,
                        loff_t bpos, enum silofs_stype stype,
                        enum silofs_height height, loff_t voff)
{
	silofs_oaddr_setup(&uaddr->oaddr, blobid, bpos, stype_size(stype));
	uaddr->voff = voff;
	uaddr->stype = stype;
	uaddr->height = height;
}

void silofs_uaddr_reset(struct silofs_uaddr *uaddr)
{
	silofs_oaddr_reset(&uaddr->oaddr);
	uaddr->voff = SILOFS_OFF_NULL;
	uaddr->stype = SILOFS_STYPE_NONE;
}

void silofs_uaddr_assign(struct silofs_uaddr *uaddr,
                         const struct silofs_uaddr *other)
{
	silofs_oaddr_assign(&uaddr->oaddr, &other->oaddr);
	uaddr->voff = other->voff;
	uaddr->stype = other->stype;
	uaddr->height = other->height;
}

long silofs_uaddr_compare(const struct silofs_uaddr *uaddr1,
                          const struct silofs_uaddr *uaddr2)
{
	long cmp;

	cmp = (long)uaddr1->height - (long)uaddr2->height;
	if (cmp) {
		return cmp;
	}
	cmp = (long)uaddr1->stype - (long)uaddr2->stype;
	if (cmp) {
		return cmp;
	}
	cmp = uaddr1->voff - uaddr2->voff;
	if (cmp) {
		return cmp;
	}
	cmp = silofs_oaddr_compare(&uaddr1->oaddr, &uaddr2->oaddr);
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

const struct silofs_blobid *
silofs_uaddr_blobid(const struct silofs_uaddr *uaddr)
{
	return &uaddr->oaddr.bka.blobid;
}

void silofs_uaddr64b_reset(struct silofs_uaddr64b *uadr)
{
	silofs_oaddr48b_reset(&uadr->oaddr);
	uadr->voff = silofs_off_to_cpu(SILOFS_OFF_NULL);
	uadr->stype = SILOFS_STYPE_NONE;
	uadr->height = 0xFF;
}

void silofs_uaddr64b_set(struct silofs_uaddr64b *uadr,
                         const struct silofs_uaddr *uaddr)
{
	silofs_oaddr48b_set(&uadr->oaddr, &uaddr->oaddr);
	uadr->voff = silofs_cpu_to_off(uaddr->voff);
	uadr->stype = (uint8_t)uaddr->stype;
	uadr->height = (uint8_t)uaddr->height;
}

void silofs_uaddr64b_parse(const struct silofs_uaddr64b *uadr,
                           struct silofs_uaddr *uaddr)
{
	silofs_oaddr48b_parse(&uadr->oaddr, &uaddr->oaddr);
	uaddr->voff = silofs_off_to_cpu(uadr->voff);
	uaddr->stype = (enum silofs_stype)(uadr->stype);
	uaddr->height = uadr->height;
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

void silofs_vaddr56_set(struct silofs_vaddr56 *vadr, loff_t off)
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

loff_t silofs_vaddr56_parse(const struct silofs_vaddr56 *vadr)
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
	return off;
}

void silofs_vaddr64_set(struct silofs_vaddr64 *vadr,
                        const struct silofs_vaddr *vaddr)
{
	vadr->voff_stype = cpu_to_voff_stype(vaddr->off, vaddr->stype);
}

void silofs_vaddr64_parse(const struct silofs_vaddr64 *vadr,
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

	silofs_vrange128_set(vrng, &vrange);
}

void silofs_vrange128_set(struct silofs_vrange128 *vrng,
                          const struct silofs_vrange *vrange)
{
	vrng->beg = silofs_cpu_to_off(vrange->beg);
	vrng->len_height = cpu_to_len_height(vrange->len, vrange->height);
}

void silofs_vrange128_parse(const struct silofs_vrange128 *vrng,
                            struct silofs_vrange *vrange)
{
	loff_t beg;
	size_t len;
	enum silofs_height height;

	beg = silofs_off_to_cpu(vrng->beg);
	len_height_to_cpu(vrng->len_height, &len, &height);
	silofs_vrange_setup(vrange, height, beg, off_end(beg, len));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_iv_of_oaddr(struct silofs_iv *iv, const struct silofs_oaddr *oaddr)
{
	STATICASSERT_GE(ARRAY_SIZE(iv->iv), 16);

	blobid_as_iv(&oaddr->bka.blobid, iv);
	iv->iv[8] ^= (uint8_t)(oaddr->pos & 0xFF);
	iv->iv[9] ^= (uint8_t)((oaddr->pos >> 8) & 0xFF);
	iv->iv[10] ^= (uint8_t)((oaddr->pos >> 16) & 0xFF);
	iv->iv[11] ^= (uint8_t)((oaddr->pos >> 24) & 0xFF);
	iv->iv[12] ^= (uint8_t)((oaddr->pos >> 32) & 0xFF);
	iv->iv[13] ^= (uint8_t)((oaddr->pos >> 40) & 0xFF);
	iv->iv[14] ^= (uint8_t)((oaddr->pos >> 48) & 0xFF);
	iv->iv[15] ^= (uint8_t)((oaddr->pos >> 56) & 0xFF);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_check_fs_capacity(size_t cap_size)
{
	if (cap_size < SILOFS_CAPACITY_SIZE_MIN) {
		return -EINVAL;
	}
	if (cap_size > SILOFS_CAPACITY_SIZE_MAX) {
		return -EINVAL;
	}
	return 0;
}

int silofs_calc_fs_capacity(size_t capcity_want, size_t *out_capacity)
{
	int err;
	const size_t align_size = SILOFS_BLOB_SIZE_MAX;

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

long silofs_uuid_compare(const struct silofs_uuid *uu1,
                         const struct silofs_uuid *uu2)
{
	return memcmp(uu1->uu, uu2->uu, sizeof(uu1->uu));
}

void silofs_uuid_name(const struct silofs_uuid *uu, struct silofs_namebuf *nb)
{
	char buf[40] = "";

	uuid_unparse_lower(uu->uu, buf);
	strncpy(nb->name, buf, sizeof(nb->name));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_namebuf_reset(struct silofs_namebuf *nb)
{
	memset(nb, 0, sizeof(*nb));
}

void silofs_namebuf_assign(struct silofs_namebuf *nb,
                           const struct silofs_namebuf *other)
{
	memcpy(nb, other, sizeof(*nb));
}

void silofs_namebuf_assign2(struct silofs_namebuf *nb,
                            const struct silofs_name *name)
{
	STATICASSERT_EQ(sizeof(nb->name), sizeof(name->name));

	memcpy(nb->name, name->name, sizeof(nb->name));
	nb->name[sizeof(nb->name) - 1] = '\0';
}

void silofs_namebuf_str(const struct silofs_namebuf *nb,
                        struct silofs_namestr *name)
{
	name->s.str = nb->name;
	name->s.len = strlen(nb->name);
}

void silofs_namebuf_assign_str(struct silofs_namebuf *nb,
                               const struct silofs_namestr *name)
{
	const size_t len = silofs_min(name->s.len, sizeof(nb->name) - 1);

	memcpy(nb->name, name->s.str, len);
	nb->name[len] = '\0';
}

void silofs_namebuf_copyto(const struct silofs_namebuf *nb,
                           struct silofs_name *name)
{
	STATICASSERT_EQ(sizeof(nb->name), sizeof(name->name));

	memcpy(name->name, nb->name, sizeof(name->name));
}

bool silofs_namebuf_isequal(const struct silofs_namebuf *nb,
                            const struct silofs_namestr *name)
{
	const size_t len = strlen(nb->name);

	return (name->s.len == len) && !memcmp(nb->name, name->s.str, len);
}

void silofs_namestr_init(struct silofs_namestr *nstr, const char *name)
{
	nstr->s.str = name;
	nstr->s.len = strnlen(name, SILOFS_NAME_MAX + 1);
}

bool silofs_namestr_isequal(const struct silofs_namestr *nstr,
                            const struct silofs_namestr *other)
{
	const size_t len = nstr->s.len;

	return (len == other->s.len) &&
	       !silofs_str_compare(nstr->s.str, other->s.str, len);
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

