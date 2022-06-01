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
#include <silofs/fs/types.h>
#include <silofs/fs/nodes.h>
#include <silofs/fs/address.h>
#include <silofs/fs/private.h>
#include <stdlib.h>
#include <stdint.h>
#include <endian.h>
#include <errno.h>
#include <ctype.h>

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

uint64_t silofs_hash256_to_u64(const struct silofs_hash256 *hash)
{
	const uint8_t *h = hash->hash;

	STATICASSERT_EQ(ARRAY_SIZE(hash->hash), 4 * sizeof(uint64_t));

	return u64_of(h) ^ u64_of(h + 8) ^ u64_of(h + 16) ^ u64_of(h + 24);
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

static uint64_t cpu_to_len_height(size_t len, size_t height)
{
	uint64_t val;

	silofs_assert_lt(len, (1L << 54));
	silofs_assert_le(height, SILOFS_SUPER_HEIGHT);

	val = ((uint64_t)len << 8) | (height & 0xFF);
	return silofs_cpu_to_le64(val);
}

static void len_height_to_cpu(uint64_t len_height,
                              size_t *out_len, size_t *out_height)
{
	const uint64_t val = silofs_le64_to_cpu(len_height);

	*out_len = val >> 8;
	*out_height = val & 0xFF;

	silofs_assert_lt(*out_len, (1L << 54));
	silofs_assert_le(*out_height, SILOFS_SUPER_HEIGHT);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static silofs_lba_t lba_plus(silofs_lba_t lba, size_t nbk)
{
	return lba + (silofs_lba_t)nbk;
}

static silofs_lba_t lba_kbn_to_off(silofs_lba_t lba, size_t kbn)
{
	return lba_to_off(lba) + (silofs_lba_t)(kbn * SILOFS_KB_SIZE);
}

loff_t silofs_off_within(loff_t off, size_t bsz)
{
	const size_t uoff = (size_t)off;

	silofs_assert_gt(bsz, 0);
	silofs_assert_ge(off, 0);
	silofs_assert(!off_isnull(off));

	return (loff_t)(uoff % bsz);
}

loff_t silofs_off_in_bk(loff_t off)
{
	STATICASSERT_LT(SILOFS_OFF_NULL, 0);

	return silofs_off_within(off, SILOFS_BK_SIZE);
}

loff_t silofs_off_to_vsec_start(loff_t voff)
{
	return off_align(voff, SILOFS_VSEC_SIZE);
}

loff_t silofs_off_to_vsec_next(loff_t voff, size_t nvsec)
{
	const loff_t voff_next = off_end(voff, nvsec * SILOFS_VSEC_SIZE);

	return silofs_off_to_vsec_start(voff_next);
}

loff_t silofs_off_to_spnode_start(loff_t voff)
{
	return off_align(voff, SILOFS_SPNODE_VRANGE_SIZE);
}

loff_t silofs_off_to_spnode_next(loff_t voff)
{
	const loff_t voff_next = off_end(voff, SILOFS_SPNODE_VRANGE_SIZE);

	return silofs_off_to_spnode_start(voff_next);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_stype_isunode(enum silofs_stype stype)
{
	bool ret;

	switch (stype) {
	case SILOFS_STYPE_SUPER:
	case SILOFS_STYPE_SPSTAT:
	case SILOFS_STYPE_SPNODE:
	case SILOFS_STYPE_SPLEAF:
		ret = true;
		break;
	case SILOFS_STYPE_ITNODE:
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
	case SILOFS_STYPE_MAX:
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
	case SILOFS_STYPE_ITNODE:
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
	case SILOFS_STYPE_SPSTAT:
	case SILOFS_STYPE_SPNODE:
	case SILOFS_STYPE_SPLEAF:
	case SILOFS_STYPE_ANONBK:
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_MAX:
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
	case SILOFS_STYPE_SPSTAT:
	case SILOFS_STYPE_SPNODE:
	case SILOFS_STYPE_SPLEAF:
	case SILOFS_STYPE_ITNODE:
	case SILOFS_STYPE_INODE:
	case SILOFS_STYPE_XANODE:
	case SILOFS_STYPE_DTNODE:
	case SILOFS_STYPE_FTNODE:
	case SILOFS_STYPE_SYMVAL:
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_MAX:
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
	case SILOFS_STYPE_SPSTAT:
		return sizeof(struct silofs_spstat_node);
	case SILOFS_STYPE_SPNODE:
		return sizeof(struct silofs_spmap_node);
	case SILOFS_STYPE_SPLEAF:
		return sizeof(struct silofs_spmap_leaf);
	case SILOFS_STYPE_ITNODE:
		return sizeof(struct silofs_itable_node);
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
	case SILOFS_STYPE_MAX:
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

static void xid_xor_with(struct silofs_xid *xid,
                         const struct silofs_xid *other)
{
	for (size_t i = 0; i < ARRAY_SIZE(xid->id); ++i) {
		xid->id[i] ^= other->id[i];
	}
}

static void xid_mkrand(struct silofs_xid *xid)
{
	silofs_getentropy(xid->id, sizeof(xid->id));
}

void silofs_xid_generate(struct silofs_xid *xid)
{
	union {
		struct timespec   ts;
		struct silofs_xid xi;
		long zero;
	} u = { .zero = 0 };

	silofs_ts_gettime(&u.ts, 1);
	xid_mkrand(xid);
	xid_xor_with(xid, &u.xi);
}

static void xid_assign(struct silofs_xid *xid,
                       const struct silofs_xid *other)
{
	memcpy(xid->id, other->id, sizeof(xid->id));
}

static long xid_compare(const struct silofs_xid *xid1,
                        const struct silofs_xid *xid2)
{
	return memcmp(xid1->id, xid2->id, sizeof(xid1->id));
}

uint64_t silofs_xid_as_u64(const struct silofs_xid *xid)
{
	STATICASSERT_EQ(ARRAY_SIZE(xid->id), 16);

	return u64_of(&xid->id[0]) ^ u64_of(&xid->id[8]);
}

bool silofs_xid_isequal(const struct silofs_xid *xid1,
                        const struct silofs_xid *xid2)
{
	return (xid_compare(xid1, xid2) == 0);
}

static void xid_to_name(const struct silofs_xid *xid, char *name)
{
	for (size_t i = 0; i < ARRAY_SIZE(xid->id); ++i) {
		byte_to_ascii(xid->id[i], name + (2 * i));
	}
}

static size_t xid_name_len(const struct silofs_xid *xid)
{
	return 2 * ARRAY_SIZE(xid->id);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_xid128_set(struct silofs_xid128 *xid128,
                       const struct silofs_xid *xid)
{
	STATICASSERT_EQ(sizeof(xid128->id), sizeof(xid->id));
	STATICASSERT_EQ(ARRAY_SIZE(xid128->id), 16);

	memcpy(xid128->id, xid->id, sizeof(xid128->id));
}

void silofs_xid128_parse(const struct silofs_xid128 *xid128,
                         struct silofs_xid *xid)
{
	STATICASSERT_EQ(sizeof(xid128->id), sizeof(xid->id));
	STATICASSERT_EQ(ARRAY_SIZE(xid->id), 16);

	memcpy(xid->id, xid128->id, sizeof(xid->id));
}

static void xxid256_set(struct silofs_xxid256 *xxid256,
                        const struct silofs_xxid *xxid)
{
	STATICASSERT_EQ(sizeof(xxid256->u.xid), sizeof(xxid->u.xid));
	STATICASSERT_EQ(ARRAY_SIZE(xxid256->u.xid), ARRAY_SIZE(xxid->u.xid));
	STATICASSERT_EQ(ARRAY_SIZE(xxid256->u.xid), 2);

	silofs_xid128_set(&xxid256->u.xid[0], &xxid->u.xid[0]);
	silofs_xid128_set(&xxid256->u.xid[1], &xxid->u.xid[1]);
}

static void xxid256_parse(const struct silofs_xxid256 *xxid256,
                          struct silofs_xxid *xxid)
{
	STATICASSERT_EQ(sizeof(xxid256->u.xid), sizeof(xxid->u.xid));
	STATICASSERT_EQ(ARRAY_SIZE(xxid256->u.xid), ARRAY_SIZE(xxid->u.xid));
	STATICASSERT_EQ(ARRAY_SIZE(xxid256->u.xid), 2);

	silofs_xid128_parse(&xxid256->u.xid[0], &xxid->u.xid[0]);
	silofs_xid128_parse(&xxid256->u.xid[1], &xxid->u.xid[1]);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void xxid_assign(struct silofs_xxid *xxid,
                        const struct silofs_xxid *other)
{
	STATICASSERT_EQ(sizeof(xxid->u.xid), sizeof(xxid->u.tid));
	STATICASSERT_EQ(sizeof(xxid->u.xid), sizeof(xxid->u.cid));

	xid_assign(&xxid->u.xid[0], &other->u.xid[0]);
	xid_assign(&xxid->u.xid[1], &other->u.xid[1]);
}

static long xxid_compare(const struct silofs_xxid *xxid1,
                         const struct silofs_xxid *xxid2)
{
	long cmp;

	cmp = xid_compare(&xxid1->u.xid[0], &xxid2->u.xid[0]);
	if (cmp) {
		return cmp;
	}
	cmp = xid_compare(&xxid1->u.xid[1], &xxid2->u.xid[1]);
	if (cmp) {
		return cmp;
	}
	return 0;
}

static uint64_t xxid_as_u64(const struct silofs_xxid *xxid)
{
	return silofs_xid_as_u64(&xxid->u.xid[0]) ^
	       silofs_xid_as_u64(&xxid->u.xid[1]);
}

static void xxid_to_name(const struct silofs_xxid *xxid, char *name)
{
	xid_to_name(&xxid->u.xid[0], name);
	xid_to_name(&xxid->u.xid[1], name + xid_name_len(&xxid->u.xid[0]));
}

static size_t xxid_name_len(const struct silofs_xxid *xxid)
{
	return 2 * xid_name_len(&xxid->u.xid[0]);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_blobid s_blobid_none = {
	.size = 0,
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
	return silofs_blobid_size(blobid) == 0;
}

loff_t silofs_blobid_pos(const struct silofs_blobid *blobid, loff_t off)
{
	const size_t blob_size = silofs_blobid_size(blobid);

	return blob_size ? silofs_off_within(off, blob_size) : 0;
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

void silofs_blobid_reset(struct silofs_blobid *blobid)
{
	memset(blobid, 0, sizeof(*blobid));
	blobid->size = 0;
}

void silofs_blobid_assign(struct silofs_blobid *blobid,
                          const struct silofs_blobid *other)
{
	xxid_assign(&blobid->xxid, &other->xxid);
	blobid->size = other->size;
}

long silofs_blobid_compare(const struct silofs_blobid *blobid1,
                           const struct silofs_blobid *blobid2)
{
	long cmp;

	cmp = (long)(blobid2->size) - (long)(blobid1->size);
	if (cmp) {
		return cmp;
	}
	cmp = xxid_compare(&blobid1->xxid, &blobid2->xxid);
	if (cmp) {
		return cmp;
	}
	return 0;
}

bool silofs_blobid_isequal(const struct silofs_blobid *blobid,
                           const struct silofs_blobid *other)
{
	return silofs_blobid_compare(blobid, other) == 0;
}

uint64_t silofs_blobid_as_u64(const struct silofs_blobid *blobid)
{
	return xxid_as_u64(&blobid->xxid);
}

uint64_t silofs_blobid_hkey(const struct silofs_blobid *blobid)
{
	const uint64_t hk = silofs_blobid_as_u64(blobid);

	return hk ^ blobid->size;
}

static size_t blobid_size_for(size_t obj_size, size_t nobjs)
{
	const size_t bk_size = SILOFS_BK_SIZE;

	return div_round_up(nobjs * obj_size, bk_size) * bk_size;
}

void silofs_blobid_make_tas(struct silofs_blobid *blobid,
                            const struct silofs_xid *treeid,
                            size_t obj_size, size_t nobjs)
{
	struct silofs_xxid_tas *tid = &blobid->xxid.u.tid;

	xid_assign(&tid->tree_id, treeid);
	xid_mkrand(&tid->uniq_id);
	blobid->size = blobid_size_for(obj_size, nobjs);
}

void silofs_blobid_make_cas(struct silofs_blobid *blobid,
                            const struct silofs_hash256 *hash, size_t size)
{
	struct silofs_xxid_cas *cid = &blobid->xxid.u.cid;

	STATICASSERT_EQ(sizeof(cid->hash), sizeof(hash->hash));

	memcpy(cid->hash, hash->hash, sizeof(hash->hash));
	blobid->size = size;
}

int silofs_blobid_to_name(const struct silofs_blobid *blobid,
                          char *name, size_t nmax, size_t *out_len)
{
	*out_len = xxid_name_len(&blobid->xxid);
	if (nmax <= *out_len) {
		return -EINVAL;
	}
	xxid_to_name(&blobid->xxid, name);
	name[*out_len] = '\0';
	return 0;
}

void silofs_blobid40b_reset(struct silofs_blobid40b *blid)
{
	memset(blid, 0, sizeof(*blid));
	blid->size = 0;
}

void silofs_blobid40b_set(struct silofs_blobid40b *blid,
                          const struct silofs_blobid *blobid)
{
	xxid256_set(&blid->xxid, &blobid->xxid);
	blid->size = silofs_cpu_to_le32((uint32_t)blobid->size);
	blid->reserved = 0;
}

void silofs_blobid40b_parse(const struct silofs_blobid40b *blid,
                            struct silofs_blobid *blobid)
{
	xxid256_parse(&blid->xxid, &blobid->xxid);
	blobid->size = silofs_le32_to_cpu(blid->size);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_packid s_packid_none = {
	.blobid.size = 0,
	.pmode = SILOFS_PACK_NONE,
};

const struct silofs_packid *silofs_packid_none(void)
{
	return &s_packid_none;
}

bool silofs_packid_isnull(const struct silofs_packid *packid)
{
	return (packid->pmode == SILOFS_PACK_NONE) ||
	       silofs_blobid_isnull(&packid->blobid);
}

void silofs_packid_reset(struct silofs_packid *packid)
{
	silofs_blobid_reset(&packid->blobid);
	packid->pmode = SILOFS_PACK_NONE;
}

void silofs_packid_setup(struct silofs_packid *packid,
                         const struct silofs_blobid *blobid)
{
	silofs_blobid_assign(&packid->blobid, blobid);
	packid->pmode = SILOFS_PACK_SIMPLE;
}

void silofs_packid_assign(struct silofs_packid *packid,
                          const struct silofs_packid *other)
{
	silofs_blobid_assign(&packid->blobid, &other->blobid);
	packid->pmode = other->pmode;
}

void silofs_packid64b_reset(struct silofs_packid64b *paid)
{
	silofs_blobid40b_reset(&paid->blobid);
	paid->pmode = 0;
	memset(paid->reserved, 0, sizeof(paid->reserved));
}

void silofs_packid64b_set(struct silofs_packid64b *paid,
                          const struct silofs_packid *packid)
{
	silofs_blobid40b_set(&paid->blobid, &packid->blobid);
	paid->pmode = (uint8_t)packid->pmode;
	memset(paid->reserved, 0, sizeof(paid->reserved));
}

void silofs_packid64b_parse(const struct silofs_packid64b *paid,
                            struct silofs_packid *packid)
{
	silofs_blobid40b_parse(&paid->blobid, &packid->blobid);
	packid->pmode = (enum silofs_pack_mode)paid->pmode;
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
	bkaddr->lba = lba;
}

static void silofs_bkaddr_reset(struct silofs_bkaddr *bkaddr)
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

static bool silofs_bkaddr_isnull(const struct silofs_bkaddr *bkaddr)
{
	return lba_isnull(bkaddr->lba) ||
	       silofs_blobid_isnull(&bkaddr->blobid);
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
		silofs_assert_lt(off, blobid->size);
		silofs_assert_le(off_end(off, len), blobid->size);
		silofs_assert_le(len, SILOFS_BK_SIZE);

		oaddr->len = len;
		oaddr->pos = silofs_blobid_pos(blobid, off);
	} else {
		oaddr->len = 0;
		oaddr->pos = SILOFS_OFF_NULL;
	}
}

static void oaddr_setup_by(struct silofs_oaddr *oaddr,
                           const struct silofs_blobid *blobid,
                           const struct silofs_vaddr *vaddr)
{
	const loff_t bpos = silofs_blobid_pos(blobid, vaddr->voff);

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


static void silofs_oaddr48b_reset(struct silofs_oaddr48b *oaddr48)
{
	silofs_blobid40b_reset(&oaddr48->blobid);
	oaddr48->pos = 0;
	oaddr48->len = 0;
}

static void silofs_oaddr48b_set(struct silofs_oaddr48b *oaddr48,
                                const struct silofs_oaddr *oaddr)
{
	silofs_blobid40b_set(&oaddr48->blobid, &oaddr->bka.blobid);
	oaddr48->pos = silofs_cpu_to_le32((uint32_t)(oaddr->pos));
	oaddr48->len = silofs_cpu_to_le32((uint32_t)(oaddr->len));
}

static void silofs_oaddr48b_parse(const struct silofs_oaddr48b *oaddr48,
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
                        const struct silofs_blobid *blobid, loff_t bpos,
                        enum silofs_stype stype, size_t height, loff_t voff)
{
	silofs_oaddr_setup(&uaddr->oaddr, blobid, bpos, stype_size(stype));
	uaddr->voff = voff;
	uaddr->stype = stype;
	uaddr->height = (unsigned int)height;
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

silofs_lba_t silofs_uaddr_lba(const struct silofs_uaddr *uaddr)
{
	return silofs_off_to_lba(uaddr->voff);
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

void silofs_taddr_setup(struct silofs_taddr *taddr,
                        const struct silofs_xid *tree_id,
                        loff_t voff, size_t height)
{
	xid_assign(&taddr->tree_id, tree_id);
	taddr->voff = voff;
	taddr->height = (unsigned int)height;
}

void silofs_taddr_by_uaddr(struct silofs_taddr *taddr,
                           const struct silofs_uaddr *uaddr)
{
	const struct silofs_xxid_tas *tas =
		        &uaddr->oaddr.bka.blobid.xxid.u.tid;

	xid_assign(&taddr->tree_id, &tas->tree_id);
	taddr->voff = uaddr->voff;
	taddr->height = uaddr->height;
}

bool silofs_taddr_isequal(const struct silofs_taddr *taddr1,
                          const struct silofs_taddr *taddr2)
{
	return (taddr1->height == taddr2->height) &&
	       (taddr1->voff == taddr2->voff) &&
	       silofs_xid_isequal(&taddr1->tree_id, &taddr2->tree_id);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_vaddr s_vaddr_none = {
	.voff = SILOFS_OFF_NULL,
	.stype = SILOFS_STYPE_NONE,
	.len = 0,
};

const struct silofs_vaddr *silofs_vaddr_none(void)
{
	return &s_vaddr_none;
}

loff_t silofs_vaddr_off(const struct silofs_vaddr *vaddr)
{
	return vaddr->voff;
}

enum silofs_stype silofs_vaddr_stype(const struct silofs_vaddr *vaddr)
{
	return vaddr->stype;
}

long silofs_vaddr_compare(const struct silofs_vaddr *vaddr1,
                          const struct silofs_vaddr *vaddr2)
{
	long cmp;

	cmp = (long)vaddr1->len - (long)vaddr2->len;
	if (cmp) {
		return cmp;
	}
	cmp = vaddr1->voff - vaddr2->voff;
	if (cmp) {
		return cmp;
	}
	cmp = vaddr1->stype - vaddr2->stype;
	if (cmp) {
		return cmp;
	}
	return 0;
}

void silofs_vaddr_setup(struct silofs_vaddr *vaddr,
                        enum silofs_stype stype, loff_t voff)
{
	vaddr->stype = stype;
	vaddr->voff = voff;
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
	vaddr->voff = other->voff;
	vaddr->len = other->len;
}

void silofs_vaddr_reset(struct silofs_vaddr *vaddr)
{
	vaddr->stype = SILOFS_STYPE_NONE;
	vaddr->voff = SILOFS_OFF_NULL;
	vaddr->len = 0;
}

bool silofs_vaddr_isnull(const struct silofs_vaddr *vaddr)
{
	return !vaddr->len || off_isnull(vaddr->voff) ||
	       stype_isnone(vaddr->stype);
}

bool silofs_vaddr_isdata(const struct silofs_vaddr *vaddr)
{
	return stype_isdata(vaddr->stype);
}

bool silofs_vaddr_isdatabk(const struct silofs_vaddr *vaddr)
{
	return stype_isequal(vaddr_stype(vaddr), SILOFS_STYPE_DATABK);
}

silofs_lba_t silofs_vaddr_lba(const struct silofs_vaddr *vaddr)
{
	return off_to_lba(vaddr->voff);
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
	vadr->voff_stype = cpu_to_voff_stype(vaddr->voff, vaddr->stype);
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

static ssize_t uspace_height_to_stepsz(size_t height)
{
	const ssize_t bk_size = SILOFS_BK_SIZE;
	const ssize_t nchilds = SILOFS_UNODE_NCHILDS;
	ssize_t stepsz;

	switch (height) {
	case SILOFS_DATABK_HEIGHT:
		stepsz = bk_size;
		break;
	case SILOFS_SPLEAF_HEIGHT:
		stepsz = bk_size * nchilds;
		break;
	case SILOFS_SPNODE2_HEIGHT:
		stepsz = bk_size * nchilds * nchilds;
		break;
	case SILOFS_SPNODE3_HEIGHT:
		stepsz = bk_size * nchilds * nchilds * nchilds;
		break;
	case SILOFS_SUPER_HEIGHT:
		stepsz = bk_size * nchilds * nchilds * nchilds * nchilds;
		break;
	default:
		stepsz = -1;
		break;
	}
	return stepsz;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_vrange_within(const struct silofs_vrange *vrange, loff_t off)
{
	return (vrange->beg <= off) && (off < vrange->end);
}

void silofs_vrange_setup(struct silofs_vrange *vrange,
                         size_t height, loff_t beg, loff_t end)
{
	silofs_assert_le(beg, end);
	silofs_assert_gt(height, 0);

	vrange->beg = beg;
	vrange->end = end;
	vrange->len = off_ulen(beg, end);
	vrange->height = height;
	vrange->stepsz = uspace_height_to_stepsz(height - 1);
}

void silofs_vrange_setup_sub(struct silofs_vrange *vrange,
                             const struct silofs_vrange *other, loff_t beg)
{
	silofs_assert_ge(beg, other->beg);

	silofs_vrange_setup(vrange, other->height, beg, other->end);
}

void silofs_vrange_setup_by(struct silofs_vrange *vrange,
                            size_t height, loff_t voff_base)
{
	const ssize_t stepsz = uspace_height_to_stepsz(height);
	const loff_t beg = off_align(voff_base, stepsz);

	silofs_vrange_setup(vrange, height, beg, off_next(beg, stepsz));
}

void silofs_vrange_of_spleaf(struct silofs_vrange *vrange, loff_t voff)
{
	silofs_vrange_setup_by(vrange, SILOFS_SPLEAF_HEIGHT, voff);
}

void silofs_vrange_of_spnode(struct silofs_vrange *vrange,
                             size_t height, loff_t voff)
{
	silofs_assert_ge(height, SILOFS_SPNODE2_HEIGHT);
	silofs_assert_le(height, SILOFS_SPNODE3_HEIGHT);

	silofs_vrange_setup_by(vrange, height, voff);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_vrange128_reset(struct silofs_vrange128 *vrng)
{
	struct silofs_vrange vrange = {
		.beg = SILOFS_OFF_NULL,
		.end = SILOFS_OFF_NULL,
		.len = 0,
		.height = 0,
		.stepsz = 0,
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
	size_t height;

	beg = silofs_off_to_cpu(vrng->beg);
	len_height_to_cpu(vrng->len_height, &len, &height);
	silofs_vrange_setup(vrange, height, beg, off_end(beg, len));
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
	const size_t align_size = SILOFS_VSEC_SIZE;

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
	const char *s = buf;
	char *t = nb->name;

	uuid_unparse_lower(uu->uu, buf);
	while (*s != '\0') {
		if (isxdigit(*s)) {
			*t = *s;
		}
		t++;
		s++;
	}
	*t = '\0';
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
	return !ino_isnull(ino) ? 0 : -EFSCORRUPTED;
}

int silofs_verify_off(loff_t off)
{
	return (off_isnull(off) || (off >= 0)) ? 0 : -EFSCORRUPTED;
}

