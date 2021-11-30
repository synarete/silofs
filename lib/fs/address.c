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
#include <silofs/fs/nodes.h>
#include <silofs/fs/address.h>
#include <silofs/fs/private.h>
#include <stdlib.h>
#include <stdint.h>
#include <endian.h>
#include <errno.h>
#include <ctype.h>


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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
	size_t sz;

	switch (stype) {
	case SILOFS_STYPE_SUPER:
		sz = sizeof(struct silofs_super_block);
		break;
	case SILOFS_STYPE_SPNODE:
		sz = sizeof(struct silofs_spmap_node);
		break;
	case SILOFS_STYPE_SPLEAF:
		sz = sizeof(struct silofs_spmap_leaf);
		break;
	case SILOFS_STYPE_ITNODE:
		sz = sizeof(struct silofs_itable_node);
		break;
	case SILOFS_STYPE_INODE:
		sz = sizeof(struct silofs_inode);
		break;
	case SILOFS_STYPE_XANODE:
		sz = sizeof(struct silofs_xattr_node);
		break;
	case SILOFS_STYPE_DTNODE:
		sz = sizeof(struct silofs_dtree_node);
		break;
	case SILOFS_STYPE_FTNODE:
		sz = sizeof(struct silofs_ftree_node);
		break;
	case SILOFS_STYPE_SYMVAL:
		sz = sizeof(struct silofs_symlnk_value);
		break;
	case SILOFS_STYPE_DATA1K:
		sz = sizeof(struct silofs_data_block1);
		break;
	case SILOFS_STYPE_DATA4K:
		sz = sizeof(struct silofs_data_block4);
		break;
	case SILOFS_STYPE_DATABK:
	case SILOFS_STYPE_ANONBK:
		sz = sizeof(struct silofs_data_block);
		break;
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_MAX:
	default:
		sz = 0;
		break;
	}
	return sz;
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

static void uint64_to_ascii(uint64_t u, char *a)
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

static uint64_t ascii_to_uint64(const char *a)
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

void silofs_metaid_generate(struct silofs_metaid *mid)
{
	silofs_getentropy(mid->id, sizeof(mid->id));
}

static void metaid_assign(struct silofs_metaid *mid,
                          const struct silofs_metaid *other)
{
	mid->id[0] = other->id[0];
	mid->id[1] = other->id[1];
}

static long metaid_compare(const struct silofs_metaid *mid1,
                           const struct silofs_metaid *mid2)
{
	long cmp;

	cmp = (long)(mid1->id[0]) - (long)(mid2->id[0]);
	if (cmp) {
		return cmp;
	}
	cmp = (long)(mid1->id[1]) - (long)(mid2->id[1]);
	if (cmp) {
		return cmp;
	}
	return 0;
}

uint64_t silofs_metaid_hkey(const struct silofs_metaid *mid)
{
	STATICASSERT_EQ(ARRAY_SIZE(mid->id), 2);

	return mid->id[0] ^ mid->id[1];
}

static uint64_t metaid_as_u64(const struct silofs_metaid *mid)
{
	return silofs_metaid_hkey(mid);
}

bool silofs_metaid_isequal(const struct silofs_metaid *mid1,
                           const struct silofs_metaid *mid2)
{
	return (metaid_compare(mid1, mid2) == 0);
}

void silofs_metaid_to_name(const struct silofs_metaid *mid, char *name)
{
	uint64_to_ascii(mid->id[0], name);
	uint64_to_ascii(mid->id[1], name + 16);
}

void silofs_metaid_from_name(struct silofs_metaid *mid, const char *name)
{
	mid->id[0] = ascii_to_uint64(name);
	mid->id[1] = ascii_to_uint64(name + 16);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_metaid128_set(struct silofs_metaid128 *metaid128,
                          const struct silofs_metaid *mid)
{
	STATICASSERT_EQ(sizeof(metaid128->id), sizeof(mid->id));
	STATICASSERT_EQ(ARRAY_SIZE(metaid128->id), 2);

	metaid128->id[0] = silofs_cpu_to_le64(mid->id[0]);
	metaid128->id[1] = silofs_cpu_to_le64(mid->id[1]);
}

void silofs_metaid128_parse(const struct silofs_metaid128 *metaid128,
                            struct silofs_metaid *mid)
{
	STATICASSERT_EQ(sizeof(metaid128->id), sizeof(mid->id));
	STATICASSERT_EQ(ARRAY_SIZE(mid->id), 2);

	mid->id[0] = silofs_le64_to_cpu(metaid128->id[0]);
	mid->id[1] = silofs_le64_to_cpu(metaid128->id[1]);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_blobid s_blobid_none = {
	.size = 0,
	.height = -1,
};

const struct silofs_blobid *silofs_blobid_none(void)
{
	return &s_blobid_none;
}

size_t silofs_blobid_size(const struct silofs_blobid *bid)
{
	return bid->size;
}

ssize_t silofs_blobid_ssize(const struct silofs_blobid *bid)
{
	return (ssize_t)silofs_blobid_size(bid);
}

static bool silofs_blobid_isnull(const struct silofs_blobid *bid)
{
	return !bid->size || (bid->height < 0);
}

static loff_t blobid_off_within(const struct silofs_blobid *bid, loff_t off)
{
	const size_t blob_size = silofs_blobid_size(bid);

	return blob_size ? silofs_off_within(off, blob_size) : 0;
}

void silofs_blobid_reset(struct silofs_blobid *bid)
{
	memset(bid, 0, sizeof(*bid));
	bid->size = 0;
	bid->height = -1;
}

static void blobid_generate_for(struct silofs_blobid *bid,
                                const struct silofs_metaid *treeid)
{
	metaid_assign(&bid->tree_id, treeid);
	silofs_metaid_generate(&bid->uniq_id);
}

void silofs_blobid_assign(struct silofs_blobid *bid,
                          const struct silofs_blobid *other)
{
	metaid_assign(&bid->tree_id, &other->tree_id);
	metaid_assign(&bid->uniq_id, &other->uniq_id);
	bid->size = other->size;
	bid->height = other->height;
}

long silofs_blobid_compare(const struct silofs_blobid *bid1,
                           const struct silofs_blobid *bid2)
{
	long cmp;

	cmp = bid2->height - bid1->height;
	if (cmp) {
		return cmp;
	}
	cmp = (long)(bid2->size) - (long)(bid1->size);
	if (cmp) {
		return cmp;
	}
	cmp = metaid_compare(&bid1->tree_id, &bid2->tree_id);
	if (cmp) {
		return cmp;
	}
	cmp = metaid_compare(&bid1->uniq_id, &bid2->uniq_id);
	if (cmp) {
		return cmp;
	}
	return 0;
}

bool silofs_blobid_isequal(const struct silofs_blobid *bid,
                           const struct silofs_blobid *other)
{
	return silofs_blobid_compare(bid, other) == 0;
}

uint64_t silofs_blobid_hkey(const struct silofs_blobid *bid)
{
	const uint32_t rot = (uint32_t)bid->height;
	const uint64_t thk = silofs_metaid_hkey(&bid->tree_id);
	const uint64_t uhk = silofs_metaid_hkey(&bid->uniq_id);

	return silofs_rotate64(thk, rot) ^ uhk ^ bid->size;
}

uint64_t silofs_blobid_as_u64(const struct silofs_blobid *bid)
{
	return metaid_as_u64(&bid->tree_id) ^ metaid_as_u64(&bid->uniq_id);
}

int silofs_blobid_to_name(const struct silofs_blobid *bid,
                          char *name, size_t nmax, size_t *out_len)
{
	int err = -EINVAL;
	const size_t metaid_name_len = 2 * SILOFS_METAID_SIZE;
	const size_t blobid_name_len = 2 * metaid_name_len;

	if (nmax >= blobid_name_len) {
		silofs_metaid_to_name(&bid->tree_id, name);
		silofs_metaid_to_name(&bid->uniq_id, name + metaid_name_len);
		*out_len = blobid_name_len;
		if (nmax > blobid_name_len) {
			name[blobid_name_len] = '\0';
		}
		err = 0;
	}
	return err;
}

int silofs_check_blobid_ascii_name(const char *name, size_t nlen)
{
	int ret;
	const size_t metaid_name_len = 2 * SILOFS_METAID_SIZE;
	const size_t blobid_name_len = 2 * metaid_name_len;

	if (nlen < blobid_name_len) {
		return -EINVAL;
	}
	for (size_t i = 0; i < nlen; ++i) {
		ret = silofs_ascii_to_nibble(name[i]);
		if (ret < 0) {
			return -EINVAL;
		}
	}
	return 0;
}

static size_t blobid_size_for(size_t obj_size, size_t nobjs)
{
	const size_t bk_size = SILOFS_BK_SIZE;

	return div_round_up(nobjs * obj_size, bk_size) * bk_size;
}

void silofs_blobid_make(struct silofs_blobid *bid,
                        const struct silofs_metaid *treeid,
                        size_t obj_size, size_t nobjs, size_t height)
{
	blobid_generate_for(bid, treeid);
	bid->size = blobid_size_for(obj_size, nobjs);
	bid->height = (int)height;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_blobid40b_reset(struct silofs_blobid40b *bid40)
{
	memset(bid40, 0, sizeof(*bid40));
	bid40->size = 0;
	bid40->height = 0xFF;
}

void silofs_blobid40b_set(struct silofs_blobid40b *bid40,
                          const struct silofs_blobid *bid)
{
	silofs_metaid128_set(&bid40->tree_id, &bid->tree_id);
	silofs_metaid128_set(&bid40->uniq_id, &bid->uniq_id);
	bid40->size = silofs_cpu_to_le32((uint32_t)bid->size);
	bid40->height = (bid->height < 0) ? 0xFF : (uint8_t)bid->height;
	bid40->flags = 0;
	bid40->reserved = 0;
}

void silofs_blobid40b_parse(const struct silofs_blobid40b *bid40,
                            struct silofs_blobid *bid)
{
	silofs_metaid128_parse(&bid40->tree_id, &bid->tree_id);
	silofs_metaid128_parse(&bid40->uniq_id, &bid->uniq_id);
	bid->height = (bid40->height == 0xFF) ? -1 : (int)bid40->height;
	bid->size = silofs_le32_to_cpu(bid40->size);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_oaddr s_oaddr_none = {
	.pos = SILOFS_OFF_NULL,
};

const struct silofs_oaddr *silofs_oaddr_none(void)
{
	return &s_oaddr_none;
}

void silofs_oaddr_setup(struct silofs_oaddr *oaddr,
                        const struct silofs_blobid *bid,
                        size_t len, loff_t off)
{
	silofs_blobid_assign(&oaddr->bid, bid);
	if (bid->size && !off_isnull(off)) {
		oaddr->len = len;
		oaddr->pos = blobid_off_within(bid, off);
	} else {
		oaddr->len = 0;
		oaddr->pos = SILOFS_OFF_NULL;
	}
}

void silofs_oaddr_setup_by(struct silofs_oaddr *oaddr,
                           const struct silofs_blobid *bid,
                           const struct silofs_vaddr *vaddr)
{
	silofs_oaddr_setup(oaddr, bid, vaddr->len, vaddr->voff);
}

void silofs_oaddr_reset(struct silofs_oaddr *oaddr)
{
	silofs_blobid_reset(&oaddr->bid);
	oaddr->len = 0;
	oaddr->pos = SILOFS_OFF_NULL;
}

void silofs_oaddr_assign(struct silofs_oaddr *oaddr,
                         const struct silofs_oaddr *other)
{
	silofs_blobid_assign(&oaddr->bid, &other->bid);
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
	cmp = silofs_blobid_compare(&oaddr1->bid, &oaddr2->bid);
	if (cmp) {
		return cmp;
	}
	return 0;
}

bool silofs_oaddr_isnull(const struct silofs_oaddr *oaddr)
{
	return off_isnull(oaddr->pos) || silofs_blobid_isnull(&oaddr->bid);
}

bool silofs_oaddr_isvalid(const struct silofs_oaddr *oaddr)
{
	const loff_t end = off_end(oaddr->pos, oaddr->len);
	const ssize_t bid_size = (ssize_t)(oaddr->bid.size);

	return !silofs_oaddr_isnull(oaddr) && (end <= bid_size);
}

bool silofs_oaddr_isequal(const struct silofs_oaddr *oaddr,
                          const struct silofs_oaddr *other)
{
	return ((oaddr->len == other->len) &&
	        (oaddr->pos == other->pos) &&
	        silofs_blobid_isequal(&oaddr->bid, &other->bid));
}

silofs_lba_t silofs_oaddr_lba(const struct silofs_oaddr *oaddr)
{
	return off_to_lba(oaddr->pos);
}

void silofs_oaddr_of_bk(struct silofs_oaddr *oaddr,
                        const struct silofs_blobid *bid, silofs_lba_t lba)
{
	silofs_oaddr_setup(oaddr, bid, SILOFS_BK_SIZE, lba_to_off(lba));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void silofs_oaddr48b_reset(struct silofs_oaddr48b *oaddr48)
{
	silofs_blobid40b_reset(&oaddr48->bid);
	oaddr48->pos = 0;
	oaddr48->len = 0;
}

static void silofs_oaddr48b_set(struct silofs_oaddr48b *oaddr48,
                                const struct silofs_oaddr *oaddr)
{
	silofs_blobid40b_set(&oaddr48->bid, &oaddr->bid);
	oaddr48->pos = silofs_cpu_to_le32((uint32_t)(oaddr->pos));
	oaddr48->len = silofs_cpu_to_le32((uint32_t)(oaddr->len));
}

static void silofs_oaddr48b_parse(const struct silofs_oaddr48b *oaddr48,
                                  struct silofs_oaddr *oaddr)
{
	silofs_blobid40b_parse(&oaddr48->bid, &oaddr->bid);
	oaddr->pos = (loff_t)silofs_le32_to_cpu(oaddr48->pos);
	oaddr->len = (size_t)silofs_le32_to_cpu(oaddr48->len);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_ovaddr_setup(struct silofs_ovaddr *ova,
                         const struct silofs_oaddr *oaddr,
                         const struct silofs_vaddr *vaddr)
{
	oaddr_assign(&ova->oaddr, oaddr);
	vaddr_assign(&ova->vaddr, vaddr);
}

void silofs_ovaddr_assign(struct silofs_ovaddr *ova,
                          const struct silofs_ovaddr *other)
{
	oaddr_assign(&ova->oaddr, &other->oaddr);
	vaddr_assign(&ova->vaddr, &other->vaddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_uaddr s_uaddr_none = {
	.oaddr.bid.size = 0,
	.oaddr.bid.height = -1,
	.oaddr.pos = SILOFS_OFF_NULL,
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
	       silofs_oaddr_isnull(&uaddr->oaddr);
}

void silofs_uaddr_setup(struct silofs_uaddr *uaddr,
                        const struct silofs_blobid *bid,
                        enum silofs_stype stype, loff_t bpos, loff_t voff)
{
	silofs_oaddr_setup(&uaddr->oaddr, bid, stype_size(stype), bpos);
	uaddr->voff = voff;
	uaddr->stype = stype;
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
}

void silofs_uaddr_to_oaddr(const struct silofs_uaddr *uaddr,
                           struct silofs_oaddr *oaddr)
{
	oaddr_assign(oaddr, &uaddr->oaddr);
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
	cmp = silofs_oaddr_compare(&uaddr1->oaddr, &uaddr2->oaddr);
	if (cmp) {
		return cmp;
	}
	return 0;
}

void silofs_uaddr_make_for_super(struct silofs_uaddr *uaddr,
                                 const struct silofs_blobid *bid)
{
	silofs_assert_eq(bid->height, SILOFS_SUPER_HEIGHT);
	silofs_uaddr_setup(uaddr, bid, SILOFS_STYPE_SUPER, 0, 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_uaddr56b_reset(struct silofs_uaddr56b *uaddr56)
{
	silofs_oaddr48b_reset(&uaddr56->oaddr);
	uaddr56->voff_stype = 0;
}

void silofs_uaddr56b_set(struct silofs_uaddr56b *uaddr56,
                         const struct silofs_uaddr *uaddr)
{
	silofs_oaddr48b_set(&uaddr56->oaddr, &uaddr->oaddr);
	uaddr56->voff_stype =
	        cpu_to_voff_stype(uaddr->voff, uaddr->stype);
}

void silofs_uaddr56b_parse(const struct silofs_uaddr56b *uaddr56,
                           struct silofs_uaddr *uaddr)
{
	silofs_oaddr48b_parse(&uaddr56->oaddr, &uaddr->oaddr);
	voff_stype_to_cpu(uaddr56->voff_stype,
	                  &uaddr->voff, &uaddr->stype);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_taddr_setup(struct silofs_taddr *taddr,
                        const struct silofs_metaid *tree_id,
                        loff_t voff, size_t height)
{
	metaid_assign(&taddr->tree_id, tree_id);
	taddr->voff = voff;
	taddr->height = (int)height;
}

void silofs_taddr_by_uaddr(struct silofs_taddr *taddr,
                           const struct silofs_uaddr *uaddr)
{
	metaid_assign(&taddr->tree_id, &uaddr->oaddr.bid.tree_id);
	taddr->voff = uaddr->voff;
	taddr->height = uaddr->oaddr.bid.height;
}

bool silofs_taddr_isequal(const struct silofs_taddr *taddr1,
                          const struct silofs_taddr *taddr2)
{
	return (taddr1->height == taddr2->height) &&
	       (taddr1->voff == taddr2->voff) &&
	       metaid_isequal(&taddr1->tree_id, &taddr2->tree_id);
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

size_t silofs_vrange_length(const struct silofs_vrange *vrange)
{
	return off_ulen(vrange->beg, vrange->end);
}

bool silofs_vrange_within(const struct silofs_vrange *vrange, loff_t off)
{
	return (vrange->beg <= off) && (off < vrange->end);
}

void silofs_vrange_setup(struct silofs_vrange *vrange, loff_t beg, loff_t end)
{
	silofs_assert_le(beg, end);
	vrange->beg = beg;
	vrange->end = end;
}

void silofs_vrange_setup_by(struct silofs_vrange *vrange,
                            size_t height, loff_t voff_base)
{
	loff_t beg;
	size_t height_iter = 0;
	ssize_t span = SILOFS_BK_SIZE;

	height = min(height, SILOFS_SUPER_HEIGHT);
	while (height_iter <= height) {
		if (height_iter == SILOFS_SPLEAF_HEIGHT) {
			span *= SILOFS_NBK_IN_VSEC;
		} else if ((height_iter > SILOFS_SPLEAF_HEIGHT) &&
		           (height_iter <= SILOFS_SPNODE_HEIGHT_MAX)) {
			span *= SILOFS_SPMAP_NODE_NCHILDS;
		} else if (height_iter > SILOFS_SPNODE_HEIGHT_MAX) {
			span *= SILOFS_SUPER_NODE_NCHILDS;
			break;
		}
		height_iter++;
	}
	beg = off_align(voff_base, span);
	silofs_vrange_setup(vrange, beg, off_next(beg, span));
}

void silofs_vrange_of_spleaf(struct silofs_vrange *vrange, loff_t voff)
{
	silofs_vrange_setup_by(vrange, SILOFS_SPLEAF_HEIGHT, voff);
}

void silofs_vrange_of_spnode(struct silofs_vrange *vrange,
                             size_t height, loff_t voff)
{
	silofs_vrange_setup_by(vrange, height, voff);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_vrange128_reset(struct silofs_vrange128 *vrng)
{
	struct silofs_vrange vrange = {
		.beg = SILOFS_OFF_NULL,
		.end = SILOFS_OFF_NULL,
	};

	silofs_vrange128_set(vrng, &vrange);
}

void silofs_vrange128_set(struct silofs_vrange128 *vrng,
                          const struct silofs_vrange *vrange)
{
	vrng->beg = silofs_cpu_to_off(vrange->beg);
	vrng->end = silofs_cpu_to_off(vrange->end);
}

void silofs_vrange128_parse(const struct silofs_vrange128 *vrng,
                            struct silofs_vrange *vrange)
{
	vrange->beg = silofs_off_to_cpu(vrng->beg);
	vrange->end = silofs_off_to_cpu(vrng->end);
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

void silofs_namebuf_assign_str(struct silofs_namebuf *nb,
                               const struct silofs_namestr *name)
{
	const size_t len = silofs_min(name->str.len, sizeof(nb->name) - 1);

	memcpy(nb->name, name->str.str, len);
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

	return (name->str.len == len) && !memcmp(nb->name, name->str.str, len);
}

void silofs_namebuf_str(const struct silofs_namebuf *nb,
                        struct silofs_namestr *name)
{
	name->str.str = nb->name;
	name->str.len = strlen(nb->name);
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
