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
#include <silofs/pv.h>
#include <uuid/uuid.h>
#include <stdlib.h>
#include <stdint.h>
#include <endian.h>
#include <errno.h>
#include <ctype.h>

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_off_isnull(loff_t off)
{
	STATICASSERT_LT(SILOFS_OFF_NULL, 0);

	return (off < 0);
}

loff_t silofs_off_min(loff_t off1, loff_t off2)
{
	return (off1 < off2) ? off1 : off2;
}

loff_t silofs_off_max(loff_t off1, loff_t off2)
{
	return (off1 > off2) ? off1 : off2;
}

loff_t silofs_off_end(loff_t off, size_t len)
{
	return off + (loff_t)len;
}

silofs_lba_t silofs_off_to_lba(loff_t off)
{
	return !silofs_off_isnull(off) ?
	       (off / SILOFS_LBK_SIZE) : SILOFS_LBA_NULL;
}

loff_t silofs_off_in_lbk(loff_t off)
{
	return silofs_off_remainder(off, SILOFS_LBK_SIZE);
}

loff_t silofs_off_remainder(loff_t off, size_t len)
{
	return off % (ssize_t)len;
}

loff_t silofs_off_align(loff_t off, ssize_t align)
{
	return (off / align) * align;
}

loff_t silofs_off_align_to_lbk(loff_t off)
{
	return silofs_off_align(off, SILOFS_LBK_SIZE);
}

loff_t silofs_off_next(loff_t off, ssize_t len)
{
	return silofs_off_align(off + len, len);
}

ssize_t silofs_off_diff(loff_t beg, loff_t end)
{
	return end - beg;
}

ssize_t silofs_off_len(loff_t beg, loff_t end)
{
	return silofs_off_diff(beg, end);
}

size_t silofs_off_ulen(loff_t beg, loff_t end)
{
	return (size_t)silofs_off_len(beg, end);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool lba_isequal(silofs_lba_t lba1, silofs_lba_t lba2)
{
	return (lba1 == lba2);
}

bool silofs_lba_isnull(silofs_lba_t lba)
{
	return lba_isequal(lba, SILOFS_LBA_NULL);
}

loff_t silofs_lba_to_off(silofs_lba_t lba)
{
	return !silofs_lba_isnull(lba) ?
	       (lba * SILOFS_LBK_SIZE) : SILOFS_OFF_NULL;
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

void silofs_pvid_generate(struct silofs_pvid *pvid)
{
	silofs_uuid_generate(&pvid->uuid);
}

void silofs_pvid_assign(struct silofs_pvid *pvid,
                        const struct silofs_pvid *other)
{
	silofs_uuid_assign(&pvid->uuid, &other->uuid);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_lvid_generate(struct silofs_lvid *lvid)
{
	silofs_uuid_generate(&lvid->uuid);
}

void silofs_lvid_assign(struct silofs_lvid *lvid,
                        const struct silofs_lvid *other)
{
	silofs_uuid_assign(&lvid->uuid, &other->uuid);
}

long silofs_lvid_compare(const struct silofs_lvid *lvid1,
                         const struct silofs_lvid *lvid2)
{
	const struct silofs_uuid *uu1 = &lvid1->uuid;
	const struct silofs_uuid *uu2 = &lvid2->uuid;

	return memcmp(uu1->uu, uu2->uu, sizeof(uu1->uu));
}

bool silofs_lvid_isequal(const struct silofs_lvid *lvid1,
                         const struct silofs_lvid *lvid2)
{
	return (silofs_lvid_compare(lvid1, lvid2) == 0);
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_lsegid s_lsegid_none = {
	.size = 0,
	.vspace = SILOFS_STYPE_NONE,
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
	return (lsegid->size == 0);
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
	lsegid->voff = SILOFS_OFF_NULL;
	lsegid->size = 0;
	lsegid->vspace = SILOFS_STYPE_NONE;
	lsegid->height = SILOFS_HEIGHT_NONE;
}

void silofs_lsegid_assign(struct silofs_lsegid *lsegid,
                          const struct silofs_lsegid *other)
{
	silofs_lvid_assign(&lsegid->lvid, &other->lvid);
	lsegid->voff = other->voff;
	lsegid->size = other->size;
	lsegid->vspace = other->vspace;
	lsegid->height = other->height;
}

long silofs_lsegid_compare(const struct silofs_lsegid *lsegid1,
                           const struct silofs_lsegid *lsegid2)
{
	long cmp;

	cmp = (long)(lsegid2->vspace) - (long)(lsegid1->vspace);
	if (cmp) {
		return cmp;
	}
	cmp = (long)(lsegid2->height) - (long)(lsegid1->height);
	if (cmp) {
		return cmp;
	}
	cmp = (long)(lsegid2->size) - (long)(lsegid1->size);
	if (cmp) {
		return cmp;
	}
	cmp = (long)(lsegid2->voff) - (long)(lsegid1->voff);
	if (cmp) {
		return cmp;
	}
	cmp = silofs_lvid_compare(&lsegid1->lvid, &lsegid2->lvid);
	if (cmp) {
		return cmp;
	}
	return 0;
}

bool silofs_lsegid_isequal(const struct silofs_lsegid *lsegid,
                           const struct silofs_lsegid *other)
{
	return silofs_lsegid_compare(lsegid, other) == 0;
}

uint64_t silofs_lsegid_hash64(const struct silofs_lsegid *lsegid)
{
	struct silofs_lsegid32b bid = { .size = 0 };

	silofs_lsegid32b_htox(&bid, lsegid);
	return silofs_hash_xxh64(&bid, sizeof(bid), lsegid->vspace);
}

void silofs_lsegid_setup(struct silofs_lsegid *lsegid,
                         const struct silofs_lvid *lvid,
                         loff_t voff, enum silofs_stype vspace,
                         enum silofs_height height)
{
	const size_t sz = height_to_lseg_size(height);

	silofs_lvid_assign(&lsegid->lvid, lvid);
	lsegid->size = sz;
	lsegid->voff = sz ? off_align(voff, (ssize_t)sz) : SILOFS_OFF_NULL;
	lsegid->height = height;
	lsegid->vspace = vspace;
}

static void lsegid_as_iv(const struct silofs_lsegid *lsegid,
                         struct silofs_iv *out_iv)
{
	STATICASSERT_EQ(sizeof(lsegid->lvid), sizeof(*out_iv));
	STATICASSERT_EQ(sizeof(lsegid->lvid.uuid), sizeof(out_iv->iv));
	STATICASSERT_GE(ARRAY_SIZE(out_iv->iv), 16);

	memcpy(out_iv->iv, &lsegid->lvid.uuid, sizeof(out_iv->iv));
	out_iv->iv[0] ^= (uint8_t)(lsegid->voff & 0xFF);
	out_iv->iv[1] ^= (uint8_t)((lsegid->voff >> 8) & 0xFF);
	out_iv->iv[2] ^= (uint8_t)((lsegid->voff >> 16) & 0xFF);
	out_iv->iv[3] ^= (uint8_t)((lsegid->voff >> 24) & 0xFF);
	out_iv->iv[4] ^= (uint8_t)((lsegid->voff >> 32) & 0xFF);
	out_iv->iv[5] ^= (uint8_t)((lsegid->voff >> 40) & 0xFF);
	out_iv->iv[6] ^= (uint8_t)((lsegid->voff >> 48) & 0xFF);
	out_iv->iv[7] ^= (uint8_t)((lsegid->voff >> 56) & 0xFF);

	out_iv->iv[14] ^= (uint8_t)lsegid->vspace;
	out_iv->iv[15] ^= (uint8_t)lsegid->height;
}

void silofs_lsegid32b_reset(struct silofs_lsegid32b *lsegid32)
{
	memset(lsegid32, 0, sizeof(*lsegid32));
	lsegid32->voff = SILOFS_OFF_NULL;
	lsegid32->size = 0;
	lsegid32->vspace = SILOFS_STYPE_NONE;
	lsegid32->height = SILOFS_HEIGHT_LAST;
}

void silofs_lsegid32b_htox(struct silofs_lsegid32b *lsegid32,
                           const struct silofs_lsegid *lsegid)
{
	memset(lsegid32, 0, sizeof(*lsegid32));
	silofs_lvid_assign(&lsegid32->lvid, &lsegid->lvid);
	lsegid32->voff = silofs_cpu_to_off(lsegid->voff);
	lsegid32->size = silofs_cpu_to_le32((uint32_t)lsegid->size);
	lsegid32->vspace = (uint8_t)lsegid->vspace;
	lsegid32->height = (uint8_t)lsegid->height;
}

void silofs_lsegid32b_xtoh(const struct silofs_lsegid32b *lsegid32,
                           struct silofs_lsegid *lsegid)
{
	silofs_lvid_assign(&lsegid->lvid, &lsegid32->lvid);
	lsegid->voff = silofs_off_to_cpu(lsegid32->voff);
	lsegid->size = silofs_le32_to_cpu(lsegid32->size);
	lsegid->vspace = (enum silofs_stype)lsegid32->vspace;
	lsegid->height = (enum silofs_height)lsegid32->height;
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
                        const struct silofs_lsegid *lsegid,
                        loff_t off, size_t len)
{
	silofs_lsegid_assign(&laddr->lsegid, lsegid);
	if (lsegid->size && !off_isnull(off)) {
		laddr->len = len;
		laddr->pos = silofs_lsegid_pos(lsegid, off);
	} else {
		laddr->len = 0;
		laddr->pos = SILOFS_OFF_NULL;
	}
}

void silofs_laddr_reset(struct silofs_laddr *laddr)
{
	silofs_lsegid_reset(&laddr->lsegid);
	laddr->len = 0;
	laddr->pos = SILOFS_OFF_NULL;
}

void silofs_laddr_assign(struct silofs_laddr *laddr,
                         const struct silofs_laddr *other)
{
	silofs_lsegid_assign(&laddr->lsegid, &other->lsegid);
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
	cmp = silofs_lsegid_compare(&laddr1->lsegid, &laddr2->lsegid);
	if (cmp) {
		return cmp;
	}
	return 0;
}

bool silofs_laddr_isnull(const struct silofs_laddr *laddr)
{
	return silofs_off_isnull(laddr->pos) ||
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
	return ((laddr->len == other->len) && (laddr->pos == other->pos) &&
	        silofs_lsegid_isequal(&laddr->lsegid, &other->lsegid));
}

void silofs_laddr_as_iv(const struct silofs_laddr *laddr,
                        struct silofs_iv *out_iv)
{
	STATICASSERT_GE(ARRAY_SIZE(out_iv->iv), 16);

	memset(out_iv, 0, sizeof(*out_iv));
	lsegid_as_iv(&laddr->lsegid, out_iv);
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
	silofs_lsegid32b_reset(&laddr48->lsegid);
	laddr48->pos = 0;
	laddr48->len = 0;
}

void silofs_laddr48b_htox(struct silofs_laddr48b *laddr48,
                          const struct silofs_laddr *laddr)
{
	silofs_lsegid32b_htox(&laddr48->lsegid, &laddr->lsegid);
	laddr48->pos = silofs_cpu_to_le32((uint32_t)(laddr->pos));
	laddr48->len = silofs_cpu_to_le32((uint32_t)(laddr->len));
}

void silofs_laddr48b_xtoh(const struct silofs_laddr48b *laddr48,
                          struct silofs_laddr *laddr)
{
	silofs_lsegid32b_xtoh(&laddr48->lsegid, &laddr->lsegid);
	laddr->pos = (loff_t)silofs_le32_to_cpu(laddr48->pos);
	laddr->len = (size_t)silofs_le32_to_cpu(laddr48->len);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_paddr s_paddr_none = {
	.index = 0,
	.off = SILOFS_OFF_NULL,
	.len = 0
};

const struct silofs_paddr *silofs_paddr_none(void)
{
	return &s_paddr_none;
}

bool silofs_paddr_isnull(const struct silofs_paddr *paddr)
{
	return !paddr->index || !paddr->len || off_isnull(paddr->off);
}

void silofs_paddr_assign(struct silofs_paddr *paddr,
                         const struct silofs_paddr *other)
{
	silofs_pvid_assign(&paddr->pvid, &other->pvid);
	paddr->index = other->index;
	paddr->off = other->off;
	paddr->len = other->len;
}


void silofs_paddr32b_reset(struct silofs_paddr32b *paddr32)
{
	memset(paddr32, 0, sizeof(*paddr32));
	paddr32->index = 0;
	paddr32->len = 0;
	paddr32->off = SILOFS_OFF_NULL;
}

void silofs_paddr32b_htox(struct silofs_paddr32b *paddr32,
                          const struct silofs_paddr *paddr)
{
	silofs_pvid_assign(&paddr32->pvid, &paddr->pvid);
	paddr32->index = silofs_cpu_to_le32((uint32_t)(paddr->index));
	paddr32->len = silofs_cpu_to_le32((uint32_t)(paddr->len));
	paddr32->off = silofs_cpu_to_off(paddr->off);
}

void silofs_paddr32b_xtoh(const struct silofs_paddr32b *paddr32,
                          struct silofs_paddr *paddr)
{
	silofs_pvid_assign(&paddr->pvid, &paddr32->pvid);
	paddr->index = silofs_le32_to_cpu(paddr32->index);
	paddr->len = silofs_le32_to_cpu(paddr32->len);
	paddr->off = silofs_off_to_cpu(paddr32->off);
}
