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
#include "infra.h"
#include "offlba.h"
#include "ltype.h"
#include "htox.h"
#include "vaddr.h"
#include "private.h"

static uint64_t cpu_to_voff_ltype(loff_t voff, enum silofs_ltype ltype)
{
	uint64_t voff_ltype;
	const uint64_t mask = 0xFF;
	const uint64_t uoff = (uint64_t)voff;
	const uint64_t ultype = (uint64_t)ltype;

	if (!silofs_ltype_isnone(ltype)) {
		silofs_assert_eq(uoff & mask, 0);

		voff_ltype = ((uoff & ~mask) | (ultype & mask));
		voff_ltype = silofs_cpu_to_le64(voff_ltype);
	} else {
		voff_ltype = 0;
	}
	return voff_ltype;
}

static void voff_ltype_to_cpu(uint64_t voff_ltype, loff_t *out_voff,
                              enum silofs_ltype *out_ltype)
{
	const uint64_t mask = 0xFF;
	const uint64_t uoff = voff_ltype & ~mask;
	const uint64_t ultype = voff_ltype & mask;

	if (voff_ltype > 0) {
		*out_voff = (loff_t)uoff;
		*out_ltype = (enum silofs_ltype)ultype;
	} else {
		*out_voff = SILOFS_OFF_NULL;
		*out_ltype = SILOFS_LTYPE_NONE;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_vaddr s_silofs_vaddr_none = {
	.off = SILOFS_OFF_NULL,
	.ltype = SILOFS_LTYPE_NONE,
};

const struct silofs_vaddr *silofs_vaddr_none(void)
{
	return &s_silofs_vaddr_none;
}

size_t silofs_vaddr_len(const struct silofs_vaddr *vaddr)
{
	return (size_t)silofs_ltype_size(vaddr->ltype);
}

long silofs_vaddr_compare(const struct silofs_vaddr *vaddr1,
                          const struct silofs_vaddr *vaddr2)
{
	long cmp;

	cmp = vaddr1->ltype - vaddr2->ltype;
	if (cmp) {
		return cmp;
	}
	cmp = vaddr1->off - vaddr2->off;
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

void silofs_vaddr_setup(struct silofs_vaddr *vaddr, enum silofs_ltype ltype,
                        loff_t voff)
{
	vaddr->ltype = ltype;
	vaddr->off = voff;
}

void silofs_vaddr_setup2(struct silofs_vaddr *vaddr, enum silofs_ltype ltype,
                         silofs_lba_t lba)
{
	silofs_vaddr_setup(vaddr, ltype, silofs_lba_to_off(lba));
}

void silofs_vaddr_of_lsmap(struct silofs_vaddr *vaddr,
                           enum silofs_ltype refltype, loff_t pos)
{
	const ssize_t step = sizeof(struct silofs_lsmap);
	ssize_t lseg_idx;
	ssize_t refl_idx;
	ssize_t span;
	loff_t off;

	// all sort of hidden assumptions here -- FIXME
	STATICASSERT_EQ(SILOFS_LTYPE_INODE, 6);
	STATICASSERT_EQ(SILOFS_LTYPE_DATABK - SILOFS_LTYPE_INODE + 1, 8);
	STATICASSERT_EQ(SILOFS_LTYPE_DATABK + 1, SILOFS_LTYPE_LAST);
	STATICASSERT_EQ(sizeof(struct silofs_lsmap), SILOFS_LBK_SIZE);

	silofs_assert_ge(refltype, SILOFS_LTYPE_INODE);
	silofs_assert_le(refltype, SILOFS_LTYPE_DATABK);

	lseg_idx = pos / SILOFS_LSEG_SIZE_MAX;
	refl_idx = (ssize_t)refltype - SILOFS_LTYPE_INODE;
	span = SILOFS_LTYPE_DATABK - SILOFS_LTYPE_INODE + 1;
	off = ((lseg_idx * span) + refl_idx + 1) * step; /* zero is reserved */

	silofs_vaddr_setup(vaddr, SILOFS_LTYPE_LSMAP, off);
}

void silofs_vaddr_assign(struct silofs_vaddr *vaddr,
                         const struct silofs_vaddr *other)
{
	vaddr->ltype = other->ltype;
	vaddr->off = other->off;
}

void silofs_vaddr_reset(struct silofs_vaddr *vaddr)
{
	vaddr->ltype = SILOFS_LTYPE_NONE;
	vaddr->off = SILOFS_OFF_NULL;
}

bool silofs_vaddr_isnull(const struct silofs_vaddr *vaddr)
{
	return silofs_off_isnull(vaddr->off) ||
	       silofs_ltype_isnone(vaddr->ltype);
}

bool silofs_vaddr_isdata(const struct silofs_vaddr *vaddr)
{
	return silofs_ltype_isdata(vaddr->ltype);
}

bool silofs_vaddr_isdatabk(const struct silofs_vaddr *vaddr)
{
	return vaddr->ltype == SILOFS_LTYPE_DATABK;
}

bool silofs_vaddr_isinode(const struct silofs_vaddr *vaddr)
{
	return silofs_ltype_isinode(vaddr->ltype);
}

static silofs_lba_t lba_kbn_to_off(silofs_lba_t lba, size_t kbn)
{
	return silofs_lba_to_off(lba) + (silofs_lba_t)(kbn * SILOFS_KB_SIZE);
}

static silofs_lba_t lba_plus(silofs_lba_t lba, size_t nlbk)
{
	return lba + (silofs_lba_t)nlbk;
}

void silofs_vaddr_by_spleaf(struct silofs_vaddr *vaddr,
                            enum silofs_ltype ltype, loff_t voff_base,
                            size_t bn, size_t kbn)
{
	const silofs_lba_t lba_base = silofs_off_to_lba(voff_base);
	const silofs_lba_t lba = lba_plus(lba_base, bn);
	const loff_t off = lba_kbn_to_off(lba, kbn);

	silofs_vaddr_setup(vaddr, ltype, off);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_vaddr56 s_vaddr56_null = {
	.b = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
};

void silofs_vaddr56_htox(struct silofs_vaddr56 *vadr, loff_t off)
{
	const uint64_t uoff = (uint64_t)off;

	if (!silofs_off_isnull(off)) {
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
	vadr->voff_ltype = cpu_to_voff_ltype(vaddr->off, vaddr->ltype);
}

void silofs_vaddr64_xtoh(const struct silofs_vaddr64 *vadr,
                         struct silofs_vaddr *vaddr)
{
	loff_t voff;
	enum silofs_ltype ltype;

	voff_ltype_to_cpu(vadr->voff_ltype, &voff, &ltype);
	silofs_vaddr_setup(vaddr, ltype, voff);
}
