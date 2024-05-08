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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_ovid_generate(struct silofs_ovid *ovid)
{
	silofs_uuid_generate(&ovid->uuid);
}

void silofs_ovid_assign(struct silofs_ovid *ovid,
                        const struct silofs_ovid *other)
{
	silofs_uuid_assign(&ovid->uuid, &other->uuid);
}

static long ovid_compare(const struct silofs_ovid *ovid1,
                         const struct silofs_ovid *ovid2)
{
	return silofs_uuid_compare(&ovid1->uuid, &ovid2->uuid);
}

uint64_t silofs_ovid_hash64(const struct silofs_ovid *ovid)
{
	uint64_t u[2] = { 0, 0 };

	silofs_uuid_as_u64s(&ovid->uuid, u);
	return u[0] ^ u[1];
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_oaddr s_oaddr_none = {
	.index = 0,
	.off = SILOFS_OFF_NULL,
	.len = 0
};

const struct silofs_oaddr *silofs_oaddr_none(void)
{
	return &s_oaddr_none;
}

bool silofs_oaddr_isnull(const struct silofs_oaddr *oaddr)
{
	return (oaddr->otype == SILOFS_OTYPE_NONE) ||
	       !oaddr->index || !oaddr->len || off_isnull(oaddr->off);
}

void silofs_oaddr_reset(struct silofs_oaddr *oaddr)
{
	silofs_memzero(&oaddr->ovid, sizeof(oaddr->ovid));
	oaddr->index = 0;
	oaddr->otype = SILOFS_OTYPE_NONE;
	oaddr->off = SILOFS_OFF_NULL;
	oaddr->len = 0;
}

void silofs_oaddr_assign(struct silofs_oaddr *oaddr,
                         const struct silofs_oaddr *other)
{
	silofs_ovid_assign(&oaddr->ovid, &other->ovid);
	oaddr->index = other->index;
	oaddr->otype = other->otype;
	oaddr->off = other->off;
	oaddr->len = other->len;
}

long silofs_oaddr_compare(const struct silofs_oaddr *oaddr1,
                          const struct silofs_oaddr *oaddr2)
{
	long cmp;

	cmp = ovid_compare(&oaddr1->ovid, &oaddr2->ovid);
	if (cmp) {
		return cmp;
	}
	cmp = (long)oaddr1->index - (long)oaddr2->index;
	if (cmp) {
		return cmp;
	}
	cmp = (long)oaddr1->otype - (long)oaddr2->otype;
	if (cmp) {
		return cmp;
	}
	cmp = (long)oaddr1->off - (long)oaddr2->off;
	if (cmp) {
		return cmp;
	}
	cmp = (long)oaddr1->len - (long)oaddr2->len;
	if (cmp) {
		return cmp;
	}
	return 0;
}

static void
cpu_to_off_otype(uint64_t *off_otype, loff_t off, enum silofs_otype otype)
{
	uint64_t val;

	if (off_isnull(off)) {
		STATICASSERT_EQ(SILOFS_OTYPE_NONE, 0);
		val = 0;
	} else {
		val = ((uint64_t)off) << 8 | ((uint64_t)otype & 0xFF);
	}
	*off_otype = silofs_cpu_to_le64(val);
}

static void
off_otype_to_cpu(uint64_t off_otype, loff_t *off, enum silofs_otype *otype)
{
	uint64_t val;

	val = silofs_le64_to_cpu(off_otype);
	if (val == 0) {
		*off = SILOFS_OFF_NULL;
		*otype = SILOFS_OTYPE_NONE;
	} else {
		*off = (loff_t)(val >> 8);
		*otype = (enum silofs_otype)(val & 0xFF);
	}
}

void silofs_oaddr32b_reset(struct silofs_oaddr32b *oaddr32)
{
	memset(oaddr32, 0, sizeof(*oaddr32));
	oaddr32->index = 0;
	oaddr32->len = 0;
	oaddr32->off_otype = 0;
}

void silofs_oaddr32b_htox(struct silofs_oaddr32b *oaddr32,
                          const struct silofs_oaddr *oaddr)
{
	silofs_ovid_assign(&oaddr32->ovid, &oaddr->ovid);
	oaddr32->index = silofs_cpu_to_le32(oaddr->index);
	oaddr32->len = silofs_cpu_to_le32((uint32_t)(oaddr->len));
	cpu_to_off_otype(&oaddr32->off_otype, oaddr->off, oaddr->otype);
}

void silofs_oaddr32b_xtoh(const struct silofs_oaddr32b *oaddr32,
                          struct silofs_oaddr *oaddr)
{
	silofs_ovid_assign(&oaddr->ovid, &oaddr32->ovid);
	oaddr->index = silofs_le32_to_cpu(oaddr32->index);
	oaddr->len = silofs_le32_to_cpu(oaddr32->len);
	off_otype_to_cpu(oaddr32->off_otype, &oaddr->off, &oaddr->otype);
}
