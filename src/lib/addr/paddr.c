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

void silofs_pvid_generate(struct silofs_pvid *pvid)
{
	silofs_uuid_generate(&pvid->uuid);
}

void silofs_pvid_assign(struct silofs_pvid *pvid,
                        const struct silofs_pvid *other)
{
	silofs_uuid_assign(&pvid->uuid, &other->uuid);
}

static long pvid_compare(const struct silofs_pvid *pvid1,
                         const struct silofs_pvid *pvid2)
{
	return silofs_uuid_compare(&pvid1->uuid, &pvid2->uuid);
}

uint64_t silofs_pvid_hash64(const struct silofs_pvid *pvid)
{
	uint64_t u[2] = { 0, 0 };

	silofs_uuid_as_u64s(&pvid->uuid, u);
	return u[0] ^ u[1];
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
	return (paddr->ptype == SILOFS_PTYPE_NONE) ||
	       !paddr->index || !paddr->len || off_isnull(paddr->off);
}

void silofs_paddr_reset(struct silofs_paddr *paddr)
{
	silofs_memzero(&paddr->pvid, sizeof(paddr->pvid));
	paddr->index = 0;
	paddr->ptype = SILOFS_PTYPE_NONE;
	paddr->off = SILOFS_OFF_NULL;
	paddr->len = 0;
}

void silofs_paddr_assign(struct silofs_paddr *paddr,
                         const struct silofs_paddr *other)
{
	silofs_pvid_assign(&paddr->pvid, &other->pvid);
	paddr->index = other->index;
	paddr->ptype = other->ptype;
	paddr->off = other->off;
	paddr->len = other->len;
}

long silofs_paddr_compare(const struct silofs_paddr *paddr1,
                          const struct silofs_paddr *paddr2)
{
	long cmp;

	cmp = pvid_compare(&paddr1->pvid, &paddr2->pvid);
	if (cmp) {
		return cmp;
	}
	cmp = (long)paddr1->index - (long)paddr2->index;
	if (cmp) {
		return cmp;
	}
	cmp = (long)paddr1->ptype - (long)paddr2->ptype;
	if (cmp) {
		return cmp;
	}
	cmp = (long)paddr1->off - (long)paddr2->off;
	if (cmp) {
		return cmp;
	}
	cmp = (long)paddr1->len - (long)paddr2->len;
	if (cmp) {
		return cmp;
	}
	return 0;
}

static void
cpu_to_off_ptype(uint64_t *off_ptype, loff_t off, enum silofs_ptype ptype)
{
	uint64_t val;

	if (off_isnull(off)) {
		STATICASSERT_EQ(SILOFS_PTYPE_NONE, 0);
		val = 0;
	} else {
		val = ((uint64_t)off) << 8 | ((uint64_t)ptype & 0xFF);
	}
	*off_ptype = silofs_cpu_to_le64(val);
}

static void
off_ptype_to_cpu(uint64_t off_ptype, loff_t *off, enum silofs_ptype *ptype)
{
	uint64_t val;

	val = silofs_le64_to_cpu(off_ptype);
	if (val == 0) {
		*off = SILOFS_OFF_NULL;
		*ptype = SILOFS_PTYPE_NONE;
	} else {
		*off = (loff_t)(val >> 8);
		*ptype = (enum silofs_ptype)(val & 0xFF);
	}
}

void silofs_paddr32b_reset(struct silofs_paddr32b *paddr32)
{
	memset(paddr32, 0, sizeof(*paddr32));
	paddr32->index = 0;
	paddr32->len = 0;
	paddr32->off_ptype = 0;
}

void silofs_paddr32b_htox(struct silofs_paddr32b *paddr32,
                          const struct silofs_paddr *paddr)
{
	silofs_pvid_assign(&paddr32->pvid, &paddr->pvid);
	paddr32->index = silofs_cpu_to_le32(paddr->index);
	paddr32->len = silofs_cpu_to_le32((uint32_t)(paddr->len));
	cpu_to_off_ptype(&paddr32->off_ptype, paddr->off, paddr->ptype);
}

void silofs_paddr32b_xtoh(const struct silofs_paddr32b *paddr32,
                          struct silofs_paddr *paddr)
{
	silofs_pvid_assign(&paddr->pvid, &paddr32->pvid);
	paddr->index = silofs_le32_to_cpu(paddr32->index);
	paddr->len = silofs_le32_to_cpu(paddr32->len);
	off_ptype_to_cpu(paddr32->off_ptype, &paddr->off, &paddr->ptype);
}
