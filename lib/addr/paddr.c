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

static void pvid_reset(struct silofs_pvid *pvid)
{
	memset(pvid, 0, sizeof(*pvid));
}

static long pvid_compare(const struct silofs_pvid *pvid1,
                         const struct silofs_pvid *pvid2)
{
	return silofs_uuid_compare(&pvid1->uuid, &pvid2->uuid);
}

bool silofs_pvid_isequal(const struct silofs_pvid *pvid1,
                         const struct silofs_pvid *pvid2)
{
	return (pvid_compare(pvid1, pvid2) == 0);
}

uint64_t silofs_pvid_hash64(const struct silofs_pvid *pvid)
{
	uint64_t u[2] = { 0, 0 };

	silofs_uuid_as_u64s(&pvid->uuid, u);
	return u[0] ^ u[1];
}

void silofs_pvid_to_str(const struct silofs_pvid *pvid,
                        struct silofs_strbuf *sbuf)
{
	silofs_uuid_unparse(&pvid->uuid, sbuf);
}

int silofs_pvid_from_str(struct silofs_lvid *pvid,
                         const struct silofs_strview *sv)
{
	return silofs_uuid_parse(&pvid->uuid, sv);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_psid s_psid_none = {
	.index = 0,
	.ptype = SILOFS_PTYPE_NONE,
};

const struct silofs_psid *silofs_psid_none(void)
{
	return &s_psid_none;
}

bool silofs_psid_isnull(const struct silofs_psid *psid)
{
	return (psid->ptype == SILOFS_PTYPE_NONE) || (psid->index == 0);
}

bool silofs_psid_has_pvid(const struct silofs_psid *psid,
                          const struct silofs_pvid *pvid)
{
	return silofs_pvid_isequal(&psid->pvid, pvid);
}

void silofs_psid_reset(struct silofs_psid *psid)
{
	pvid_reset(&psid->pvid);
	psid->index = 0;
	psid->ptype = SILOFS_PTYPE_NONE;
}

void silofs_psid_assign(struct silofs_psid *psid,
                        const struct silofs_psid *other)
{
	silofs_pvid_assign(&psid->pvid, &other->pvid);
	psid->index = other->index;
	psid->ptype = other->ptype;
}

static long psid_compare(const struct silofs_psid *psid1,
                         const struct silofs_psid *psid2)
{
	long cmp;

	cmp = pvid_compare(&psid1->pvid, &psid2->pvid);
	if (cmp) {
		return cmp;
	}
	cmp = (long)(psid2->index) - (long)(psid1->index);
	if (cmp) {
		return cmp;
	}
	cmp = (long)(psid2->ptype) - (long)(psid1->ptype);
	if (cmp) {
		return cmp;
	}
	return 0;
}

bool silofs_psid_isequal(const struct silofs_psid *psid,
                         const struct silofs_psid *other)
{
	return psid_compare(psid, other) == 0;
}

uint64_t silofs_psid_hash64(const struct silofs_psid *psid)
{
	struct silofs_psid32b psid32b;
	const uint64_t seed1 = ((uint64_t)psid->index) << 11;
	const uint64_t seed2 = (uint64_t)psid->ptype;

	silofs_psid32b_htox(&psid32b, psid);
	return silofs_hash_xxh64(&psid32b, sizeof(psid32b), seed1 | seed2);
}

void silofs_psid32b_htox(struct silofs_psid32b *psid32,
                         const struct silofs_psid *psid)
{
	memset(psid32, 0, sizeof(*psid32));
	silofs_pvid_assign(&psid32->pvid, &psid->pvid);
	psid32->index = silofs_cpu_to_le32(psid->index);
	psid32->ptype = (uint8_t)psid->ptype;
}

void silofs_psid32b_xtoh(const struct silofs_psid32b *psid32,
                         struct silofs_psid *psid)
{
	silofs_pvid_assign(&psid->pvid, &psid32->pvid);
	psid->index = silofs_le32_to_cpu(psid32->index);
	psid->ptype = (enum silofs_ptype)psid32->ptype;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_paddr s_paddr_none = {
	.psid.index = 0,
	.psid.ptype = SILOFS_PTYPE_NONE,
	.off = SILOFS_OFF_NULL,
	.len = 0
};

const struct silofs_paddr *silofs_paddr_none(void)
{
	return &s_paddr_none;
}

bool silofs_paddr_isnull(const struct silofs_paddr *paddr)
{
	return silofs_psid_isnull(&paddr->psid) ||
	       !paddr->len || off_isnull(paddr->off);
}

void silofs_paddr_reset(struct silofs_paddr *paddr)
{
	silofs_psid_reset(&paddr->psid);
	paddr->off = SILOFS_OFF_NULL;
	paddr->len = 0;
}

void silofs_paddr_assign(struct silofs_paddr *paddr,
                         const struct silofs_paddr *other)
{
	silofs_psid_assign(&paddr->psid, &other->psid);
	paddr->off = other->off;
	paddr->len = other->len;
}

long silofs_paddr_compare(const struct silofs_paddr *paddr1,
                          const struct silofs_paddr *paddr2)
{
	long cmp;

	cmp = psid_compare(&paddr1->psid, &paddr2->psid);
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

void silofs_paddr48b_reset(struct silofs_paddr48b *paddr48)
{
	memset(paddr48, 0, sizeof(*paddr48));
}

void silofs_paddr48b_htox(struct silofs_paddr48b *paddr48,
                          const struct silofs_paddr *paddr)
{
	silofs_paddr48b_reset(paddr48);
	silofs_psid32b_htox(&paddr48->psid, &paddr->psid);
	paddr48->off = silofs_cpu_to_off(paddr->off);
	paddr48->len = silofs_cpu_to_le32((uint32_t)paddr->len);
}

void silofs_paddr48b_xtoh(const struct silofs_paddr48b *paddr48,
                          struct silofs_paddr *paddr)
{
	silofs_psid32b_xtoh(&paddr48->psid, &paddr->psid);
	paddr->off = silofs_off_to_cpu(paddr48->off);
	paddr->len = silofs_le32_to_cpu(paddr48->len);
}
