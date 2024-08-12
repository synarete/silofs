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

static const struct silofs_psegid s_psegid_none = {
	.index = 0,
	.ptype = SILOFS_PTYPE_NONE,
};

const struct silofs_psegid *silofs_psegid_none(void)
{
	return &s_psegid_none;
}

bool silofs_psegid_isnull(const struct silofs_psegid *psegid)
{
	return (psegid->ptype == SILOFS_PTYPE_NONE) || (psegid->index == 0);
}

bool silofs_psegid_has_pvid(const struct silofs_psegid *psegid,
                            const struct silofs_pvid *pvid)
{
	return silofs_pvid_isequal(&psegid->pvid, pvid);
}

void silofs_psegid_reset(struct silofs_psegid *psegid)
{
	pvid_reset(&psegid->pvid);
	psegid->index = 0;
	psegid->ptype = SILOFS_PTYPE_NONE;
}

void silofs_psegid_assign(struct silofs_psegid *psegid,
                          const struct silofs_psegid *other)
{
	silofs_pvid_assign(&psegid->pvid, &other->pvid);
	psegid->index = other->index;
	psegid->ptype = other->ptype;
}

static long psegid_compare(const struct silofs_psegid *psegid1,
                           const struct silofs_psegid *psegid2)
{
	long cmp;

	cmp = pvid_compare(&psegid1->pvid, &psegid2->pvid);
	if (cmp) {
		return cmp;
	}
	cmp = (long)(psegid2->index) - (long)(psegid1->index);
	if (cmp) {
		return cmp;
	}
	cmp = (long)(psegid2->ptype) - (long)(psegid1->ptype);
	if (cmp) {
		return cmp;
	}
	return 0;
}

bool silofs_psegid_isequal(const struct silofs_psegid *psegid,
                           const struct silofs_psegid *other)
{
	return psegid_compare(psegid, other) == 0;
}

uint64_t silofs_psegid_hash64(const struct silofs_psegid *psegid)
{
	struct silofs_psegid32b psegid32b;
	const uint64_t seed1 = ((uint64_t)psegid->index) << 11;
	const uint64_t seed2 = (uint64_t)psegid->ptype;

	silofs_psegid32b_htox(&psegid32b, psegid);
	return silofs_hash_xxh64(&psegid32b, sizeof(psegid32b), seed1 | seed2);
}

void silofs_psegid32b_htox(struct silofs_psegid32b *psegid32,
                           const struct silofs_psegid *psegid)
{
	memset(psegid32, 0, sizeof(*psegid32));
	silofs_pvid_assign(&psegid32->pvid, &psegid->pvid);
	psegid32->index = silofs_cpu_to_le32(psegid->index);
	psegid32->ptype = (uint8_t)psegid->ptype;
}

void silofs_psegid32b_xtoh(const struct silofs_psegid32b *psegid32,
                           struct silofs_psegid *psegid)
{
	silofs_pvid_assign(&psegid->pvid, &psegid32->pvid);
	psegid->index = silofs_le32_to_cpu(psegid32->index);
	psegid->ptype = (enum silofs_ptype)psegid32->ptype;
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
	return silofs_psegid_isnull(&paddr->psid) ||
	       !paddr->len || off_isnull(paddr->off);
}

void silofs_paddr_reset(struct silofs_paddr *paddr)
{
	silofs_psegid_reset(&paddr->psid);
	paddr->off = SILOFS_OFF_NULL;
	paddr->len = 0;
}

void silofs_paddr_assign(struct silofs_paddr *paddr,
                         const struct silofs_paddr *other)
{
	silofs_psegid_assign(&paddr->psid, &other->psid);
	paddr->off = other->off;
	paddr->len = other->len;
}

long silofs_paddr_compare(const struct silofs_paddr *paddr1,
                          const struct silofs_paddr *paddr2)
{
	long cmp;

	cmp = psegid_compare(&paddr1->psid, &paddr2->psid);
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
	silofs_psegid32b_htox(&paddr48->psid, &paddr->psid);
	paddr48->off = silofs_cpu_to_off(paddr->off);
	paddr48->len = silofs_cpu_to_le32((uint32_t)paddr->len);
}

void silofs_paddr48b_xtoh(const struct silofs_paddr48b *paddr48,
                          struct silofs_paddr *paddr)
{
	silofs_psegid32b_xtoh(&paddr48->psid, &paddr->psid);
	paddr->off = silofs_off_to_cpu(paddr48->off);
	paddr->len = silofs_le32_to_cpu(paddr48->len);
}
