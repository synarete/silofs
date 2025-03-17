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
#include <silofs/infra.h>
#include "str.h"
#include "htox.h"
#include "offlba.h"
#include "volid.h"
#include "paddr.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

uint32_t silofs_ptype_size(enum silofs_ptype ptype)
{
	switch (ptype) {
	case SILOFS_PTYPE_CHKPT:
		return sizeof(struct silofs_chkpt_node);
	case SILOFS_PTYPE_BTNODE:
		return sizeof(struct silofs_btree_node);
	case SILOFS_PTYPE_NONE:
	case SILOFS_PTYPE_DATA:
	case SILOFS_PTYPE_LAST:
	default:
		break;
	}
	return 0;
}

static bool ptype_isdata(enum silofs_ptype ptype)
{
	bool ret;

	switch (ptype) {
	case SILOFS_PTYPE_DATA:
		ret = true;
		break;
	case SILOFS_PTYPE_CHKPT:
	case SILOFS_PTYPE_BTNODE:
	case SILOFS_PTYPE_NONE:
	case SILOFS_PTYPE_LAST:
	default:
		ret = false;
		break;
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_pvsid s_pvsid_none = {
	.index = 0,
};

const struct silofs_pvsid *silofs_pvsid_none(void)
{
	return &s_pvsid_none;
}

void silofs_pvsid_init(struct silofs_pvsid *pvsid,
                       const struct silofs_volid *volid, uint32_t idx)
{
	silofs_volid_assign(&pvsid->volid, volid);
	pvsid->index = idx;
}

void silofs_pvsid_fini(struct silofs_pvsid *pvsid)
{
	silofs_volid_reset(&pvsid->volid);
	pvsid->index = 0;
}

bool silofs_pvsid_isnull(const struct silofs_pvsid *pvsid)
{
	return (pvsid->index == 0);
}

bool silofs_pvsid_has_volid(const struct silofs_pvsid *pvsid,
                            const struct silofs_volid *volid)
{
	return silofs_volid_isequal(&pvsid->volid, volid);
}

void silofs_pvsid_generate(struct silofs_pvsid *pvsid)
{
	silofs_volid_generate(&pvsid->volid);
	pvsid->index = 1;
}

void silofs_pvsid_reset(struct silofs_pvsid *pvsid)
{
	silofs_volid_reset(&pvsid->volid);
	pvsid->index = 0;
}

void silofs_pvsid_assign(struct silofs_pvsid *pvsid,
                         const struct silofs_pvsid *other)
{
	silofs_volid_assign(&pvsid->volid, &other->volid);
	pvsid->index = other->index;
}

static long pvsid_compare(const struct silofs_pvsid *pvsid1,
                          const struct silofs_pvsid *pvsid2)
{
	long cmp;

	cmp = silofs_volid_compare(&pvsid1->volid, &pvsid2->volid);
	if (cmp) {
		return cmp;
	}
	cmp = (long)(pvsid2->index) - (long)(pvsid1->index);
	if (cmp) {
		return cmp;
	}
	return 0;
}

bool silofs_pvsid_isequal(const struct silofs_pvsid *pvsid,
                          const struct silofs_pvsid *other)
{
	return pvsid_compare(pvsid, other) == 0;
}

uint64_t silofs_pvsid_hash64(const struct silofs_pvsid *pvsid)
{
	struct silofs_pvsid32b pvsid32b;

	silofs_pvsid32b_htox(&pvsid32b, pvsid);
	return silofs_hash_xxh64(&pvsid32b, sizeof(pvsid32b), pvsid->index);
}

void silofs_pvsid_to_str(const struct silofs_pvsid *pvsid,
                         struct silofs_strbuf *out_sbuf)
{
	struct silofs_strbuf sbuf;

	silofs_volid_to_str(&pvsid->volid, &sbuf);
	silofs_strbuf_sprintf(out_sbuf, "%s:%u", sbuf.str, pvsid->index);
}

void silofs_pvsid32b_htox(struct silofs_pvsid32b *pvsid32,
                          const struct silofs_pvsid *pvsid)
{
	memset(pvsid32, 0, sizeof(*pvsid32));
	silofs_volid_assign(&pvsid32->volid, &pvsid->volid);
	pvsid32->index = silofs_cpu_to_le32(pvsid->index);
}

void silofs_pvsid32b_xtoh(const struct silofs_pvsid32b *pvsid32,
                          struct silofs_pvsid *pvsid)
{
	silofs_volid_assign(&pvsid->volid, &pvsid32->volid);
	pvsid->index = silofs_le32_to_cpu(pvsid32->index);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_paddr s_paddr_none = {
	.pvsid.index = 0,
	.off = SILOFS_OFF_NULL,
	.len = 0,
	.ptype = SILOFS_PTYPE_NONE,
};

const struct silofs_paddr *silofs_paddr_none(void)
{
	return &s_paddr_none;
}

bool silofs_paddr_isnull(const struct silofs_paddr *paddr)
{
	return (paddr->ptype == SILOFS_PTYPE_NONE) || !paddr->len ||
	       off_isnull(paddr->off) || silofs_pvsid_isnull(&paddr->pvsid);
}

void silofs_paddr_init(struct silofs_paddr *paddr,
                       const struct silofs_pvsid *pvsid,
                       enum silofs_ptype ptype, loff_t off, size_t len)
{
	silofs_pvsid_assign(&paddr->pvsid, pvsid);
	paddr->off = off;
	paddr->len = len;
	paddr->ptype = ptype;
}

void silofs_paddr_fini(struct silofs_paddr *paddr)
{
	silofs_pvsid_reset(&paddr->pvsid);
	paddr->off = SILOFS_OFF_NULL;
	paddr->len = 0;
	paddr->ptype = SILOFS_PTYPE_NONE;
}

void silofs_paddr_reset(struct silofs_paddr *paddr)
{
	silofs_paddr_fini(paddr);
}

void silofs_paddr_assign(struct silofs_paddr *paddr,
                         const struct silofs_paddr *other)
{
	silofs_pvsid_assign(&paddr->pvsid, &other->pvsid);
	paddr->off = other->off;
	paddr->len = other->len;
	paddr->ptype = other->ptype;
}

bool silofs_paddr_isdata(const struct silofs_paddr *paddr)
{
	return ptype_isdata(paddr->ptype);
}

long silofs_paddr_compare(const struct silofs_paddr *paddr1,
                          const struct silofs_paddr *paddr2)
{
	long cmp;

	cmp = pvsid_compare(&paddr1->pvsid, &paddr2->pvsid);
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
	cmp = (long)paddr1->ptype - (long)paddr2->ptype;
	if (cmp) {
		return cmp;
	}
	return 0;
}

bool silofs_paddr_isequal(const struct silofs_paddr *paddr1,
                          const struct silofs_paddr *paddr2)
{
	return (silofs_paddr_compare(paddr1, paddr2) == 0);
}

void silofs_paddr48b_reset(struct silofs_paddr48b *paddr48)
{
	memset(paddr48, 0, sizeof(*paddr48));
}

void silofs_paddr48b_htox(struct silofs_paddr48b *paddr48,
                          const struct silofs_paddr *paddr)
{
	silofs_paddr48b_reset(paddr48);
	silofs_pvsid32b_htox(&paddr48->pvsid, &paddr->pvsid);
	paddr48->off = silofs_cpu_to_off(paddr->off);
	paddr48->len = silofs_cpu_to_le32((uint32_t)paddr->len);
	paddr48->ptype = (uint8_t)(paddr->ptype);
}

void silofs_paddr48b_xtoh(const struct silofs_paddr48b *paddr48,
                          struct silofs_paddr *paddr)
{
	silofs_pvsid32b_xtoh(&paddr48->pvsid, &paddr->pvsid);
	paddr->off = silofs_off_to_cpu(paddr48->off);
	paddr->len = silofs_le32_to_cpu(paddr48->len);
	paddr->ptype = (enum silofs_ptype)(paddr48->ptype);
}
