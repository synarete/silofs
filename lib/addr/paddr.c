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
#include "str.h"
#include "htox.h"
#include "offlba.h"
#include "blobid.h"
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

static const struct silofs_paddr s_silofs_paddr_none = {
	.blobidx.index = 0,
	.off = SILOFS_OFF_NULL,
	.len = 0,
	.ptype = SILOFS_PTYPE_NONE,
};

const struct silofs_paddr *silofs_paddr_none(void)
{
	return &s_silofs_paddr_none;
}

bool silofs_paddr_isnull(const struct silofs_paddr *paddr)
{
	return (paddr->ptype == SILOFS_PTYPE_NONE) || !paddr->len ||
	       silofs_off_isnull(paddr->off) ||
	       silofs_blobidx_isnull(&paddr->blobidx);
}

void silofs_paddr_init(struct silofs_paddr *paddr,
                       const struct silofs_blobidx *blobidx,
                       enum silofs_ptype ptype, loff_t off, size_t len)
{
	silofs_blobidx_assign(&paddr->blobidx, blobidx);
	paddr->off = off;
	paddr->len = len;
	paddr->ptype = ptype;
}

void silofs_paddr_fini(struct silofs_paddr *paddr)
{
	silofs_blobidx_reset(&paddr->blobidx);
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
	silofs_blobidx_assign(&paddr->blobidx, &other->blobidx);
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

	cmp = silofs_blobidx_compare(&paddr1->blobidx, &paddr2->blobidx);
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

void silofs_paddr64b_reset(struct silofs_paddr64b *paddr64)
{
	memset(paddr64, 0, sizeof(*paddr64));
}

void silofs_paddr64b_htox(struct silofs_paddr64b *paddr64,
                          const struct silofs_paddr *paddr)
{
	silofs_paddr64b_reset(paddr64);
	silofs_blobidx32b_htox(&paddr64->blobidx, &paddr->blobidx);
	paddr64->off = silofs_cpu_to_off(paddr->off);
	paddr64->len = silofs_cpu_to_le32((uint32_t)paddr->len);
	paddr64->ptype = (uint8_t)(paddr->ptype);
}

void silofs_paddr64b_xtoh(const struct silofs_paddr64b *paddr64,
                          struct silofs_paddr *paddr)
{
	silofs_blobidx32b_xtoh(&paddr64->blobidx, &paddr->blobidx);
	paddr->off = silofs_off_to_cpu(paddr64->off);
	paddr->len = silofs_le32_to_cpu(paddr64->len);
	paddr->ptype = (enum silofs_ptype)(paddr64->ptype);
}
