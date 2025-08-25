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

static const struct silofs_paddr s_silofs_paddr_none = {
	.pos = SILOFS_OFF_nullptr,
	.mtype = SILOFS_MTYPE_NONE,
};

const struct silofs_paddr *silofs_paddr_none(void)
{
	return &s_silofs_paddr_none;
}

bool silofs_paddr_isnull(const struct silofs_paddr *paddr)
{
	return (paddr->mtype == SILOFS_MTYPE_NONE) ||
	       silofs_off_isnull(paddr->pos);
}

void silofs_paddr_init(struct silofs_paddr *paddr,
                       const struct silofs_blobid *blobid,
                       enum silofs_mtype mtype, loff_t off)
{
	silofs_blobid_assign(&paddr->blobid, blobid);
	paddr->pos = off;
	paddr->mtype = mtype;
}

void silofs_paddr_fini(struct silofs_paddr *paddr)
{
	silofs_blobid_reset(&paddr->blobid);
	paddr->pos = SILOFS_OFF_nullptr;
	paddr->mtype = SILOFS_MTYPE_NONE;
}

void silofs_paddr_reset(struct silofs_paddr *paddr)
{
	silofs_paddr_fini(paddr);
}

void silofs_paddr_assign(struct silofs_paddr *paddr,
                         const struct silofs_paddr *other)
{
	silofs_blobid_assign(&paddr->blobid, &other->blobid);
	paddr->pos = other->pos;
	paddr->mtype = other->mtype;
}

long silofs_paddr_compare(const struct silofs_paddr *paddr1,
                          const struct silofs_paddr *paddr2)
{
	long cmp;

	cmp = silofs_blobid_compare(&paddr1->blobid, &paddr2->blobid);
	if (cmp) {
		return cmp;
	}
	cmp = (long)paddr1->pos - (long)paddr2->pos;
	if (cmp) {
		return cmp;
	}
	cmp = (long)paddr1->mtype - (long)paddr2->mtype;
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
	silofs_blobid_assign(&paddr64->blobid, &paddr->blobid);
	paddr64->pos = silofs_cpu_to_off(paddr->pos);
	paddr64->mtype = silofs_cpu_to_le16((uint16_t)(paddr->mtype));
}

void silofs_paddr64b_xtoh(const struct silofs_paddr64b *paddr64,
                          struct silofs_paddr *paddr)
{
	silofs_blobid_assign(&paddr->blobid, &paddr64->blobid);
	paddr->pos = silofs_off_to_cpu(paddr64->pos);
	paddr->mtype = silofs_le16_to_cpu(paddr64->mtype);
}
