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
#include <stdio.h>
#include "infra.h"
#include "str.h"
#include "crypt.h"
#include "htox.h"
#include "offlba.h"
#include "mtype.h"
#include "blobid.h"
#include "paddr.h"

static const struct silofs_paddr s_silofs_paddr_none = {
	.pos = SILOFS_OFF_NULL,
};

const struct silofs_paddr *silofs_paddr_none(void)
{
	return &s_silofs_paddr_none;
}

static void paddr_init_by_self(struct silofs_paddr *paddr)
{
	paddr->mtype = silofs_blobid_get_mtype(&paddr->blobid);
	paddr->btype = silofs_blobid_get_btype(&paddr->blobid);
}

void silofs_paddr_init(struct silofs_paddr *paddr,
                       const struct silofs_blobid *blobid, off_t pos)
{
	silofs_blobid_copyto(blobid, &paddr->blobid);
	paddr->pos = pos;
	paddr_init_by_self(paddr);
}

void silofs_paddr_fini(struct silofs_paddr *paddr)
{
	silofs_paddr_reset(paddr);
}

void silofs_paddr_reset(struct silofs_paddr *paddr)
{
	silofs_blobid_reset(&paddr->blobid);
	paddr->pos = SILOFS_OFF_NULL;
}

void silofs_paddr_assign(struct silofs_paddr *paddr,
                         const struct silofs_paddr *other)
{
	silofs_blobid_copyto(&other->blobid, &paddr->blobid);
	paddr->pos = other->pos;
	paddr->mtype = other->mtype;
	paddr->btype = other->btype;
}

bool silofs_paddr_isequal(const struct silofs_paddr *paddr,
                          const struct silofs_paddr *other)
{
	return (paddr->pos == other->pos) &&
	       silofs_blobid_isequal(&paddr->blobid, &other->blobid);
}

bool silofs_paddr_isnull(const struct silofs_paddr *paddr)
{
	return (paddr->pos == SILOFS_OFF_NULL);
}

long silofs_paddr_compare(const struct silofs_paddr *paddr1,
                          const struct silofs_paddr *paddr2)
{
	long cmp;

	cmp = (long)(paddr1->pos - paddr2->pos);
	if (cmp) {
		return cmp;
	}
	cmp = silofs_blobid_compare(&paddr1->blobid, &paddr2->blobid);
	if (cmp) {
		return cmp;
	}
	return 0;
}

off_t silofs_paddr_next(const struct silofs_paddr *paddr)
{
	const size_t len = silofs_mtype_size(paddr->mtype);

	return silofs_off_end(paddr->pos, len);
}

void silofs_paddr64b_htox(struct silofs_paddr64b *paddr64,
                          const struct silofs_paddr *paddr)
{
	memset(paddr64, 0, sizeof(*paddr64));
	silofs_blobid_copyto(&paddr->blobid, &paddr64->blobid);
	paddr64->pos = silofs_cpu_to_off(paddr->pos);
}

void silofs_paddr64b_xtoh(const struct silofs_paddr64b *paddr64,
                          struct silofs_paddr *paddr)
{
	silofs_blobid_copyto(&paddr64->blobid, &paddr->blobid);
	paddr->pos = silofs_off_to_cpu(paddr64->pos);
	paddr_init_by_self(paddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_bcursor s_silofs_cursor_none = {
	.blobsz = 0,
};

const struct silofs_bcursor *silofs_cursor_none(void)
{
	return &s_silofs_cursor_none;
}

void silofs_bcursor128b_reset(struct silofs_bcursor128b *bcur128)
{
	silofs_bcursor128b_htox(bcur128, silofs_cursor_none());
}

void silofs_bcursor128b_xtoh(const struct silofs_bcursor128b *bcur128,
                             struct silofs_bcursor *bcur)
{
	silofs_paddr64b_xtoh(&bcur128->paddr, &bcur->paddr);
	bcur->blobsz = silofs_le64_to_cpu(bcur128->blobsz);
}

void silofs_bcursor128b_htox(struct silofs_bcursor128b *bcur128,
                             const struct silofs_bcursor *bcur)
{
	silofs_paddr64b_htox(&bcur128->paddr, &bcur->paddr);
	bcur128->blobsz = silofs_cpu_to_le64(bcur->blobsz);
}
