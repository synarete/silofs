/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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
#include "infra.h"
#include "str.h"
#include "htox.h"
#include "offlba.h"
#include "stype.h"
#include "blobid.h"
#include "paddr.h"

static const struct silofs_paddr s_silofs_paddr_none = {
	.pos = SILOFS_OFF_NULL,
};

const struct silofs_paddr *silofs_paddr_none(void)
{
	return &s_silofs_paddr_none;
}

static void paddr_update_by(struct silofs_paddr *paddr,
                            const struct silofs_blobid56b *blobid56b)
{
	paddr->mtype = silofs_blobid56b_get_mtype(blobid56b);
}

void silofs_paddr_init(struct silofs_paddr *paddr,
                       const struct silofs_blobid56b *blobid56b, off_t pos)
{
	silofs_blobid56b_assign(&paddr->blobid56b, blobid56b);
	paddr->pos = pos;
	paddr_update_by(paddr, blobid56b);
}

void silofs_paddr_fini(struct silofs_paddr *paddr)
{
	silofs_paddr_reset(paddr);
}

void silofs_paddr_reset(struct silofs_paddr *paddr)
{
	silofs_blobid56b_reset(&paddr->blobid56b);
	paddr->pos = SILOFS_OFF_NULL;
}

void silofs_paddr_assign(struct silofs_paddr *paddr,
                         const struct silofs_paddr *other)
{
	silofs_blobid56b_copyto(&other->blobid56b, &paddr->blobid56b);
	paddr->pos   = other->pos;
	paddr->mtype = other->mtype;
}

bool silofs_paddr_isequal(const struct silofs_paddr *paddr,
                          const struct silofs_paddr *other)
{
	return (paddr->pos == other->pos) &&
	       silofs_blobid56b_isequal(&paddr->blobid56b, &other->blobid56b);
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
	cmp = silofs_blobid56b_compare(&paddr1->blobid56b, &paddr2->blobid56b);
	if (cmp) {
		return cmp;
	}
	return 0;
}

static off_t paddr_next_off(const struct silofs_paddr *paddr)
{
	const size_t len = silofs_mtype_size(paddr->mtype);

	return silofs_off_end(paddr->pos, len);
}

void silofs_paddr_next(const struct silofs_paddr *paddr,
                       struct silofs_paddr *out_next)
{
	const off_t off = paddr_next_off(paddr);

	silofs_paddr_init(out_next, &paddr->blobid56b, off);
}

void silofs_paddr64b_htox(struct silofs_paddr64b *paddr64,
                          const struct silofs_paddr *paddr)
{
	memset(paddr64, 0, sizeof(*paddr64));
	silofs_blobid56b_copyto(&paddr->blobid56b, &paddr64->blobid56b);
	paddr64->pos = silofs_cpu_to_off(paddr->pos);
}

void silofs_paddr64b_xtoh(const struct silofs_paddr64b *paddr64,
                          struct silofs_paddr *paddr)
{
	silofs_blobid56b_assign(&paddr->blobid56b, &paddr64->blobid56b);
	paddr->pos = silofs_off_to_cpu(paddr64->pos);
	paddr_update_by(paddr, &paddr64->blobid56b);
}
