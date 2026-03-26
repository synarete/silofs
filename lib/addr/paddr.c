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
#include <silofs/infra.h>
#include <silofs/str.h>
#include <silofs/addr.h>

static const struct silofs_paddr s_silofs_paddr_none = {
	.ptype = SILOFS_PTYPE_NONE,
	.pos   = SILOFS_OFF_NULL,
};

const struct silofs_paddr *silofs_paddr_none(void)
{
	return &s_silofs_paddr_none;
}

void silofs_paddr_init(struct silofs_paddr *paddr,
                       const struct silofs_blobid *blobid, off_t pos)
{
	silofs_blobid_assign(&paddr->blobid, blobid);
	paddr->pos   = pos;
	paddr->ptype = blobid->stype.ptype;
}

void silofs_paddr_fini(struct silofs_paddr *paddr)
{
	silofs_paddr_reset(paddr);
}

void silofs_paddr_reset(struct silofs_paddr *paddr)
{
	silofs_blobid_reset(&paddr->blobid);
	paddr->pos   = SILOFS_OFF_NULL;
	paddr->ptype = SILOFS_PTYPE_NONE;
}

void silofs_paddr_assign(struct silofs_paddr *paddr,
                         const struct silofs_paddr *other)
{
	silofs_blobid_assign(&paddr->blobid, &other->blobid);
	paddr->pos   = other->pos;
	paddr->ptype = other->ptype;
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

long silofs_paddr_compare(const struct silofs_paddr *paddr,
                          const struct silofs_paddr *other)
{
	long cmp;

	cmp = (long)(paddr->pos - other->pos);
	if (cmp) {
		return cmp;
	}
	cmp = silofs_blobid_compare(&paddr->blobid, &other->blobid);
	if (cmp) {
		return cmp;
	}
	return 0;
}

static off_t paddr_next_off(const struct silofs_paddr *paddr)
{
	const size_t len = silofs_blobid_slotsize(&paddr->blobid);

	silofs_assert_gt(len, 0);
	silofs_assert_eq(paddr->pos % (long)len, 0);

	return silofs_off_end(paddr->pos, len);
}

void silofs_paddr_next(const struct silofs_paddr *paddr,
                       struct silofs_paddr *out_next)
{
	const off_t off = paddr_next_off(paddr);

	silofs_paddr_init(out_next, &paddr->blobid, off);
}

void silofs_paddr64b_htox(struct silofs_paddr64b *paddr64,
                          const struct silofs_paddr *paddr)
{
	memset(paddr64, 0, sizeof(*paddr64));
	silofs_blobid56b_htox(&paddr64->blobid56b, &paddr->blobid);
	paddr64->pos = silofs_cpu_to_off(paddr->pos);
}

void silofs_paddr64b_xtoh(const struct silofs_paddr64b *paddr64,
                          struct silofs_paddr *paddr)
{
	silofs_blobid56b_xtoh(&paddr64->blobid56b, &paddr->blobid);
	paddr->pos   = silofs_off_to_cpu(paddr64->pos);
	paddr->ptype = paddr->blobid.stype.ptype;
}
