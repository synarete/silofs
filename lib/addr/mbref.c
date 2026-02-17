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
#include "blobid.h"
#include "paddr.h"
#include "mbref.h"

void silofs_mbref_setup(struct silofs_mbref *mbref,
                        const struct silofs_blobid56bx *blobid56bx)
{
	silofs_blobid56bx_assign(&mbref->bx, blobid56bx);
}

void silofs_mbref_assign(struct silofs_mbref *mbref,
                         const struct silofs_mbref *other)
{
	silofs_mbref_setup(mbref, &other->bx);
}

void silofs_mbref_derive(struct silofs_mbref *mbref,
                         const struct silofs_mdigest_hd *md_hd,
                         const struct silofs_paddr *paddr)
{
	struct silofs_blobid56bx blobid56bx;

	silofs_assert_eq(paddr->mtype, SILOFS_MTYPE_MBR);
	silofs_assert_eq(paddr->pos, 0);

	silofs_blobid56bx_derive(&blobid56bx, md_hd, &paddr->blobid56b);
	silofs_mbref_setup(mbref, &blobid56bx);
}

bool silofs_mbref_isequal(const struct silofs_mbref *mbref,
                          const struct silofs_mbref *other)
{
	return silofs_blobid56bx_isequal(&mbref->bx, &other->bx);
}

int silofs_mbref_from_str(struct silofs_mbref *mbref, const char *str,
                          size_t len)
{
	return silofs_blobid56bx_from_str(&mbref->bx, str, len);
}

int silofs_mbref_to_str(const struct silofs_mbref *mbref, char *str, size_t n)
{
	return silofs_blobid56bx_to_str(&mbref->bx, str, n);
}

void silofs_mbrefs_assign(struct silofs_mbrefs *mbrefs,
                          const struct silofs_mbrefs *other)
{
	silofs_mbref_assign(&mbrefs->main, &other->main);
	silofs_mbref_assign(&mbrefs->base, &other->base);
	silofs_mbref_assign(&mbrefs->fork, &other->fork);
}
