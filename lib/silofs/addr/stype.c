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
#include <silofs/addr.h>

void silofs_stype_clear(struct silofs_stype *stype)
{
	stype->ptype = SILOFS_PTYPE_NONE;
	stype->ltype = SILOFS_LTYPE_NONE;
}

void silofs_stype_assign(struct silofs_stype *stype,
                         const struct silofs_stype *other)
{
	stype->ptype = other->ptype;
	stype->ltype = other->ltype;
}

long silofs_stype_compare(const struct silofs_stype *stype,
                          const struct silofs_stype *other)
{
	long cmp;

	if (stype->ptype != other->ptype) {
		cmp = (long)stype->ptype - (long)other->ptype;
	} else if (stype->ltype != other->ltype) {
		cmp = (long)stype->ltype - (long)other->ltype;
	} else {
		cmp = 0;
	}
	return cmp;
}

size_t silofs_stype_size(const struct silofs_stype *stype)
{
	size_t sz;

	if (stype->ptype == SILOFS_PTYPE_LNODE) {
		sz = silofs_ltype_size(stype->ltype);
	} else {
		sz = silofs_ptype_size(stype->ptype);
	}
	return sz;
}
