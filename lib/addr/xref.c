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
#include "str.h"
#include "caddr.h"
#include "xref.h"

void silofs_xref_reset(struct silofs_xref *xref)
{
	memset(xref->s, 0, sizeof(xref->s));
}

bool silofs_xref_isnull(const struct silofs_xref *xref)
{
	return xref->s[0] == '\0';
}

void silofs_xref_from_caddr(struct silofs_xref *xref,
                            const struct silofs_caddr *caddr)
{
	silofs_caddr_to_str(caddr, xref->s, sizeof(xref->s));
}

int silofs_xref_to_caddr(const struct silofs_xref *xref,
                         struct silofs_caddr *out_caddr)
{
	const size_t lim = sizeof(xref->s);
	const size_t n = silofs_str_nlength(xref->s, lim);
	int ret = -SILOFS_EINVAL;

	if (n < lim) {
		ret = silofs_caddr_from_str(out_caddr, xref->s, n);
	}
	return ret;
}

static int
expect_ctype(const struct silofs_caddr *caddr, enum silofs_ctype ctype_expect)
{
	int err = 0;

	if (caddr->ctype != ctype_expect) {
		switch (ctype_expect) {
		case SILOFS_CTYPE_MBR:
			err = -SILOFS_EBADMBR;
			break;
		case SILOFS_CTYPE_PACKIDX:
			err = -SILOFS_EBADPACK;
			break;
		case SILOFS_CTYPE_ENCSEG:
		case SILOFS_CTYPE_NONE:
		default:
			err = -SILOFS_EINVAL;
			break;
		}
	}
	return err;
}

int silofs_xref_to_caddr_with(const struct silofs_xref *xref,
                              enum silofs_ctype ctype_expect,
                              struct silofs_caddr *out_caddr)
{
	int err;

	err = silofs_xref_to_caddr(xref, out_caddr);
	if (!err) {
		err = expect_ctype(out_caddr, ctype_expect);
	}
	return err;
}
