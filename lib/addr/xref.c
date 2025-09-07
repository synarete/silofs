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
#include "baddr.h"
#include "xref.h"

void silofs_xref_reset(struct silofs_xref *xref)
{
	memset(xref->s, 0, sizeof(xref->s));
}

bool silofs_xref_isnull(const struct silofs_xref *xref)
{
	return xref->s[0] == '\0';
}

void silofs_xref_from_baddr(struct silofs_xref *xref,
                            const struct silofs_baddr *baddr)
{
	silofs_baddr_to_str(baddr, xref->s, sizeof(xref->s));
}

static int
xref_to_strview(const struct silofs_xref *xref, struct silofs_strview *out_sv)
{
	struct silofs_strview sv;

	silofs_strview_init(&sv, xref->s);
	silofs_strview_strip_ws(&sv, out_sv);
	return silofs_strview_isascii(out_sv) ? 0 : -SILOFS_EILLSTR;
}

static int strview_to_baddr(const struct silofs_strview *sv,
                            struct silofs_baddr *out_baddr)
{
	return silofs_baddr_from_str(out_baddr, sv->str, sv->len);
}

int silofs_xref_to_baddr(const struct silofs_xref *xref,
                         struct silofs_baddr *out_baddr)
{
	struct silofs_strview sv = { .len = 0 };
	int err;

	err = xref_to_strview(xref, &sv);
	if (!err) {
		err = strview_to_baddr(&sv, out_baddr);
	}
	return err;
}
