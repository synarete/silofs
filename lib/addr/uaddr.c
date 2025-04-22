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
#include "crypt.h"
#include "offlba.h"
#include "htox.h"
#include "uaddr.h"

static const struct silofs_uaddr s_uaddr_none = {
	.laddr.lsid.lsize = 0,
	.laddr.lsid.ltype = SILOFS_LTYPE_NONE,
	.laddr.pos = SILOFS_OFF_NULL,
	.voff = SILOFS_OFF_NULL,
};

const struct silofs_uaddr *silofs_uaddr_none(void)
{
	return &s_uaddr_none;
}

bool silofs_uaddr_isnull(const struct silofs_uaddr *uaddr)
{
	return off_isnull(uaddr->voff) || silofs_laddr_isnull(&uaddr->laddr);
}

void silofs_uaddr_setup(struct silofs_uaddr *uaddr,
                        const struct silofs_lsid *lsid, loff_t pos,
                        loff_t voff)
{
	silofs_laddr_setup(&uaddr->laddr, lsid, pos);
	uaddr->voff = voff;
}

void silofs_uaddr_reset(struct silofs_uaddr *uaddr)
{
	silofs_laddr_reset(&uaddr->laddr);
	uaddr->voff = SILOFS_OFF_NULL;
}

void silofs_uaddr_assign(struct silofs_uaddr *uaddr,
                         const struct silofs_uaddr *other)
{
	silofs_laddr_assign(&uaddr->laddr, &other->laddr);
	uaddr->voff = other->voff;
}

long silofs_uaddr_compare(const struct silofs_uaddr *uaddr1,
                          const struct silofs_uaddr *uaddr2)
{
	long cmp;

	cmp = silofs_laddr_compare(&uaddr1->laddr, &uaddr2->laddr);
	if (cmp) {
		return cmp;
	}
	cmp = uaddr1->voff - uaddr2->voff;
	if (cmp) {
		return cmp;
	}
	return 0;
}

bool silofs_uaddr_isequal(const struct silofs_uaddr *uaddr1,
                          const struct silofs_uaddr *uaddr2)
{
	return (silofs_uaddr_compare(uaddr1, uaddr2) == 0);
}

const struct silofs_volumeid *
silofs_uaddr_volumeid(const struct silofs_uaddr *uaddr)
{
	return &uaddr->laddr.lsid.volumeid;
}

const struct silofs_lsid *silofs_uaddr_lsid(const struct silofs_uaddr *uaddr)
{
	return &uaddr->laddr.lsid;
}

enum silofs_ltype silofs_uaddr_ltype(const struct silofs_uaddr *uaddr)
{
	return silofs_laddr_ltype(&uaddr->laddr);
}

enum silofs_height silofs_uaddr_height(const struct silofs_uaddr *uaddr)
{
	return uaddr->laddr.lsid.height;
}

void silofs_uaddr64b_reset(struct silofs_uaddr64b *uaddr64)
{
	silofs_laddr48b_reset(&uaddr64->laddr);
	uaddr64->voff = silofs_off_to_cpu(SILOFS_OFF_NULL);
}

void silofs_uaddr64b_htox(struct silofs_uaddr64b *uaddr64,
                          const struct silofs_uaddr *uaddr)
{
	silofs_laddr48b_htox(&uaddr64->laddr, &uaddr->laddr);
	uaddr64->voff = silofs_cpu_to_off(uaddr->voff);
}

void silofs_uaddr64b_xtoh(const struct silofs_uaddr64b *uaddr64,
                          struct silofs_uaddr *uaddr)
{
	silofs_laddr48b_xtoh(&uaddr64->laddr, &uaddr->laddr);
	uaddr->voff = silofs_off_to_cpu(uaddr64->voff);
}
