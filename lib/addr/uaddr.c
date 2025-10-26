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
	.laddr.pos = SILOFS_OFF_NULL,
	.voff = SILOFS_OFF_NULL,
};

const struct silofs_uaddr *silofs_uaddr_none(void)
{
	return &s_uaddr_none;
}

bool silofs_uaddr_isnull(const struct silofs_uaddr *uaddr)
{
	return silofs_off_isnull(uaddr->voff) ||
	       silofs_laddr_isnull(&uaddr->laddr);
}

void silofs_uaddr_setup(struct silofs_uaddr *uaddr,
                        const struct silofs_lsid *lsid, off_t pos, off_t voff)
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

const struct silofs_blobid *
silofs_uaddr_blobid(const struct silofs_uaddr *uaddr)
{
	return &uaddr->laddr.lsid.blobid;
}

const struct silofs_lsid *silofs_uaddr_lsid(const struct silofs_uaddr *uaddr)
{
	return &uaddr->laddr.lsid;
}

enum silofs_mtype silofs_uaddr_mtype(const struct silofs_uaddr *uaddr)
{
	return silofs_laddr_mtype(&uaddr->laddr);
}

enum silofs_height silofs_uaddr_height(const struct silofs_uaddr *uaddr)
{
	return silofs_blobid_get_height(&uaddr->laddr.lsid.blobid);
}

void silofs_uaddr128b_reset(struct silofs_uaddr128b *uaddr128)
{
	silofs_laddr96b_reset(&uaddr128->laddr);
	uaddr128->voff = silofs_off_to_cpu(SILOFS_OFF_NULL);
}

void silofs_uaddr128b_htox(struct silofs_uaddr128b *uaddr128,
                           const struct silofs_uaddr *uaddr)
{
	silofs_laddr96b_htox(&uaddr128->laddr, &uaddr->laddr);
	uaddr128->voff = silofs_cpu_to_off(uaddr->voff);
}

void silofs_uaddr128b_xtoh(const struct silofs_uaddr128b *uaddr128,
                           struct silofs_uaddr *uaddr)
{
	silofs_laddr96b_xtoh(&uaddr128->laddr, &uaddr->laddr);
	uaddr->voff = silofs_off_to_cpu(uaddr128->voff);
}
