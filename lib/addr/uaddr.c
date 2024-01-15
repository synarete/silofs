/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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
#include <silofs/addr.h>

static const struct silofs_uaddr s_uaddr_none = {
	.laddr.lsegid.size = 0,
	.laddr.pos = SILOFS_OFF_NULL,
	.laddr.ltype = SILOFS_LTYPE_NONE,
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
                        const struct silofs_lsegid *lsegid,
                        loff_t pos, enum silofs_ltype ltype, loff_t voff)
{
	const size_t lsz = ltype_size(ltype);

	silofs_laddr_setup(&uaddr->laddr, lsegid, ltype, pos, lsz);
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

const struct silofs_lvid *
silofs_uaddr_lvid(const struct silofs_uaddr *uaddr)
{
	return &uaddr->laddr.lsegid.lvid;
}

const struct silofs_lsegid *
silofs_uaddr_lsegid(const struct silofs_uaddr *uaddr)
{
	return &uaddr->laddr.lsegid;
}

enum silofs_height silofs_uaddr_height(const struct silofs_uaddr *uaddr)
{
	return uaddr->laddr.lsegid.height;
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_ulink_assign(struct silofs_ulink *ulink,
                         const struct silofs_ulink *other)
{
	silofs_ulink_assign2(ulink, &other->uaddr, &other->riv);
}

void silofs_ulink_assign2(struct silofs_ulink *ulink,
                          const struct silofs_uaddr *uaddr,
                          const struct silofs_iv *iv)
{
	silofs_uaddr_assign(&ulink->uaddr, uaddr);
	silofs_iv_assign(&ulink->riv, iv);
}

void silofs_ulink_reset(struct silofs_ulink *ulink)
{
	silofs_uaddr_reset(&ulink->uaddr);
	silofs_iv_reset(&ulink->riv);
}

void silofs_ulink_as_llink(const struct silofs_ulink *ulink,
                           struct silofs_llink *out_llink)
{
	silofs_llink_setup(out_llink, &ulink->uaddr.laddr, &ulink->riv);
}
