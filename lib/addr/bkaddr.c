/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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


static const struct silofs_bkaddr s_bkaddr_none = {
	.lba = SILOFS_LBA_NULL,
};

const struct silofs_bkaddr *silofs_bkaddr_none(void)
{
	return &s_bkaddr_none;
}

void silofs_bkaddr_setup(struct silofs_bkaddr *bkaddr,
                         const struct silofs_lsegid *lsegid,
                         silofs_lba_t abs_lba)
{
	loff_t pos;
	loff_t abs_off;
	silofs_lba_t lba;

	if (silofs_lba_isnull(abs_lba)) {
		pos = SILOFS_OFF_NULL;
		lba = SILOFS_LBA_NULL;
	} else {
		abs_off = silofs_lba_to_off(abs_lba);
		pos = silofs_lsegid_pos(lsegid, abs_off);
		lba = off_to_lba(pos);
	}

	silofs_laddr_setup(&bkaddr->laddr, lsegid, pos, SILOFS_LBK_SIZE);
	bkaddr->lba = lba;
}

void silofs_bkaddr_reset(struct silofs_bkaddr *bkaddr)
{
	silofs_laddr_reset(&bkaddr->laddr);
	bkaddr->lba = SILOFS_LBA_NULL;
}

void silofs_bkaddr_by_off(struct silofs_bkaddr *bkaddr,
                          const struct silofs_lsegid *lsegid, loff_t off)
{
	silofs_bkaddr_setup(bkaddr, lsegid, off_to_lba(off));
}

void silofs_bkaddr_by_laddr(struct silofs_bkaddr *bkaddr,
                            const struct silofs_laddr *laddr)
{
	const silofs_lba_t lba = off_to_lba(laddr->pos);

	silofs_bkaddr_setup(bkaddr, &laddr->lsegid, lba);
}

bool silofs_bkaddr_isequal(const struct silofs_bkaddr *bkaddr,
                           const struct silofs_bkaddr *other)
{
	return ((bkaddr->lba == other->lba) &&
	        silofs_laddr_isequal(&bkaddr->laddr, &other->laddr));
}

long silofs_bkaddr_compare(const struct silofs_bkaddr *bkaddr1,
                           const struct silofs_bkaddr *bkaddr2)
{
	long cmp;

	cmp = bkaddr1->lba - bkaddr2->lba;
	if (cmp) {
		return cmp;
	}
	cmp = silofs_laddr_compare(&bkaddr1->laddr, &bkaddr2->laddr);
	if (cmp) {
		return cmp;
	}
	return 0;
}

void silofs_bkaddr_assign(struct silofs_bkaddr *bkaddr,
                          const struct silofs_bkaddr *other)
{
	silofs_laddr_assign(&bkaddr->laddr, &other->laddr);
	bkaddr->lba = other->lba;
}

bool silofs_bkaddr_isnull(const struct silofs_bkaddr *bkaddr)
{
	return silofs_lba_isnull(bkaddr->lba) ||
	       silofs_laddr_isnull(&bkaddr->laddr);
}
