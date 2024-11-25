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
#include <silofs/errors.h>
#include <silofs/infra.h>
#include <silofs/addr.h>

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_off_isnull(loff_t off)
{
	STATICASSERT_LT(SILOFS_OFF_NULL, 0);

	return (off < 0);
}

loff_t silofs_off_min(loff_t off1, loff_t off2)
{
	return (off1 < off2) ? off1 : off2;
}

loff_t silofs_off_max(loff_t off1, loff_t off2)
{
	return (off1 > off2) ? off1 : off2;
}

loff_t silofs_off_end(loff_t off, size_t len)
{
	return off + (loff_t)len;
}

silofs_lba_t silofs_off_to_lba(loff_t off)
{
	return !silofs_off_isnull(off) ? (off / SILOFS_LBK_SIZE) :
					 SILOFS_LBA_NULL;
}

loff_t silofs_off_in_lbk(loff_t off)
{
	return silofs_off_remainder(off, SILOFS_LBK_SIZE);
}

loff_t silofs_off_next_lbk(loff_t off)
{
	return silofs_off_next(off, SILOFS_LBK_SIZE);
}

loff_t silofs_off_remainder(loff_t off, size_t len)
{
	return off % (ssize_t)len;
}

loff_t silofs_off_align(loff_t off, ssize_t align)
{
	return (off / align) * align;
}

loff_t silofs_off_align_to_lbk(loff_t off)
{
	return silofs_off_align(off, SILOFS_LBK_SIZE);
}

loff_t silofs_off_next(loff_t off, ssize_t len)
{
	return silofs_off_align(off + len, len);
}

ssize_t silofs_off_diff(loff_t beg, loff_t end)
{
	return end - beg;
}

ssize_t silofs_off_len(loff_t beg, loff_t end)
{
	return silofs_off_diff(beg, end);
}

size_t silofs_off_ulen(loff_t beg, loff_t end)
{
	return (size_t)silofs_off_len(beg, end);
}

int silofs_verify_off(loff_t off)
{
	return (off_isnull(off) || (off >= 0)) ? 0 : -SILOFS_EFSCORRUPTED;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool lba_isequal(silofs_lba_t lba1, silofs_lba_t lba2)
{
	return (lba1 == lba2);
}

bool silofs_lba_isnull(silofs_lba_t lba)
{
	return lba_isequal(lba, SILOFS_LBA_NULL);
}

loff_t silofs_lba_to_off(silofs_lba_t lba)
{
	return !silofs_lba_isnull(lba) ? (lba * SILOFS_LBK_SIZE) :
					 SILOFS_OFF_NULL;
}
