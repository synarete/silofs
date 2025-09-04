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
#include <silofs/ondisk.h>
#include "infra.h"
#include "offlba.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_off_isnull(off_t off)
{
	SILOFS_STATICASSERT_LT(SILOFS_OFF_nullptr, 0);

	return (off < 0);
}

off_t silofs_off_min(off_t off1, off_t off2)
{
	return (off1 < off2) ? off1 : off2;
}

off_t silofs_off_max(off_t off1, off_t off2)
{
	return (off1 > off2) ? off1 : off2;
}

off_t silofs_off_end(off_t off, size_t len)
{
	return off + (off_t)len;
}

silofs_lba_t silofs_off_to_lba(off_t off)
{
	return !silofs_off_isnull(off) ? (off / SILOFS_LBK_SIZE) :
	                                 SILOFS_LBA_nullptr;
}

off_t silofs_off_in_lbk(off_t off)
{
	return silofs_off_remainder(off, SILOFS_LBK_SIZE);
}

off_t silofs_off_next_lbk(off_t off)
{
	return silofs_off_next(off, SILOFS_LBK_SIZE);
}

off_t silofs_off_remainder(off_t off, size_t len)
{
	return off % (ssize_t)len;
}

off_t silofs_off_align(off_t off, ssize_t align)
{
	return (off / align) * align;
}

off_t silofs_off_align_to_lbk(off_t off)
{
	return silofs_off_align(off, SILOFS_LBK_SIZE);
}

off_t silofs_off_next(off_t off, ssize_t len)
{
	return silofs_off_align(off + len, len);
}

ssize_t silofs_off_diff(off_t beg, off_t end)
{
	return end - beg;
}

ssize_t silofs_off_len(off_t beg, off_t end)
{
	return silofs_off_diff(beg, end);
}

size_t silofs_off_ulen(off_t beg, off_t end)
{
	return (size_t)silofs_off_len(beg, end);
}

int silofs_verify_off(off_t off)
{
	return (silofs_off_isnull(off) || (off >= 0)) ? 0 :
	                                                -SILOFS_EFSCORRUPTED;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool lba_isequal(silofs_lba_t lba1, silofs_lba_t lba2)
{
	return (lba1 == lba2);
}

bool silofs_lba_isnull(silofs_lba_t lba)
{
	return lba_isequal(lba, SILOFS_LBA_nullptr);
}

off_t silofs_lba_to_off(silofs_lba_t lba)
{
	return !silofs_lba_isnull(lba) ? (lba * SILOFS_LBK_SIZE) :
	                                 SILOFS_OFF_nullptr;
}
