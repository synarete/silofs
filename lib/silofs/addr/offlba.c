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
#include <silofs/ondisk.h>
#include <silofs/infra.h>
#include <silofs/addr.h>

bool silofs_off_isnull(off_t off)
{
	SILOFS_STATICASSERT_LT(SILOFS_OFF_NULL, 0);

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

off_t silofs_off_remainder(off_t off, size_t len)
{
	return off % (ssize_t)len;
}

off_t silofs_off_align(off_t off, ssize_t align)
{
	return (off / align) * align;
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
	if (!silofs_off_isnull(off)) {
		const int64_t off64 = (int64_t)off;

		if ((off < 0) || (off64 == INT64_MAX)) {
			return -SILOFS_EFSCORRUPTED;
		}
	}
	return 0;
}
