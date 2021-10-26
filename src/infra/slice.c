/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2021 Shachar Sharon
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
#include <silofs/infra/utility.h>
#include <silofs/infra/slice.h>
#include <string.h>
#include <stdint.h>

void silofs_slice_init(struct silofs_slice *sl, void *p, size_t n)
{
	sl->ptr = p;
	sl->cap = n;
	sl->len = 0;
}

void silofs_slice_fini(struct silofs_slice *sl)
{
	sl->ptr = NULL;
	sl->cap = 0;
	sl->len = 0;
}

static size_t slice_rem(const struct silofs_slice *sl)
{
	return (sl->cap - sl->len);
}

static size_t slice_append_cnt(const struct silofs_slice *sl, size_t len_want)
{
	return silofs_min(len_want, slice_rem(sl));
}

static uint8_t *slice_end(const struct silofs_slice *sl)
{
	return (uint8_t *)sl->ptr + sl->len;
}

void *silofs_slice_end(const struct silofs_slice *sl)
{
	return slice_end(sl);
}

size_t silofs_slice_append(struct silofs_slice *sl, const void *p, size_t len)
{
	const size_t cnt = slice_append_cnt(sl, len);

	memcpy(slice_end(sl), p, cnt);
	sl->len += cnt;
	return cnt;
}

