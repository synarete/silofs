/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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
#include <silofs/utility.h>
#include <silofs/bytebuf.h>
#include <string.h>
#include <stdint.h>

void silofs_bytebuf_init(struct silofs_bytebuf *bb, void *p, size_t n)
{
	bb->ptr = p;
	bb->cap = n;
	bb->len = 0;
}

void silofs_bytebuf_init2(struct silofs_bytebuf *bb, void *p, size_t n)
{
	bb->ptr = p;
	bb->cap = n;
	bb->len = n;
}

void silofs_bytebuf_fini(struct silofs_bytebuf *bb)
{
	bb->ptr = NULL;
	bb->cap = 0;
	bb->len = 0;
}

void silofs_bytebuf_reset(struct silofs_bytebuf *bb)
{
	bb->ptr = NULL;
	bb->cap = 0;
	bb->len = 0;
}

static size_t bytebuf_rem(const struct silofs_bytebuf *bb)
{
	return (bb->cap - bb->len);
}

static size_t
bytebuf_append_cnt(const struct silofs_bytebuf *bb, size_t len_want)
{
	return silofs_min(len_want, bytebuf_rem(bb));
}

static uint8_t *bytebuf_at(const struct silofs_bytebuf *bb, size_t pos)
{
	return (uint8_t *)bb->ptr + pos;
}

static uint8_t *bytebuf_end(const struct silofs_bytebuf *bb)
{
	return bytebuf_at(bb, bb->len);
}

void *silofs_bytebuf_end(const struct silofs_bytebuf *bb)
{
	return bytebuf_end(bb);
}

bool silofs_bytebuf_has_free(const struct silofs_bytebuf *bb, size_t cnt)
{
	return (cnt <= bytebuf_rem(bb));
}

size_t silofs_bytebuf_append(struct silofs_bytebuf *bb,
                             const void *p, size_t len)
{
	const size_t cnt = bytebuf_append_cnt(bb, len);

	memcpy(bytebuf_end(bb), p, cnt);
	bb->len += cnt;
	return cnt;
}

size_t silofs_bytebuf_append2(struct silofs_bytebuf *bb,
                              const struct silofs_bytebuf *other)
{
	return silofs_bytebuf_append(bb, other->ptr, other->len);
}

static size_t
bytebuf_insert_cnt(const struct silofs_bytebuf *bb, size_t pos, size_t len)
{
	return (pos < bb->cap) ? silofs_min(bb->cap - pos, len) : 0;
}

size_t silofs_bytebuf_insert(struct silofs_bytebuf *bb, size_t pos,
                             const void *p, size_t len)
{
	const size_t cnt = bytebuf_insert_cnt(bb, pos, len);
	const size_t end = pos + cnt;

	memcpy(bytebuf_at(bb, pos), p, cnt);
	bb->len = silofs_max(bb->len, end);
	return cnt;
}



